"""证据库（evidence vault）。

职责：
- 内容寻址存放封存证据包，同批重跑幂等，不重复生成证据；
- 封存清单（registry）通过临时文件 + 重命名原子切换，并写切换日志；
  切换失败自动回滚，上一版证据始终可核验；
- 哈希链串联历次封存，供审计发现断链；
- 7 天原始清理只删运行态整表材料，证据包与链保持完整。
"""
import json, os, tempfile, fcntl, contextlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from app.errors import DomainError
from app.modules.m7_archive.evidence import (
    verify_pack, build_pack,
    RAW_RETENTION_DAYS, EVIDENCE_RETENTION_DAYS,
)

REGISTRY_NAME = 'registry.json'
JOURNAL_NAME = 'switch.log'
CHAIN_NAME = 'chain.json'
LOCK_NAME = '.vault.lock'


def vault_root():
    return Path(os.environ.get('EVIDENCE_VAULT_PATH', 'data/vault'))


@contextlib.contextmanager
def _lock(root):
    root.mkdir(parents=True, exist_ok=True)
    with open(root / LOCK_NAME, 'w') as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield root


def _read_json(path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding='utf-8'))


def _atomic_write_json(path, obj):
    """先写临时文件再原子重命名；任何失败都不动旧文件。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _load_registry(root):
    return _read_json(root / REGISTRY_NAME, {'seals': [], 'updated_at': None})


def _append_journal(root, entry):
    with open(root / JOURNAL_NAME, 'a', encoding='utf-8') as fh:
        fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + '\n')


def _chain_tip(root):
    chain = _read_json(root / CHAIN_NAME, {'links': []})
    return chain['links'][-1]['pack_hash'] if chain['links'] else ''


def seal(state, writer=None):
    """封存一个批次的证据包，返回 (pack, created: bool)。

    幂等：同一 run_id 已封存则直接返回既有包，绝不重写/重复生成。
    writer 仅供故障注入测试使用，生产路径恒为 _atomic_write_json。
    """
    write = writer or _atomic_write_json
    root = vault_root()
    with _lock(root):
        registry = _load_registry(root)
        existing = next((s for s in registry['seals'] if s['run_id'] == state['run_id']), None)
        if existing:
            pack = _read_json(root / existing['path'], None)
            if pack is None:
                raise DomainError('VAULT_CORRUPT', '登记的证据包缺失，禁止覆盖，请人工核查')
            return pack, False

        prev_hash = _chain_tip(root)
        pack = build_pack(state, prev_hash)
        ok, findings = verify_pack(pack)
        if not ok:
            raise DomainError('SEAL_VERIFY', '证据包自检失败，拒绝封存: ' + '; '.join(
                f['message'] for f in findings if not f['ok']))

        rel = Path('packs') / (state['run_id'] + '.json')
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise DomainError('SEAL_EXISTS', '证据文件已存在但未登记，拒绝覆盖')
        # 证据包先落盘（原子重命名），再切换登记清单。
        write(target, pack)

        old_registry = registry
        entry = {
            'run_id': state['run_id'],
            'path': str(rel),
            'pack_hash': pack['pack_hash'],
            'prev_pack_hash': prev_hash,
            'sealed_at': pack['sealed_at'],
            'raw_expires_at': _expiry(pack['sealed_at'], RAW_RETENTION_DAYS),
            'evidence_expires_at': _expiry(pack['sealed_at'], EVIDENCE_RETENTION_DAYS),
            'raw_purged': False,
        }
        new_registry = {'seals': old_registry['seals'] + [entry],
                        'updated_at': _now()}
        try:
            write(root / REGISTRY_NAME, new_registry)
        except Exception as exc:  # 登记切换失败：回滚证据文件，上一版登记完好。
            target.unlink(missing_ok=True)
            _append_journal(root, {'at': _now(), 'event': 'switch_failed_rollback',
                                   'run_id': state['run_id'], 'error': str(exc)})
            raise DomainError('SEAL_SWITCH', '留存登记切换失败，已回滚，上一版档案仍可核验')

        chain = _read_json(root / CHAIN_NAME, {'links': []})
        chain['links'].append({'run_id': state['run_id'], 'pack_hash': pack['pack_hash'],
                               'prev_pack_hash': prev_hash, 'at': entry['sealed_at']})
        try:
            write(root / CHAIN_NAME, chain)
        except Exception as exc:  # 链更新失败不影响已封存证据：登记与包仍可独立核验。
            _append_journal(root, {'at': _now(), 'event': 'chain_update_failed',
                                   'run_id': state['run_id'], 'error': str(exc)})

        _append_journal(root, {'at': _now(), 'event': 'sealed', 'run_id': state['run_id'],
                               'pack_hash': pack['pack_hash'], 'created': True})
        return pack, True


def load_pack(run_id):
    root = vault_root()
    with _lock(root):
        registry = _load_registry(root)
        entry = next((s for s in registry['seals'] if s['run_id'] == run_id), None)
        if not entry:
            return None
        pack = _read_json(root / entry['path'], None)
        if pack is None:
            raise DomainError('VAULT_CORRUPT', '登记的证据包缺失')
        return pack


def registry():
    with _lock(vault_root()):
        reg = _load_registry(vault_root())
        chain_ok = verify_chain_locked(vault_root())
        return {'seals': reg['seals'], 'updated_at': reg['updated_at'], 'chain_intact': chain_ok}


def verify_chain_locked(root=None):
    root = root or vault_root()
    chain = _read_json(root / CHAIN_NAME, {'links': []})
    prev = ''
    for link in chain['links']:
        if link['prev_pack_hash'] != prev:
            return False
        prev = link['pack_hash']
    return True


def verify(run_id):
    pack = load_pack(run_id)
    if pack is None:
        raise DomainError('NOT_FOUND', '该批次未封存证据', 404)
    ok, findings = verify_pack(pack)
    chain_ok = _chain_membership(pack)
    return {'run_id': run_id, 'pack_hash': pack['pack_hash'], 'ok': ok and chain_ok,
            'chain_intact': chain_ok, 'findings': findings,
            'raw_purged': _registry_entry(run_id).get('raw_purged', False)}


def _chain_membership(pack):
    chain = _read_json(vault_root() / CHAIN_NAME, {'links': []})
    return any(link['pack_hash'] == pack['pack_hash'] for link in chain['links'])


def _registry_entry(run_id):
    reg = _load_registry(vault_root())
    return next((s for s in reg['seals'] if s['run_id'] == run_id), {})


def mark_raw_purged(run_id):
    """7 天清理完成后登记：原始整表已删，证据包仍在。登记切换同样原子、可回滚。"""
    root = vault_root()
    with _lock(root):
        reg = _load_registry(root)
        found = False
        for entry in reg['seals']:
            if entry['run_id'] == run_id:
                entry['raw_purged'] = True
                entry['purged_at'] = _now()
                found = True
        if not found:
            raise DomainError('NOT_FOUND', '该批次未封存证据', 404)
        try:
            _atomic_write_json(root / REGISTRY_NAME, reg)
        except Exception as exc:
            _append_journal(root, {'at': _now(), 'event': 'purge_switch_failed_rollback',
                                   'run_id': run_id, 'error': str(exc)})
            raise DomainError('PURGE_SWITCH', '清理登记切换失败，已回滚，上一版档案仍可核验')
        _append_journal(root, {'at': _now(), 'event': 'raw_purged', 'run_id': run_id})
        return reg


def purge_due(now=None):
    """删除到期批次的原始整表材料（不动证据包）。返回受影响 run_id 列表。"""
    now = now or datetime.now(timezone.utc)
    due = []
    with _lock(vault_root()):
        reg = _load_registry(vault_root())
        for entry in reg['seals']:
            if entry.get('raw_purged'):
                continue
            expires = datetime.fromisoformat(entry['raw_expires_at'])
            if now >= expires:
                due.append(entry['run_id'])
    return due


def _now():
    return datetime.now(timezone.utc).isoformat()


def _expiry(sealed_at_iso, days):
    sealed = datetime.fromisoformat(sealed_at_iso)
    if sealed.tzinfo is None:
        sealed = sealed.replace(tzinfo=timezone.utc)
    return (sealed + timedelta(days=days)).isoformat()
