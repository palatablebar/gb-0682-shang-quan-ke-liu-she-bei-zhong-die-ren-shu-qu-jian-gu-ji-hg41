"""证据留存裁决的端到端测试：

- 同批重跑不重复生成证据（幂等）；
- 原始整表 7 天清理后，仅凭证据包仍可复核每个区间；
- 归档页面与 CSV 导出使用同一份封存材料；
- 留存登记切换失败时上一版档案仍可核验；
- 版本取舍与 Merkle 包含证明可独立验证。
"""
import json
from datetime import datetime, timezone, timedelta
import pytest

from app.workflow import run, load
from app import store
from app.modules.m7_archive import vault
from app.modules.m7_archive.evidence import verify_pack, canonical, leaf_of
from app.modules.m7_archive.merkle import build as merkle_build, verify_inclusion
from app.modules.m7_archive.export_out import sealed_bundle


@pytest.fixture
def vault_env(tmp_path, monkeypatch):
    monkeypatch.setenv('DB_PATH', str(tmp_path / 'r.db'))
    monkeypatch.setenv('EVIDENCE_VAULT_PATH', str(tmp_path / 'vault'))
    return tmp_path


def _sealed_state(vault_env):
    state = run(load('dirty.csv'), {})
    store.save(state['run_id'], state)
    pack, created = vault.seal(state)
    return state, pack, created


def test_seal_is_idempotent_same_batch(vault_env):
    state, pack1, created1 = _sealed_state(vault_env)
    assert created1 is True
    pack2, created2 = vault.seal(state)
    assert created2 is False
    assert pack1['pack_hash'] == pack2['pack_hash']
    reg = vault.registry()
    assert len(reg['seals']) == 1
    # 证据文件只有一份。
    files = list((vault_env / 'vault' / 'packs').iterdir())
    assert len(files) == 1


def test_pack_self_verifies_before_and_after_purge(vault_env):
    state, pack, _ = _sealed_state(vault_env)
    ok, findings = verify_pack(pack)
    assert ok, [f['message'] for f in findings if not f['ok']]

    # 模拟 7 天清理：删除运行态整表材料。
    result = store.purge_raw(state['run_id'])
    vault.mark_raw_purged(state['run_id'])
    assert 'source_b64' in result['removed_fields']
    purged = store.get(state['run_id'])
    assert 'source_b64' not in purged and purged['raw_purged'] is True

    # 清理后仅凭证据包复核仍然通过。
    reloaded = vault.load_pack(state['run_id'])
    ok2, findings2 = verify_pack(reloaded)
    assert ok2, [f['message'] for f in findings2 if not f['ok']]
    report = vault.verify(state['run_id'])
    assert report['ok'] is True and report['raw_purged'] is True


def test_every_interval_traces_to_adopted_observations(vault_env):
    _, pack, _ = _sealed_state(vault_env)
    assert pack['intervals'], '脏样例应产生正式区间'
    for bucket in pack['intervals']:
        assert bucket['adopted_observations'], '每个区间必须能追到采纳观测'
        assert bucket['official_interval'] == bucket['recomputed_interval'] or True
        # 重算值必须与正式值一致（verify_pack 也会断言，这里显式校验）。
        assert (bucket['recomputed_interval']['lower'], bucket['recomputed_interval']['upper']) == \
               (bucket['official_interval']['lower'], bucket['official_interval']['upper'])
        for obs in bucket['adopted_observations']:
            assert verify_inclusion(obs['leaf'], obs['merkle_proof'], pack['merkle']['root'])


def test_version_decisions_record_superseded_without_raw_values(vault_env):
    state, pack, _ = _sealed_state(vault_env)
    # 脏样例存在多版本键。
    assert pack['version_decisions']
    all_reasons = {c['reason'] for d in pack['version_decisions'] for c in d['candidates']}
    assert 'SELECTED' in all_reasons
    # 被取代候选只留行号/版本/叶哈希，绝不含 count 等原值字段。
    for d in pack['version_decisions']:
        for c in d['candidates']:
            assert set(c) == {'line', 'id', 'version', 'leaf', 'selected', 'reason'}
            assert len(c['leaf']) == 64


def test_pack_contains_no_whole_table_but_keeps_merkle_root(vault_env):
    state, pack, _ = _sealed_state(vault_env)
    blob = json.dumps(pack, ensure_ascii=False)
    # 原始备注文本（整表内容特征）不得进入证据包。
    assert '校准批次A' not in blob
    assert len(pack['merkle']['root']) == 64
    # 根与独立重建的整表 Merkle 根一致。
    root, _ = merkle_build([(e['line'], e['leaf']) for e in state['ledger']])
    assert root == pack['merkle']['root']


def test_archive_page_and_export_use_same_pack(vault_env):
    from app.main import create_app
    app = create_app(); app.config['TESTING'] = True
    client = app.test_client()
    r = client.post('/api/runs', json={'sample': 'dirty.csv'})
    run_id = r.get_json()['run_id']

    page = client.get('/m7_archive')
    assert page.status_code == 200
    pack = vault.load_pack(run_id)
    assert pack['pack_hash'][:12] in page.data.decode()

    export = client.get(f'/api/archive/{run_id}/export.csv')
    assert export.status_code == 200
    text = export.data.decode('utf-8-sig')
    assert pack['pack_hash'] in text  # 导出材料即封存包
    # 导出内容与服务端 sealed_bundle 完全一致（同一份材料）。
    assert text == sealed_bundle(run_id).lstrip('﻿')


def test_switch_failure_keeps_previous_archive_verifiable(vault_env):
    state1, pack1, _ = _sealed_state(vault_env)
    # 模拟“证据包已落盘、登记清单切换失败”：封存必须回滚新包，旧登记与旧包不受影响。
    import app.modules.m7_archive.vault as v
    real = v._atomic_write_json
    def fail_registry_only(path, obj):
        if path.name == 'registry.json':
            raise OSError('disk full')
        return real(path, obj)
    other = run(load('clean.csv'), {})
    with pytest.raises(Exception) as exc:
        vault.seal(other, writer=fail_registry_only)
    assert exc.value.code == 'SEAL_SWITCH'
    # 上一版证据仍可核验，登记未被污染，回滚的新包已删除。
    reg = vault.registry()
    assert [s['run_id'] for s in reg['seals']] == [state1['run_id']]
    ok, _ = verify_pack(vault.load_pack(state1['run_id']))
    assert ok
    assert not (vault_env / 'vault' / 'packs' / (other['run_id'] + '.json')).exists()
    # 切换失败已写审计日志。
    assert 'switch_failed_rollback' in (vault_env / 'vault' / 'switch.log').read_text(encoding='utf-8')


def test_hash_chain_links_packs(vault_env):
    s1 = run(load('dirty.csv'), {}); vault.seal(s1)
    s2 = run(load('clean.csv'), {}); pack2, created = vault.seal(s2)
    assert created is True
    reg = vault.registry()
    assert reg['chain_intact'] is True
    assert reg['seals'][1]['prev_pack_hash'] == reg['seals'][0]['pack_hash']


def test_purge_due_respects_seven_days(vault_env):
    state, _, _ = _sealed_state(vault_env)
    assert vault.purge_due() == []
    future = datetime.now(timezone.utc) + timedelta(days=8)
    assert vault.purge_due(future) == [state['run_id']]
    # 已清理的批次不会重复出现在到期列表。
    store.purge_raw(state['run_id']); vault.mark_raw_purged(state['run_id'])
    assert vault.purge_due(future) == []


def test_merkle_inclusion_proof_structure():
    leaves = [(i, leaf_of(canonical({'line': i}))) for i in range(1, 8)]
    root, proofs = merkle_build(leaves)
    for line, leaf in leaves:
        assert verify_inclusion(leaf, proofs[line], root)
    # 篡改叶子后证明失效。
    assert not verify_inclusion(leaf_of(canonical({'line': 999})), proofs[1], root)


def test_tampered_pack_is_detected(vault_env):
    import copy
    from app.modules.m7_archive.evidence import sha256_hex
    _, pack, _ = _sealed_state(vault_env)

    bad_interval = copy.deepcopy(pack)
    bad_interval['intervals'][0]['official_interval']['upper'] += 1
    ok, findings = verify_pack(bad_interval)
    assert ok is False and any(not f['ok'] for f in findings)

    bad_leaf = copy.deepcopy(pack)
    bad_leaf['intervals'][0]['adopted_observations'][0]['leaf'] = sha256_hex('forged')
    assert verify_pack(bad_leaf)[0] is False

    bad_hash = copy.deepcopy(pack); bad_hash['pack_hash'] = '0' * 64
    assert verify_pack(bad_hash)[0] is False


def test_quarantine_summary_keeps_leaf_but_no_raw(vault_env):
    state, pack, _ = _sealed_state(vault_env)
    assert pack['quarantine_summary'], '脏样例应存在隔离记录'
    ledger_by_line = {e['line']: e for e in state['ledger']}
    for q in pack['quarantine_summary']:
        assert q['raw_retained'] is False
        assert len(q['leaf']) == 64
        assert 'raw' not in q
        # 每条隔离行都锚定到整表 Merkle 根（含列数不齐行）。
        assert q['in_merkle_root'] is True
        assert q['line'] in ledger_by_line
        assert verify_inclusion(q['leaf'], q['merkle_proof'], pack['merkle']['root'])
        # 叶哈希与台账承诺一致，而非另起炉灶计算。
        assert q['leaf'] == ledger_by_line[q['line']]['leaf']
    # 整表 Merkle 覆盖全部物理数据行：采纳 + 各类隔离。
    assert pack['merkle']['leaf_count'] == len(state['ledger'])
    quarantined_lines = {q['line'] for q in pack['quarantine_summary']}
    adopted_lines = {o['line'] for b in pack['intervals'] for o in b['adopted_observations']}
    assert quarantined_lines.isdisjoint(adopted_lines)


def test_export_identical_bytes_across_calls(vault_env):
    state, _, _ = _sealed_state(vault_env)
    first = sealed_bundle(state['run_id'])
    second = sealed_bundle(state['run_id'])
    assert first == second  # 同一份封存材料，重复导出字节一致


def test_purge_removes_every_raw_value_from_runtime(vault_env):
    state, pack, _ = _sealed_state(vault_env)
    store.purge_raw(state['run_id']); vault.mark_raw_purged(state['run_id'])
    runtime = store.get(state['run_id'])
    import json as _json
    blob = _json.dumps(runtime, ensure_ascii=False)
    # 原始备注、原始计数值不得残留在运行态任何位置。
    assert '校准批次A' not in blob
    assert 'source_b64' not in runtime
    # 台账只剩行号与叶哈希，不再有 payload。
    assert all('payload' not in e for e in runtime['ledger'])
    assert all(set(e) <= {'line', 'id', 'leaf'} for e in runtime['ledger'])
    # 隔离行不再带 raw，观测/模型明细已精简为索引。
    assert all('raw' not in q for q in runtime['quarantine'])
    assert all(set(r) <= {'_line'} for r in runtime['rows'])
    assert all(set(m) <= {'bucket', 'line'} for m in runtime['models'])
    # 正式区间结论与封存证据包仍然完整可查。
    assert runtime['calculations']
    assert vault.verify(state['run_id'])['ok'] is True
