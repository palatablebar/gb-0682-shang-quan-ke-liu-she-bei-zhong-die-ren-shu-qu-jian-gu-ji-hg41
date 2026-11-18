"""证据导出：与归档页面共用同一份封存证据包（single source of truth）。

导出 CSV 的全部行都由 vault 中的 sealed pack 生成；原始整表清理后仍可导出。
未封存批次拒绝导出，避免页面与文件使用不同材料。
"""
import io, csv, json, hashlib
from app.errors import DomainError
from app.modules.m7_archive import vault


def bundle(state):
    """预览/旧入口兼容：由运行态生成同样结构的 CSV（未封存材料，标注 preview）。"""
    out = io.StringIO(newline=''); writer = csv.writer(out)
    rid = state.get('run_id', 'preview')
    writer.writerow(['记录类型', '批次', '键/行号', '观测ID', '原因码', '内容'])
    writer.writerow(['封存清单', rid, '', '', '', json.dumps(state.get('manifest', {}), ensure_ascii=False, sort_keys=True)])
    writer.writerow(['对账', rid, '', '', '', json.dumps(state.get('reconcile', {}), ensure_ascii=False, sort_keys=True)])
    for row in state.get('calculations', []):
        writer.writerow(['正式区间', rid, row.get('id', ''), row.get('line', ''), row.get('code', ''),
                         json.dumps(row, ensure_ascii=False, sort_keys=True)])
    for row in state['quarantine']:
        writer.writerow(['隔离摘要', rid, row['line'], row.get('id', ''), row['code'],
                         json.dumps({'line': row['line'], 'id': row.get('id', ''), 'code': row['code']},
                                    ensure_ascii=False, sort_keys=True)])
    return '﻿' + out.getvalue()


def checksum(state):
    return hashlib.sha256(bundle(state).encode('utf-8')).hexdigest()


def sealed_bundle(run_id):
    """正式导出：只认证据库中的封存包。"""
    pack = vault.load_pack(run_id)
    if pack is None:
        raise DomainError('NOT_SEALED', '该批次尚未封存证据，无法导出（归档页与导出必须使用同一份封存材料）', 409)
    out = io.StringIO(newline=''); writer = csv.writer(out)
    writer.writerow(['记录类型', '批次', '键/行号', '观测ID', '原因码', '内容'])
    writer.writerow(['封存清单', run_id, 'pack_hash', '', '',
                     json.dumps({k: pack[k] for k in
                                 ('schema_version', 'rule_version', 'parameters', 'sealed_at',
                                  'retention', 'source', 'merkle', 'prev_pack_hash', 'pack_hash')},
                                ensure_ascii=False, sort_keys=True)])
    writer.writerow(['对账', run_id, '', '', '', json.dumps(pack['reconcile'], ensure_ascii=False, sort_keys=True)])
    for decision in pack['version_decisions']:
        for cand in decision['candidates']:
            writer.writerow(['版本取舍', run_id, '|'.join(map(str, decision['key'])), cand['id'],
                             cand['reason'], json.dumps(cand, ensure_ascii=False, sort_keys=True)])
    for bucket in pack['intervals']:
        writer.writerow(['正式区间', run_id, bucket['bucket'], bucket['source_line'],
                         bucket['official_interval']['code'],
                         json.dumps({'official_interval': bucket['official_interval'],
                                     'recomputed_interval': bucket['recomputed_interval'],
                                     'intersection_basis': bucket['intersection_basis']},
                                    ensure_ascii=False, sort_keys=True)])
        for obs in bucket['adopted_observations']:
            writer.writerow(['采纳观测', run_id, bucket['bucket'], obs['id'], 'SELECTED',
                             json.dumps(obs, ensure_ascii=False, sort_keys=True)])
    for q in pack['quarantine_summary']:
        writer.writerow(['隔离摘要', run_id, q['line'], q['id'], q['code'],
                         json.dumps(q, ensure_ascii=False, sort_keys=True)])
    return '﻿' + out.getvalue()


def sealed_checksum(run_id):
    return hashlib.sha256(sealed_bundle(run_id).encode('utf-8')).hexdigest()
