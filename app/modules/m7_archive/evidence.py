"""正式区间证据包的构建与独立复核。

留存原则（7 天原始 / 365 天证据）：
- 证据包只含被采纳观测、版本取舍、交集推导、隔离摘要与整表 Merkle 锚点，
  不含原始整表，也不含被丢弃行的字段值；
- 清理后仅凭证据包即可复核：区间公式可重算、叶哈希可验包含、链上摘要自洽。
"""
import hashlib,json
from app.config import RULE_VERSION
from app.modules.m7_archive.merkle import build as merkle_build, verify_inclusion, leaf_hash as _leaf_hash

RAW_RETENTION_DAYS = 7
EVIDENCE_RETENTION_DAYS = 365
SCHEMA_VERSION = 'evidence-1.0'


def canonical(obj):
    """跨进程稳定的规范化 JSON 字节（排序键、无多余空白、不转义非 ASCII）。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def leaf_of(payload):
    if isinstance(payload, dict):
        payload = canonical(payload)
    return _leaf_hash(payload)


# ---------------------------------------------------------------- 版本取舍

def version_decisions(state):
    """从 M3 的分组过程材料生成版本取舍记录。

    每组观测键只留：候选版本的行号/版本/叶哈希/是否选中/原因码；
    被取代行的字段值不进证据包。
    """
    ledger = {entry['line']: entry for entry in state.get('ledger', [])}
    decisions = []
    for item in state.get('version_groups', []):
        candidates = []
        for cand in item['candidates']:
            line = cand['line']
            candidates.append({
                'line': line,
                'id': cand.get('id', ''),
                'version': cand['version'],
                'leaf': ledger.get(line, {}).get('leaf', ''),
                'selected': bool(cand.get('selected')),
                'reason': cand.get('reason', ''),
            })
        decisions.append({
            'key': item['key'],
            'rule': '同键取最高 version；最高版多记录且数值不一致则整组 CONFLICT 隔离，不做覆盖',
            'candidates': candidates,
        })
    return decisions


# ---------------------------------------------------------------- 交集推导

def trace_bounds(model):
    """与 m5_calculate.rules.bounds 同一公式，额外返回逐步依据。"""
    zones = model['zones']; keys = sorted(zones); pairs = model['pairs']
    values = [zones[k] for k in keys]
    steps = {'zones': {k: zones[k] for k in keys}, 'pairs': pairs, 'triple': model.get('triple')}
    if len(keys) == 1:
        low = high = values[0]
        steps['formula'] = '单区域：区间即区域观测本身'
        steps['intersection_lower'] = steps['intersection_upper'] = 0
        return low, high, steps
    if len(keys) == 2:
        common = pairs.get('|'.join(keys))
        if common is not None:
            low = high = sum(values) - common
            steps['formula'] = '两区域已知交集 I：联合 = A + B − I'
            steps['intersection_lower'] = steps['intersection_upper'] = common
        else:
            low, high = max(values), sum(values)
            steps['formula'] = '两区域无交集观测：联合下界 max(A,B)，上界 A+B'
            steps['intersection_lower'] = 0
            steps['intersection_upper'] = min(values)
        return low, high, steps
    a, b, c = keys
    ab = pairs['|'.join([a, b])]; ac = pairs['|'.join([a, c])]; bc = pairs['|'.join([b, c])]
    low = max(0, ab + ac - zones[a], ab + bc - zones[b], ac + bc - zones[c])
    high = min(ab, ac, bc)
    steps['triple_lower_terms'] = [0, ab + ac - zones[a], ab + bc - zones[b], ac + bc - zones[c]]
    steps['triple_upper_terms'] = [ab, ac, bc]
    if model.get('triple') is not None:
        low = max(low, model['triple']); high = min(high, model['triple'])
        steps['triple_observed'] = model['triple']
    base = sum(values) - ab - ac - bc
    steps['formula'] = '三区域：T ∈ [max(0,AB+AC−A,AB+BC−B,AC+BC−C), min(AB,AC,BC)]；联合 = A+B+C−AB−AC−BC+T'
    steps['base'] = base
    steps['intersection_lower'] = low
    steps['intersection_upper'] = high
    return base + low, base + high, steps


def proofs_leaf(state, line):
    for entry in state.get('ledger', []):
        if entry['line'] == line:
            return entry['leaf']
    return ''


# ---------------------------------------------------------------- 封存

def build_pack(state, prev_pack_hash=''):
    """由流水线终态构建自洽证据包（不写盘）。"""
    ledger = state.get('ledger', [])
    ledger_by_line = {e['line']: e for e in ledger}
    root, proofs = merkle_build([(e['line'], e['leaf']) for e in ledger])

    buckets = []
    for item in state['models']:
        calc = next((c for c in state['calculations'] if c['id'] == item['bucket']), None)
        if calc is None:
            continue
        low, high, steps = trace_bounds(item['model'])
        adopted = [row for row in state['observations'] if row['bucket'] == item['bucket']]
        buckets.append({
            'bucket': item['bucket'],
            'source_line': item['line'],
            'official_interval': {'lower': calc['lower'], 'upper': calc['upper'], 'code': calc['code']},
            'recomputed_interval': {'lower': low, 'upper': high},
            'intersection_basis': steps,
            'adopted_observations': [
                {
                    'line': r['_line'], 'id': r['id'], 'version': r['version'], 'kind': r['kind'],
                    'left': r['left'], 'right': r.get('right', ''), 'count': r['count'], 'unit': r['unit'],
                    'leaf': proofs_leaf(state, r['_line']),
                    'merkle_proof': proofs.get(r['_line'], []),
                }
                for r in adopted
            ],
        })

    quarantine_digest = []
    for q in state['quarantine']:
        # 叶哈希优先取整表台账承诺（含 WIDTH 行），使隔离行同样锚定到 Merkle 根；
        # 台账缺失时退化为对原值即时计算。两种情况下 raw 字段值都不进证据包。
        leaf = ledger_by_line.get(q['line'], {}).get('leaf') or (
            leaf_of(canonical(q.get('raw', {}))) if q.get('raw') is not None else '')
        quarantine_digest.append({
            'line': q['line'], 'id': q.get('id', ''), 'code': q['code'],
            'leaf': leaf,
            'in_merkle_root': q['line'] in ledger_by_line,
            'merkle_proof': proofs.get(q['line'], []),
            'raw_retained': False,
        })

    pack = {
        'schema_version': SCHEMA_VERSION,
        'run_id': state['run_id'],
        'rule_version': RULE_VERSION,
        'parameters': state.get('parameters', {}),
        'sealed_at': state['manifest']['generated_at'],
        'retention': {
            'raw_records_days': RAW_RETENTION_DAYS,
            'evidence_days': EVIDENCE_RETENTION_DAYS,
            'policy': '原始记录7天后删除；正式区间证据包留存365天；证据包不含原始整表',
        },
        'source': {
            'sha256': state['manifest']['sha256'],
            'input_count': state['input_count'],
            'ledger_lines': [e['line'] for e in ledger],
        },
        'merkle': {
            'root': root,
            'leaf_count': len(ledger),
            'tree_note': '全部原始数据行的叶承诺；清理后仅凭根与包含证明复核，不保留整表',
        },
        'version_decisions': version_decisions(state),
        'intervals': buckets,
        'quarantine_summary': quarantine_digest,
        'reconcile': state.get('reconcile', {}),
        'business': state.get('business', {}),
        'prev_pack_hash': prev_pack_hash,
    }
    pack['pack_hash'] = sha256_hex(canonical(_without(pack, 'pack_hash')))
    return pack


def _without(d, key):
    return {k: v for k, v in d.items() if k != key}


# ---------------------------------------------------------------- 清理后复核

def verify_pack(pack):
    """仅凭证据包复核（清理后可用）。返回 (ok, findings)。"""
    findings = []

    def check(cond, message):
        findings.append({'ok': bool(cond), 'message': message})
        return bool(cond)

    ok = True
    expect_hash = sha256_hex(canonical(_without(pack, 'pack_hash')))
    ok &= check(expect_hash == pack.get('pack_hash'), '证据包自哈希与内容一致')
    root = pack['merkle']['root']

    for bucket in pack['intervals']:
        # 1) 区间可由交集依据重算。
        low, high, _ = trace_bounds(bucket['intersection_basis'])
        official = bucket['official_interval']
        ok &= check((low, high) == (official['lower'], official['upper']),
                    f"{bucket['bucket']} 重算区间 ({low},{high}) 与正式区间一致")
        # 2) 每条采纳观测：叶哈希与 Merkle 包含证明可验。
        for obs in bucket['adopted_observations']:
            ok &= check(verify_inclusion(obs['leaf'], obs['merkle_proof'], root),
                        f"{bucket['bucket']} 行{obs['line']} 观测包含于整表 Merkle 根")
        # 3) 模型中的每个数值都能追到被采纳观测。
        basis = bucket['intersection_basis']
        for zone, value in basis['zones'].items():
            match = next((o for o in bucket['adopted_observations']
                          if o['kind'] == 'zone' and o['left'] == zone and o['count'] == value), None)
            ok &= check(match is not None, f"{bucket['bucket']} 区域 {zone}={value} 可追溯到采纳观测")
        for pair_key, value in basis['pairs'].items():
            left, right = pair_key.split('|')
            match = next((o for o in bucket['adopted_observations']
                          if o['kind'] == 'pair' and o['left'] == left and o['right'] == right
                          and o['count'] == value), None)
            ok &= check(match is not None, f"{bucket['bucket']} 交集 {pair_key}={value} 可追溯到采纳观测")
        if basis.get('triple') is not None:
            match = next((o for o in bucket['adopted_observations']
                          if o['kind'] == 'triple' and o['count'] == basis['triple']), None)
            ok &= check(match is not None, f"{bucket['bucket']} 三方交集 T={basis['triple']} 可追溯到采纳观测")

    # 3b) 隔离行（含列数不齐）的叶承诺必须锚定到整表 Merkle 根，包含证明可独立验证。
    for q in pack.get('quarantine_summary', []):
        if q.get('in_merkle_root', True):
            ok &= check(verify_inclusion(q['leaf'], q.get('merkle_proof', []), root),
                        f"隔离行 {q['line']}（{q['code']}）包含于整表 Merkle 根")

    # 4) 版本取舍：被选中候选都能在某区间的采纳观测中找到，且证明有效。
    selected_lines = {o['line'] for b in pack['intervals'] for o in b['adopted_observations']}
    for decision in pack['version_decisions']:
        chosen = [c for c in decision['candidates'] if c['selected']]
        for cand in chosen:
            ok &= check(cand['line'] in selected_lines,
                        f"观测键 {decision['key']} 选中行 {cand['line']} 进入正式区间证据")
        for cand in decision['candidates']:
            if cand['selected']:
                ok &= check(cand['reason'] == 'SELECTED', f"行 {cand['line']} 选中原因码正确")
            else:
                ok &= check(cand['reason'] in ('VERSION_SUPERSEDED', 'CONFLICT'),
                            f"行 {cand['line']} 未采纳原因码 {cand['reason']} 合规")

    # 5) 对账自洽。
    rec = pack.get('reconcile', {})
    ok &= check(rec.get('balanced') is True, '封存批次对账平衡（输入=采纳+隔离+空行+表头+重复）')
    ok &= check(pack['merkle']['leaf_count'] == len(pack['source']['ledger_lines']),
                'Merkle 叶数与原始数据行台账一致')
    return ok, findings
