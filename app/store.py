import sqlite3,json,os
from pathlib import Path
from app.errors import DomainError

# 7 天到期必须删除的整表材料字段；证据包（vault）不在本库，不受影响。
RAW_FIELDS=('source_b64',)

def _strip_raw(body):
    """删除整表材料：源字节、台账原始载荷、运行态观测明细与隔离原值。

    保留区间结论、对账、行号与叶哈希作为对照锚点；完整可复核材料在证据库封存包中。
    """
    for field in RAW_FIELDS:
        body.pop(field, None)
    for entry in body.get('ledger', []):
        entry.pop('payload', None)  # 叶哈希与行号保留，原始字段值删除
    # 运行态行对象中的原始值快照同样属于整表材料。
    for q in body.get('quarantine', []):
        q.pop('raw', None)
    # 采纳观测明细已进入封存证据包，运行态只保留行号索引。
    for collection in ('rows', 'observations'):
        slim = []
        for row in body.get(collection, []):
            line = row.get('_line') if isinstance(row, dict) else None
            slim.append({'_line': line} if line is not None else {})
        if collection in body:
            body[collection] = slim
    # 约束模型中的区域/交集计数同样是原始观测派生值，精简为桶与来源行索引。
    if 'models' in body:
        body['models'] = [{'bucket': m.get('bucket'), 'line': m.get('line')}
                          for m in body['models'] if isinstance(m, dict)]
    return body

def connection():
    path=Path(os.environ.get('DB_PATH','data/records.db'));path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(path,timeout=10);db.row_factory=sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, body TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, decision TEXT NOT NULL DEFAULT "待复核")')
    db.execute('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY,value TEXT NOT NULL)')
    return db

def save(run_id, body):
    with connection() as db:
        db.execute('INSERT OR IGNORE INTO runs(id,body) VALUES (?,?)',(run_id,json.dumps(body,ensure_ascii=False)))
        db.execute("INSERT INTO meta(key,value) VALUES ('latest',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(run_id,))
    return get(run_id)

def get(run_id):
    with connection() as db:r=db.execute('SELECT * FROM runs WHERE id=?',(run_id,)).fetchone()
    if not r:raise DomainError('NOT_FOUND','批次不存在',404)
    body=json.loads(r['body']);body.update(run_id=r['id'],review_version=r['version'],decision=r['decision']);return body

def history():
    with connection() as db:rows=db.execute("SELECT id,version,decision FROM runs ORDER BY CASE WHEN id=(SELECT value FROM meta WHERE key='latest') THEN 0 ELSE 1 END,rowid DESC LIMIT 100").fetchall()
    return [dict(r) for r in rows]

def review(run_id, version, decision):
    if decision not in ('通过','退回'):raise DomainError('DECISION','复核状态无效')
    with connection() as db:
        cur=db.execute('UPDATE runs SET version=version+1,decision=? WHERE id=? AND version=?',(decision,run_id,version))
        if cur.rowcount!=1:
            if not db.execute('SELECT 1 FROM runs WHERE id=?',(run_id,)).fetchone():raise DomainError('NOT_FOUND','批次不存在',404)
            raise DomainError('STALE','复核版本已更新，请刷新',409)
    return get(run_id)

def purge_raw(run_id):
    """删除某批次的原始整表材料（7 天清理）。

    删除源字节、台账原始载荷与隔离原值；保留区间结论、行号与叶哈希用于对照。
    证据库中的封存包不受影响。
    """
    with connection() as db:
        r=db.execute('SELECT body FROM runs WHERE id=?',(run_id,)).fetchone()
        if not r:raise DomainError('NOT_FOUND','批次不存在',404)
        body=json.loads(r['body'])
        removed={field:True for field in RAW_FIELDS if field in body}
        removed['ledger_payloads']=sum(1 for e in body.get('ledger', []) if 'payload' in e)
        removed['quarantine_raw']=sum(1 for q in body.get('quarantine', []) if 'raw' in q)
        _strip_raw(body)
        body['raw_purged']=True
        db.execute('UPDATE runs SET body=? WHERE id=?',(json.dumps(body,ensure_ascii=False),run_id))
    return {'run_id':run_id,'removed_fields':sorted(k for k,v in removed.items() if v),'raw_purged':True}
