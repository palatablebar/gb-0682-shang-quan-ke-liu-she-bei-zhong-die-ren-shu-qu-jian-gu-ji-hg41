from app.modules.m7_archive.export_out import checksum, sealed_checksum
from app.modules.m7_archive import vault

def execute(state):
    state['archive']={'sha256':checksum(state),'evidence_count':len(state.get('calculations',[]))+len(state['quarantine']),
        'ready':state.get('reconcile',{}).get('balanced',False)}
    return state

def seal_run(state):
    """提交后封存：同批重跑幂等，返回证据包与是否新生成。"""
    pack, created = vault.seal(state)
    state['archive']['sealed']=True
    state['archive']['pack_hash']=pack['pack_hash']
    state['archive']['pack_created']=created
    state['archive']['export_sha256']=sealed_checksum(state['run_id'])
    return state, pack
