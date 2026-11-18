from collections import defaultdict
from decimal import Decimal
from datetime import datetime
ALIASES={'东门':'A','中庭':'B','西门':'C','A':'A','B':'B','C':'C'}

def apply(state):
    groups=defaultdict(list);bad=[]
    for r in state['rows']:
        r['bucket']=datetime.fromisoformat(r['bucket']).replace(minute=0,second=0,microsecond=0).isoformat()
        r['left']=ALIASES.get(r['left'],r['left']);r['right']=ALIASES.get(r['right'],r['right'])
        value=Decimal(str(r['count']))
        factor={'人':Decimal(1),'千人':Decimal(1000)}.get(r['unit'])
        if factor is None:bad.append((r,'UNIT'));continue
        value*=factor
        if value<0 or value!=value.to_integral_value() or value>1000000 or r['kind'] not in ('zone','pair','triple'):
            bad.append((r,'RANGE'));continue
        r['count']=int(value)
        if r['kind']=='pair':r['left'],r['right']=sorted([r['left'],r['right']])
        key=(r['bucket'],r['kind'],r['left'],r['right']);groups[key].append(r)
    selected=[];version_groups=[]
    for key,rows in groups.items():
        high=max(Decimal(str(r['version'])) for r in rows);latest=[r for r in rows if Decimal(str(r['version']))==high]
        conflict=len({r['count'] for r in latest})>1
        if conflict:
            bad.extend((r,'CONFLICT') for r in latest)
        else:
            winner=sorted(latest,key=lambda r:r['id'])[0];selected.append(winner)
        # 版本取舍留痕：只记行号/版本/结论/原因码，字段值留给台账叶哈希承载。
        candidates=[]
        for r in sorted(rows,key=lambda r:(r['_line'],r['id'])):
            if conflict and r in latest:
                reason='CONFLICT';is_selected=False
            elif not conflict and r is winner:
                reason='SELECTED';is_selected=True
            else:
                reason='VERSION_SUPERSEDED';is_selected=False
            candidates.append({'line':r['_line'],'id':r['id'],'version':r['version'],
                               'selected':is_selected,'reason':reason})
        version_groups.append({'key':list(key),'candidates':candidates})
    badlines={r['_line'] for r,_ in bad}
    state['rows']=[r for r in state['rows'] if r['_line'] not in badlines]
    for r,c in bad:state['quarantine'].append({'line':r['_line'],'id':r['id'],'code':c,'raw':r['_raw']})
    state['observations']=selected
    state['version_groups']=version_groups
    return state
