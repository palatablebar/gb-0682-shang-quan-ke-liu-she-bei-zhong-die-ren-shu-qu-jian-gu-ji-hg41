import csv,io
from app.errors import DomainError
from app.config import REQUIRED
from app.modules.m1_ingest.decode import decode
from app.modules.m7_archive.evidence import canonical, leaf_of

def read(raw):
    text,encoding=decode(raw)
    if not text:raise DomainError('EMPTY_FILE','文件为空')
    if not text.strip():raise DomainError('BLANK_FILE','文件仅含空行')
    reader=csv.reader(io.StringIO(text,newline=''))
    try:header=[s.strip().lstrip('﻿') for s in next(reader)]
    except (StopIteration,csv.Error):raise DomainError('HEADER','无法读取表头')
    if len(set(header))!=len(header) or not set(REQUIRED)<=set(header):raise DomainError('HEADER','表头缺失或重复')
    out={'rows':[],'quarantine':[],'input_count':0,'blank_count':0,'header_count':0,'duplicate_count':0,'encoding':encoding,
         # 原始行台账：对每条物理记录（含列数不齐的隔离行）建立叶承诺，
         # 作为“整表”Merkle 的素材；只存规范化载荷与叶哈希，不复制整表字节，
         # 7 天清理时随运行态一并删除。
         'ledger':[]}
    try:
        for row in reader:
            out['input_count']+=1;line=reader.line_num
            if not row or not any(s.strip() for s in row):out['blank_count']+=1;continue
            if row==header:out['header_count']+=1;continue
            if len(row)!=len(header):
                out['quarantine'].append({'line':line,'id':'','code':'WIDTH','raw':row})
                payload=canonical({'_shape':'width_mismatch','cells':list(row)})
                out['ledger'].append({'line':line,'id':'','payload':payload,'leaf':leaf_of(payload)})
                continue
            item=dict(zip(header,row));item['_line']=line;item['_raw']=dict(item);out['rows'].append(item)
            payload=canonical({k:item[k] for k in header})
            out['ledger'].append({'line':line,'id':item.get('id',''),'payload':payload,'leaf':leaf_of(payload)})
    except csv.Error as exc:raise DomainError('CSV',str(exc))
    if out['input_count']==0:raise DomainError('HEADER_ONLY','文件仅含表头')
    return out
