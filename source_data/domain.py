"""检查归档长度及逻辑窗口清单。"""
import hashlib,io
from .io import asset,integer
from .tarwindow import TarArchive

def summarize(v,root):
    raw,digest=asset(root,v['source'])
    if len(raw)<512 or len(raw)%512:raise ValueError('归档物理长度未对齐')
    for q in v['windows']:integer(q['entity']);integer(q['start']);integer(q['length'])
    return {'raw_bytes':len(raw),'physical_blocks':len(raw)//512,'sha256':digest,'requested_windows':len(v['windows'])}

def collect(v,root):
    """按清单窗口取资料：只读命中物理范围，孔洞以有界零块返回，不把整包落地展开。"""
    raw,digest=asset(root,v['source'])
    max_chunk=integer(v.get('max_chunk_bytes',1<<20),minimum=1)
    max_members=integer(v.get('max_index_members',10000),minimum=1)
    queries=v['windows']
    if not isinstance(queries,list):raise ValueError('windows应为列表')
    for q in queries:
        integer(q['entity'],minimum=1);integer(q['start']);integer(q['length'])
    archive=TarArchive(io.BytesIO(raw),digest,max_members=max_members)
    windows=[]
    for q in queries:
        w=archive.window(q['entity'],q['start'],q['length'],max_chunk=max_chunk)
        digest_h=hashlib.sha256();chunks=[]
        for c in w.chunks:
            digest_h.update(c.data)
            rec={'source':c.source,'logical':c.logical,'length':c.length}
            if c.physical is not None:rec['physical']=c.physical
            chunks.append(rec)
        windows.append({'entity':w.member.entity,'name':w.member.name,'start':w.start,
                        'requested_length':q['length'],'returned_length':w.returned_length,
                        'truncated':w.truncated,'sha256':digest_h.hexdigest(),'chunks':chunks})
    return {'sha256':digest,'tail_status':archive.tail_status,
            'members':[m.summary(digest) for m in archive.members],'windows':windows}
