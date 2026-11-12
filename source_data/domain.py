"""检查归档长度及逻辑窗口清单。"""
from .io import asset,integer

def summarize(v,root):
    raw,digest=asset(root,v['source'])
    if len(raw)<512 or len(raw)%512:raise ValueError('归档物理长度未对齐')
    for q in v['windows']:integer(q['entity']);integer(q['start']);integer(q['length'])
    return {'raw_bytes':len(raw),'physical_blocks':len(raw)//512,'sha256':digest,'requested_windows':len(v['windows'])}
