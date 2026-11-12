"""TAR逻辑窗口只读索引。

支持未压缩POSIX ustar、PAX全局/局部扩展头与GNU PAX sparse 1.0；
其他GNU sparse版本、旧式GNU扩展与链接成员只列不支持，不跟随符号链接。
索引只读头部、PAX数据与稀疏extent表，窗口按extent命中物理范围，
孔洞以有界零块迭代返回，不把整包落地展开。语义见docs/data-contract.md。
"""

BLOCK=512
NUL_BLOCK=b'\0'*BLOCK
_REGULAR=(0x00,0x30)  # NUL或'0'
_TYPE_REASON={
    0x31:'硬链接成员只列不支持',
    0x32:'符号链接成员只列不支持',
    0x33:'字符设备成员只列不支持',
    0x34:'块设备成员只列不支持',
    0x35:'目录成员只列不支持',
    0x36:'FIFO成员只列不支持',
    0x4B:'旧式GNU扩展只列不支持',
    0x4C:'旧式GNU扩展只列不支持',
    0x53:'旧式GNU稀疏成员只列不支持',
}

class TarError(ValueError):
    """归档结构或窗口查询不合法。"""

def _align(n):
    return (n+BLOCK-1)//BLOCK*BLOCK

def _number(raw,label):
    """非负八进制或GNU正base-256；负base-256拒绝。"""
    if not raw:raise TarError(f'{label}数字字段为空')
    if raw[0]&0x80:
        if raw[0]==0xFF:raise TarError(f'{label}不接受负base-256数')
        value=raw[0]&0x7F
        for b in raw[1:]:value=value<<8|b
        return value
    i=0
    while i<len(raw) and raw[i] in (0,0x20):i+=1
    j=i
    while j<len(raw) and 0x30<=raw[j]<=0x37:j+=1
    if j==i:raise TarError(f'{label}不是合法八进制数')
    if any(c not in (0,0x20) for c in raw[j:]):raise TarError(f'{label}数字尾部含非法字符')
    return int(raw[i:j],8)

def _decimal(text,label):
    if not text or not text.isascii() or not text.isdigit():raise TarError(f'{label}应为非负十进制数')
    return int(text)

def _decimal_bytes(raw,label):
    if not raw or any(c<0x30 or c>0x39 for c in raw):raise TarError(f'{label}应为非负十进制数')
    return int(raw)

def _text(raw,label):
    try:return raw.split(b'\0')[0].decode('utf8')
    except UnicodeDecodeError as e:raise TarError(f'{label}应为UTF-8') from e

def normalize_path(name):
    """POSIX语义归一化：拒绝根路径、上级逃逸与NUL，反斜杠保留字面。"""
    if not isinstance(name,str):raise TarError('路径应为字符串')
    if '\x00' in name:raise TarError('路径含NUL字符')
    if name.startswith('/'):raise TarError('拒绝绝对路径')
    parts=[]
    for seg in name.split('/'):
        if seg in ('','.'):continue
        if seg=='..':raise TarError('路径含上级逃逸')
        parts.append(seg)
    if not parts:raise TarError('路径为空或为根')
    return '/'.join(parts)

def _pax_records(payload):
    """解析PAX记录：长度含长度数字、空格与换行，按UTF-8字节计数。"""
    records=[];pos=0
    while pos<len(payload):
        space=payload.find(b' ',pos)
        if space<0:raise TarError('PAX记录缺少长度空格')
        digits=payload[pos:space]
        if not digits or any(c<0x30 or c>0x39 for c in digits):raise TarError('PAX记录长度应为十进制数字')
        length=int(digits)
        if length<len(digits)+4:raise TarError('PAX记录长度无法容纳键值与换行')
        end=pos+length
        if end>len(payload):raise TarError('PAX记录长度越过扩展数据')
        record=payload[pos:end]
        if record[-1:]!=b'\n':raise TarError('PAX记录缺少换行结尾')
        body=record[len(digits)+1:-1]
        eq=body.find(b'=')
        if eq<=0:raise TarError('PAX记录缺少等号或键为空')
        try:
            key=body[:eq].decode('utf8');value=body[eq+1:].decode('utf8')
        except UnicodeDecodeError as e:raise TarError('PAX键值应为UTF-8') from e
        records.append((key,value))
        pos=end
    return records

class _Header:
    __slots__=('name','prefix','mode','uid','gid','size','mtime','checksum','typeflag','linkname','uname','gname')

def _header(block,offset):
    stored=_number(block[148:156],'checksum')
    computed=sum(block[:148])+0x20*8+sum(block[156:])
    if stored!=computed:raise TarError(f'块{offset//BLOCK}头校验和不符')
    if block[257:262]!=b'ustar':raise TarError(f'块{offset//BLOCK}不是ustar头')
    h=_Header()
    h.name=_text(block[0:100],'name')
    h.mode=_number(block[100:108],'mode')
    h.uid=_number(block[108:116],'uid')
    h.gid=_number(block[116:124],'gid')
    h.size=_number(block[124:136],'size')
    h.mtime=_number(block[136:148],'mtime')
    h.checksum=stored
    h.typeflag=block[156]
    h.linkname=_text(block[157:257],'linkname')
    h.uname=_text(block[265:297],'uname')
    h.gname=_text(block[297:329],'gname')
    h.prefix=_text(block[345:500],'prefix')
    return h

def _header_dict(h):
    return {'name':h.name,'prefix':h.prefix,'mode':h.mode,'uid':h.uid,'gid':h.gid,
            'size':h.size,'mtime':h.mtime,'checksum':h.checksum,
            'linkname':h.linkname,'uname':h.uname,'gname':h.gname}

class Chunk:
    """窗口输出块；source为hole时无物理来源、不读归档字节。"""
    __slots__=('source','logical','length','physical','data')
    def __init__(self,source,logical,length,physical,data):
        self.source=source;self.logical=logical;self.length=length
        self.physical=physical;self.data=data

class Window:
    """一次逻辑窗口查询；chunks为惰性迭代器，块长不超过max_chunk。"""
    def __init__(self,member,start,requested,returned,truncated,chunks):
        self.member=member;self.start=start;self.requested_length=requested
        self.returned_length=returned;self.truncated=truncated;self.chunks=chunks
    def read_all(self):
        """拼接全部块；仅适合小窗口，调用方自负内存。"""
        return b''.join(c.data for c in self.chunks)

class Member:
    """索引成员：原头、PAX覆盖来源、逻辑extent及物理偏移。"""
    def __init__(self):
        self.entity=0;self.name='';self.typeflag='0';self.supported=False;self.reason=None
        self.logical_size=0;self.physical_size=0;self.header_offset=0;self.data_offset=0
        self.header={};self.pax={};self.pax_source={};self.extents=[];self.sparse=False
    def summary(self,digest):
        s={'id':f'{digest}:{self.entity}','entity':self.entity,'name':self.name,
           'typeflag':self.typeflag,'supported':self.supported,
           'logical_size':self.logical_size,'physical_size':self.physical_size,
           'header_offset':self.header_offset,'data_offset':self.data_offset,
           'header':self.header,
           'pax':{k:{'value':v,'source':self.pax_source[k]} for k,v in self.pax.items()},
           'extents':[{'logical':o,'length':l,'physical':p} for o,l,p in self.extents]}
        if not self.supported:s['reason']=self.reason
        if self.sparse:s['sparse']=True
        return s

class TarArchive:
    """只读TAR索引。fileobj需支持seek/read；只读取头部、PAX数据与稀疏表。"""
    def __init__(self,fileobj,digest='',max_members=10000):
        if type(max_members) is not int or max_members<1:raise TarError('max_index_members应为正整数')
        self._f=fileobj;self.digest=digest
        self.members=[];self.tail_status='truncated'
        fileobj.seek(0,2);self._file_size=fileobj.tell()
        self._build(max_members)

    def _read_at(self,offset,length):
        self._f.seek(offset)
        out=bytearray()
        while len(out)<length:
            part=self._f.read(length-len(out))
            if not part:break
            out+=part
        return bytes(out)

    def _zeros_from(self,offset):
        pos=offset
        while pos<self._file_size:
            n=min(1<<20,self._file_size-pos)
            if self._read_at(pos,n).strip(b'\0'):return False
            pos+=n
        return True

    def _build(self,max_members):
        global_pax={};local_pax={};local_deleted=set()
        offset=0
        while True:
            block=self._read_at(offset,BLOCK)
            if len(block)<BLOCK:
                self.tail_status='truncated'
                return
            if block==NUL_BLOCK:
                second=self._read_at(offset+BLOCK,BLOCK)
                if len(second)<BLOCK:self.tail_status='truncated'
                elif second!=NUL_BLOCK:self.tail_status='garbage'
                else:self.tail_status='ok' if self._zeros_from(offset+2*BLOCK) else 'garbage'
                return
            h=_header(block,offset)
            data_offset=offset+BLOCK
            if h.typeflag in (0x67,0x78):  # g全局 / x局部，不计实体、不消耗局部状态
                if data_offset+h.size>self._file_size:
                    self.tail_status='truncated'
                    return
                payload=self._read_at(data_offset,h.size)
                if h.typeflag==0x67:
                    for k,v in _pax_records(payload):
                        if v=='':global_pax.pop(k,None)
                        else:global_pax[k]=v
                else:
                    for k,v in _pax_records(payload):
                        if v=='':local_pax.pop(k,None);local_deleted.add(k)
                        else:local_pax[k]=v;local_deleted.discard(k)
                offset=data_offset+_align(h.size)
                continue
            entity=len(self.members)+1
            if entity>max_members:raise TarError('实体数量超过max_index_members')
            merged=dict(global_pax)
            for k in local_deleted:merged.pop(k,None)
            merged.update(local_pax)
            provenance={k:('local' if k in local_pax else 'global') for k in merged}
            member=self._make_member(entity,h,merged,provenance,offset,data_offset)
            if data_offset+member.physical_size>self._file_size:
                self.tail_status='truncated'
                return
            self.members.append(member)
            local_pax.clear();local_deleted.clear()
            offset=data_offset+_align(member.physical_size)

    def _make_member(self,entity,h,merged,provenance,header_offset,data_offset):
        flag=h.typeflag
        ustar_name=h.prefix+'/'+h.name if h.prefix else h.name
        physical=_decimal(merged['size'],'PAX size') if 'size' in merged else h.size
        sparse='GNU.sparse.major' in merged or 'GNU.sparse.minor' in merged
        name=merged.get('path') or (merged.get('GNU.sparse.name') if sparse else None) or ustar_name
        m=Member()
        m.entity=entity;m.name=normalize_path(name)
        m.typeflag=chr(flag) if flag else '0'
        m.header=_header_dict(h);m.pax=dict(merged);m.pax_source=dict(provenance)
        m.header_offset=header_offset;m.data_offset=data_offset
        m.physical_size=physical;m.logical_size=physical
        if flag in _REGULAR:
            if sparse:
                major=merged.get('GNU.sparse.major');minor=merged.get('GNU.sparse.minor')
                if major is None or minor is None:raise TarError('GNU sparse版本键不完整')
                if (major,minor)==('1','0'):
                    if 'GNU.sparse.realsize' not in merged:raise TarError('缺少GNU.sparse.realsize')
                    realsize=_decimal(merged['GNU.sparse.realsize'],'GNU.sparse.realsize')
                    m.extents=self._sparse_extents(data_offset,physical,realsize)
                    m.logical_size=realsize;m.sparse=True;m.supported=True
                else:
                    m.reason=f'GNU sparse {major}.{minor}版本只列不支持'
            else:
                m.extents=[(0,physical,data_offset)]
                m.supported=True
        else:
            m.reason=_TYPE_REASON.get(flag,'未知类型成员只列不支持')
        return m

    def _sparse_extents(self,data_offset,physical,realsize):
        """GNU sparse 1.0：十进制行extent表，跳到512对齐数据块，数据依extent次序相接。"""
        raw=bytearray();pos=data_offset;end=data_offset+physical
        lines=[];need=None
        while need is None or len(lines)<need:
            nl=raw.find(b'\n')
            if nl<0:
                if pos>=end:raise TarError('稀疏extent表超出成员数据')
                part=self._read_at(pos,min(BLOCK,end-pos))
                if not part:raise TarError('稀疏extent表超出成员数据')
                raw+=part;pos+=len(part)
                continue
            line=bytes(raw[:nl]);del raw[:nl+1]
            lines.append(line)
            if len(lines)==1:need=1+2*_decimal_bytes(line,'稀疏extent数量')
        table_len=sum(len(l)+1 for l in lines)
        data_start=data_offset+_align(table_len)
        if data_start>end:raise TarError('稀疏extent表越过成员物理大小')
        pairs=[]
        for i in range(0,len(lines)-1,2):
            pairs.append((_decimal_bytes(lines[1+i],'extent偏移'),_decimal_bytes(lines[2+i],'extent长度')))
        if sum(ln for _,ln in pairs)!=physical-_align(table_len):
            raise TarError('稀疏数据字节数与归档size、padding不符')
        extents=[];prev_end=0;cursor=data_start
        for i,(off,ln) in enumerate(pairs):
            if off<prev_end:raise TarError('稀疏extent逆序或重叠')
            if ln==0 and i!=len(pairs)-1:raise TarError('仅末extent允许长度0')
            if off+ln>realsize:raise TarError('稀疏extent越过realsize')
            extents.append((off,ln,cursor))
            prev_end=off+ln;cursor+=ln
        return extents

    def member(self,entity):
        if type(entity) is not int or not 1<=entity<=len(self.members):
            raise TarError(f'实体序号越界:{entity!r}')
        return self.members[entity-1]

    def resolve(self,name=None,entity=None):
        """按实体序号或名称定位；名称有多项时必须明确序号，不悄悄取最后一个。"""
        if entity is not None:return self.member(entity)
        wanted=normalize_path(name)
        hits=[m.entity for m in self.members if m.name==wanted]
        if not hits:raise TarError(f'成员不存在:{wanted}')
        if len(hits)>1:raise TarError(f'名称{wanted}对应多个实体{hits}，需明确序号')
        return self.members[hits[0]-1]

    def window(self,ref,start,length,max_chunk=1<<20):
        """逻辑窗口[start,start+length)，越过EOF截短，空窗口合法。普通与稀疏成员同一接口。"""
        member=ref if isinstance(ref,Member) else self.member(ref)
        for label,x in (('start',start),('length',length)):
            if type(x) is not int or x<0:raise TarError(f'{label}应为非负整数')
        if type(max_chunk) is not int or max_chunk<1:raise TarError('max_chunk应为正整数')
        if not member.supported:raise TarError(member.reason or '成员不支持窗口读取')
        logical=member.logical_size
        truncated=length>0 and start+length>logical
        end=min(start+length,logical)
        if end<start:end=start
        return Window(member,start,length,end-start,truncated,self._chunks(member,start,end,max_chunk))

    def _chunks(self,member,start,end,max_chunk):
        pos=start
        for off,ln,phys in member.extents:
            if pos>=end:break
            extent_end=off+ln
            if extent_end<=pos:continue
            if off>=end:break
            if pos<off:
                hole_end=min(off,end)
                while pos<hole_end:
                    n=min(max_chunk,hole_end-pos)
                    yield Chunk('hole',pos,n,None,b'\0'*n)
                    pos+=n
            data_end=min(extent_end,end)
            cursor=max(pos,off);p=phys+(cursor-off)
            while cursor<data_end:
                n=min(max_chunk,data_end-cursor)
                data=self._read_at(p,n)
                if len(data)!=n:raise TarError('归档物理数据不完整')
                yield Chunk('data',cursor,n,p,data)
                cursor+=n;p+=n
            pos=max(pos,data_end)
        while pos<end:
            n=min(max_chunk,end-pos)
            yield Chunk('hole',pos,n,None,b'\0'*n)
            pos+=n

    def index(self):
        return {'sha256':self.digest,'tail_status':self.tail_status,
                'members':[m.summary(self.digest) for m in self.members]}
