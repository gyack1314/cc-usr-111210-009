"""TAR逻辑窗口：索引、稀疏、PAX、路径与尾部状态检查。"""
import hashlib,io,json,unittest
from pathlib import Path
from source_data.domain import collect
from source_data.tarwindow import TarArchive,TarError,normalize_path

def octal(value,length):
    return f'{value:0{length-1}o}'.encode()+b'\0'

def base256(value,length=12):
    out=bytearray(length)
    for i in range(length-1,0,-1):out[i]=value&0xFF;value>>=8
    if value>0x7F:raise ValueError('超出base-256表示范围')
    out[0]=0x80|value
    return bytes(out)

def header(name,size,typeflag=b'0',prefix=b'',linkname=b'',mtime=0,mode=0o644,uid=0,gid=0,
           uname=b'u',gname=b'g',size_field=None,magic=b'ustar\0'):
    h=bytearray(512)
    name=name.encode() if isinstance(name,str) else name
    h[0:len(name)]=name
    h[100:108]=octal(mode,8);h[108:116]=octal(uid,8);h[116:124]=octal(gid,8)
    h[124:136]=size_field if size_field is not None else octal(size,12)
    h[136:148]=octal(mtime,12)
    h[156:157]=typeflag
    linkname=linkname.encode() if isinstance(linkname,str) else linkname
    h[157:157+len(linkname)]=linkname
    h[257:257+len(magic)]=magic;h[263:265]=b'00'
    h[265:265+len(uname)]=uname;h[297:297+len(gname)]=gname
    prefix=prefix.encode() if isinstance(prefix,str) else prefix
    h[345:345+len(prefix)]=prefix
    h[148:156]=b'        '
    h[148:156]=f'{sum(h):06o}\0 '.encode()
    return bytes(h)

def pax_payload(records):
    out=b''
    for key,value in records:
        body=f'{key}={value}'.encode('utf8')
        length=len(body)+2
        while len(str(length))+len(body)+2!=length:length=len(str(length))+len(body)+2
        out+=f'{length} '.encode()+body+b'\n'
    return out

def member(name,data,typeflag=b'0',size=None,**kw):
    if size is None:size=len(data)
    if len(data)>size:raise ValueError('数据长于size')
    payload=data+b'\0'*(size-len(data))
    return header(name,size,typeflag,**kw)+payload+b'\0'*(-size%512)

def pax_member(records,name='pax',flag=b'x'):
    return member(name,pax_payload(records),flag)

def sparse_table(extents):
    lines=[str(len(extents))]
    for off,ln in extents:lines+=[str(off),str(ln)]
    return ('\n'.join(lines)+'\n').encode()

def sparse1(name,realsize,extents,data,table=None,size=None,extra=()):
    if table is None:table=sparse_table(extents)
    payload=table+b'\0'*(-len(table)%512)+data
    if size is None:size=len(payload)
    records=[('GNU.sparse.major','1'),('GNU.sparse.minor','0'),
             ('GNU.sparse.name',name),('GNU.sparse.realsize',str(realsize))]+list(extra)
    return pax_member(records,'sparse-meta')+member('placeholder',payload,size=size)

END=b'\0'*1024

class CountingReader:
    """记录每次物理读取的范围，证明只读命中区域。"""
    def __init__(self,raw):self._io=io.BytesIO(raw);self.reads=[]
    def seek(self,offset,whence=0):return self._io.seek(offset,whence)
    def read(self,n=-1):
        pos=self._io.tell();data=self._io.read(n)
        if data:self.reads.append((pos,len(data)))
        return data
    def tell(self):return self._io.tell()
    @property
    def total(self):return sum(n for _,n in self.reads)

WAREHOUSE=Path('data/warehouse.tar').read_bytes()
WAREHOUSE_DIGEST=hashlib.sha256(WAREHOUSE).hexdigest()

def warehouse():
    return TarArchive(io.BytesIO(WAREHOUSE),WAREHOUSE_DIGEST)

class WarehouseTests(unittest.TestCase):
    def test_index(self):
        a=warehouse()
        self.assertEqual(a.tail_status,'ok')
        self.assertEqual([m.entity for m in a.members],[1,2,3])
        self.assertEqual([m.name for m in a.members],['plain.txt','sparse.log','plain.txt'])
        plain,sparse,_=a.members
        self.assertEqual(plain.pax,{'comment':'warehouse'})
        self.assertEqual(plain.pax_source,{'comment':'global'})
        self.assertEqual(sparse.logical_size,32)
        self.assertEqual(sparse.physical_size,517)
        self.assertTrue(sparse.sparse)
        self.assertEqual([(o,l) for o,l,_ in sparse.extents],[(2,3),(10,2)])
        self.assertEqual(sparse.pax['GNU.sparse.realsize'],'32')
        self.assertEqual(sparse.pax_source['GNU.sparse.realsize'],'local')
        self.assertEqual(sparse.pax['comment'],'warehouse')
        self.assertEqual(sparse.pax_source['comment'],'global')
        self.assertEqual(sparse.header['name'],'placeholder')
        self.assertEqual(sparse.header['size'],517)
        summary=sparse.summary(WAREHOUSE_DIGEST)
        self.assertEqual(summary['id'],f'{WAREHOUSE_DIGEST}:2')
        self.assertEqual(summary['pax']['GNU.sparse.realsize'],{'value':'32','source':'local'})
        self.assertEqual(summary['extents'][0]['physical'],sparse.data_offset+512)

    def test_window_bytes(self):
        a=warehouse()
        w=a.window(1,0,5,max_chunk=4096)
        self.assertEqual(w.read_all(),b'hello')
        self.assertFalse(w.truncated)
        self.assertEqual(a.window(3,1,2).read_all(),b'or')
        w=a.window(2,0,16)
        self.assertEqual(w.read_all(),b'\0\0ABC\0\0\0\0\0de\0\0\0\0')
        w=a.window(2,0,16)
        kinds=[(c.source,c.logical,c.length) for c in w.chunks]
        self.assertEqual(kinds,[('hole',0,2),('data',2,3),('hole',5,5),('data',10,2),('hole',12,4)])

    def test_eof_truncation(self):
        a=warehouse()
        w=a.window(1,3,10)
        self.assertEqual(w.read_all(),b'lo')
        self.assertTrue(w.truncated)
        self.assertEqual(w.returned_length,2)
        w=a.window(1,5,4)
        self.assertEqual(w.read_all(),b'')
        self.assertTrue(w.truncated)
        self.assertEqual(w.returned_length,0)
        w=a.window(1,2,0)
        self.assertEqual(w.read_all(),b'')
        self.assertFalse(w.truncated)

    def test_hole_window_reads_nothing(self):
        reader=CountingReader(WAREHOUSE)
        a=TarArchive(reader,WAREHOUSE_DIGEST)
        before=reader.total
        w=a.window(2,13,19,max_chunk=4096)
        self.assertFalse(w.truncated)
        chunks=list(w.chunks)
        self.assertEqual(reader.total,before)
        self.assertEqual([(c.source,c.length) for c in chunks],[('hole',19)])
        self.assertEqual(b''.join(c.data for c in chunks),b'\0'*19)

    def test_duplicate_names_need_ordinal(self):
        a=warehouse()
        with self.assertRaises(TarError):a.resolve(name='plain.txt')
        self.assertEqual(a.resolve(name='plain.txt',entity=1).entity,1)
        self.assertEqual(a.window(a.resolve(name='plain.txt',entity=3),0,5).read_all(),b'world')
        self.assertEqual(a.resolve(name='sparse.log').entity,2)
        with self.assertRaises(TarError):a.resolve(name='absent')
        with self.assertRaises(TarError):a.member(4)
        with self.assertRaises(TarError):a.member(0)

    def test_member_id_is_digest_plus_ordinal(self):
        a=warehouse()
        ids=[m.summary(WAREHOUSE_DIGEST)['id'] for m in a.members]
        self.assertEqual(ids,[f'{WAREHOUSE_DIGEST}:{i}' for i in (1,2,3)])

class TailTests(unittest.TestCase):
    def test_missing_end_blocks(self):
        raw=Path('data/missing-end.tar').read_bytes()
        a=TarArchive(io.BytesIO(raw),hashlib.sha256(raw).hexdigest())
        self.assertEqual(a.tail_status,'truncated')
        self.assertEqual(len(a.members),3)
        self.assertEqual(a.window(1,0,5).read_all(),b'hello')

    def test_garbage_after_end_blocks(self):
        a=TarArchive(io.BytesIO(WAREHOUSE+b'X'*512),'x')
        self.assertEqual(a.tail_status,'garbage')
        self.assertEqual(len(a.members),3)

    def test_single_zero_block_then_junk(self):
        raw=member('a.txt',b'abc')+b'\0'*512+b'Y'*512
        a=TarArchive(io.BytesIO(raw),'x')
        self.assertEqual(a.tail_status,'garbage')

    def test_truncated_mid_member(self):
        raw=header('a.txt',1000)+b'abc'
        a=TarArchive(io.BytesIO(raw),'x')
        self.assertEqual(a.tail_status,'truncated')
        self.assertEqual(a.members,[])

    def test_empty_archive(self):
        a=TarArchive(io.BytesIO(b''),'x')
        self.assertEqual(a.tail_status,'truncated')
        self.assertEqual(a.members,[])

class PaxTests(unittest.TestCase):
    def test_global_local_and_deletion(self):
        raw=b''.join([
            pax_member([('comment','g1'),('x-key','shared')],'global',b'g'),
            member('a.txt',b'AAAA'),
            pax_member([('comment','')]),
            member('b.txt',b'BBBB'),
            pax_member([('one','1')]),
            pax_member([('two','2')]),
            member('c.txt',b'CCCC'),
            member('d.txt',b'DDDD'),
            END])
        a=TarArchive(io.BytesIO(raw),'x')
        self.assertEqual([m.name for m in a.members],['a.txt','b.txt','c.txt','d.txt'])
        ma,mb,mc,md=a.members
        self.assertEqual(ma.pax,{'comment':'g1','x-key':'shared'})
        self.assertEqual(mb.pax,{'x-key':'shared'})
        self.assertEqual(mb.pax_source,{'x-key':'global'})
        self.assertEqual(mc.pax,{'comment':'g1','x-key':'shared','one':'1','two':'2'})
        self.assertEqual(mc.pax_source['one'],'local')
        self.assertEqual(mc.pax_source['two'],'local')
        self.assertEqual(md.pax,{'comment':'g1','x-key':'shared'})

    def test_local_path_and_empty_deletion(self):
        raw=b''.join([
            pax_member([('path','renamed.txt')]),
            member('orig.txt',b'AAAA'),
            pax_member([('path',''),('path','')]),
            member('keep.txt',b'BBBB'),
            END])
        a=TarArchive(io.BytesIO(raw),'x')
        self.assertEqual([m.name for m in a.members],['renamed.txt','keep.txt'])

    def test_global_deletion(self):
        raw=b''.join([
            pax_member([('comment','g1')],'g1',b'g'),
            pax_member([('comment','')],'g2',b'g'),
            member('a.txt',b'AAAA'),
            END])
        a=TarArchive(io.BytesIO(raw),'x')
        self.assertEqual(a.members[0].pax,{})

    def test_pax_size_overrides_physical(self):
        payload=b'xyz'
        raw=b''.join([pax_member([('size','3')]),
                      header('a.txt',999)+payload+b'\0'*(-3%512),
                      END])
        a=TarArchive(io.BytesIO(raw),'x')
        m=a.members[0]
        self.assertEqual(m.physical_size,3)
        self.assertEqual(m.header['size'],999)
        self.assertEqual(a.window(1,0,3).read_all(),b'xyz')

    def test_pax_malformed(self):
        cases=[b'1 a=b\n',          # 长度小于自身数字
               b'99 a=b\n',         # 长度越过扩展数据
               b'8 a=bcdef',        # 缺少换行
               b'6 ab=c',           # 长度不含换行位置
               b'6 abc\n',          # 键值缺少等号
               b'5 =v\n']           # 键为空
        for payload in cases:
            raw=member('pax',payload,b'x')+member('a.txt',b'AAAA')+END
            with self.subTest(payload=payload):
                with self.assertRaises(TarError):TarArchive(io.BytesIO(raw),'x')

    def test_pax_utf8_value(self):
        raw=b''.join([pax_member([('path','日志/履约.txt')]),member('x',b'AAAA'),END])
        a=TarArchive(io.BytesIO(raw),'x')
        self.assertEqual(a.members[0].name,'日志/履约.txt')

class NumberTests(unittest.TestCase):
    def test_base256_size(self):
        raw=member('a.txt',b'hello',size_field=base256(5))+END
        a=TarArchive(io.BytesIO(raw),'x')
        self.assertEqual(a.window(1,0,5).read_all(),b'hello')

    def test_negative_base256_rejected(self):
        raw=member('a.txt',b'hello',size_field=b'\xff'+b'\xff'*11)+END
        with self.assertRaises(TarError):TarArchive(io.BytesIO(raw),'x')

    def test_bad_octal_rejected(self):
        raw=member('a.txt',b'hello',size_field=b'0000 8000000')+END
        with self.assertRaises(TarError):TarArchive(io.BytesIO(raw),'x')

    def test_checksum_required(self):
        blk=bytearray(header('a.txt',5))
        blk[0]=ord('b')
        raw=bytes(blk)+b'hello'+b'\0'*507+END
        with self.assertRaises(TarError):TarArchive(io.BytesIO(raw),'x')

    def test_magic_required(self):
        raw=member('a.txt',b'hello',magic=b'xxxxxx')+END
        with self.assertRaises(TarError):TarArchive(io.BytesIO(raw),'x')

class PathTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_path('a/./b'),'a/b')
        self.assertEqual(normalize_path('a//b/'),'a/b')
        self.assertEqual(normalize_path('a\\b'),'a\\b')
        for bad in ('/etc/passwd','//a//b/','a/../b','..','','nul\x00x','/'):
            with self.subTest(bad=bad):
                with self.assertRaises(TarError):normalize_path(bad)

    def test_malicious_member_name_rejected(self):
        raw=member('../evil',b'x')+END
        with self.assertRaises(TarError):TarArchive(io.BytesIO(raw),'x')
        raw=member('/abs',b'x')+END
        with self.assertRaises(TarError):TarArchive(io.BytesIO(raw),'x')

    def test_prefix_join(self):
        raw=member('b.txt',b'hi',prefix='a')+END
        a=TarArchive(io.BytesIO(raw),'x')
        self.assertEqual(a.members[0].name,'a/b.txt')

class UnsupportedTests(unittest.TestCase):
    def test_listed_but_not_readable(self):
        raw=b''.join([
            member('link',b'',b'2',linkname='target'),
            member('hard',b'',b'1',linkname='target'),
            member('dir/',b'',b'5'),
            member('fifo',b'',b'6'),
            member('char',b'',b'3'),
            member('block',b'',b'4'),
            member('long',b'x'*100,b'L'),
            member('oldsparse',b'x'*512,b'S'),
            END])
        a=TarArchive(io.BytesIO(raw),'x')
        self.assertEqual(len(a.members),8)
        for m in a.members:
            with self.subTest(name=m.name):
                self.assertFalse(m.supported)
                self.assertTrue(m.reason)
                with self.assertRaises(TarError):a.window(m,0,1)
        self.assertEqual(a.members[0].header['linkname'],'target')

    def test_other_sparse_versions_unsupported(self):
        for major,minor in (('0','0'),('0','1'),('2','0')):
            records=[('GNU.sparse.major',major),('GNU.sparse.minor',minor),('GNU.sparse.realsize','100')]
            raw=pax_member(records,'sparse-meta')+member('placeholder',b'x'*512)+END
            with self.subTest(major=major,minor=minor):
                a=TarArchive(io.BytesIO(raw),'x')
                self.assertFalse(a.members[0].supported)
                self.assertIn('sparse',a.members[0].reason)
                with self.assertRaises(TarError):a.window(1,0,1)

class SparseTests(unittest.TestCase):
    def test_zero_length_last_extent(self):
        raw=sparse1('s.log',20,[(2,3),(5,0)],b'ABC')+END
        a=TarArchive(io.BytesIO(raw),'x')
        self.assertEqual(a.window(1,0,8).read_all(),b'\0\0ABC\0\0\0')

    def test_empty_extent_table(self):
        raw=sparse1('s.log',100,[],b'')+END
        a=TarArchive(io.BytesIO(raw),'x')
        reader_ok=a.window(1,0,10,max_chunk=4)
        self.assertEqual([c.length for c in reader_ok.chunks],[4,4,2])

    def test_overlap_rejected(self):
        raw=sparse1('s.log',20,[(2,5),(4,2)],b'ABCDEFG')+END
        with self.assertRaises(TarError):TarArchive(io.BytesIO(raw),'x')

    def test_reversed_rejected(self):
        raw=sparse1('s.log',20,[(10,2),(3,2)],b'ABCD')+END
        with self.assertRaises(TarError):TarArchive(io.BytesIO(raw),'x')

    def test_beyond_realsize_rejected(self):
        raw=sparse1('s.log',32,[(30,5)],b'ABCDE')+END
        with self.assertRaises(TarError):TarArchive(io.BytesIO(raw),'x')

    def test_size_mismatch_rejected(self):
        raw=sparse1('s.log',20,[(2,3)],b'ABC',size=512+4)+END
        with self.assertRaises(TarError):TarArchive(io.BytesIO(raw),'x')

    def test_zero_length_middle_rejected(self):
        raw=sparse1('s.log',20,[(2,0),(5,2)],b'AB')+END
        with self.assertRaises(TarError):TarArchive(io.BytesIO(raw),'x')

    def test_missing_realsize_rejected(self):
        records=[('GNU.sparse.major','1'),('GNU.sparse.minor','0')]
        raw=pax_member(records,'sparse-meta')+member('placeholder',b'0\n'+b'\0'*510)+END
        with self.assertRaises(TarError):TarArchive(io.BytesIO(raw),'x')

    def test_max_members(self):
        with self.assertRaises(TarError):
            TarArchive(io.BytesIO(WAREHOUSE),WAREHOUSE_DIGEST,max_members=2)

class LargeSparseTests(unittest.TestCase):
    """40GiB逻辑稀疏日志：证明只读命中物理范围、缓存有界。"""

    REALSIZE=40*1024**3
    EXTENTS=[(0,5,b'START'),(REALSIZE-3,3,b'END')]

    @classmethod
    def setUpClass(cls):
        table=sparse_table([(o,l) for o,l,_ in cls.EXTENTS])
        data=b''.join(d for _,_,d in cls.EXTENTS)
        cls.raw=sparse1('big.log',cls.REALSIZE,[(o,l) for o,l,_ in cls.EXTENTS],data)+END
        cls.table_len=len(table)

    def open(self):
        reader=CountingReader(self.raw)
        return TarArchive(reader,'big'),reader

    def test_logical_not_physical(self):
        a,_=self.open()
        m=a.members[0]
        self.assertEqual(m.logical_size,self.REALSIZE)
        self.assertEqual(m.physical_size,512+8)
        self.assertLess(len(self.raw),8192)

    def test_index_reads_bounded(self):
        a,reader=self.open()
        self.assertLess(reader.total,16384)
        lo=a.members[0].extents[0][2]
        hi=a.members[0].extents[-1][2]+3
        for pos,n in reader.reads:
            self.assertTrue(pos+n<=lo or pos>=hi,(pos,n))

    def test_huge_hole_window(self):
        a,reader=self.open()
        before=reader.total
        length=64*1024**2
        w=a.window(1,1024**2,length,max_chunk=1024**2)
        digest=hashlib.sha256();count=0;peak=0
        for c in w.chunks:
            self.assertEqual(c.source,'hole')
            self.assertIsNone(c.physical)
            peak=max(peak,c.length)
            digest.update(c.data);count+=c.length
        self.assertEqual(count,length)
        self.assertLessEqual(peak,1024**2)
        self.assertEqual(reader.total,before)
        expect=hashlib.sha256()
        zero=b'\0'*(1024**2)
        for _ in range(length//len(zero)):expect.update(zero)
        self.assertEqual(digest.hexdigest(),expect.hexdigest())

    def test_window_hitting_end_extent(self):
        a,reader=self.open()
        before=list(reader.reads)
        w=a.window(1,self.REALSIZE-4,5,max_chunk=1024)
        self.assertTrue(w.truncated)
        self.assertEqual(w.returned_length,4)
        chunks=list(w.chunks)
        self.assertEqual(b''.join(c.data for c in chunks),b'\0END')
        self.assertEqual([c.source for c in chunks],['hole','data'])
        new_reads=reader.reads[len(before):]
        extent_phys=a.members[0].extents[1][2]
        self.assertEqual(new_reads,[(extent_phys,3)])

    def test_window_hitting_start_extent(self):
        a,_=self.open()
        w=a.window(1,0,8,max_chunk=2)
        self.assertEqual([c.data for c in w.chunks],[b'ST',b'AR',b'T',b'\0\0',b'\0'])

class CollectTests(unittest.TestCase):
    """清单窗口采集：摘要与逐块来源。"""

    def load(self,name):
        return json.loads(Path(f'data/{name}').read_text(encoding='utf8'))

    def test_normal_manifest(self):
        out=collect(self.load('normal.json'),Path('data'))
        self.assertEqual(out['tail_status'],'ok')
        self.assertEqual(len(out['members']),3)
        expect=[b'hello',b'\0\0ABC\0\0\0\0\0de\0\0\0\0',b'or']
        self.assertEqual([w['sha256'] for w in out['windows']],
                         [hashlib.sha256(x).hexdigest() for x in expect])
        w=out['windows'][1]
        self.assertEqual(w['name'],'sparse.log')
        self.assertFalse(w['truncated'])
        self.assertEqual([c['source'] for c in w['chunks']],['hole','data','hole','data','hole'])
        data_chunks=[c for c in w['chunks'] if c['source']=='data']
        self.assertEqual([(c['logical'],c['length']) for c in data_chunks],[(2,3),(10,2)])
        self.assertTrue(all('physical' in c for c in data_chunks))
        self.assertTrue(all('physical' not in c for c in w['chunks'] if c['source']=='hole'))

    def test_hole_manifest(self):
        out=collect(self.load('hole-window.json'),Path('data'))
        w=out['windows'][0]
        self.assertEqual(w['returned_length'],19)
        self.assertEqual(w['chunks'],[{'source':'hole','logical':13,'length':19}])
        self.assertEqual(w['sha256'],hashlib.sha256(b'\0'*19).hexdigest())

    def test_missing_end_manifest(self):
        out=collect(self.load('missing-end-blocks.json'),Path('data'))
        self.assertEqual(out['tail_status'],'truncated')
        self.assertEqual(out['windows'][0]['sha256'],hashlib.sha256(b'hello').hexdigest())

    def test_invalid_config_rejected(self):
        with self.assertRaises(ValueError):collect(self.load('invalid-config.json'),Path('data'))

if __name__=='__main__':
    unittest.main()
