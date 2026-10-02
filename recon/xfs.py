import struct, os, sys
ISO="/home/donnie/Downloads/Grabbed by the Ghoulies (USA) (En,Fr,De,Es,It).iso"
SEC=2048
f=open(ISO,'rb')
def read_at(lba,n): f.seek(lba*SEC); return f.read(n)

def try_rec(d, off):
    if off+6 > SEC: return None
    A,=struct.unpack_from('<I',d,off)
    attrs=d[off+4]; nl=d[off+5]
    if attrs not in (0x10,0x20): return None
    if not (1<=nl<=14): return None
    name=d[off+6:off+6+nl]
    if not all(32<=c<127 for c in name): return None
    p=(off+6+nl+3)&~3
    if p+8>SEC: return None
    f1,f2=struct.unpack_from('<HH',d,p)
    f3,=struct.unpack_from('<I',d,p+4)
    return dict(name=name.decode('latin1'), A=A, attrs=attrs, f1=f1, f2=f2, startLba=f3, next=p+8)

def parse_dir(lba):
    d=read_at(lba,SEC)
    recs=[]; off=8
    while off < SEC:
        r=try_rec(d,off)
        if r is None: break
        recs.append(r); off=r['next']
    return d,recs

def isdir(r): return r['f1']==0 and r['f2']==0 and r['A']%SEC==0

def walk(lba, depth=0, seen=None, out=None):
    if seen is None: seen=set()
    if out is None: out=[]
    if lba in seen: return out
    seen.add(lba)
    d,recs=parse_dir(lba)
    i=0
    while i<len(recs):
        r=recs[i]
        di=isdir(r)
        if di:
            kids=[]
            j=i+1
            while j<len(recs) and recs[j]['attrs']!=0x10:
                kids.append(recs[j]); j+=1
            out.append((r, kids, depth, lba))
            for k in kids:
                out.append((k, [], depth+1, lba))
            i=j
        else:
            out.append((r, [], depth, lba))
            i+=1
    return out

if __name__=="__main__":
    d,recs=parse_dir(264)
    print(f"root LBA264: {len(recs)} records")
    for r in recs:
        tag = "[DIR ]" if isdir(r) else "[FILE]"
        print(f"  {tag} {r['name']:<12} attrs=0x{r['attrs']:02x} A={r['A']:<10} f1={r['f1']:<6} f2={r['f2']:<6} startLba={r['startLba']}")
