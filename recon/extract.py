import struct, os, sys
ISO="/home/donnie/Downloads/Grabbed by the Ghoulies (USA) (En,Fr,De,Es,It).iso"
OUT="/tmp/opencode/ghoulies/extracted"
SEC=2048
os.makedirs(OUT, exist_ok=True)
f=open(ISO,'rb')

def read_at(lba, nbytes):
    f.seek(lba*SEC); return f.read(nbytes)

def parse_dir(lba):
    """Yield (name, attrs, startLba, size, isdir) in order, recursing into child entries."""
    d = read_at(lba, SEC)
    recs=[]
    off=8
    while off+14 <= SEC:
        A,=struct.unpack_from('<I',d,off)
        attrs=d[off+4]; nl=d[off+5]
        if nl==0 or nl>14: break
        name=d[off+6:off+6+nl]
        if not all(32<=c<127 for c in name): break
        p=off+6+nl
        p=(p+3)&~3
        if p+8>SEC: break
        f1,f2=struct.unpack_from('<HH',d,p)
        f3,=struct.unpack_from('<I',d,p+4)
        recs.append((name.decode('latin1'), A, attrs, f1, f2, f3, p+12))
        off=(p+12+3)&~3
    # build tree: a record with f1==0 and f2==0 and A%2048==0 is a dir; following
    # non-0x10 records are its children
    out=[]; i=0
    while i < len(recs):
        n,A,at,f1,f2,f3,end=recs[i]
        isdir = (f1==0 and f2==0 and A%SEC==0)
        if isdir:
            kids=[]
            j=i+1
            while j<len(recs) and recs[j][2]!=0x10:
                kids.append(recs[j]); j+=1
            out.append((n, A, at, f1, f2, f3, True, kids))
            i=j
        else:
            out.append((n, A, at, f1, f2, f3, False, []))
            i+=1
    return out

def walk(lba, path, depth=0, seen=None):
    if seen is None: seen=set()
    if lba in seen: return
    seen.add(lba)
    for (n,A,at,f1,f2,f3,isdir,kids) in parse_dir(lba):
        p=os.path.join(path,n)
        if isdir:
            print("  "*depth + f"[DIR ] {n:<14} startLba={f3:<10} A={A}")
            walk(f3, p, depth+1, seen)
        else:
            print("  "*depth + f"[FILE] {n:<14} startLba={f3:<10} size={A:<10} f1={f1} f2={f2}")
        # also recurse into explicit kids list (already handled above)

def extract(name, lba, size, dest):
    f.seek(lba*SEC)
    rem=size
    with open(dest,'wb') as o:
        CH=1024*1024
        while rem>0:
            b=f.read(min(CH,rem))
            if not b: break
            o.write(b); rem-=len(b)
    return size-rem

if __name__=="__main__":
    print("=== ROOT @ LBA 264 ===")
    entries=parse_dir(264)
    found={}
    def rec(lba, depth=0, seen=None):
        if seen is None: seen=set()
        if lba in seen: return
        seen.add(lba)
        for (n,A,at,f1,f2,f3,isdir,_k) in parse_dir(lba):
            print("  "*depth + (f"[DIR ] {n:<14} startLba={f3:<10} A={A}" if isdir else f"[FILE] {n:<14} startLba={f3:<10} size={A:<10}"))
            found[n]=(f3,A,isdir)
            if isdir and depth<6: rec(f3, depth+1, seen)
    rec(264)
    print()
    for want in ("default.xbe","cdx.xbe"):
        if want in found and not found[want][2]:
            lba,size,_=found[want]
            dest=os.path.join(OUT,want)
            got=extract(want,lba,size,dest)
            print(f"extracted {want}: {got} bytes -> {dest}")
