import sys, os
P="/home/donnie/Downloads/Grabbed by the Ghoulies (USA) (En,Fr,De,Es,It).iso"
f=open(P,'rb')
SEC=2048
size=os.path.getsize(P)
nsec=size//SEC
print("size",size,"sectors",nsec,"remainder",size%SEC)
# find first non-zero sector
firstnz=None
CH=2048*2048  # 4MB chunks
pos=0
nz_runs=[]
inrun=False
runstart=0
while pos<size:
    f.seek(pos); b=f.read(min(CH,size-pos))
    if b.strip(b'\x00'):
        s0=pos//SEC; e0=(pos+len(b))//SEC
        if not inrun:
            runstart=s0; inrun=True
        nz_runs.append((runstart,e0))
    else:
        if inrun:
            nz_runs[-1]=(nz_runs[-1][0], pos//SEC)
            inrun=False
    pos+=len(b)
if inrun: nz_runs[-1]=(nz_runs[-1][0], nsec)
# merge
merged=[]
for r in nz_runs:
    if merged and r[0]-merged[-1][1] <= 4: merged[-1]=(merged[-1][0], r[1])
    else: merged.append(list(r) if False else (r[0],r[1]))
merged=[list(m) for m in merged]
out=[]
for m in merged:
    if m[1]-m[0] < 8: continue
    out.append(m)
print("non-zero regions (sectors, >=8 sec):")
for a,b in out[:80]:
    print(f"  {a} - {b}   ({(b-a)*2048/1e6:.1f} MB)")
print("total regions:",len(out))
