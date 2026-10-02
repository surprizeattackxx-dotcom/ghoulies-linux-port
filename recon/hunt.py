P="/home/donnie/Downloads/Grabbed by the Ghoulies (USA) (En,Fr,De,Es,It).iso"
needles=[b'xboxkrnl.lib',b'xboxd3d8k.lib',b'xacteng.lib',b'xonline.lib',b'dsound.lib',
         b'.pdb',b'xcode',b'.text\x00',b'kernel32',b'XBOXKRNL',b'xgraphics.lib',b'binkw32',
         b'Xbox 360',b'xbox 360',b'Copyright (C) 199',b'Microsoft Corporation',b'Rare Ltd']
f=open(P,'rb'); pos=0; CH=8*1024*1024; size=2709585920
res={n:[] for n in needles}
while pos<size:
    f.seek(pos); b=f.read(CH+256)
    for n in needles:
        i=b.find(n)
        while i!=-1:
            res[n].append(pos+i); i=b.find(n,i+1)
    pos+=CH
for n in needles:
    v=res[n]
    if v: print(f"{n.decode('latin1'):<26} {len(v):>6} hits  LBAs: {[x//2048 for x in v[:12]]}")
    else: print(f"{n.decode('latin1'):<26}        0")
