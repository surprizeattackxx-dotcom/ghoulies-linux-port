P="/home/donnie/Downloads/Grabbed by the Ghoulies (USA) (En,Fr,De,Es,It).iso"
f=open(P,'rb')
sigs={b'XBEH':[], b'XBOF':[], b'XBSF':[], b'XSIB':[]}
pos=0; CH=8*1024*1024; size=2709585920
while pos<size:
    f.seek(pos); b=f.read(CH+64)
    for s in sigs:
        i=b.find(s)
        while i!=-1:
            sigs[s].append(pos+i); i=b.find(s,i+1)
    pos+=CH
for s,v in sigs.items():
    print(s.decode(), len(v), "offsets:", v[:20], "-> LBAs:", [x//2048 for x in v[:20]])
