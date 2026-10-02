import re
P="/home/donnie/Downloads/Grabbed by the Ghoulies (USA) (En,Fr,De,Es,It).iso"
SEC=2048
sigs={
 'MZ/DOS-PE':b'MZ',
 'GRP(lucas)':b'GRP\x1a',
 'LGRP':b'LGRP',
 'PKzip':b'PK\x03\x04',
 'RIFF':b'RIFF',
 'OggS':b'OggS',
 'PNG':b'\x89PNG',
 'JPEG':b'\xff\xd8\xff',
 'MPEGvideo':b'\x00\x00\x01\xb3',
 'MPEG-audio':b'\xff\xfb',
 'ADPCM/DVI':b'DVI ',
 'Mach-O':b'\xfe\xed\xfa',
 'ELF':b'\x7fELF',
 'PE\0\0':b'PE\x00\x00',
}
hits={k:[] for k in sigs}
f=open(P,'rb')
pos=0
CH=8*1024*1024
size=2709585920
while pos<size:
    f.seek(pos); b=f.read(CH+64)
    base=pos
    for k,s in sigs.items():
        i=b.find(s)
        while i!=-1:
            off=base+i
            if off>=size: break
            hits[k].append(off//SEC)
            i=b.find(s,i+1)
    pos+=CH
for k,v in hits.items():
    if not v: continue
    uniq=[]
    prev=-10
    for s in v:
        if s!=prev: uniq.append(s)
        prev=s
    print(f"{k}: {len(v)} hits, {len(uniq)} uniq sectors, first 25: {uniq[:25]}")
print("done")
