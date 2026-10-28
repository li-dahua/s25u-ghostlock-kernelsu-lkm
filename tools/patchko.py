import struct, subprocess, sys, shutil
ELF="/data/fw/ap/vmlinux.elf"
KO=sys.argv[1]; OUT=sys.argv[2] if len(sys.argv)>2 else KO+".patched"
f=open(ELF,"rb").read()
e_phoff=struct.unpack_from("<Q",f,0x20)[0]; e_phnum=struct.unpack_from("<H",f,0x38)[0]; e_phentsize=struct.unpack_from("<H",f,0x36)[0]
segs=[]
for i in range(e_phnum):
    t,fl,off,va,pa,fs,ms,al=struct.unpack_from("<IIQQQQQQ",f,e_phoff+i*e_phentsize)
    if t==1 and fs: segs.append((va,va+fs,off))
def rd(va,n):
    for s,e,off in segs:
        if s<=va and va+n<=e: return f[off+(va-s):off+(va-s)+n]
    raise Exception("unmapped %x"%va)
KS,KE=0xffffffc081815c30,0xffffffc08181f998
GS,GE=0xffffffc08181f998,0xffffffc08182fc1c
CS,CG=0xffffffc08182fc1c,0xffffffc081833094
addrs={}
for l in subprocess.run(["nm",ELF],capture_output=True,text=True).stdout.splitlines():
    p=l.split()
    if len(p)==3 and p[2].startswith("__ksymtab_"): addrs[p[2][10:]]=int(p[0],16)
def dc(s):
    a=addrs.get(s)
    if a is None: return None
    if KS<=a<KE: return struct.unpack("<I",rd(CS+4*((a-KS)//12),4))[0]
    if GS<=a<GE: return struct.unpack("<I",rd(CG+4*((a-GS)//12),4))[0]
    return None
shutil.copyfile(KO,OUT); k=bytearray(open(OUT,"rb").read())
shoff=struct.unpack_from("<Q",k,0x28)[0]; shents=struct.unpack_from("<H",k,0x3a)[0]
shnum=struct.unpack_from("<H",k,0x3c)[0]; shstr=struct.unpack_from("<H",k,0x3e)[0]
def sh(i): return struct.unpack_from("<IIQQQQIIQQ",k,shoff+i*shents)
st=sh(shstr)
def nm(i):
    s=st[4]+i; return bytes(k[s:k.index(b"\0",s)]).decode()
n=0
for i in range(shnum):
    name,typ,fl,addr,off,size,link,info,align,ent=sh(i)
    if nm(name)!="__versions": continue
    for j in range(0,size,64):
        crc=struct.unpack_from("<Q",k,off+j)[0]
        sym=bytes(k[off+j+8:off+j+64]).split(b"\0")[0].decode()
        d=dc(sym)
        if d is not None and d!=crc:
            struct.pack_into("<Q",k,off+j,d); n+=1; print("  %-30s %08x -> %08x"%(sym,crc,d))
open(OUT,"wb").write(k)
print("patched %d -> %s"%(n,OUT))
