import struct, subprocess, sys

ELF = "/data/fw/ap/vmlinux.elf"
KO = "/data/tools/KernelSU/kernel/kernelsu.ko"

# --- parse ELF program headers for vaddr->file offset mapping ---
f = open(ELF, "rb").read()
e_phoff = struct.unpack_from("<Q", f, 0x20)[0]
e_phentsize = struct.unpack_from("<H", f, 0x36)[0]
e_phnum = struct.unpack_from("<H", f, 0x38)[0]
segs = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<IIQQQQQQ", f, o)
    if p_type == 1 and p_filesz:
        segs.append((p_vaddr, p_vaddr + p_filesz, p_offset))

def rd(vaddr, n):
    for s, e, off in segs:
        if s <= vaddr and vaddr + n <= e:
            fo = off + (vaddr - s)
            return f[fo:fo + n]
    raise Exception("vaddr not mapped: %x" % vaddr)

KSYM_START = 0xffffffc081815c30
KSYM_END   = 0xffffffc08181f998
KSYM_GPL_START = 0xffffffc08181f998
KSYM_GPL_END   = 0xffffffc08182fc1c
CRC_START = 0xffffffc08182fc1c
CRC_GPL_START = 0xffffffc081833094

def dev_crc(sym):
    out = subprocess.run(["nm", ELF], capture_output=True, text=True).stdout
    return out

# build symbol address map
addrs = {}
for line in subprocess.run(["nm", ELF], capture_output=True, text=True).stdout.splitlines():
    p = line.split()
    if len(p) == 3 and p[2].startswith("__ksymtab_"):
        addrs[p[2][len("__ksymtab_"):]] = int(p[0], 16)

def get_crc(sym):
    a = addrs.get(sym)
    if a is None:
        return None
    if KSYM_START <= a < KSYM_END:
        idx = (a - KSYM_START) // 12
        return struct.unpack("<I", rd(CRC_START + 4 * idx, 4))[0]
    if KSYM_GPL_START <= a < KSYM_GPL_END:
        idx = (a - KSYM_GPL_START) // 12
        return struct.unpack("<I", rd(CRC_GPL_START + 4 * idx, 4))[0]
    return None

# --- parse .ko __versions ---
k = open(KO, "rb").read()
e_shoff = struct.unpack_from("<Q", k, 0x28)[0]
e_shentsize = struct.unpack_from("<H", k, 0x3a)[0]
e_shnum = struct.unpack_from("<H", k, 0x3c)[0]
e_shstrndx = struct.unpack_from("<H", k, 0x3e)[0]
def sh(i):
    o = e_shoff + i * e_shentsize
    return struct.unpack_from("<IIQQQQIIQQ", k, o)
st = sh(e_shstrndx)
def nm(i):
    s = st[4] + i
    return k[s:k.index(b"\0", s)].decode()
ko = []
for i in range(e_shnum):
    name, typ, flags, addr, off, size, link, info, align, entsize = sh(i)
    if nm(name) == "__versions":
        d = k[off:off + size]
        for j in range(0, len(d), 64):
            ko.append((d[j + 8:j + 64].split(b"\0")[0].decode(), struct.unpack_from("<Q", d, j)[0]))

ok = bad = miss = 0
badlist = []
for name, crc in ko:
    dc = get_crc(name)
    if dc is None:
        miss += 1
        badlist.append((name, crc, None))
    elif dc == crc:
        ok += 1
    else:
        bad += 1
        badlist.append((name, crc, dc))

print("total=%d match=%d mismatch=%d missing=%d" % (len(ko), ok, bad, miss))
for n, a, b in badlist:
    print("  DIFF %-40s built=%08x dev=%s" % (n, a, "N/A" if b is None else "%08x" % b))
