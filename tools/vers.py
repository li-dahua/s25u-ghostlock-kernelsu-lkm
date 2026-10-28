import struct, sys
path = sys.argv[1]
f = open(path, "rb").read()
e_shoff = struct.unpack_from("<Q", f, 0x28)[0]
e_shentsize = struct.unpack_from("<H", f, 0x3a)[0]
e_shnum = struct.unpack_from("<H", f, 0x3c)[0]
e_shstrndx = struct.unpack_from("<H", f, 0x3e)[0]

def sh(i):
    o = e_shoff + i * e_shentsize
    name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from("<IIQQQQIIQQ", f, o)
    return dict(name=name, typ=typ, off=off, size=size)

strtab = sh(e_shstrndx)

def nm(x):
    s = strtab["off"] + x
    return f[s:f.index(b"\0", s)].decode()

out = []
for i in range(e_shnum):
    s = sh(i)
    if nm(s["name"]) == "__versions":
        d = f[s["off"]:s["off"] + s["size"]]
        for j in range(0, len(d), 64):
            crc = struct.unpack_from("<Q", d, j)[0]
            name = d[j + 8:j + 64].split(b"\0")[0].decode()
            out.append((name, crc))
print(len(out), "entries")
for n, c in out:
    print("%s %08x" % (n, c))
