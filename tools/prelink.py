#!/usr/bin/env python3
"""Prelink a .ko for a kernel whose exported symbols are trimmed:
rewrite undefined symbols into SHN_ABS symbols pointing at real runtime
addresses taken from /proc/kallsyms (root, kptr_restrict=0)."""
import struct, sys

MAXSYM = 400000


def load_kallsyms(path):
    m = {}
    for line in open(path, "r", errors="replace"):
        p = line.split()
        if len(p) == 3:
            try:
                addr = int(p[0], 16)
            except ValueError:
                continue
            if addr and p[2] not in m:
                m[p[2]] = addr
    return m


def main():
    ko, ks, out = sys.argv[1], sys.argv[2], sys.argv[3]
    km = load_kallsyms(ks)
    f = bytearray(open(ko, "rb").read())
    e_shoff = struct.unpack_from("<Q", f, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", f, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", f, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", f, 0x3E)[0]

    def sh(i):
        return struct.unpack_from("<IIQQQQIIQQ", f, e_shoff + i * e_shentsize)

    strtab_off = sh(e_shstrndx)[4]

    def sec_name(off):
        s = strtab_off + off
        return bytes(f[s:f.index(b"\0", s)]).decode()

    patched = missing = 0
    missing_names = []
    for i in range(e_shnum):
        name, typ, flags, addr, off, size, link, info, align, ent = sh(i)
        if typ != 2:  # SHT_SYMTAB
            continue
        stroff = sh(link)[4]
        for j in range(1, size // 24):
            so = off + j * 24
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", f, so)
            if st_shndx != 0:
                continue
            e = f.index(b"\0", stroff + st_name)
            nm = bytes(f[stroff + st_name:e]).decode()
            if nm in ("__this_module", "_GLOBAL_OFFSET_TABLE_", ""):
                continue
            a = km.get(nm)
            if a:
                struct.pack_into("<IBBHQQ", f, so, st_name, st_info, st_other, 0xFFF1, a, st_size)
                patched += 1
            else:
                missing += 1
                missing_names.append(nm)
    open(out, "wb").write(f)
    print("prelinked=%d unresolved=%d -> %s" % (patched, missing, out))
    for n in missing_names:
        print("  UNRESOLVED:", n)


main()
