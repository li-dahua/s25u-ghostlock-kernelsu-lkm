import struct, sys

def parse(path):
    d = open(path, "rb").read()
    magic, ver, flags, hdr_len = struct.unpack_from("<HBB I" if False else "<HBBI", d, 0)
    if magic != 0xEB9F:
        raise SystemExit("bad magic %x in %s" % (magic, path))
    type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", d, 8)
    tbase = hdr_len + type_off
    sbase = hdr_len + str_off
    strs = d[sbase:sbase + str_len]
    def S(o):
        if o == 0: return ""
        e = strs.find(b"\0", o)
        return strs[o:e].decode("utf-8", "replace")
    types = [None]  # id 1-based
    off = 0
    while off < type_len:
        name_off, info, size = struct.unpack_from("<III", d, tbase + off)
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        kflag = (info >> 31) & 1
        p = tbase + off + 12
        members = []
        extra = 0
        if kind in (4, 5):  # STRUCT / UNION
            for i in range(vlen):
                m_name, m_type, m_off = struct.unpack_from("<III", d, p + i * 12)
                if kflag:
                    bit_off = m_off & 0xFFFFFF
                    bsz = m_off >> 24
                else:
                    bit_off = m_off
                    bsz = 0
                members.append((S(m_name), m_type, bit_off, bsz))
            extra = vlen * 12
        elif kind == 1:  # INT
            extra = 4
        elif kind == 3:  # ARRAY
            extra = 12
        elif kind == 6:  # ENUM
            extra = vlen * 8
        elif kind == 13:  # FUNC_PROTO
            extra = vlen * 8
        elif kind == 14:  # VAR
            extra = 4
        elif kind == 15:  # DATASEC
            extra = vlen * 12
        elif kind == 17:  # DECL_TAG
            extra = 4
        elif kind == 19:  # ENUM64
            extra = vlen * 12
        types.append(dict(name=S(name_off), kind=kind, size=size, members=members, id=len(types)))
        off += 12 + extra
    return types

def find(types, name, kind=4):
    out = [t for t in types if t and t["name"] == name and t["kind"] == kind]
    return out

a = parse(sys.argv[1])
b = parse(sys.argv[2])

def dump(t, types, depth=0, seen=None):
    lines = []
    lines.append("struct %s size=%d" % (t["name"], t["size"]))
    for n, ty, bo, bsz in t["members"]:
        lines.append("  %-32s off=%4d bits(%d bytes)" % (n, bo, bo // 8))
    return lines

names = sys.argv[3:] or ["module", "cred", "task_struct", "file", "kernel_param", "kmem_cache", "crypto_shash"]
for nm in names:
    ta = find(a, nm); tb = find(b, nm)
    print("=" * 70)
    print("### %s  | s9380 found=%d   aosp found=%d" % (nm, len(ta), len(tb)))
    if not ta or not tb:
        continue
    A, B = ta[0], tb[0]
    print("  size: s9380=%d  aosp=%d   %s" % (A["size"], B["size"], "SAME" if A["size"] == B["size"] else "DIFF"))
    da = {n: (bo, bsz) for n, ty, bo, bsz in A["members"]}
    db = {n: (bo, bsz) for n, ty, bo, bsz in B["members"]}
    onlyA = [n for n in da if n not in db]
    onlyB = [n for n in db if n not in da]
    diffs = [n for n in da if n in db and da[n][0] != db[n][0]]
    if onlyA: print("  only in s9380: %s" % ", ".join(onlyA))
    if onlyB: print("  only in aosp : %s" % ", ".join(onlyB))
    for n in diffs:
        print("  offset diff %-28s s9380=%d  aosp=%d" % (n, da[n][0] // 8, db[n][0] // 8))
    if not (onlyA or onlyB or diffs):
        print("  members identical")
