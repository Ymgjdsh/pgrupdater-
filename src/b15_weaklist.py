#!/usr/bin/env python3
"""b15: full list of strong->weak bind flips introduced by the converter (UnityFramework),
with the library each symbol is imported from. Uses 0-based chained pointer ordinals."""
import struct, collections

FW_P = r"H:/file/phi/work/UnityFramework"
FW_Q = r"H:/file/phi/out/UnityFramework.v4"


def rd(b, o, f):
    return struct.unpack_from(f, b, o)


def uleb(b, p):
    r = s = 0
    while True:
        x = b[p]; p += 1
        r |= (x & 0x7F) << s
        if not (x & 0x80):
            return r, p
        s += 7


def parse(path):
    b = open(path, "rb").read()
    ncmds, = rd(b, 16, "<I")
    o = 32
    cmds = []
    for _ in range(ncmds):
        c, cs = rd(b, o, "<II")
        cmds.append((c, cs, o))
        o += cs
    segs, dylibs = [], []
    info = chained = None
    for c, cs, o in cmds:
        if c == 0x19:
            nm = b[o + 8:o + 24].split(b"\0")[0].decode()
            va, vs, fo, fs = rd(b, o + 24, "<QQQQ")
            segs.append(dict(name=nm, vmaddr=va, vmsize=vs, fileoff=fo, filesize=fs))
        elif c in (0xC, 0x80000018, 0x8000001F):
            no, = rd(b, o + 8, "<I")
            dylibs.append((c == 0x80000018, b[o + 24:o + 24 + no].split(b"\0")[0].decode()))
        elif c == 0x80000034:
            do, ds = rd(b, o + 8, "<II"); chained = (do, ds)
        elif c == 0x80000022:
            info = rd(b, o + 8, "<10I")
    return dict(b=b, segs=segs, dylibs=dylibs, chained=chained, info=info)


def pristine(path):
    m = parse(path)
    b = m["b"]
    ib = [s for s in m["segs"] if s["name"] == "__TEXT"][0]["vmaddr"]
    do, ds = m["chained"]
    ver, starts, imports_off, symbols_off, imp_count, imp_fmt, sym_fmt = rd(b, do, "<7I")
    imports = []
    for i in range(imp_count):
        raw, = rd(b, do + imports_off + 4 * i, "<I")
        name_off = raw >> 9
        e = b.find(b"\0", do + symbols_off + name_off)
        imports.append((b[do + symbols_off + name_off:e].decode("utf-8", "replace"), raw & 0xFF, (raw >> 8) & 1))
    scount, = rd(b, do + starts, "<I")
    gei = [rd(b, do + starts + 4 + 4 * i, "<I")[0] for i in range(scount)]
    out = {}
    for sio in gei:
        if sio == 0:
            continue
        p = do + starts + sio
        size, page_size, ptr_fmt, seg_off = rd(b, p, "<IHHQ")
        maxv, page_count = rd(b, p + 16, "<IH")
        base = p + 22
        for pg in range(page_count):
            ps, = rd(b, base + 2 * pg, "<H")
            if ps == 0xFFFF:
                continue
            offs = [ps]
            if ps & 0x8000:
                cnt = ps & 0x7FFF
                offs = [rd(b, base + 2 * page_count + 2 * k, "<H")[0] for k in range(cnt)]
            for o0 in offs:
                loc = ib + seg_off + pg * page_size + o0
                while True:
                    fo = loc - ib
                    if fo < 0 or fo + 8 > len(b):
                        break
                    raw, = rd(b, fo, "<Q")
                    nxt = (raw >> 51) & 0xFFF
                    if (raw >> 63) & 1:
                        ordn = raw & 0xFFFFFF
                        nm, lib, weak = imports[ordn] if 0 <= ordn < len(imports) else ("<ord %d>" % ordn, -1, -1)
                        out[loc] = (nm, lib, weak)
                    if nxt == 0:
                        break
                    loc += nxt * 4
    return m, out


def patched(path):
    m = parse(path)
    b = m["b"]
    bind_off, bind_sz = m["info"][2], m["info"][3]
    p, end = bind_off, bind_off + bind_sz
    seg_idx = seg_off = None
    seg_off = 0
    sym = None; flags = 0; ordn = None
    out = {}
    while p < end:
        b0 = b[p]; op, imm = b0 & 0xF0, b0 & 0x0F; p += 1

        def L():
            return (m["segs"][seg_idx]["vmaddr"] if seg_idx is not None else 0) + seg_off

        def rec():
            nonlocal seg_off
            out[L()] = (sym, ordn, flags); seg_off += 8
        if op == 0x00:
            break
        elif op == 0x10:
            ordn = imm
        elif op == 0x20:
            ordn, p = uleb(b, p)
        elif op == 0x30:
            ordn = 0 if imm == 0 else imm - 16
        elif op == 0x40:
            flags = imm; e = b.find(b"\0", p, end); sym = b[p:e].decode("utf-8", "replace"); p = e + 1
        elif op == 0x50:
            pass
        elif op == 0x60:
            _, p = uleb(b, p)
        elif op == 0x70:
            seg_idx = imm; seg_off, p = uleb(b, p)
        elif op == 0x80:
            d, p = uleb(b, p); seg_off += d
        elif op == 0x90:
            rec()
        elif op == 0xA0:
            rec(); d, p = uleb(b, p); seg_off += d
        elif op == 0xB0:
            rec(); seg_off += imm * 8
        elif op == 0xC0:
            c, p = uleb(b, p); skip, p = uleb(b, p)
            for _ in range(c):
                rec(); seg_off += skip
    return m, out


pm, pf = pristine(FW_P)
qm, qf = patched(FW_Q)
dylibs = pm["dylibs"]
flips = []
for s in sorted(set(pf) & set(qf)):
    pn, pl, pw = pf[s]
    qn, qo, qfl = qf[s]
    if pn != qn:
        print("!!! name mismatch at 0x%x: %s vs %s" % (s, pn, qn))
    if pw == 0 and (qfl & 1):
        flips.append((s, pn, pl))
print("strong->weak flipped slots: %d ; distinct names: %d" % (len(flips), len({f[1] for f in flips})))
cat = collections.Counter()
non_swift = []
for s, n, l in flips:
    if n.startswith("_$s") or n.startswith("_$S"):
        cat["swift mangled ($s)"] += 1
    else:
        cat["other"] += 1
        non_swift.append((n, l, s))
print("categorisation: %s" % dict(cat))
print()
print("library distribution of flipped symbols (import lib_ordinal -> dylib):")
libc = collections.Counter()
for s, n, l in flips:
    dn = dylibs[l - 1][1] if 1 <= l <= len(dylibs) else "ord %d" % l
    libc[dn] += 1
for dn, c in libc.most_common():
    print("   %-60s %d" % (dn, c))
print()
print("NON-Swift flipped names (complete list, %d):" % len(non_swift))
for n, l, s in sorted(non_swift):
    dn = dylibs[l - 1][1] if 1 <= l <= len(dylibs) else "ord %d" % l
    print("   0x%08x  %-46s  %s" % (s, n, dn))
sw = sorted({f[1] for f in flips if f[1].startswith("_$s") or f[1].startswith("_$S")})
print()
print("Swift flipped names: %d (first 25)" % len(sw))
for n in sw[:25]:
    print("   %s" % n)
open("b15_non_swift_flips.txt", "w").write("\n".join("%s\t%s" % (n, dylibs[l - 1][1] if 1 <= l <= len(dylibs) else "?") for n, l, s in sorted(non_swift)))
open("b15_swift_flips.txt", "w").write("\n".join(sw))
print()
print("written b15_non_swift_flips.txt and b15_swift_flips.txt")
