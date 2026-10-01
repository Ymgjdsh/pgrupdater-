#!/usr/bin/env python3
"""b17: does the working 3.19.0 build bind the same Swift symbols (and how)?"""
import struct, zipfile

IPA319 = r"H:/file/phi/games.Pigeon.Phigros_3.19.0_und3fined.ipa"

flips = {l.split("\t")[0] for l in open("b15_non_swift_flips.txt").read().splitlines() if l}
flips |= {l for l in open("b15_swift_flips.txt").read().splitlines() if l}
missing16 = {l for l in open("b16_missing_flips.txt").read().splitlines() if l}


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


def parse(path=None, data=None):
    b = data if data is not None else open(path, "rb").read()
    ncmds, = rd(b, 16, "<I")
    o = 32
    segs = []
    info = None
    symoff = nsyms = stroff = 0
    for _ in range(ncmds):
        c, cs = rd(b, o, "<II")
        if c == 0x19:
            nm = b[o + 8:o + 24].split(b"\0")[0].decode()
            va, vs, fo, fs = rd(b, o + 24, "<QQQQ")
            segs.append(dict(name=nm, vmaddr=va, vmsize=vs, fileoff=fo, filesize=fs))
        elif c == 0x80000022:
            info = rd(b, o + 8, "<10I")
        elif c == 0x2:
            symoff, nsyms, stroff, strsize = rd(b, o + 8, "<IIII")
        o += cs
    return dict(b=b, segs=segs, info=info, symoff=symoff, nsyms=nsyms, stroff=stroff)


def binds(m):
    b = m["b"]
    bind_off, bind_sz = m["info"][2], m["info"][3]
    p, end = bind_off, bind_off + bind_sz
    seg_idx = None; seg_off = 0; sym = None; flags = 0
    out = {}
    while p < end:
        b0 = b[p]; op, imm = b0 & 0xF0, b0 & 0x0F; p += 1

        def rec():
            nonlocal seg_off
            out.setdefault(sym, []).append(flags & 1)
            seg_off += 8
        if op == 0x00:
            break
        elif op == 0x10:
            pass
        elif op == 0x20:
            _, p = uleb(b, p)
        elif op == 0x30:
            pass
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
    return out


z = zipfile.ZipFile(IPA319)
m = parse(data=z.read("Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework"))
b = binds(m)
print("3.19.0 framework total bound symbols: %d" % len(b))
weak = {k for k, v in b.items() if any(v)}
strong = {k for k, v in b.items() if not all(v)}
print("   bound weak-only: %d ; bound strong (at least once): %d" % (len(weak), len({k for k, v in b.items() if any(x == 0 for x in v)})))

for label, s in [("403 flipped names", flips), ("13 names not in 12.2 runtime", missing16)]:
    inter = s & set(b)
    st = {n for n in inter if any(x == 0 for x in b[n])}
    wk = inter - st
    print()
    print("%s: referenced by 3.19.0 = %d (bound STRONG %d, weak-only %d); NOT referenced = %d"
          % (label, len(inter), len(st), len(wk), len(s - set(b))))
    print("   bound strong by 3.19.0 (must exist on the target device): %s" % sorted(st)[:25])
    print("   weak-only in 3.19.0: %s" % sorted(wk)[:15])
sw = sorted({n for n in b if n.startswith("_$s") or n.startswith("_$S") or n.startswith("_swift_")})
print()
print("3.19.0 framework references %d Swift-looking symbols; e.g. %s" % (len(sw), sw[:12]))
