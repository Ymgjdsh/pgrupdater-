#!/usr/bin/env python3
"""In a CLASSIC (iOS 12 compatible) build such as 3.19.0, are the IMP fields of
*protocol* method lists NULL?  That tells us what a relative imp offset of 0
has to become in the rewritten absolute tables.

usage: python protocheck319.py <classic macho>
"""
import struct
import sys
import chained2dyld as C

m = C.MachO(open(sys.argv[1], "rb").read())
buf = m.buf


def u64(va):
    fo = m.foff(va)
    return struct.unpack_from("<Q", buf, fo)[0] if fo is not None else None


def u32(va):
    fo = m.foff(va)
    return struct.unpack_from("<I", buf, fo)[0] if fo is not None else None


def lst(va, label, stats):
    """walk a classic method list and classify the imp fields"""
    if not va:
        return
    hdr, cnt = u32(va), u32(va + 4)
    entsize = hdr & 0xffff
    if entsize != 24:
        print(f"    !! {label} list 0x{va:x} hdr=0x{hdr:08x} entsize={entsize}")
        return
    zero = nonzero = 0
    for i in range(cnt):
        imp = u64(va + 8 + 24 * i + 16)
        sec = m.sect_of(imp) if imp else None
        if imp == 0:
            zero += 1
        else:
            nonzero += 1
        if i < 2:
            sel = u64(va + 8 + 24 * i)
            nm = bytes(buf[m.foff(sel):m.foff(sel) + 32]).split(b"\0")[0].decode("latin-1") if sel else "?"
            print(f"    {label} list 0x{va:x} count={cnt} [{i}] {nm!r} "
                  f"imp=0x{imp:x}({sec['name'] if sec else 'NULL'})")
    stats[(label, "zero" if zero and not nonzero else "nonzero" if nonzero else "empty")] += 1
    stats[(label, "zero_entries")] += zero
    stats[(label, "nonzero_entries")] += nonzero


stats = {}
for secname in ("__objc_protolist", "__objc_catlist", "__objc_classlist"):
    sec = next((s for s in m.sections if s["name"] == secname and s["size"]), None)
    if not sec:
        print(f"no {secname}")
        continue
    print(f"\n{secname}: 0x{sec['addr']:x}+0x{sec['size']:x}")
    n = sec["size"] // 8
    for i in range(n):
        pv = u64(sec["addr"] + 8 * i)
        if not pv:
            continue
        if secname == "__objc_protolist":
            name = u64(pv + 8)
            nm = bytes(buf[m.foff(name):m.foff(name) + 40]).split(b"\0")[0].decode("latin-1")
            if i < 2:
                print(f"  protocol[{i}] 0x{pv:x} {nm!r}")
            for k, lab in ((3, "proto.im"), (4, "proto.cm"), (5, "proto.opt.im"), (6, "proto.opt.cm")):
                lst(u64(pv + 8 * k), lab, stats)
        elif secname == "__objc_catlist":
            name = u64(pv)
            cls = u64(pv + 8)
            nm = bytes(buf[m.foff(name):m.foff(name) + 40]).split(b"\0")[0].decode("latin-1")
            if i < 2:
                print(f"  category[{i}] 0x{pv:x} {nm!r}")
            lst(u64(pv + 16), "cat.im", stats)
            lst(u64(pv + 24), "cat.cm", stats)
        else:
            ro = u64(pv) & ~0x7
            nm = bytes(buf[m.foff(u64(ro + 24)):m.foff(u64(ro + 24)) + 40]).split(b"\0")[0].decode("latin-1")
            if i < 2:
                print(f"  class[{i}] 0x{pv:x} ro=0x{ro:x} {nm!r}")
            lst(u64(ro + 32), "cls.im", stats)

print()
for k in sorted(stats, key=str):
    print(f"  {k}: {stats[k]}")
