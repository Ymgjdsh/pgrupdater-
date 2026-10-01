"""Dump a vtable/pointer table with nearest-preceding symbol names.

usage: python vt.py <macho> <va> [count]
"""
import sys

import chained2dyld as C
import symat

path = sys.argv[1]
va = int(sys.argv[2], 0)
count = int(sys.argv[3], 0) if len(sys.argv) > 3 else 8

m = C.MachO(open(path, "rb").read())
im = symat.lbl.Img(path)
syms = sorted(symat.symbols(im))


def nearest(a):
    best = None
    for v, ntype, nsect, name in syms:
        if v <= a:
            best = (v, name)
        else:
            break
    if best is None:
        return f"<below first symbol {a:#x}>"
    return f"{best[1]} +{a - best[0]:#x}"


for i in range(count):
    a = va + 8 * i
    try:
        val = C.rd(m.buf, m.foff(a), "Q")[0]
    except Exception as exc:  # pragma: no cover
        print(f"{a:#x}: <unmapped: {exc}>")
        break
    sec = m.sect_of(val) if val else None
    print(f"{a:#x}: {val:#018x}  [{sec}]  {nearest(val) if val else ''}")
