#!/usr/bin/env python3
"""Classify every pointer written into __DATA_METHLIST by field kind."""
import collections
import struct
import sys
import chained2dyld as C

cm = C.MachO(open(sys.argv[1], "rb").read())
buf = cm.buf
ns = [x for x in cm.sections if x["seg"] == C.REL_METH_SEG and x["name"] == "__objc_methlist"][0]
kind_by = collections.Counter()
sec_by_kind = collections.defaultdict(collections.Counter)
bad = []
cur = ns["addr"]
i = 0
while cur + 8 <= ns["addr"] + ns["size"]:
    hdr, cnt = C.rd(buf, cm.foff(cur), "II")
    for j in range(cnt):
        fo = cm.foff(cur) + 8 + 24 * j
        vals = struct.unpack_from("<QQQ", buf, fo)
        for k, v in enumerate(("sel", "types", "imp")):
            s = cm.sect_of(vals[k])
            name = f"{s['seg']},{s['name']}" if s else "?"
            if name == "__TEXT,__objc_methlist":
                bad.append((hex(cur + 8 + 24 * j + 8 * k), v, k, j))
            sec_by_kind[v][name] += 1
    cur += 8 + 24 * cnt
    i += 1
for k in ("sel", "types", "imp"):
    print(f"{k:6s}: " + ", ".join(f"{s}={n}" for s, n in sec_by_kind[k].most_common(8)))
print(f"\n{len(bad)} field(s) land in the old __objc_methlist, e.g.")
for b in bad[:6]:
    voff, v, k, j = b
    print(f"  field {'sel/types/imp'.split('/')[k]} of method {j} at 0x{voff}: 0x{v:x}")
