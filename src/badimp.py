#!/usr/bin/env python3
"""Dump the method entries whose decoded IMP does not land in __text."""
import struct
import sys
import chained2dyld as C

cm = C.MachO(open(sys.argv[1], "rb").read())
buf = cm.buf
ns = [x for x in cm.sections if x["seg"] == C.REL_METH_SEG and x["name"] == "__objc_methlist"][0]
old = [x for x in cm.sections if x["seg"] == "__TEXT" and x["name"] == "__objc_methlist"][0]
lo, hi = old["addr"], old["addr"] + old["size"]
print(f"old section 0x{lo:x}+0x{old['size']:x} ends 0x{hi:x}")

shown, total, lists = 0, 0, {}
cur = ns["addr"]
while cur + 8 <= ns["addr"] + ns["size"]:
    hdr, cnt = C.rd(buf, cm.foff(cur), "II")
    for j in range(cnt):
        fo = cm.foff(cur) + 8 + 24 * j
        sel, types, imp = struct.unpack_from("<QQQ", buf, fo)
        if lo <= imp < hi:
            total += 1
            if shown < 8:
                shown += 1
                print(f"\nlist 0x{cur:x} hdr={hdr} count={cnt} method {j}")
                print(f"  sel   0x{sel:x}  {bytes(buf[cm.foff(sel):cm.foff(sel)+32]).split(b'\\0')[0]!r}")
                print(f"  types 0x{types:x} {bytes(buf[cm.foff(types):cm.foff(types)+32]).split(b'\\0')[0]!r}")
                print(f"  imp   0x{imp:x} -> {cm.sect_of(imp)['name']}  (delta from list start 0x{imp-cur:x})")
    lists.setdefault(hdr, 0)
    cur += 8 + 24 * cnt
print(f"\n{total} bad imp field(s)")
