#!/usr/bin/env python3
"""For a selector name, show the pristine relative entry and every candidate
base convention, so we can tell which one yields a real __text IMP."""
import sys
import chained2dyld as C

pm = C.MachO(open(sys.argv[1], "rb").read())
buf = pm.buf
want = sys.argv[2]
fix = C.decode_fixups(pm)["fixups"]
by_va = {f["vmaddr"]: f for f in fix if f["foff"] is not None}
s = [x for x in pm.sections if x["seg"] == "__TEXT" and x["name"] == "__objc_methlist" and x["size"]][0]


def cstr(va, n=40):
    fo = pm.foff(va)
    return bytes(buf[fo:fo + n]).split(b"\0")[0].decode("latin-1") if fo else "?"


cur = s["addr"]
while cur + 8 <= s["addr"] + s["size"]:
    hdr, cnt = C.rd(buf, pm.foff(cur), "II")
    for j in range(cnt):
        fva = cur + 8 + 12 * j
        rn, rt, ri = C.rd(buf, pm.foff(fva), "iii")
        nv = fva + rn
        f = by_va.get(nv)
        sel = cstr(f["target"], 48) if f else "?"
        if sel != want:
            continue
        print(f"pristine list 0x{cur:x} hdr=0x{hdr:08x} count={cnt} method {j} entry 0x{fva:x}")
        print(f"  raw  rel_name={rn} rel_types={rt} rel_imp={ri}"
              f"  (0x{rn & 0xffffffff:x} 0x{rt & 0xffffffff:x} 0x{ri & 0xffffffff:x})")
        print(f"  name field 0x{fva:x} -> 0x{nv:x} ({pm.sect_of(nv)['name']}) sel={sel!r}")
        for base_name, base in (("field", fva + 8), ("entry", fva), ("list", cur), ("entry+4", fva + 4)):
            v = base + ri
            sc = pm.sect_of(v)
            print(f"  imp = {base_name:7s} + rel = 0x{v:x} -> "
                  f"{sc['seg'] + ',' + sc['name'] if sc else '?'}"
                  f"{'  (4-byte aligned)' if v % 4 == 0 else ''}")
        d = fva + rt + 4
        print(f"  types field base: field -> 0x{fva + 4 + rt:x} ({pm.sect_of(fva + 4 + rt)['name']})"
              f" {cstr(fva + 4 + rt, 24)!r}")
        break
    cur = C.round_up(cur + 8 + 12 * cnt, 8)
