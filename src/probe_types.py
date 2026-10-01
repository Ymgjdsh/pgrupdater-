#!/usr/bin/env python3
"""Show how the relative `types`/`name`/`imp` fields of the first few lists resolve."""
import sys
import chained2dyld as C

path = sys.argv[1] if len(sys.argv) > 1 else "work/UnityFramework"
nlist = int(sys.argv[2]) if len(sys.argv) > 2 else 3
m = C.MachO(open(path, "rb").read())
buf = m.buf
dec = C.decode_fixups(m)
by_va = {f["vmaddr"]: f for f in dec["fixups"] if f["foff"] is not None}

s = next(x for x in m.sections if x["name"] == "__objc_methlist" and x["size"])
print(f"section {s['seg']},{s['name']} 0x{s['addr']:x}+0x{s['size']:x}")


def cstr(va, maxlen=48):
    fo = m.foff(va)
    if fo is None:
        return "<nofile>"
    raw = bytes(buf[fo:fo + maxlen])
    return raw.split(b"\0")[0].decode("latin-1")


cur, shown = s["addr"], 0
while shown < nlist and cur + 8 <= s["addr"] + s["size"]:
    hdr = C.rd(buf, m.foff(cur), "I")[0]
    cnt = C.rd(buf, m.foff(cur) + 4, "I")[0]
    print(f"\nlist 0x{cur:x} hdr=0x{hdr:08x} count={cnt}")
    for i in range(min(cnt, 4)):
        fva = cur + 8 + 12 * i
        rn, rt, ri = C.rd(buf, m.foff(fva), "iii")
        tv = fva + 4 + rt
        iv = fva + 8 + ri
        nv = fva + rn
        tsec = m.sect_of(tv)
        print(f"  m{i}: name -> 0x{nv:x} {m.sect_of(nv)['name']:16s}"
              f" sel={cstr(by_va[nv]['target'], 24) if nv in by_va else '?'}")
        print(f"      types -> 0x{tv:x} {tsec['name']:16s} {cstr(tv, 28)!r}")
        print(f"      imp   -> 0x{iv:x} {m.sect_of(iv)['name']}")
    cur = C.round_up(cur + 8 + 12 * cnt, 8)
    shown += 1
