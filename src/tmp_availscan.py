#!/usr/bin/env python3
"""tmp_availscan.py <macho> [lo] [hi]  --  tally every `bl` target inside a VA
window and print the hot ones (candidate runtime primitives).

Used to make sure patch_v14.py patches *every* platform-version primitive:
`__isPlatformVersionAtLeast` @0x143b914 has 72 callers; if another helper in
the same region has many callers too, it is a second availability fork.
"""
import sys, struct
import chained2dyld as C

lo = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x143B000
hi = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x1440000

m = C.MachO(open(sys.argv[1], "rb").read())
tally = {}
for sec in m.sections:
    if sec["name"] not in ("__text", "__stubs", "__objc_stubs"):
        continue
    fo = m.foff(sec["addr"])
    if fo is None:
        continue
    buf = m.buf[fo:fo + sec["size"]]
    n = len(buf) // 4
    for i in range(n):
        w = struct.unpack_from("<I", buf, i * 4)[0]
        if (w & 0xFC000000) != 0x94000000:
            continue
        pc = sec["addr"] + i * 4
        d = w & 0x03FFFFFF
        if d & (1 << 25):
            d -= 1 << 26
        t = pc + d * 4
        if lo <= t < hi:
            tally[t] = tally.get(t, 0) + 1

print("== bl targets in 0x%x..0x%x (count >= 3)" % (lo, hi))
for t in sorted(tally, key=lambda k: -tally[k]):
    if tally[t] >= 3:
        print("   0x%x  %d caller(s)" % (t, tally[t]))
print("== total hot targets:", sum(1 for t in tally if tally[t] >= 3))
