import collections

import chained2dyld as C

for p in (r"work\Phigros.main", r"out\Phigros.v6"):
    m = C.MachO(open(p, "rb").read())
    try:
        fx = C.decode_fixups(m)["fixups"]
    except Exception as e:
        print(p, "no chained fixups:", e)
        fx = []
    binds = collections.Counter(f["name"] for f in fx if f["kind"] == "bind")
    print(f"--- {p}: {len(fx)} fixups")
    for k, v in binds.items():
        print(f"    bind {k} x{v}")
    stubs = [s for s in m.sections if s["name"] == "__objc_stubs"]
    if stubs:
        st = stubs[0]
        va, size = st["addr"], st["size"]
        print(f"    __objc_stubs {va:#x} size {size:#x} "
              f"({size // 32} x 32B, {size // 16} x 16B)")
        for i in range(0, min(size, 0x40), 16):
            w = C.rd(m.buf, m.foff(va + i), "IIII")
            print(f"      {va + i:#x}: " + " ".join(f"{x:08x}" for x in w))
    for name in ("__objc_selrefs", "__objc_classrefs"):
        sec = [s for s in m.sections if s["name"] == name]
        for s in sec:
            vals = [C.rd(m.buf, m.foff(s["addr"]) + 8 * i, "Q")[0]
                    for i in range(min(s["size"] // 8, 40))]
            print(f"    {name}: {s['size'] // 8} slots")
            for v in vals:
                if name == "__objc_selrefs" and v:
                    try:
                        fo = m.foff(v)
                        z = m.buf.find(b"\0", fo)
                        print(f"      -> {bytes(m.buf[fo:z]).decode('latin1')!r}")
                    except Exception as e:
                        print(f"      -> {v:#x} ({e})")
                elif v:
                    print(f"      -> {v:#x}")
