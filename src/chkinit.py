#!/usr/bin/env python3
"""Compare pristine __TEXT,__init_offsets with converted __DATA_CONST,__mod_init_func.

Order matters: dyld runs the initializers in array order, so a reordering in the
conversion would change C++ static-init order (and can leave a global
half-constructed, e.g. an empty boost::asio any_executor).

usage: python chkinit.py <pristine> <converted>
"""
import struct
import sys

import chained2dyld as C


def sect(m, name):
    for s in m.sections:
        if s["name"] == name:
            return s
    return None


def main(argv):
    p = C.MachO(open(argv[0], "rb").read())
    c = C.MachO(open(argv[1], "rb").read())
    pbuf = open(argv[0], "rb").read()
    cbuf = open(argv[1], "rb").read()

    ps = sect(p, "__init_offsets")
    cs = sect(c, "__mod_init_func")
    if ps is None or cs is None:
        sys.exit("missing section")
    print("pristine __init_offsets  addr=0x%x size=0x%x (off=0x%x)"
          % (ps["addr"], ps["size"], ps["offset"]))
    print("converted __mod_init_func addr=0x%x size=0x%x (off=0x%x)"
          % (cs["addr"], cs["size"], cs["offset"]))
    pn = ps["size"] // 4
    cn = cs["size"] // 8
    print("entries pristine=%d converted=%d" % (pn, cn))
    poffs = struct.unpack_from("<%dI" % pn, pbuf, ps["offset"])
    cptrs = struct.unpack_from("<%dQ" % cn, cbuf, cs["offset"])
    base = p.preferred_base if hasattr(p, "preferred_base") else 0x100000000
    bad = []
    for i in range(min(pn, cn)):
        want = base + poffs[i]
        if cptrs[i] != want:
            bad.append((i, poffs[i], want, cptrs[i]))
    print("order-preserving (ptr[i] == base + off[i]): %s"
          % ("YES" if not bad else "NO (%d mismatches)" % len(bad)))
    for i, o, w, g in bad[:20]:
        print("  idx %4d off=0x%08x want=0x%016x got=0x%016x" % (i, o, w, g))
    # any duplicates / ordering anomalies in pristine
    print("pristine offsets strictly increasing: %s"
          % (all(poffs[i] < poffs[i + 1] for i in range(pn - 1))))
    print("converted ptrs strictly increasing: %s"
          % (all(cptrs[i] < cptrs[i + 1] for i in range(cn - 1))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
