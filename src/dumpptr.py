#!/usr/bin/env python3
"""dumpptr.py <macho> <va> <count> -- dump a pointer table, resolving each target string."""
import sys

import chained2dyld as C


def main(argv):
    if len(argv) != 4:
        print(__doc__)
        return 2
    path, va, n = argv[1], int(argv[2], 0), int(argv[3], 0)
    m = C.MachO(open(path, "rb").read())
    dec = C.decode_fixups(m)
    tgt = {f["vmaddr"]: f.get("target") for f in dec["fixups"] if f.get("target")}
    for i in range(n):
        slot = va + i * 8
        t = tgt.get(slot)
        s = ""
        if t:
            try:
                fo = m.foff(t)
                end = m.buf.index(b"\0", fo)
                s = m.buf[fo:end].decode("utf-8", "replace")[:48]
            except Exception:
                s = "<unreadable>"
        print("0x%08x -> %-14s %s" % (slot, ("0x%x" % t) if t else "-", s))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
