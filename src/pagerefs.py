#!/usr/bin/env python3
"""Count ADRP references to a set of pages in the code sections.

usage: python pagerefs.py <macho> <page> [page...]
"""
import struct
import sys

import chained2dyld as C


def main(argv):
    m = C.MachO(open(argv[0], "rb").read())
    buf = m.buf
    codes = [s for s in m.sections
             if s["seg"] == "__TEXT" and (s["flags"] & 0x80000400)]
    for a in argv[1:]:
        page = int(a, 0)
        n, out = 0, []
        for sec in codes:
            for i in range(0, sec["size"] - 4, 4):
                w = struct.unpack_from("<I", buf, sec["offset"] + i)[0]
                if (w & 0x9F000000) != 0x90000000:
                    continue
                imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)
                if imm & (1 << 20):
                    imm -= (1 << 21)
                pc = sec["addr"] + i
                if ((pc & ~0xFFF) + (imm << 12)) == page:
                    n += 1
                    if len(out) < 8:
                        out.append("%s@0x%x" % (sec["name"], pc))
        print("page 0x%x: %d adrp reference(s) %s" % (page, n, " ".join(out)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
