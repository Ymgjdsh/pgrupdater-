#!/usr/bin/env python3
"""addrefs.py <macho> <addr-lo> <addr-hi>

List every code site that materialises an address inside [lo,hi] -- both
"ADRP + ADD #imm" (address of data) and "ADRP + LDR #off" (loading a pointer
slot).  Prints "kind addr pc".
"""
import struct
import sys

import chained2dyld as C


def main(argv):
    if len(argv) != 4:
        print(__doc__)
        return 2
    path, lo, hi = argv[1], int(argv[2], 0), int(argv[3], 0)
    m = C.MachO(open(path, "rb").read())
    buf = m.buf
    codes = [s for s in m.sections if s["seg"] == "__TEXT" and (s["flags"] & 0x80000400)]
    out = []
    for sec in codes:
        for i in range(0, sec["size"] - 8, 4):
            w = struct.unpack_from("<I", buf, sec["offset"] + i)[0]
            if (w & 0x9F000000) != 0x90000000:                 # ADRP
                continue
            pc = sec["addr"] + i
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = (immhi << 2 | immlo)
            if imm & (1 << 20):
                imm -= (1 << 21)
            page = (pc & ~0xFFF) + (imm << 12)
            rn = w & 0x1F
            w2 = struct.unpack_from("<I", buf, sec["offset"] + i + 4)[0]
            if ((w2 >> 5) & 0x1F) != rn:
                continue
            if (w2 & 0xFF800000) == 0x91000000:                 # ADD (imm)
                a = page + ((w2 >> 10) & 0xFFF)
                if lo <= a <= hi:
                    out.append(("ADD", a, pc))
            elif (w2 & 0xFFC00000) == 0xF9400000:               # LDR 64-bit
                a = page + ((w2 >> 10) & 0xFFF) * 8
                if lo <= a <= hi:
                    out.append(("LDR", a, pc))
    for kind, a, pc in sorted(out, key=lambda t: (t[1], t[2])):
        print("%-4s 0x%08x <- code 0x%08x" % (kind, a, pc))
    print("%d site(s) in [0x%x,0x%x]" % (len(out), lo, hi))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
