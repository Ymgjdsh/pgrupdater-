#!/usr/bin/env python3
"""wideaddrefs.py <macho> <target-va> [window]

Like addrefs.py but tolerant: find every ADRP to the target's page and look
ahead up to `window` instructions (default 6) for an ADD/LDR with the same
base register whose immediate resolves to the target.  Used to count *all*
uses of a constant object such as an NSString literal.
"""
import struct
import sys

import chained2dyld as C


def main(argv):
    path, target = argv[1], int(argv[2], 0)
    win = int(argv[3], 0) if len(argv) > 3 else 6
    m = C.MachO(open(path, "rb").read())
    buf = m.buf
    page = target & ~0xFFF
    hits = []
    for sec in m.sections:
        if sec["seg"] != "__TEXT" or not (sec["flags"] & 0x80000400):
            continue
        n = sec["size"] // 4
        for i in range(n):
            pc = sec["addr"] + i * 4
            w = struct.unpack_from("<I", buf, sec["offset"] + i * 4)[0]
            if (w & 0x9F000000) != 0x90000000:
                continue
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = (immhi << 2 | immlo)
            if imm & (1 << 20):
                imm -= (1 << 21)
            if (pc & ~0xFFF) + (imm << 12) != page:
                continue
            rn = w & 0x1F
            for k in range(1, win + 1):
                if i + k >= n:
                    break
                w2 = struct.unpack_from("<I", buf, sec["offset"] + (i + k) * 4)[0]
                if ((w2 >> 5) & 0x1F) != rn:
                    continue
                if (w2 & 0xFF800000) == 0x91000000:      # ADD imm (no shift)
                    if page + ((w2 >> 10) & 0xFFF) == target:
                        hits.append(("ADD", pc, pc + k * 4))
                        break
                elif (w2 & 0xFFC00000) == 0xF9400000:    # LDR 64
                    if page + ((w2 >> 10) & 0xFFF) * 8 == target:
                        hits.append(("LDR", pc, pc + k * 4))
                        break
    for kind, pc, at in sorted(hits, key=lambda h: h[1]):
        print("%-4s adrp@0x%08x  op@0x%08x" % (kind, pc, at))
    print("%d use(s) of 0x%x" % (len(hits), target))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
