#!/usr/bin/env python3
"""strrefs.py <macho> <string-va> [window]

Find code that materialises the address of a string constant (ADRP [+ ADD])
inside any instruction section, and disassemble around each hit.  Complement of
selsites.py (which handles ADRP+LDR slot loads).
"""
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

import chained2dyld as C


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    path, target = argv[0], int(argv[1], 0)
    win = int(argv[2], 0) if len(argv) > 2 else 0x30
    m = C.MachO(open(path, "rb").read())
    buf = m.buf
    codes = [s for s in m.sections if s["seg"] == "__TEXT" and (s["flags"] & 0x80000400)]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    page, off12 = target & ~0xFFF, target & 0xFFF
    hits = []
    for sec in codes:
        for i in range(0, sec["size"] - 8, 4):
            w = struct.unpack_from("<I", buf, sec["offset"] + i)[0]
            if (w & 0x9F000000) != 0x90000000:          # ADRP
                continue
            pc = sec["addr"] + i
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = (immhi << 2 | immlo)
            if imm & (1 << 20):
                imm -= (1 << 21)
            if ((pc & ~0xFFF) + (imm << 12)) != page:
                continue
            rn = w & 0x1F
            w2 = struct.unpack_from("<I", buf, sec["offset"] + i + 4)[0]
            same = ((w2 >> 5) & 0x1F) == rn
            if (w2 & 0xFF800000) == 0x91000000 and same:      # ADD (imm), 64-bit
                if ((w2 >> 10) & 0xFFF) == off12:
                    hits.append((sec["name"], pc))
            elif (w2 & 0xFFC00000) == 0xF9400000 and same:    # LDR 64-bit
                if ((w2 >> 10) & 0xFFF) * 8 == off12:
                    hits.append((sec["name"], pc))
    print("%d reference(s) to string 0x%x" % (len(hits), target))
    for name, pc in hits:
        print("---- hit in %s at 0x%x" % (name, pc))
        fo = m.foff(pc)
        for ins in md.disasm(bytes(buf[fo:fo + win]), pc):
            print("  0x%08X  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
