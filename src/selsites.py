#!/usr/bin/env python3
"""Find code that references a GOT/const slot, and disassemble around it.

usage: python selsites.py <macho> <slot-va> [window]

Scans __TEXT for ADRP whose page target is the slot's page, then checks the
following instruction for a matching LDR.  Prints the disassembly window after
each hit so the selector argument (loaded before objc_msgSend) is visible.
"""
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

import chained2dyld as C


def main(argv):
    path, slot = argv[0], int(argv[1], 0)
    win = int(argv[2], 0) if len(argv) > 2 else 0x20
    m = C.MachO(open(path, "rb").read())
    buf = m.buf
    codes = [s for s in m.sections if s["seg"] == "__TEXT"
             and (s["flags"] & 0x80000400)]
    if not codes:
        raise SystemExit("no instruction sections found")
    print("scanning " + ", ".join("%s (%d bytes)" % (s["name"], s["size"]) for s in codes))
    start, size, off = codes[0]["addr"], codes[0]["size"], codes[0]["offset"]
    page = slot & ~0xFFF
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    hits = []
    pageonly = []
    for sec in codes:
        s_start, s_size, s_off = sec["addr"], sec["size"], sec["offset"]
        for i in range(0, s_size - 16, 4):
            w = struct.unpack_from("<I", buf, s_off + i)[0]
            if (w & 0x9F000000) != 0x90000000:      # ADRP
                continue
            pc = s_start + i
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = (immhi << 2 | immlo)
            if imm & (1 << 20):
                imm -= (1 << 21)
            if ((pc & ~0xFFF) + (imm << 12)) != page:
                continue
            # next instruction must be an LDR using the same register with offset
            w2 = struct.unpack_from("<I", buf, s_off + i + 4)[0]
            if (w2 & 0xFFC00000) != 0xF9400000:
                pageonly.append((sec["name"], pc))
                continue
            rt = w2 & 0x1F
            rn = (w2 >> 5) & 0x1F
            if rn != (w & 0x1F):
                pageonly.append((sec["name"], pc))
                continue
            ldr_off = ((w2 >> 10) & 0xFFF) * 8
            if slot & 0xFFF != ldr_off:
                pageonly.append((sec["name"], pc))
                continue
            hits.append((sec["name"], pc))
    print("%d reference(s) to slot 0x%x (page-only ADRPs: %d)"
          % (len(hits), slot, len(pageonly)))
    for name, pc in hits:
        print("---- hit in %s at 0x%x" % (name, pc))
        fo = m.foff(pc)
        for ins in md.disasm(bytes(buf[fo:fo + win]), pc):
            print("  0x%08X  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
