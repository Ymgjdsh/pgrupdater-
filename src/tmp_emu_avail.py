"""tmp_emu_avail.py <macho> <cave-va-hex> -- emulate the v14 availability stub.

Runs the stub for a set of (major,minor,subminor) requests and prints the
answer.  Expected for --avail=12.5.8: 1 for <= 12.5.8, 0 above.
"""
import sys
import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *


def main(path, cave):
    m = open(path, "rb").read()
    # find the file offset of the cave via a minimal Mach-O walk
    import chained2dyld as C
    mo = C.MachO(m)
    fo = mo.foff(cave)
    code = m[fo:fo + 0x40]
    BASE = cave & ~0xFFFF
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(BASE, 0x10000)
    uc.mem_write(BASE, m[mo.foff(BASE):mo.foff(BASE) + 0x10000])
    STACK = BASE + 0x8000
    STOP = cave + 0x80

    cases = [(12, 5, 8, 1), (12, 5, 7, 1), (12, 4, 0, 1), (12, 6, 0, 0),
             (11, 0, 0, 1), (13, 0, 0, 0), (14, 1, 0, 0), (12, 5, 9, 0),
             (2, 0, 0, 1), (99, 0, 0, 0)]
    stop = [False]

    def hook(uc, addr, size, user):
        if addr == STOP:
            stop[0] = True
            uc.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook)
    bad = 0
    for ma, mi, su, want in cases:
        uc.reg_write(UC_ARM64_REG_X0, 2)     # platform = iOS
        uc.reg_write(UC_ARM64_REG_X1, ma)
        uc.reg_write(UC_ARM64_REG_X2, mi)
        uc.reg_write(UC_ARM64_REG_X3, su)
        uc.reg_write(UC_ARM64_REG_X4, 0xDEAD)
        uc.reg_write(UC_ARM64_REG_SP, STACK)
        uc.reg_write(UC_ARM64_REG_X30, STOP)
        uc.emu_start(cave, STOP, count=64)
        got = uc.reg_read(UC_ARM64_REG_X0)
        ok = (got == want)
        bad += 0 if ok else 1
        print("   @available(%2d.%d.%d) -> %d  %s"
              % (ma, mi, su, got, "ok" if ok else "FAIL (want %d)" % want))
    print("emu_avail: %d case(s), %d FAIL" % (len(cases), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], int(sys.argv[2], 0)))
