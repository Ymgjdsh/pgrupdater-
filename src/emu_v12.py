#!/usr/bin/env python3
"""Emulate the v12 asio guard: an empty executor must return cleanly, a valid
one must still reach the shared Ex::execute helper.

usage: python emu_v12.py <v12raw>
"""
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_PC, UC_ARM64_REG_SP,
                                 UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                 UC_ARM64_REG_X29, UC_ARM64_REG_X30)

PAGE = 0x1000
CODE_PAGES = [(0x11D1000, 0x2000), (0x444C000, 0x1000)]
SENTINEL = 0x8000000
SITES = [(0x11D12F4, 0x11D12F8), (0x11D1C68, 0x11D12F8)]


def load(path):
    buf = open(path, "rb").read()
    return buf


def build(buf):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    for va, size in CODE_PAGES:
        uc.mem_map(va, size)
        uc.mem_write(va, buf[va:va + size])
    uc.mem_map(SENTINEL, PAGE)
    uc.mem_write(SENTINEL, struct.pack("<I", 0xD65F03C0))  # ret
    uc.mem_map(0x70000000, PAGE)
    return uc


def run(buf, site, x0, x30_target):
    """returns (stop_pc, trace)"""
    uc = build(buf)
    trace = []
    stop = []

    def hook(uc, address, size, user):
        trace.append(address)
        if address == x30_target or address == 0x11D12F8:
            stop.append(address)
            uc.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.reg_write(UC_ARM64_REG_PC, site)
    uc.reg_write(UC_ARM64_REG_X0, x0)
    uc.reg_write(UC_ARM64_REG_X1, 0x70000010)
    uc.reg_write(UC_ARM64_REG_X29, 0x70000080)
    uc.reg_write(UC_ARM64_REG_X30, x30_target)
    uc.reg_write(UC_ARM64_REG_SP, 0x70000080)
    uc.emu_start(site, 0, count=64)
    return stop[0] if stop else None, trace


def main(argv):
    buf = load(argv[0])
    ok = fail = 0
    for site, helper in SITES:
        # empty executor (x0 == 0) must take the new `ret`, never reach the helper
        stop, trace = run(buf, site, 0, SENTINEL)
        if stop == SENTINEL:
            print("ok   site 0x%x empty x0 -> clean return (%s)"
                  % (site, " ".join(hex(a) for a in trace)))
            ok += 1
        else:
            print("FAIL site 0x%x empty x0 -> %s" % (site, hex(stop) if stop else "no stop"))
            fail += 1
        # non-empty executor must still reach the helper
        stop, trace = run(buf, site, 0x12345000, SENTINEL)
        if stop == helper:
            print("ok   site 0x%x x0!=0 -> helper 0x%x (%s)"
                  % (site, helper, " ".join(hex(a) for a in trace)))
            ok += 1
        else:
            print("FAIL site 0x%x x0!=0 -> %s" % (site, hex(stop) if stop else "no stop"))
            fail += 1
    print("%d ok, %d FAIL" % (ok, fail))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
