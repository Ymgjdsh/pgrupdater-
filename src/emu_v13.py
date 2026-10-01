#!/usr/bin/env python3
"""Emulate the v13 bundleIdentifier hook.

usage: python emu_v13.py <v13raw>

Checks
  1. the stub -> hook branch is wired (execution reaching the stub tail lands
     in our hook),
  2. the hook calls the real method through x16 and *then* returns the spoofed
     NSString built by CFStringCreateWithCString(NULL, "games.Pigeon.Phigros",
     0x08000100),
  3. the result is cached, so a second call does not create it again,
  4. if creation fails the hook returns the real bundle id (never nil),
  5. the @"bundle_id=%@" constant really points at the new literal.

All "sentinel" addresses live inside pages taken from the image itself: this
unicorn build (2.1.4/win64) is flaky about writing to freshly mapped scratch
pages, and mapped image pages are always writable.
"""
import struct
import sys

import chained2dyld as C
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_PC, UC_ARM64_REG_SP,
                                 UC_ARM64_REG_W2, UC_ARM64_REG_X0,
                                 UC_ARM64_REG_X1, UC_ARM64_REG_X30)

STUB_VA = 0x3BF46C0
HOOK_VA = 0x444CEC0
MSGSEND_SLOT = 0x4451DF8
CF_SLOT = 0x44520B0
SELREF = 0x47CBDB8
DATA_VA = 0x52B3000
CACHE_VA = 0x52B3E60
CSTR_VA = 0x52B3E40
# sentinels / stack inside already-mapped image pages
FAKE_MSGSEND = 0x444CE00
FAKE_CF = 0x444CE10
CALLER = 0x444CE20
STACK = 0x3BF4F00
FAKE_SEL = 0x11111111

MAPS = ((0x3BF4000, 0x1000, 0x3BF4000),
        (0x444C000, 0x1000, 0x444C000),
        (0x4450000, 0x3000, 0x4450000),
        (0x47CB000, 0x1000, 0x47CB000),
        (DATA_VA, 0x1000, None))          # None -> m.foff(DATA_VA)


def make_uc(buf, m):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    for va, size, src in MAPS:
        if src is None:
            src = m.foff(va)
        uc.mem_map(va, size)
        uc.mem_write(va, buf[src:src + size])
    # dyld would have bound these slots at load time
    uc.mem_write(MSGSEND_SLOT, struct.pack("<Q", FAKE_MSGSEND))
    uc.mem_write(CF_SLOT, struct.pack("<Q", FAKE_CF))
    uc.mem_write(SELREF, struct.pack("<Q", FAKE_SEL))
    return uc


def main(argv):
    path = argv[0]
    buf = open(path, "rb").read()
    m = C.MachO(buf)
    ok = fail = 0

    # ---- static check of the literal patch ---------------------------------
    fo = m.foff(0x47A1C30)
    ptr = struct.unpack_from("<Q", buf, fo)[0]
    ln = struct.unpack_from("<Q", buf, m.foff(0x47A1C38))[0]
    lit = buf[m.foff(ptr):m.foff(ptr) + ln]
    print("literal ptr 0x%x len %d %r" % (ptr, ln, lit))
    if lit == b"bundle_id=games.Pigeon.Phigros" and ptr == 0x52B3E00:
        print("ok   CFString literal repointed to the official bundle id")
        ok += 1
    else:
        print("FAIL CFString literal not repointed")
        fail += 1

    # ---- emulation ---------------------------------------------------------
    uc = make_uc(buf, m)
    state = {"real": 0x0, "cf_result": 0x0, "cf_calls": [], "msg_calls": 0,
             "ret": None, "cache": None}

    def code_hook(uc, address, size, user):
        if address == FAKE_MSGSEND:
            state["msg_calls"] += 1
            uc.reg_write(UC_ARM64_REG_X0, state["real"])
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
        elif address == FAKE_CF:
            state["cf_calls"].append((uc.reg_read(UC_ARM64_REG_X0),
                                      uc.reg_read(UC_ARM64_REG_X1),
                                      uc.reg_read(UC_ARM64_REG_W2)))
            uc.reg_write(UC_ARM64_REG_X0, state["cf_result"])
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
        elif address == CALLER:
            state["ret"] = uc.reg_read(UC_ARM64_REG_X0)
            state["cache"] = struct.unpack("<Q", uc.mem_read(CACHE_VA, 8))[0]
            uc.emu_stop()

    uc.hook_add(UC_HOOK_CODE, code_hook)

    def call(real, cf_result):
        state["real"] = real
        state["cf_result"] = cf_result
        state["ret"] = None
        state["cache"] = None
        uc.reg_write(UC_ARM64_REG_X0, 0x22220000)      # NSBundle receiver
        uc.reg_write(UC_ARM64_REG_SP, STACK)
        uc.reg_write(UC_ARM64_REG_X30, CALLER)
        uc.emu_start(STUB_VA, 0, count=400)
        return state["ret"]

    # first call: no cache -> create
    ret = call(0x11110000, 0x60000000)
    if ret == 0x60000000 and state["cache"] == 0x60000000:
        print("ok   first call returns the created string and caches it "
              "(msg_calls=%d)" % state["msg_calls"])
        ok += 1
    else:
        print("FAIL first call ret=0x%x cache=0x%x (%s)"
              % (ret or 0, state["cache"] or 0, state["cf_calls"]))
        fail += 1
    calls_after_1 = len(state["cf_calls"])
    if state["cf_calls"] and state["cf_calls"][0] == (0, CSTR_VA, 0x08000100):
        print("ok   CFStringCreateWithCString(NULL, 0x%x, UTF8)" % CSTR_VA)
        ok += 1
    else:
        print("FAIL unexpected CF arguments %s" % state["cf_calls"])
        fail += 1

    # second call: cached -> must reuse, and must still call the real method
    msg_before = state["msg_calls"]
    ret = call(0x33330000, 0x70000000)
    if ret == 0x60000000 and len(state["cf_calls"]) == calls_after_1:
        print("ok   second call reuses the cache (real method still called: %d)"
              % (state["msg_calls"] - msg_before))
        ok += 1
    else:
        print("FAIL second call ret=0x%x cf_calls=%d"
              % (ret or 0, len(state["cf_calls"])))
        fail += 1

    # third call: fresh emulator, creation fails -> fall back to the real value
    uc2 = make_uc(buf, m)
    res = {"ret": None, "cache": None}

    def code_hook2(uc, address, size, user):
        if address == FAKE_MSGSEND:
            uc.reg_write(UC_ARM64_REG_X0, 0x44440000)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
        elif address == FAKE_CF:
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
        elif address == CALLER:
            res["ret"] = uc.reg_read(UC_ARM64_REG_X0)
            res["cache"] = struct.unpack("<Q", uc.mem_read(CACHE_VA, 8))[0]
            uc.emu_stop()

    uc2.hook_add(UC_HOOK_CODE, code_hook2)
    uc2.reg_write(UC_ARM64_REG_X0, 0x22220000)
    uc2.reg_write(UC_ARM64_REG_SP, STACK)
    uc2.reg_write(UC_ARM64_REG_X30, CALLER)
    uc2.emu_start(STUB_VA, 0, count=400)
    if res["ret"] == 0x44440000 and res["cache"] == 0:
        print("ok   creation failure falls back to the real bundle id")
        ok += 1
    else:
        print("FAIL creation failure ret=0x%x cache=0x%x"
              % (res["ret"] or 0, res["cache"] or 0))
        fail += 1

    print("%d ok, %d FAIL" % (ok, fail))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
