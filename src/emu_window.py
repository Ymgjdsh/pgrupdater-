#!/usr/bin/env python3
"""emu_window.py <converted framework> [pristine framework]

Runs the v9 window shim (chained2dyld.plan_window_shim) on the real bytes of the
converted image under unicorn, with the three __objc_stubs entries it calls replaced by
hooks, and checks the register flow the patch depends on:

  * the shim reads the _OBJC_CLASS_$_UIScreen classref slot (as bound by dyld) and
    sends -mainScreen to it,
  * it sends -bounds to the object that came back and hands that CGRect straight to
    -initWithFrame: (d0-d3 untouched -- the HFA convention the patch relies on),
  * it returns the very UIWindow instance it was given in x0,
  * x19-x28 and the frame pointers come out exactly as they went in, because the
    caller (0xF944) still releases x21/x22 afterwards.

Usage: python emu_window.py out/UnityFramework.v9raw
"""
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UcError
import unicorn.arm64_const as ua

import chained2dyld as C

PATH = sys.argv[1] if len(sys.argv) > 1 else r"out\UnityFramework.v9raw"
with open(PATH, "rb") as fh:
    buf = fh.read()
m = C.MachO(bytearray(buf))

ok, fail = 0, 0


def chk(cond, msg):
    global ok, fail
    if cond:
        ok += 1
        print("  ok   " + msg)
    else:
        fail += 1
        print("  FAIL " + msg)


# ---- locate the shim and the stubs it calls, straight out of the image
shim_va = None
for va in range(0x444CD20, 0x4450000, 4):
    code = bytes(buf[m.foff(va):m.foff(va) + 4])
    if code == struct.pack("<I", C._enc_sub_sp(0x20)):
        shim_va = va
        break
if shim_va is None:
    print("  FAIL shim not found")
    sys.exit(1)
print(f"  shim at 0x{shim_va:X}")

# the adrp/ldr pair inside the shim gives the classref slot
adrp = struct.unpack_from("<I", buf, m.foff(shim_va) + 12)[0]
ldr = struct.unpack_from("<I", buf, m.foff(shim_va) + 16)[0]
CLASS_SLOT = C._dec_adrp(adrp, shim_va + 12) + ((ldr >> 10) & 0xFFF) * 8
# the three bl targets of the shim give the stubs it calls
bls = []
k = 0
while k < 13 * 4:
    ins = struct.unpack_from("<I", buf, m.foff(shim_va) + k)[0]
    if ins & 0xFC000000 == 0x94000000:
        d = ins & 0x3FFFFFF
        if d & (1 << 25):
            d -= (1 << 26)
        bls.append((k, shim_va + k + d * 4))
    k += 4
chk(len(bls) == 3, f"shim has 3 calls: {[hex(t) for _o, t in bls]}")
MAIN_STUB, BOUNDS_STUB, INIT_STUB = [t for _o, t in bls]

FAKE_CLASS = 0x700000000000
FAKE_SCREEN = 0x700000001000
FAKE_WINDOW = 0x700000002000
CALLER = 0x700000003000
STACK = 0x700000010000
RECT = (0.0, 0.0, 768.0, 1024.0)

uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
mapped = []


def map_page(va, fill=None):
    pg = va & ~0xFFF
    if any(lo <= pg < hi for lo, hi in mapped):
        return
    uc.mem_map(pg, 0x4000)
    mapped.append((pg, pg + 0x4000))
    if fill is not None:
        uc.mem_write(pg, fill)


# one region for every __TEXT page we touch (unicorn rounds mappings up to 64 KiB,
# so neighbouring single pages collide); file offset == vmaddr inside __TEXT
TEXT_LO, TEXT_HI = 0x3BF0000, 0x4450000
uc.mem_map(TEXT_LO, TEXT_HI - TEXT_LO)
uc.mem_write(TEXT_LO, bytes(buf[TEXT_LO:TEXT_HI]))
mapped.append((TEXT_LO, TEXT_HI))
assert TEXT_LO <= shim_va < TEXT_HI and all(TEXT_LO <= t < TEXT_HI for _o, t in bls)

# scratch: one page range holding the synthetic caller and the stack
SCRATCH = 0x700000000000
uc.mem_map(SCRATCH, 0x20000)
mapped.append((SCRATCH, SCRATCH + 0x20000))
uc.mem_write(CALLER, b"\xC0\x03\x5F\xD6")        # 0x700000003000: ret
map_page(CLASS_SLOT)
uc.mem_write(CLASS_SLOT, struct.pack("<Q", FAKE_CLASS))
assert CLASS_SLOT == 0x47D3138

state = {"calls": [], "final": None}


def _d(v):
    return struct.unpack("<Q", struct.pack("<d", v))[0]


def _f(bits):
    return struct.unpack("<d", struct.pack("<Q", bits))[0]


def on_stub(uc, addr, size, ud):
    x0 = uc.reg_read(ua.UC_ARM64_REG_X0)
    if addr == MAIN_STUB:
        state["calls"].append(("mainScreen", x0))
        uc.reg_write(ua.UC_ARM64_REG_X0, FAKE_SCREEN)
    elif addr == BOUNDS_STUB:
        state["calls"].append(("bounds", x0))
        for i, v in enumerate(RECT):             # CGRect comes back in d0-d3
            uc.reg_write(getattr(ua, f"UC_ARM64_REG_D{i}"), _d(v))
    else:
        state["calls"].append(("initWithFrame:", x0,
                               [uc.reg_read(getattr(ua, f"UC_ARM64_REG_D{i}"))
                                for i in range(4)]))
        uc.reg_write(ua.UC_ARM64_REG_X0, x0)     # returns the same window
    uc.reg_write(ua.UC_ARM64_REG_PC, uc.reg_read(ua.UC_ARM64_REG_X30))


def on_caller(uc, addr, size, ud):
    state["final"] = dict(
        x=[uc.reg_read(getattr(ua, f"UC_ARM64_REG_X{i}")) for i in range(31)],
        sp=uc.reg_read(ua.UC_ARM64_REG_SP),
        fp=uc.reg_read(ua.UC_ARM64_REG_X29),
        lr=uc.reg_read(ua.UC_ARM64_REG_X30),
    )
    uc.emu_stop()


uc.hook_add(UC_HOOK_CODE, on_stub, begin=MAIN_STUB, end=MAIN_STUB + 4)
uc.hook_add(UC_HOOK_CODE, on_stub, begin=BOUNDS_STUB, end=BOUNDS_STUB + 4)
uc.hook_add(UC_HOOK_CODE, on_stub, begin=INIT_STUB, end=INIT_STUB + 4)
uc.hook_add(UC_HOOK_CODE, on_caller, begin=CALLER, end=CALLER + 4)

sentinels = {i: 0xA0 + i for i in range(11, 29)}   # x11..x28 (x19-x22 matter)
sp0 = STACK + 0x800
uc.reg_write(ua.UC_ARM64_REG_X0, FAKE_WINDOW)
uc.reg_write(ua.UC_ARM64_REG_X2, 0)                # the nil UIScene
for i, v in sentinels.items():
    uc.reg_write(getattr(ua, f"UC_ARM64_REG_X{i}"), v)
uc.reg_write(ua.UC_ARM64_REG_X29, 0x700000009000)
uc.reg_write(ua.UC_ARM64_REG_X30, CALLER)
uc.reg_write(ua.UC_ARM64_REG_SP, sp0)

try:
    uc.emu_start(shim_va, 0, count=200)
except UcError as e:
    print("  FAIL unicorn: " + str(e))
    sys.exit(1)

names = [c[0] for c in state["calls"]]
chk(names == ["mainScreen", "bounds", "initWithFrame:"],
    f"the shim sends exactly mainScreen / bounds / initWithFrame: ({names})")
if names == ["mainScreen", "bounds", "initWithFrame:"]:
    chk(state["calls"][0][1] == FAKE_CLASS,
        f"-mainScreen goes to the UIScreen classref slot value 0x{FAKE_CLASS:X}"
        f" (got 0x{state['calls'][0][1]:X})")
    chk(state["calls"][1][1] == FAKE_SCREEN,
        f"-bounds goes to the UIScreen 0x{FAKE_SCREEN:X}"
        f" (got 0x{state['calls'][1][1]:X})")
    a = state["calls"][2]
    chk(a[1] == FAKE_WINDOW, f"-initWithFrame: goes to the window 0x{FAKE_WINDOW:X}"
                             f" (got 0x{a[1]:X})")
    got = tuple(_f(b) for b in a[2])
    chk(got == RECT, f"the -bounds CGRect reaches -initWithFrame: unchanged {got}")

f = state["final"]
chk(f is not None, "the shim returned to its caller")
if f:
    chk(f["x"][0] == FAKE_WINDOW,
        f"the shim returns the window in x0 (got 0x{f['x'][0]:X})")
    bad = [i for i, v in sentinels.items() if f["x"][i] != v]
    chk(not bad, f"x11-x28 survive the shim (clobbered: {bad})")
    chk(f["sp"] == sp0, f"sp is restored (0x{f['sp']:X} vs 0x{sp0:X})")
    chk(f["fp"] == 0x700000009000, f"x29 is restored (0x{f['fp']:X})")
    chk(f["lr"] == CALLER, f"ret used the lr the caller set (0x{f['lr']:X})")

print(f"\n{ok} ok, {fail} FAIL")
sys.exit(1 if fail else 0)
