#!/usr/bin/env python3
"""verify_window.py  <pre-v9 binary> <v9 binary> [pristine]

Checks the v9 patch: the __objc_stubs entry of -initWithWindowScene: is redirected at a
shim that recreates the UIWindow the way a deployment target of iOS 12 would have (the
compiler dropped that branch for the 15.0 target of 4.0.0).

Asserts, without trusting the converter's own bookkeeping:
  1. v9 differs from its pre-image in exactly two places: the 52-byte shim inside the
     zero padding at the end of __TEXT, and bytes 0x10..0x14 of the
     -initWithWindowScene: stub (its trailing `br x16` -> `b shim`),
  2. the shim's instructions are the intended ones, its adrp/ldr read the
     _OBJC_CLASS_$_UIScreen classref slot, and its three calls land on exactly the
     pristine __objc_stubs entries of mainScreen / bounds / initWithFrame:,
  3. the patched stub still loads the -initWithWindowScene: selref, the shim is
     reachable from it with a plain `b`, and the selector's one call site (0xF944,
     in -[UnityAppController initUnityWithApplication:]) is untouched.

Usage: python verify_window.py out/UnityFramework.v3f out/UnityFramework.v9raw
"""
import struct
import sys

import capstone

import chained2dyld as C

ok = 0
fail = 0


def chk(cond, msg):
    global ok, fail
    if cond:
        ok += 1
        print("  ok   " + msg)
    else:
        fail += 1
        print("  FAIL " + msg)


def loads(path):
    with open(path, "rb") as fh:
        return C.MachO(fh.read())


pre = loads(sys.argv[1])
new = loads(sys.argv[2])
pris = loads(sys.argv[3] if len(sys.argv) > 3 else r"work\UnityFramework")

chk(len(pre.buf) == len(new.buf), f"same file size ({len(pre.buf)} vs {len(new.buf)})")
if len(pre.buf) != len(new.buf):
    sys.exit(1)

# ---- the slots / stubs of the pristine image (identical in pre: see the diff below)
fixups = C.decode_fixups(pris)["fixups"]
slots = C.find_selref_slots(pris, pris.buf, fixups)
want = {}
for sel in (C.WINDOW_SEL,) + C.WINDOW_SEL_SUPPORT:
    if sel not in slots:
        chk(False, f"pristine __objc_selrefs has {sel.decode()!r}")
        continue
    want[sel] = C.find_objc_stub_for_selref(pris, pris.buf, slots[sel])
    chk(want[sel] is not None,
        f"pristine __objc_stubs entry for {sel.decode()!r}"
        + (f" @0x{want[sel]:X}" if want[sel] else "") + f" (selref 0x{slots[sel]:X})")
if len(want) != 4:
    sys.exit(1)
wstub = want[C.WINDOW_SEL]

# ---- 1. diff v9 against its pre-image, coalescing fragments that are only split
#         because unchanged bytes (zeros) sit between changed ones
raw = []
STEP = 1 << 16
i = 0
while i < len(pre.buf):
    a = pre.buf[i:i + STEP]
    b = new.buf[i:i + STEP]
    if a != b:
        for j in range(len(a)):
            if a[j] != b[j]:
                if raw and raw[-1][1] == i + j:
                    raw[-1][1] = i + j + 1
                else:
                    raw.append([i + j, i + j + 1])
    i += STEP
runs = []
for s, e in raw:
    if runs and s - runs[-1][1] < 0x20:
        runs[-1][1] = e
    else:
        runs.append([s, e])
print("  differing ranges: " + ", ".join(f"[0x{s:X},0x{e:X})" for s, e in runs))
chk(len(runs) == 2, f"v9 differs from the pre-image in 2 ranges (found {len(runs)})")
if len(runs) != 2:
    sys.exit(1)
chk(runs[0][0] == wstub + 0x10 and runs[0][1] == wstub + 0x14,
    f"first range is the stub's last instruction @0x{wstub + 0x10:X}")
shim_fo, shim_end = runs[1]
shim_va = shim_fo                      # __TEXT.fileoff == 0 -> file offset == vmaddr
txt = new.seg_by_name["__TEXT"]
chk(txt["vmaddr"] <= shim_va and shim_end <= txt["vmaddr"] + txt["vmsize"],
    f"shim [0x{shim_va:X},0x{shim_end:X}) lies inside __TEXT")
last = max(s["addr"] + s["size"] for s in new.sections if s["seg"] == "__TEXT")
chk(shim_va >= last, f"shim starts after the last __TEXT section (0x{last:X})")

# ---- 2. the shim itself
shim = bytes(new.buf[shim_fo:shim_end])
chk(len(shim) == 52, f"shim is 52 bytes ({len(shim)})")
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
text = [f"{i.mnemonic} {i.op_str}".strip() for i in md.disasm(shim, shim_va)]
expected = [
    "sub sp, sp, #0x20",
    "stp x29, x30, [sp]",
    "str x0, [sp, #0x10]",
    f"adrp x8, #0x{0x47D3138 & ~0xFFF:x}",
    "ldr x8, [x8, #0x138]",
    "mov x0, x8",
    f"bl #0x{want[b'mainScreen']:x}",
    f"bl #0x{want[b'bounds']:x}",
    "ldr x0, [sp, #0x10]",
    f"bl #0x{want[b'initWithFrame:']:x}",
    "ldp x29, x30, [sp]",
    "add sp, sp, #0x20",
    "ret",
]
for a, b in zip(text, expected):
    if a != b:
        print(f"       got {a!r}\n      want {b!r}")
chk(text == expected, f"shim is the intended {len(expected)} instructions")

page = C._dec_adrp(struct.unpack_from("<I", shim, 12)[0], shim_va + 12)
off = ((struct.unpack_from("<I", shim, 16)[0] >> 10) & 0xFFF) * 8
slot_va = page + off
uisc = [f for f in fixups if f["kind"] == "bind" and f["name"] == "_OBJC_CLASS_$_UIScreen"]
chk(bool(uisc) and slot_va == uisc[0]["vmaddr"],
    f"shim loads the _OBJC_CLASS_$_UIScreen classref slot 0x{slot_va:X}"
    + (f" (expected 0x{uisc[0]['vmaddr']:X})" if uisc else " -- not bound at all"))

# ---- 3. the patched stub entry, and the call site that reaches it
chk(C.rd(pris.buf, pris.foff(wstub) + 0x10, "I")[0] == 0xD61F0200,
    "pristine stub ended in `br x16`")
w = C.rd(new.buf, new.foff(wstub) + 0x10, "I")[0]
chk(w & 0xFC000000 == 0x14000000, f"patched stub has a plain b (0x{w:08X})")
d = w & 0x3FFFFFF
if d & (1 << 25):
    d -= (1 << 26)
chk(wstub + 0x10 + d * 4 == shim_va,
    f"that b targets the shim (got 0x{wstub + 0x10 + d * 4:X}, want 0x{shim_va:X})")
i0, i1 = C.rd(new.buf, new.foff(wstub), "II")
pslot = C._dec_adrp(i0, wstub) + ((i1 >> 10) & 0xFFF) * 8
chk(pslot == slots[C.WINDOW_SEL],
    f"patched stub still loads the -{C.WINDOW_SEL.decode()} selref 0x{slots[C.WINDOW_SEL]:X}")

callers = []
for st in pris.sections:
    if st["seg"] != "__TEXT":
        continue
    for k in range(st["size"] // 4):
        a = st["addr"] + 4 * k
        ins = C.rd(pris.buf, st["offset"] + 4 * k, "I")[0]
        if ins & 0xFC000000 != 0x94000000:
            continue
        dd = ins & 0x3FFFFFF
        if dd & (1 << 25):
            dd -= (1 << 26)
        if a + dd * 4 == wstub:
            callers.append(a)
chk(callers == [0xF944],
    f"-{C.WINDOW_SEL.decode()} has exactly one call site {[hex(c) for c in callers]}"
    " (expected [0xf944])")
for c in callers:
    chk(C.rd(new.buf, new.foff(c), "I")[0] == C.rd(pris.buf, pris.foff(c), "I")[0],
        f"call site 0x{c:X} unchanged")

# ---- 4. the shim must be reachable from the call site through the stub (sanity)
shim_ins = bytes(new.buf[shim_fo:shim_end])
for k in (24, 28, 36):
    ins = struct.unpack_from("<I", shim_ins, k)[0]
    dd = ins & 0x3FFFFFF
    if dd & (1 << 25):
        dd -= (1 << 26)
    tgt = shim_va + k + dd * 4
    chk(tgt in want.values(), f"shim call at +0x{k:X} targets a pristine __objc_stubs "
                              f"entry 0x{tgt:X}")

print(f"\n{ok} ok, {fail} FAIL")
sys.exit(1 if fail else 0)
