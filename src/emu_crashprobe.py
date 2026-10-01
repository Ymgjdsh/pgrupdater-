#!/usr/bin/env python3
"""emu_crashprobe.py <v10 framework>

Runs the v10 signal probe (mkcrashprobe.py) on the real bytes of the patched image
under unicorn, with the _write/_exit stubs and the resume point (0x89A66C) replaced by
hooks, and checks exactly what the device log will contain:

  * the probe writes the template, then the four raw callback arguments, then the
    siginfo fields (si_signo / si_code / si_addr), then the ucontext fields
    (__pc / __lr) -- one line per stage, so a fault part way through still leaves
    whatever was already printed,
  * si_signo/si_code/si_addr land in the right columns,
  * the hex helper formats 64-bit values as lowercase, most significant nibble first,
  * x0..x3, x29, x30 and sp are restored and the original callback body at 0x89A66C
    is resumed with them, x19-x28 untouched,
  * a second entry (re-entry flag set, e.g. because the probe itself faulted) calls
    _exit(1) without writing anything else.

Usage: python emu_crashprobe.py out/UnityFramework.v10raw
"""
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UcError
import unicorn.arm64_const as ua

import chained2dyld as C
import mkcrashprobe as MK

PATH = sys.argv[1] if len(sys.argv) > 1 else r"out\UnityFramework.v10raw"
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


# ---- locate the patch and everything it references, out of the image itself
PATCH_FO = m.foff(MK.CRASH_CB_VA)
word = struct.unpack_from("<I", buf, PATCH_FO)[0]
assert word & 0xFC000000 == 0x14000000, f"0x{MK.CRASH_CB_VA:X} is not a b: 0x{word:08X}"
d = word & 0x3FFFFFF
if d & (1 << 25):
    d -= (1 << 26)
CODE_VA = MK.CRASH_CB_VA + d * 4
write_stub = MK.find_stub_for_slot(m, buf, MK.WRITE_SLOT)
exit_stub = MK.find_stub_for_slot(m, buf, MK.EXIT_SLOT)

# the adrp/add pairs at the head of the probe give the template, scratch and guard
def adrp_add_at(off, at):
    a = struct.unpack_from("<I", buf, off)[0]
    tgt = C._dec_adrp(a, at)
    nxt = struct.unpack_from("<I", buf, off + 4)[0]
    if nxt & 0xFF800000 == 0x91000000:          # add xN, xN, #imm
        tgt += ((nxt >> 10) & 0xFFF) << ((nxt >> 22) & 1)
    return tgt


fo = m.foff(CODE_VA)
GUARD_VA = adrp_add_at(fo + 7 * 4, CODE_VA + 7 * 4)
SKEL_VA = adrp_add_at(fo + 13 * 4, CODE_VA + 13 * 4)
BUF_VA = adrp_add_at(fo + 15 * 4, CODE_VA + 15 * 4)
# skel_len comes from the `mov x3, #imm` that follows the buffer address load
skel_len = None
for i in range(17, 22):
    ins = struct.unpack_from("<I", buf, fo + i * 4)[0]
    if ins & 0xFFE00000 == 0xD2800000 and ins & 0x1F == 3:
        skel_len = (ins >> 5) & 0xFFFF
        break
assert skel_len, "could not find the template length in the probe prologue"
print(f"  probe 0x{CODE_VA:X}, template 0x{SKEL_VA:X} ({skel_len} bytes), "
      f"scratch 0x{BUF_VA:X}, guard 0x{GUARD_VA:X}")
print(f"  stubs: _write 0x{write_stub:X}, _exit 0x{exit_stub:X}")

# ---- synthetic signal frame -------------------------------------------------
SIGINFO = 0x5300000
UCONTEXT = 0x5301000
MCONTEXT = 0x5302000
SIGNO, SIGCODE, SIGADDR = 11, 1, 0xB8
FAKE_PC, FAKE_LR = 0x10289A700, 0x10289A6F8
CALLER = 0x700000003000
STACK = 0x700000010000
ARG2, ARG3 = 0x1122334455667788, 0x99AABBCCDDEEFF00

uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

TEXT_LO, TEXT_HI = 0x3BF0000, 0x4450000
uc.mem_map(TEXT_LO, TEXT_HI - TEXT_LO)
uc.mem_write(TEXT_LO, bytes(buf[TEXT_LO:TEXT_HI]))
uc.mem_map(0x890000, 0x20000)                      # the original callback body we return to
uc.mem_write(0x890000, bytes(buf[0x890000:0x8B0000]))
uc.mem_map(0x52B0000, 0x10000)                     # __DATA_METHLIST slack (RW)
uc.mem_write(0x52B0000, bytes(buf[0x52B0000:0x52C0000]))
uc.mem_map(0x5300000, 0x10000)                     # siginfo + ucontext + mcontext
uc.mem_map(0x700000000000, 0x20000)                # caller + stack
uc.mem_write(CALLER, b"\xC0\x03\x5F\xD6")          # ret
assert TEXT_LO <= CODE_VA < TEXT_HI and TEXT_LO <= write_stub < TEXT_HI

uc.mem_write(SIGINFO, struct.pack("<IIII", SIGNO, 0, SIGCODE, 0)
             + struct.pack("<Q", SIGADDR))
uc.mem_write(UCONTEXT + 48, struct.pack("<Q", MCONTEXT))
uc.mem_write(MCONTEXT + 240, struct.pack("<Q", FAKE_LR))
uc.mem_write(MCONTEXT + 256, struct.pack("<Q", FAKE_PC))

state = {"lines": [], "exit": None, "resume": None}


def on_stub(uc, addr, size, ud):
    if addr == write_stub:
        fd = uc.reg_read(ua.UC_ARM64_REG_X0)
        ptr = uc.reg_read(ua.UC_ARM64_REG_X1)
        n = uc.reg_read(ua.UC_ARM64_REG_X2)
        state["lines"].append((fd, ptr, bytes(uc.mem_read(ptr, n)).decode("ascii", "replace")))
    else:
        state["exit"] = uc.reg_read(ua.UC_ARM64_REG_X0)
        uc.emu_stop()
        return
    uc.reg_write(ua.UC_ARM64_REG_PC, uc.reg_read(ua.UC_ARM64_REG_X30))


def on_resume(uc, addr, size, ud):
    state["resume"] = dict(
        x=[uc.reg_read(getattr(ua, f"UC_ARM64_REG_X{i}")) for i in range(31)],
        sp=uc.reg_read(ua.UC_ARM64_REG_SP),
        lr=uc.reg_read(ua.UC_ARM64_REG_X30))
    uc.emu_stop()


uc.hook_add(UC_HOOK_CODE, on_stub, begin=write_stub, end=write_stub + 4)
uc.hook_add(UC_HOOK_CODE, on_stub, begin=exit_stub, end=exit_stub + 4)
uc.hook_add(UC_HOOK_CODE, on_resume, begin=MK.CRASH_CB_BODY_VA,
            end=MK.CRASH_CB_BODY_VA + 4)

SENTINELS = {i: 0xB0 + i for i in range(19, 29)}
sp0 = STACK + 0x800
FP0 = 0x700000009000


def setup(guard):
    uc.mem_write(GUARD_VA, struct.pack("<Q", guard))
    uc.mem_write(BUF_VA, b"\xEE" * 256)
    state["lines"].clear()
    state["resume"] = None
    state["exit"] = None
    uc.reg_write(ua.UC_ARM64_REG_X0, SIGINFO)
    uc.reg_write(ua.UC_ARM64_REG_X1, UCONTEXT)
    uc.reg_write(ua.UC_ARM64_REG_X2, ARG2)
    uc.reg_write(ua.UC_ARM64_REG_X3, ARG3)
    for i, v in SENTINELS.items():
        uc.reg_write(getattr(ua, f"UC_ARM64_REG_X{i}"), v)
    uc.reg_write(ua.UC_ARM64_REG_X29, FP0)
    uc.reg_write(ua.UC_ARM64_REG_X30, CALLER)
    uc.reg_write(ua.UC_ARM64_REG_SP, sp0)


# ---- run 1: the normal case -------------------------------------------------
setup(0)
try:
    uc.emu_start(CODE_VA, 0, count=20000)
except UcError as e:
    print("  FAIL unicorn: " + str(e))
    sys.exit(1)

want = ("PHI12 s=%08x c=%08x a=%016x p=%016x l=%016x x0=%016x x1=%016x x2=%016x x3=%016x\n"
        % (SIGNO, SIGCODE, SIGADDR, FAKE_PC, FAKE_LR, SIGINFO, UCONTEXT, ARG2, ARG3))
lines = [l for _fd, _p, l in state["lines"]]
chk(len(state["lines"]) == 4, f"the probe writes 4 lines (got {len(state['lines'])})")
chk(all(fd == 2 for fd, _p, _l in state["lines"]), "every line goes to fd 2")
chk(all(p == BUF_VA for _f, p, _l in state["lines"]), f"every line comes from 0x{BUF_VA:X}")
chk(lines[-1] == want, "the final line decodes exactly:\n"
                       f"         {lines[-1] if lines else None}\n"
                       f"    want {want}")
chk(state["resume"] is not None, "the probe resumed Unity's callback body at 0x89A66C")
r = state["resume"]
if r:
    chk(r["x"][0] == SIGINFO and r["x"][1] == UCONTEXT and r["x"][2] == ARG2
        and r["x"][3] == ARG3, "x0-x3 are handed back unchanged")
    chk(r["sp"] == sp0, f"sp restored (0x{r['sp']:X} vs 0x{sp0:X})")
    chk(r["x"][29] == FP0 and r["lr"] == CALLER, "x29/x30 restored")
    bad = [i for i, v in SENTINELS.items() if r["x"][i] != v]
    chk(not bad, f"x19-x28 untouched (clobbered: {bad})")
chk(state["exit"] is None, "no _exit on the normal path")

# ---- run 2: re-entry (probe already ran -> must bail out) -------------------
setup(1)
try:
    uc.emu_start(CODE_VA, 0, count=200)
except UcError as e:
    print("  FAIL unicorn: " + str(e))
    sys.exit(1)
chk(state["exit"] == 1, f"the second entry calls _exit(1) (got {state['exit']})")
chk(state["lines"] == [], "the second entry writes nothing")
chk(state["resume"] is None, "the second entry never resumes the callback body")

print(f"\n{ok} ok, {fail} FAIL")
sys.exit(1 if fail else 0)
