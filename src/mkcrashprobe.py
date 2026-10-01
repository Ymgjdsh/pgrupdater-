#!/usr/bin/env python3
"""v10: instrument the PLCrashReporter signal callback that Unity 4.0.0 installs.

Why: on the device every ".ips" after the reporter is armed shows only the reporter's
own callback faulting (NULL global 0x4B3A410 + 0xB8) and then re-entering itself until
SpringBoard's watchdog SIGKILLs the app -- the *primary* signal is never recorded.

What this does (one patch, no segment/linkedit changes):
  0x89A668 (entry of Unity's `handleSignal` callback) -> `b probe`.
  The probe writes one ASCII line to fd 2, four times, in order of increasing risk:
      PHI12 s=........ c=........ a=................ p=................
            l=................ x0=................ x1=................
            x2=................ x3=................
  * log 0: the template as copied (proves the callback was entered at all)
  * log 1: the four raw callback arguments (no dereference whatsoever)
  * log 2: arg0 read as siginfo_t (si_signo at +0, si_code at +8, si_addr at +16)
  * log 3: arg1 read as ucontext_t (uc_mcontext at +48, __pc at mctx+256,
           __lr at mctx+240)
  A re-entry flag in the RW slack of __DATA_METHLIST makes the *second* entry
  `_exit(1)`, so a fault inside the probe can never re-enter the old infinite loop.
  x0..x9/x29/x30 are restored and Unity's original callback body is resumed at
  0x89A66C, so reporter behaviour after the probe is unchanged.

Data layout: code + string constant go into the zero padding at the end of __TEXT
(read-only, fine); a 256-byte scratch buffer and the re-entry flag go into the unused
tail of the RW __DATA_METHLIST segment, after the real objc_msgSend bind slot.

Usage:  python mkcrashprobe.py <in.framework> <out.framework>
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chained2dyld as C                                            # noqa: E402
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN       # noqa: E402

CRASH_CB_VA = 0x89A668          # Unity's handleSignal callback (pristine 4.0.0)
CRASH_CB_BODY_VA = 0x89A66C     # callback entry + 4 (its own prologue follows)
WRITE_SLOT = 0x4450D28          # _write (weak, libSystem)
EXIT_SLOT = 0x4450418           # _exit  (weak, libSystem)

FIELDS = [("s", 8), ("c", 8), ("a", 16), ("p", 16), ("l", 16),
          ("x0", 16), ("x1", 16), ("x2", 16), ("x3", 16)]


def assemble(src, addr):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    enc, count = ks.asm(src, addr=addr)
    if enc is None:
        raise SystemExit("keystone failed on:\n" + src)
    return bytes(bytearray(enc))


def aa(reg, target):
    """adrp+add sequence loading the absolute (unslid) address of target (PC-relative,
    so it stays correct after the image is slid)"""
    L = [f"adrp x{reg}, {target & ~0xFFF}"]
    if target & 0xFFF:
        L.append(f"add x{reg}, x{reg}, #{target & 0xFFF}")
    return L


def find_stub_for_slot(m, buf, slot):
    """vmaddr of the __TEXT,__stubs entry (12 bytes) loading `slot` from its GOT page"""
    for st in m.sections:
        if st["seg"] != "__TEXT" or st["name"] != "__stubs":
            continue
        for i in range(st["size"] // 12):
            a, o = st["addr"] + i * 12, st["offset"] + i * 12
            i0, i1 = C.rd(buf, o, "II")
            if i0 & 0x9F000000 != 0x90000000 or i1 & 0xFFC00000 != 0xF9400000:
                continue
            if (i0 & 0x1F) != (i1 & 0x1F):
                continue
            if C._dec_adrp(i0, a) + ((i1 >> 10) & 0xFFF) * 8 == slot:
                return a
    return None


def find_zero_run(m, buf, start, end, need, what):
    va = C.round_up(start, 16)
    while va + need <= end:
        fo = m.foff(va)
        if fo is None:
            raise SystemExit(f"{what}: 0x{va:X} is not file backed")
        if not any(buf[fo:fo + need]):
            return va
        va += 16
    raise SystemExit(f"{what}: no {need}-byte zero run in [0x{start:X}, 0x{end:X})")


def line_offsets():
    skel = "PHI12"
    off = {}
    for name, n in FIELDS:
        skel += f" {name}="
        off[name] = len(skel)
        skel += "." * n
    skel += "\n"
    return skel, off


def build_probe(code_va, skel_va, skel_len, buf_va, guard_va, body_va,
                write_stub, exit_stub, off):
    def write_line():
        return [f"mov w0, #2"] + aa(1, buf_va) + [f"mov x2, #{skel_len}",
                                                  f"bl {write_stub}"]

    L = ["sub sp, sp, #0x80",
         "stp x29, x30, [sp, #0x60]",
         "stp x0, x1, [sp, #0x00]",
         "stp x2, x3, [sp, #0x10]",
         "stp x4, x5, [sp, #0x20]",
         "stp x6, x7, [sp, #0x30]",
         "stp x8, x9, [sp, #0x40]"]
    # re-entry guard, checked before anything that can fault
    L += aa(9, guard_va)
    L += ["ldr x10, [x9]",
          "cbnz x10, LEXIT",
          "mov x10, #1",
          "str x10, [x9]"]
    # scratch <- template, then log 0
    L += aa(1, skel_va) + aa(2, buf_va)
    L += [f"mov x3, #{skel_len}",
          "LCOPY:",
          "ldrb w4, [x1], #1",
          "strb w4, [x2], #1",
          "subs x3, x3, #1",
          "b.ne LCOPY"]
    L += write_line()

    # ---- raw callback arguments: no dereference, cannot fault ---------------
    L += aa(11, buf_va)
    for i, name in enumerate(("x0", "x1", "x2", "x3")):
        L += [f"ldr x0, [sp, #{i * 8}]",
              f"add x1, x11, #{off[name]}",
              "mov x2, #16",
              "bl HEXN"]
    L += write_line()

    # ---- arg0 as siginfo_t -------------------------------------------------
    L += aa(11, buf_va)
    L += ["ldr x10, [sp, #0x00]",
          "ldr w0, [x10]",
          f"add x1, x11, #{off['s']}",
          "mov x2, #8",
          "bl HEXN",
          "ldr x10, [sp, #0x00]",
          "ldr w0, [x10, #8]",
          f"add x1, x11, #{off['c']}",
          "mov x2, #8",
          "bl HEXN",
          "ldr x10, [sp, #0x00]",
          "ldr x0, [x10, #16]",
          f"add x1, x11, #{off['a']}",
          "mov x2, #16",
          "bl HEXN"]
    L += write_line()

    # ---- arg1 as ucontext_t -----------------------------------------------
    L += aa(11, buf_va)
    L += ["ldr x10, [sp, #0x08]",
          "ldr x10, [x10, #48]",
          "ldr x0, [x10, #256]",
          f"add x1, x11, #{off['p']}",
          "mov x2, #16",
          "bl HEXN",
          "ldr x10, [sp, #0x08]",
          "ldr x10, [x10, #48]",
          "ldr x0, [x10, #240]",
          f"add x1, x11, #{off['l']}",
          "mov x2, #16",
          "bl HEXN"]
    L += write_line()

    # ---- resume Unity's original callback body -----------------------------
    L += ["ldp x0, x1, [sp, #0x00]",
          "ldp x2, x3, [sp, #0x10]",
          "ldp x4, x5, [sp, #0x20]",
          "ldp x6, x7, [sp, #0x30]",
          "ldp x8, x9, [sp, #0x40]",
          "ldp x29, x30, [sp, #0x60]",
          "add sp, sp, #0x80",
          f"b {body_va}"]
    L += ["LEXIT:",
          "mov w0, #1",
          f"bl {exit_stub}",
          "brk #1"]
    # ---- helper: write x2 hex digits of x0 at x1 (most significant first) ---
    L += ["HEXN:",
          "mov x3, #0",
          "HEXN_LOOP:",
          "sub x4, x2, #1",
          "sub x4, x4, x3",
          "lsl x4, x4, #2",
          "lsr x5, x0, x4",
          "and w5, w5, #0xF",
          "add w6, w5, #0x30",
          "add w7, w5, #0x57",
          "cmp w5, #10",
          "csel w5, w6, w7, lo",
          "strb w5, [x1, x3]",
          "add x3, x3, #1",
          "cmp x3, x2",
          "b.lo HEXN_LOOP",
          "ret"]
    return assemble("\n".join(L), code_va)


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 2:
        raise SystemExit(__doc__)
    src, dst = args
    buf = bytearray(open(src, "rb").read())
    m = C.MachO(bytes(buf))

    skel, off = line_offsets()
    skel_len = len(skel)
    skel_pad = C.round_up(skel_len + 1, 16)

    # RW scratch: tail of __DATA_METHLIST, after the real objc_msgSend bind slot
    seg = m.seg_by_name["__DATA_METHLIST"]
    sect = [s for s in m.sections if s["seg"] == "__DATA_METHLIST"][0]
    rw_start = C.round_up(sect["addr"] + sect["size"], 16) + 8
    rw_end = seg["vmaddr"] + seg["vmsize"]
    buf_va = find_zero_run(m, buf, rw_start, rw_end, 256, "rw scratch")
    guard_va = buf_va + 0x100

    # code + string in the zero padding at the end of __TEXT
    txt = m.seg_by_name["__TEXT"]
    txt_end = txt["vmaddr"] + txt["vmsize"]
    code_va = find_zero_run(m, buf, C.text_code_va(m, buf), txt_end, 0x200, "code")
    skel_va = code_va + 0x200

    write_stub = find_stub_for_slot(m, buf, WRITE_SLOT)
    exit_stub = find_stub_for_slot(m, buf, EXIT_SLOT)
    if write_stub is None or exit_stub is None:
        raise SystemExit("no __stubs entry for _write/_exit")

    code = build_probe(code_va, skel_va, skel_len, buf_va, guard_va,
                       CRASH_CB_BODY_VA, write_stub, exit_stub, off)
    if len(code) > 0x200:
        raise SystemExit(f"probe is {len(code)} bytes, reserve is 0x200")
    C.place_code(m, buf, code_va, code, "crash probe")
    C.place_code(m, buf, skel_va, skel.encode() + b"\0" * (skel_pad - skel_len),
                 "crash probe template")

    # patch: redirect the callback entry
    fo = m.foff(CRASH_CB_VA)
    want = assemble("sub sp, sp, #0x60", CRASH_CB_VA)
    if buf[fo:fo + 4] != want:
        raise SystemExit(f"0x{CRASH_CB_VA:X} is {buf[fo:fo+4].hex()}, expected the "
                         f"callback prologue {want.hex()}")
    struct.pack_into("<I", buf, fo, C._enc_b(code_va, CRASH_CB_VA))

    open(dst, "wb").write(bytes(buf))
    print(f"  crash_probe: code 0x{code_va:X} ({len(code)} bytes), template "
          f"0x{skel_va:X} ({skel_len} bytes)")
    print(f"  crash_probe: line {skel.strip()!r}")
    print(f"  crash_probe: fields {off}")
    print(f"  crash_probe: scratch 0x{buf_va:X}, re-entry flag 0x{guard_va:X} "
          f"(__DATA_METHLIST 0x{seg['vmaddr']:X} size 0x{seg['vmsize']:X})")
    print(f"  crash_probe: _write stub 0x{write_stub:X}, _exit stub 0x{exit_stub:X}")
    print(f"  patch crash-callback: 0x{CRASH_CB_VA:X} -> b 0x{code_va:X}")
    print(f"  {dst}: {len(buf)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
