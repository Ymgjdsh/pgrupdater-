"""patch_crashret.py <in> <out>

Neutralise Unity's bundled PLCrashReporter callback entry so the reporter stops
hiding the real fault.

Why: on every field crash (v6..v10) the .ips Thread 0 showed the *reporter's own*
secondary crash -- `ldrb w8,[x22,#0xb8]!` with x22 = 0, i.e. fault address 0xb8 --
sitting on top of the real faulting frame.  The reporter's registered handler
(0x89A5F0-0x89A64C) calls the callback whose entry is 0x89A668; if the callback
returns immediately the handler continues into its own re-raise path, so
ReportCrash gets to write an .ips carrying the TRUE signal and PC.

Patch: `0x89A668: sub sp, sp, #0x60` (ff8301d1) -> `ret` (c0035fd6).
Guarded: the original 4 bytes are checked before anything is written.
"""
import struct
import sys

import chained2dyld as C

CRASH_CB_VA = 0x89A668
PROLOGUE = bytes.fromhex("ff8301d1")   # sub sp, sp, #0x60
RET = 0xD65F03C0                       # ret


def main(argv):
    if len(argv) != 2:
        raise SystemExit(__doc__)
    src, dst = argv
    buf = bytearray(open(src, "rb").read())
    m = C.MachO(bytes(buf))
    fo = m.foff(CRASH_CB_VA)
    got = bytes(buf[fo:fo + 4])
    if got != PROLOGUE:
        raise SystemExit(f"0x{CRASH_CB_VA:X} is {got.hex()}, expected the "
                         f"callback prologue {PROLOGUE.hex()}")
    struct.pack_into("<I", buf, fo, RET)
    open(dst, "wb").write(bytes(buf))
    print(f"  crashret: 0x{CRASH_CB_VA:X} (file offset 0x{fo:X}) "
          f"{PROLOGUE.hex()} -> ret ({RET:08x})")
    print(f"  {dst}: {len(buf)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
