#!/usr/bin/env python3
"""patch_v14.py <in> <out> [--no-avail] [--avail 12.5.8] [--dry-run]

v14 = "make every @available() check answer like the reference device".

Why: this port makes the app behave like it does on iOS 12 (legacy window,
apps' absent selectors answered nil by the v8 dispatcher, ...).  The one
behavioural fork we cannot cover from the outside is the platform-version
primitive itself: on iOS 12 every `@available(iOS 13/14,*)` is false, so the
engine takes its legacy code paths; on iOS 13/14 the same checks are true and
it takes paths that this port never exercised -- the only place where the
runtime behaviour of the port forks with the host OS version.

The primitive lives at __TEXT 0x143B914:

    int __isPlatformVersionAtLeast(uint32_t platform,  // w0
                                   uint32_t major,     // w1
                                   uint32_t minor,     // w2
                                   uint32_t subminor)  // w3

It compares the *detected* OS version -- held in the compiler-rt statics
0x4B89518/0x4B8951C/0x4B89520, after 0x143B968 calls __availability_version_check
-- against (major,minor,subminor).  72 call sites in this image, i.e. every
availability check emitted by clang.

The patch replaces the first instruction with `b <cave>`; the cave answers the
comparison against a *fixed* version (default 12.5.8, the device this port is
verified on).  Effect:
  * iOS 12.5.8  : answers are bit-for-bit what the real OS answers -> no change
  * iOS 13/14/..: answers as if the OS were 12.5.8 -> the app stays on the
                  legacy paths that our other patches already make work.
`--avail 0.0` makes every check false, `--avail 99.0` makes them all true (both
useful for A/B device tests).  `--no-avail` skips the whole patch.

Only 4 bytes of code change plus the cave in existing __TEXT padding.
"""
import struct
import sys

import chained2dyld as C

# --- sites -----------------------------------------------------------------
AVAIL_ENTRY = 0x143B914
AVAIL_ENTRY_EXPECT = bytes.fromhex("ff0301d1f65701a9")   # sub sp,sp,#0x40 ; stp x22,x21,[sp,#0x10]
AVAIL_CALLERS = 72                                       # sanity: as counted by tmp_availscan.py

TEXT_CAVE_START = 0x444CF30   # free __TEXT padding after the v13 bundleIdentifier hook
CAVE_NEED = 0x40

# --- instruction encodings -------------------------------------------------
MOV_W0_0 = 0x52800000    # movz w0, #0
MOV_W0_1 = 0x52800020    # movz w0, #1   (imm16 sits in bits[20:5]!)
RET = 0xD65F03C0
COND_LT = 11
COND_GT = 12
COND_LE = 13


def cmp_imm(rn, imm12):
    assert 0 <= imm12 < 4096
    return 0x71000000 | (imm12 << 10) | (rn << 5) | 31


def b_cond(pc, cond, target):
    d = target - pc
    assert d % 4 == 0, "b.cond target not 4-aligned"
    n = d >> 2
    assert -(1 << 18) <= n < (1 << 18), "b.cond out of range"
    return 0x54000000 | ((n & 0x7FFFF) << 5) | cond


def b_insn(pc, target):
    d = target - pc
    assert d % 4 == 0
    n = d >> 2
    assert -(1 << 25) <= n < (1 << 25), "b out of range"
    return 0x14000000 | (n & 0x03FFFFFF)


def build_avail_stub(code_va, want):
    """Branch-free enough compare of (w1,w2,w3) >= want; returns bytes."""
    major, minor, sub = want
    here = lambda i: code_va + i * 4
    w = [0] * 12
    # 0: cmp w1,#major       1: b.lt -> ret1    2: b.gt -> ret0
    # 3: cmp w2,#minor       4: b.lt -> ret1    5: b.gt -> ret0
    # 6: cmp w3,#sub         7: b.le -> ret1
    # 8: ret0: mov w0,#0     9: ret
    # 10: ret1: mov w0,#1   11: ret
    w[0] = cmp_imm(1, major)
    w[1] = b_cond(here(1), COND_LT, here(10))
    w[2] = b_cond(here(2), COND_GT, here(8))
    w[3] = cmp_imm(2, minor)
    w[4] = b_cond(here(4), COND_LT, here(10))
    w[5] = b_cond(here(5), COND_GT, here(8))
    w[6] = cmp_imm(3, sub)
    w[7] = b_cond(here(7), COND_LE, here(10))
    w[8] = MOV_W0_0
    w[9] = RET
    w[10] = MOV_W0_1
    w[11] = RET
    return b"".join(struct.pack("<I", x) for x in w)


def find_zero_run(m, start_va, need):
    """First zero run of `need` bytes at or after start_va, inside __TEXT.

    The tail of __TEXT (after the last section, __eh_frame) is an executable
    segment-padding hole -- that is exactly where the v8/v9/v12/v13 patches put
    their code, so it is a proven place for hand-written ARM64.
    """
    va = start_va
    for _ in range(0x20000 // 0x10):
        seg = m.seg_of(va)
        if seg is None or seg["name"] != "__TEXT":
            raise SystemExit("0x%x is not in __TEXT (segment %s)"
                             % (va, seg and seg["name"]))
        fo = m.foff(va)
        chunk = m.buf[fo:fo + need]
        if len(chunk) == need and chunk.count(0) == need:
            return va
        va += 0x10
    raise SystemExit("no zero run of %d bytes after 0x%x" % (need, start_va))


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = [a for a in argv[1:] if a.startswith("--")]
    if len(args) != 2:
        print(__doc__)
        return 2
    src, dst = args
    dry = "--dry-run" in flags
    do_avail = "--no-avail" not in flags
    want = (12, 5, 8)
    for f in flags:
        if f.startswith("--avail="):
            want = tuple(int(x) for x in f.split("=", 1)[1].split("."))
            want = (want + (0, 0, 0))[:3]

    m = C.MachO(open(src, "rb").read())
    buf = bytearray(m.buf)
    patches = []

    def put(va, data, what):
        fo = m.foff(va)
        assert fo is not None, "0x%x not in a section" % va
        sec = m.sect_of(va)
        seg = m.seg_of(va)
        assert seg is not None and seg["name"] == "__TEXT", \
            "0x%x is in segment %s (section %s)" % (va, seg and seg["name"], sec and sec["name"])
        patches.append((va, bytes(buf[fo:fo + len(data)]), data, what))
        struct.pack_into("<%ds" % len(data), buf, fo, data)

    def rdd(va):
        return struct.unpack_from("<I", buf, m.foff(va))[0]

    if do_avail:
        got = bytes(buf[m.foff(AVAIL_ENTRY):m.foff(AVAIL_ENTRY) + 8])
        assert got == AVAIL_ENTRY_EXPECT, \
            "unexpected entry bytes at 0x%x: %s" % (AVAIL_ENTRY, got.hex())
        cave = find_zero_run(m, TEXT_CAVE_START, CAVE_NEED)
        stub = build_avail_stub(cave, want)
        put(cave, stub, "availability stub %d.%d.%d (%d bytes)"
            % (want[0], want[1], want[2], len(stub)))
        put(AVAIL_ENTRY, struct.pack("<I", b_insn(AVAIL_ENTRY, cave)),
            "entry -> availability stub (was sub sp,sp,#0x40)")
        print("avail   entry 0x%x -> cave 0x%x  answer as %d.%d.%d  (%d call sites)"
              % (AVAIL_ENTRY, cave, want[0], want[1], want[2], AVAIL_CALLERS))

    total = sum(len(p[2]) for p in patches)
    print("sites %d, changed bytes %d" % (len(patches), total))
    for va, old, new, what in patches:
        print("  0x%08x  %-12s %s -> %s" % (va, what.split()[0], old.hex(), new.hex()))
    if dry:
        print("(dry run, %s not written)" % dst)
        return 0
    open(dst, "wb").write(bytes(buf))
    print("wrote %s (%d bytes)" % (dst, len(buf)))
    changed = sum(1 for a, b in zip(m.buf, buf) if a != b)
    print("byte-diff vs input: %d" % changed)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
