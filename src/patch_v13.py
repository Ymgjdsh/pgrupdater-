#!/usr/bin/env python3
"""patch_v13.py <in> <out> [--no-hook] [--no-literal] [--dry-run]

v13 = v12 + "runtime bundle-id spoof", so TapSDK stops reporting the
sideloaded bundle id (games.Pigeon.Phigros.3PH2K5L7RG) and reports the
official one (games.Pigeon.Phigros), which is what TapTap's backend
compares against (`-101 SDK_NOT_MATCHED`).

Two independent, purely additive changes:

  (A) literal repoint -- the NSString constant @"bundle_id=%@" that the login
      URL builder feeds to -[NSString stringWithFormat:] is a __CFConstantString
      at VA 0x47A1C20 (isa@+0, flags@+8 == 0x7C8, str@+0x10, len@+0x18).
      We repoint str/len at a longer literal "bundle_id=games.Pigeon.Phigros".
      The format specifier disappears, so the runtime argument is ignored and
      the request always carries the official id.

  (B) bundleIdentifier hook -- the objc_msgSend$bundleIdentifier stub
      (0x3BF46C0) tail-jumps at its `br x16` (0x3BF46D0); we replace that with
      `b <hook>`.  The hook calls the real method through x16 (as the stub
      would have), then returns an NSString built once with
      CFStringCreateWithCString(NULL, "games.Pigeon.Phigros", UTF8) and cached
      in the free tail of __DATA_METHLIST.  If creation fails it falls back to
      the real value, so it can never turn a working call into nil.

New bytes live in the free tail of __DATA_METHLIST (verified zero) and in the
__TEXT zero run right after the v12 caves.  No segment, link-edit, method-list
or symbol-table change.
"""
import struct
import sys

import chained2dyld as C
import patch_v12 as P12

# --- sites -----------------------------------------------------------------
CFSTR_VA = 0x47A1C20          # __CFConstantString  @"bundle_id=%@"
CFSTR_STR = CFSTR_VA + 0x10   # 0x47A1C30
CFSTR_LEN = CFSTR_VA + 0x18   # 0x47A1C38
CFSTR_FLAGS = CFSTR_VA + 0x08
OLD_STR_VA = 0x4360FC4
OLD_LEN = 12

STUB_VA = 0x3BF46C0           # __objc_stubs entry: objc_msgSend$bundleIdentifier
STUB_BR_VA = STUB_VA + 0x10   # `br x16`  (0xD61F0200)
SELREF_VA = 0x47CBDB8         # x1 = SEL bundleIdentifier

TEXT_CAVE_START = 0x444CEC0   # right after the two 12-byte v12 asio caves
HOOK_NEED = 0x80

LITERAL_VA = 0x52B3E00        # new "bundle_id=games.Pigeon.Phigros"
LITERAL = b"bundle_id=games.Pigeon.Phigros\x00"
CSTR_VA = 0x52B3E40           # new "games.Pigeon.Phigros"
CSTR = b"games.Pigeon.Phigros\x00"
CACHE_VA = 0x52B3E60          # 8-byte lazily filled cache
META_END = 0x5290000 + 0x24000  # __DATA_METHLIST vm end

OFFICIAL = "games.Pigeon.Phigros"
BUNDLE_LITERAL = "bundle_id=" + OFFICIAL

# --- instruction encodings -------------------------------------------------
STP_X29X30_M32 = 0xA9BE7BFD
LDP_X29X30_P32 = 0xA8C27BFD
MOV_X29_SP = 0x910003FD
BLR_X16 = 0xD63F0200
MOV_X9_X0 = 0xAA0003E9
MOV_X9_X10 = 0xAA0A03E9
MOV_X0_X9 = 0xAA0903E0
MOV_X0_XZR = 0xAA1F03E0
MOVZ_W2_0100 = 0x52802002
MOVK_W2_0800_L16 = 0x72A10002
RET = 0xD65F03C0


def adrp(rd, va, pc):
    imm = (va & ~0xFFF) - (pc & ~0xFFF)
    assert imm % 4096 == 0
    n = imm >> 12
    assert -(1 << 20) <= n < (1 << 20), "adrp out of range: 0x%x" % n
    immlo = n & 3
    immhi = (n >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | rd


def add_imm(rd, rn, imm12):
    assert 0 <= imm12 < 4096
    return 0x91000000 | (imm12 << 10) | (rn << 5) | rd


def ldr64(rt, rn, off):
    assert off % 8 == 0 and 0 <= off < 32768
    return 0xF9400000 | ((off // 8) << 10) | (rn << 5) | rt


def str64(rt, rn, off):
    assert off % 8 == 0 and 0 <= off < 32768
    return 0xF9000000 | ((off // 8) << 10) | (rn << 5) | rt


def b_insn(pc, target):
    d = target - pc
    assert d % 4 == 0
    return 0x14000000 | ((d >> 2) & 0x03FFFFFF)


def cbz64(pc, rt, target):
    d = target - pc
    assert d % 4 == 0
    return 0xB4000000 | (((d >> 2) & 0x7FFFF) << 5) | rt


def build_hook(code_va, cf_slot_va):
    """Assemble the bundleIdentifier hook; returns bytes."""
    idx = {}

    def here(i):
        return code_va + i * 4

    words = [0] * 27
    words[0] = STP_X29X30_M32
    words[1] = MOV_X29_SP
    words[2] = BLR_X16                                     # x0 = [bundle bundleIdentifier]
    words[3] = MOV_X9_X0                                   # default answer = real value
    words[4] = str64(0, 31, 0x10)                          # fallback copy
    words[5] = adrp(8, CACHE_VA, here(5))
    words[6] = add_imm(8, 8, CACHE_VA & 0xFFF)             # x8 = &cache
    words[7] = ldr64(10, 8, 0)
    words[8] = cbz64(here(8), 10, here(11))                # no cache -> create
    words[9] = MOV_X9_X10
    words[10] = b_insn(here(10), here(24))                 # -> done
    # create:
    words[11] = str64(8, 31, 0x18)                         # save &cache
    words[12] = adrp(16, cf_slot_va, here(12))
    words[13] = ldr64(16, 16, cf_slot_va & 0xFFF)
    words[14] = MOV_X0_XZR                                 # allocator = NULL
    words[15] = adrp(1, CSTR_VA, here(15))
    words[16] = add_imm(1, 1, CSTR_VA & 0xFFF)
    words[17] = MOVZ_W2_0100
    words[18] = MOVK_W2_0800_L16                           # w2 = kCFStringEncodingUTF8
    words[19] = BLR_X16
    words[20] = ldr64(8, 31, 0x18)
    words[21] = str64(0, 8, 0)                             # cache result
    words[22] = cbz64(here(22), 0, here(24))               # failed -> keep real
    words[23] = MOV_X9_X0
    # done:
    words[24] = MOV_X0_X9
    words[25] = LDP_X29X30_P32
    words[26] = RET
    del idx
    return b"".join(struct.pack("<I", w) for w in words)


def find_zero_run(m, start_va, need):
    """First zero run of `need` bytes at or after start_va (inside __TEXT)."""
    text = m.seg_by_name.get("__TEXT")
    end = text["vmaddr"] + text["vmsize"]
    va = start_va
    while va + need <= end:
        fo = m.foff(va)
        chunk = m.buf[fo:fo + need]
        if chunk.count(0) == need:
            return va
        va += 0x10
        if (va - start_va) > 0x20000:
            break
    raise SystemExit("no zero run of %d bytes after 0x%x" % (need, start_va))


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = [a for a in argv[1:] if a.startswith("--")]
    if len(args) != 2:
        print(__doc__)
        return 2
    src, dst = args
    dry = "--dry-run" in flags
    do_hook = "--no-hook" not in flags
    do_lit = "--no-literal" not in flags

    m = C.MachO(open(src, "rb").read())
    buf = bytearray(m.buf)
    patches = []

    def put(va, data, what):
        fo = m.foff(va)
        assert fo is not None, "0x%x not in a section" % va
        patches.append((va, bytes(buf[fo:fo + len(data)]), data, what))
        struct.pack_into("<%ds" % len(data), buf, fo, data)

    def putw(va, word, what):
        put(va, struct.pack("<Q", word), what)

    def rdw(va):
        return struct.unpack_from("<Q", buf, m.foff(va))[0]

    def rdd(va):
        return struct.unpack_from("<I", buf, m.foff(va))[0]

    # ---- sanity on the input ------------------------------------------------
    if do_lit:
        assert rdw(CFSTR_VA) == 0, "CFString isa slot not a bind placeholder"
        assert rdw(CFSTR_FLAGS) == 0x7C8, "unexpected CFString flags 0x%x" % rdw(CFSTR_FLAGS)
        assert rdw(CFSTR_STR) == OLD_STR_VA, "unexpected literal ptr 0x%x" % rdw(CFSTR_STR)
        assert rdw(CFSTR_LEN) == OLD_LEN, "unexpected literal len %d" % rdw(CFSTR_LEN)
    if do_hook:
        assert rdd(STUB_BR_VA) == 0xD61F0200, "stub tail is not `br x16`"
        assert rdd(STUB_VA) & 0x9F000000 == 0x90000000, "stub head is not adrp"
        assert rdd(STUB_VA + 4) & 0xFFC00000 == 0xF9400000, "stub has no ldr x1"
        # the stub must load the bundleIdentifier selref
        w1 = rdd(STUB_VA)
        pc = STUB_VA
        immlo = (w1 >> 29) & 3
        immhi = (w1 >> 5) & 0x7FFFF
        imm = (immhi << 2 | immlo)
        if imm & (1 << 20):
            imm -= (1 << 21)
        page = (pc & ~0xFFF) + (imm << 12)
        slot = page + ((rdd(STUB_VA + 4) >> 10) & 0xFFF) * 8
        assert slot == SELREF_VA, "stub selref slot 0x%x != 0x%x" % (slot, SELREF_VA)
        for va_, want in ((LITERAL_VA, 0), (CSTR_VA, 0), (CACHE_VA, 0)):
            assert va_ + 0x30 <= META_END, "data site 0x%x outside segment" % va_
    # data sites must be free
    for va_, n in ((LITERAL_VA, len(LITERAL)), (CSTR_VA, len(CSTR)), (CACHE_VA, 8)):
        fo = m.foff(va_)
        assert m.buf[fo:fo + n].count(0) == n, "data site 0x%x is not zero" % va_

    # ---- (A) literal repoint ------------------------------------------------
    if do_lit:
        putw(CFSTR_STR, LITERAL_VA, "bundle_id literal -> 0x%x" % LITERAL_VA)
        putw(CFSTR_LEN, len(BUNDLE_LITERAL), "bundle_id literal len")
        put(LITERAL_VA, LITERAL, "new literal")

    # ---- (B) bundleIdentifier hook -----------------------------------------
    if do_hook:
        cf_va = None
        for _seg, vm, name, _ord, _weak in P12.decode_binds(m):
            if name == "_CFStringCreateWithCString":
                cf_va = vm
                break
        assert cf_va is not None, "_CFStringCreateWithCString has no bind slot"
        cave = find_zero_run(m, TEXT_CAVE_START, HOOK_NEED)
        hook = build_hook(cave, cf_va)
        put(cave, hook, "bundleIdentifier hook (%d bytes)" % len(hook))
        put(STUB_BR_VA, struct.pack("<I", b_insn(STUB_BR_VA, cave)), "stub tail -> hook")
        put(CSTR_VA, CSTR, "official-id C string")
        print("hook      0x%x (%d bytes)  CF slot 0x%x" % (cave, len(hook), cf_va))

    # ---- report -------------------------------------------------------------
    changed = 0
    for va_, old, new, what in patches:
        changed += sum(1 for a, b in zip(old, new) if a != b)
        print("%-38s @0x%08x  %s -> %s" %
              (what, va_, old.hex(), new.hex()))
    total = sum(1 for a, b in zip(m.buf, buf) if a != b)
    print("sites %d, changed bytes %d (byte-diff %d)" % (len(patches), changed, total))
    if dry:
        print("dry run -- nothing written")
        return 0
    open(dst, "wb").write(bytes(buf))
    print("wrote %s (%d bytes)" % (dst, len(buf)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
