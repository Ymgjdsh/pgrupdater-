#!/usr/bin/env python3
"""v12: (a) guard asio's empty-any_executor tail calls, (b) repoint the two
`__NSDictionary0__struct` code sites at the `__NSDictionary0__` bind slot
(iOS 12 has the latter, not the former).

usage: python patch_v12.py <in> <out> [--no-asio] [--no-dict] [--dry-run]
"""
import struct
import sys

import chained2dyld as C
from runtime_profiles import profile_for

LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022

CBZ_RT8 = 0xB4000000          # cbz x8, <imm19*4>
LDR_X8_X0_20 = 0xF9401008     # ldr x8, [x0, #0x20]
EPI1 = 0xA9417BFD             # ldp x29, x30, [sp, #0x10]
EPI2 = 0xA8C24FF4             # ldp x20, x19, [sp], #0x20
B_MASK = 0xFC000000
B_OP = 0x14000000


def uleb(b, i):
    v = s = 0
    while True:
        x = b[i]; i += 1
        v |= (x & 0x7F) << s
        if not (x & 0x80):
            return v, i
        s += 7


def sleb(b, i):
    v = s = 0
    while True:
        x = b[i]; i += 1
        v |= (x & 0x7F) << s
        s += 7
        if not (x & 0x80):
            if x & 0x40:
                v |= -(1 << s)
            return v, i


def dyld_info_lc(m):
    for c in m.cmds:
        if c["cmd"] in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            return c
    return None


def decode_binds(m):
    """classic LC_DYLD_INFO bind stream -> [(segidx, vmaddr, name, ordinal, weak)]"""
    lc = dyld_info_lc(m)
    b = m.buf
    off, size = struct.unpack_from("<II", b, lc["off"] + 16)
    out = []
    ordv, name, weak = 0, None, False
    seg, addr, addend = 0, 0, 0
    i, end = off, off + size
    while i < end:
        op = b[i]; i += 1
        imm = op & 0x0F
        kind = op & 0xF0
        if op == 0:
            break
        elif kind == 0x10:
            ordv = imm
        elif kind == 0x20:
            ordv, i = uleb(b, i)
        elif kind == 0x30:
            ordv = imm - 16 if imm >= 8 else 0
        elif kind == 0x40:
            j = i
            while b[j] != 0:
                j += 1
            name = bytes(b[i:j]).decode()
            weak = bool(imm & 1)
            i = j + 1
        elif kind == 0x50:
            pass
        elif kind == 0x60:
            addend, i = sleb(b, i)
        elif kind == 0x70:
            seg = imm
            addr, i = uleb(b, i)
            addr += m.segments[seg]["vmaddr"] if seg < len(m.segments) else 0
        elif kind == 0x80:
            d, i = uleb(b, i)
            addr += d
        elif kind == 0x90:
            out.append((seg, addr, name, ordv, weak)); addr += 8
        elif kind == 0xA0:
            d, i = uleb(b, i)
            out.append((seg, addr, name, ordv, weak)); addr += 8 + d
        elif kind == 0xB0:
            out.append((seg, addr, name, ordv, weak)); addr += 8 + imm * 8
        elif kind == 0xC0:
            cnt, i = uleb(b, i)
            skip, i = uleb(b, i)
            for _ in range(cnt):
                out.append((seg, addr, name, ordv, weak)); addr += 8 + skip
        else:
            raise SystemExit("unsupported bind opcode 0x%02x at 0x%x" % (op, i - 1))
    return out


def code_sections(m):
    return [s for s in m.sections
            if s["seg"] == "__TEXT" and (s["flags"] & 0x80000400)]


def find_zero_run(m, start, need):
    b = m.buf
    seg = m.seg_by_name["__TEXT"]
    lo = C.round_up(max(start, seg["fileoff"]), 4)
    hi = seg["fileoff"] + seg["filesize"]
    i = lo
    while i < hi - need:
        if b[i] == 0:
            j = i
            while j < hi and b[j] == 0:
                j += 1
            if j - i >= need:
                return i, j - i
            i = C.round_up(j, 4)
        else:
            i += 4
    raise SystemExit("no %d-byte zero run in __TEXT after 0x%x" % (need, start))


def find_slot_refs(m, slot):
    """[(section, va)] of ADRP+LDR pairs loading `slot`"""
    b = m.buf
    page = slot & ~0xFFF
    off12 = slot & 0xFFF
    hits = []
    for sec in code_sections(m):
        for i in range(0, sec["size"] - 8, 4):
            w = struct.unpack_from("<I", b, sec["offset"] + i)[0]
            if (w & 0x9F000000) != 0x90000000:
                continue
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = immhi << 2 | immlo
            if imm & (1 << 20):
                imm -= (1 << 21)
            pc = sec["addr"] + i
            if (pc & ~0xFFF) + (imm << 12) != page:
                continue
            w2 = struct.unpack_from("<I", b, sec["offset"] + i + 4)[0]
            if (w2 & 0xFFC00000) != 0xF9400000:
                continue
            if ((w2 >> 5) & 0x1F) != (w & 0x1F):
                continue
            if ((w2 >> 10) & 0xFFF) * 8 != off12:
                continue
            hits.append((sec["name"], pc))
    return hits


def repoint_adrp_ldr(m, adrp_va, target):
    b = m.buf
    fo = m.foff(adrp_va)
    w = struct.unpack_from("<I", b, fo)[0]
    w2 = struct.unpack_from("<I", b, fo + 4)[0]
    if (w & 0x9F000000) != 0x90000000 or (w2 & 0xFFC00000) != 0xF9400000:
        raise SystemExit("site 0x%x is not ADRP+LDR" % adrp_va)
    imm = ((target & ~0xFFF) - (adrp_va & ~0xFFF)) >> 12
    w_new = (w & 0x9F00001F) | (((imm & 3) << 29)) | (((imm >> 2) & 0x7FFFF) << 5)
    o12 = (target & 0xFFF) // 8
    w2_new = (w2 & 0xFFC003FF) | (o12 << 10)
    struct.pack_into("<II", b, fo, w_new, w2_new)
    return w, w_new, w2, w2_new


def b_insn(src, dst):
    d = dst - src
    assert d % 4 == 0 and -(1 << 27) <= d < (1 << 27), hex(d)
    return (B_OP | ((d >> 2) & 0x03FFFFFF)) & 0xFFFFFFFF


def main(argv):
    src, dst = argv[0], argv[1]
    do_asio = "--no-asio" not in argv
    do_dict = "--no-dict" not in argv
    dry = "--dry-run" in argv
    m = C.MachO(open(src, "rb").read())
    profile = profile_for(m)
    b = m.buf

    # ---------------- (a) asio empty-executor guard
    sites = []
    for sec in code_sections(m):
        for i in range(0, sec["size"] - 0x110, 4):
            if struct.unpack_from("<I", b, sec["offset"] + i)[0] != LDR_X8_X0_20:
                continue
            w2 = struct.unpack_from("<I", b, sec["offset"] + i + 4)[0]
            if (w2 >> 24) != (CBZ_RT8 >> 24) or (w2 & 0x1F) != 8:
                continue
            pc = sec["addr"] + i
            for k in range(8, 0x100, 4):
                w3 = struct.unpack_from("<I", b, sec["offset"] + i + k)[0]
                w4 = struct.unpack_from("<I", b, sec["offset"] + i + k + 4)[0]
                w5 = struct.unpack_from("<I", b, sec["offset"] + i + k + 8)[0]
                if w3 == EPI1 and w4 == EPI2 and (w5 & B_MASK) == B_OP:
                    # structural asio markers: fns_->target_type() load and
                    # the tail-call argument move x1, x19
                    words = [struct.unpack_from("<I", b, sec["offset"] + i + j)[0]
                             for j in range(4, k, 4)]
                    if 0xF9401408 not in words[:8]:
                        continue
                    if 0xAA1303E1 not in words:
                        continue
                    d = w5 & 0x03FFFFFF
                    if d & (1 << 25):
                        d -= (1 << 26)
                    tail = sec["addr"] + i + k + 8
                    sites.append((pc, tail, tail + d * 4))
                    break
    print("execute_ex-like sites: %d" % len(sites))
    for pc, tail, tgt in sites:
        print("   body 0x%x  tail-b 0x%x -> 0x%x" % (pc, tail, tgt))

    if do_asio and sites and not dry:
        need = 16 * len(sites) + 16
        start = max(profile.asio_cave, C.text_code_va(m, b))
        fo, runlen = find_zero_run(m, start, need)
        cave_va = m.seg_by_name["__TEXT"]["vmaddr"] + (fo - m.seg_by_name["__TEXT"]["fileoff"])
        print("cave area @0x%x (file 0x%x, run %d bytes)" % (cave_va, fo, runlen))
        cur = cave_va
        curfo = fo
        for pc, tail, tgt in sites:
            # cbnz x0, +8 ; ret ; b tgt
            cbnz = 0xB5000000 | ((2 & 0x7FFFF) << 5)   # x0 != 0 -> pc+8
            struct.pack_into("<III", b, curfo, cbnz, 0xD65F03C0, b_insn(cur + 8, tgt))
            struct.pack_into("<I", b, m.foff(tail), b_insn(tail, cur))
            print("   guard 0x%x -> cave 0x%x (tail 0x%x -> 0x%x)" % (tail, cur, tgt, tgt))
            cur += 16
            curfo += 16

    # ---------------- (b) __NSDictionary0__struct -> __NSDictionary0__
    if do_dict:
        binds = decode_binds(m)
        slots = {}
        for seg, addr, name, ordv, weak in binds:
            slots.setdefault(name, []).append((addr, ordv, weak))
        old = slots.get("___NSDictionary0__struct", [])
        new = slots.get("___NSDictionary0__", [])
        print("binds: %d total; struct slot %s; plain slot %s"
              % (len(binds), [hex(a) for a, _, _ in old], [hex(a) for a, _, _ in new]))
        if old and new:
            target = new[0][0]
            for name, va in find_slot_refs(m, old[0][0]):
                if dry:
                    print("   would repoint %s@0x%x -> 0x%x" % (name, va, target))
                else:
                    res = repoint_adrp_ldr(m, va, target)
                    print("   repointed %s@0x%x -> 0x%x  (%08x->%08x, %08x->%08x)"
                          % ((name, va, target) + res))

    if not dry:
        open(dst, "wb").write(bytes(b))
        print("wrote %s (%d bytes)" % (dst, len(b)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
