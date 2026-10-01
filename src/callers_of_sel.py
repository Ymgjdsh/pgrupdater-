#!/usr/bin/env python3
"""Find every direct `bl` call site of an ObjC selector, plus the enclosing
method, in a Mach-O (classic or chained).

Chain: SEL string -> __objc_selrefs slot(s) -> stub(s) that load that slot
       -> every `bl <stub>` in __TEXT (numpy-scanned).

Usage:
    python callers_of_sel.py <macho> <selector> [--context 5]
"""
import argparse
import bisect
import sys

import capstone
import numpy as np

from clsprobe import Img
import imp_rev

MD = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
MD.detail = True
ARM64_OP_REG = capstone.arm64.ARM64_OP_REG


def find_stubs(im, slots):
    """Scan the __objc_stubs/__stubs sections for `adrp xN`+`ldr xN,[xN,#off]` -> slot."""
    res = []
    for s in im.sects:
        if "stub" not in s["name"]:
            continue
        fo = im.foff(s["addr"])
        code = im.buf[fo:fo + s["size"]]
        adrp = {}
        for i in MD.disasm(code, s["addr"]):
            if i.mnemonic == "adrp" and len(i.operands) == 2 and i.operands[0].type == ARM64_OP_REG:
                try:
                    page = int(i.op_str.split(",")[-1].strip().lstrip("#"), 16)
                except ValueError:
                    continue
                adrp[i.reg_name(i.operands[0].reg)] = (i.address, page)
            elif i.mnemonic in ("ldr", "ldrsw") and len(i.operands) == 2:
                try:
                    dst = i.reg_name(i.operands[0].reg)
                    base = i.reg_name(i.operands[1].mem.base)
                    disp = i.operands[1].mem.disp
                except capstone.CsError:
                    continue
                if dst == base and base in adrp:
                    addr, page = adrp[base]
                    if addr + 4 == i.address and (page + disp) in slots:
                        res.append((addr, i.address, base, page + disp))
    return res


def bl_to(im, lo, hi, want):
    """All `bl #want` sites in [lo,hi) via a vectorised encoding scan."""
    fo = im.foff(lo)
    n = (hi - lo) // 4
    w = np.frombuffer(im.buf[fo:fo + n * 4], dtype="<u4")
    idx = np.nonzero((w & 0xFC000000) == 0x94000000)[0]
    imm = (w[idx] & 0x03FFFFFF).astype(np.int64)
    imm = np.where(imm >= (1 << 25), imm - (1 << 26), imm)
    tgt = lo + idx.astype(np.int64) * 4 + imm * 4
    return [int(lo + i * 4) for i in idx[tgt == want]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("macho")
    ap.add_argument("selector")
    ap.add_argument("--context", type=int, default=5)
    a = ap.parse_args()
    im = Img(a.macho)
    txt = next(s for s in im.segs if s["name"] == "__TEXT")
    lo, hi = txt["vmaddr"], txt["vmaddr"] + txt["filesize"]

    mn = im.sect("__objc_methname")
    blob = im.buf[im.foff(mn["addr"]):im.foff(mn["addr"]) + mn["size"]]
    needle = a.selector.encode() + b"\0"
    sel_vas, start = [], 0
    while True:
        k = blob.find(needle, start)
        if k < 0:
            break
        sel_vas.append(mn["addr"] + k)
        start = k + 1
    print(f"# SEL strings for {a.selector!r}: {[hex(v) for v in sel_vas]}")

    sr = im.sect("__objc_selrefs")
    slots = []
    for i in range(sr["size"] // 8):
        va = sr["addr"] + 8 * i
        p = im.u64(va)
        if p in sel_vas or (p and im.cstr(p) == a.selector):
            slots.append(va)
    print(f"# selref slots: {[hex(v) for v in slots]}")

    stubs = find_stubs(im, set(slots))
    print(f"# stub sites: {sorted({hex(x[0]) for x in stubs})}")

    rows = imp_rev.collect(im)
    starts = [r[0] for r in rows]
    for (st, reg) in sorted(set((x[0], x[2]) for x in stubs)):
        sites = bl_to(im, lo, hi, st)
        print(f"\n# {len(sites)} bl site(s) to stub 0x{st:X} (sel {a.selector!r})")
        for site in sites:
            i2 = bisect.bisect_right(starts, site) - 1
            owner, delta = "?", 0
            if i2 >= 0:
                imp, kind, own, sel, t, eo = rows[i2]
                owner, delta = f"{kind} {own} [{sel}]", site - imp
            print(f"\n  0x{site:X} in {owner} (+0x{delta:X})  [{im.sect_of(site)}]")
            fo = im.foff(site - 4 * a.context)
            code = im.buf[fo:fo + 4 * (2 * a.context + 1)]
            for ins in MD.disasm(code, site - 4 * a.context):
                mark = " <===" if ins.address == site else "      "
                print(f"   {mark}0x{ins.address:X}  {ins.mnemonic:8s} {ins.op_str}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
