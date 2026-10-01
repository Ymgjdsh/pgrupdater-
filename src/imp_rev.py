#!/usr/bin/env python3
"""Reverse-map an address to ObjC methods: which class/category/protocol method
contains this IMP (or is nearest before it).

Handles both classic 24-byte method lists and iOS13+ relative 12-byte lists
(the `name` field there points at a __objc_selrefs slot holding the SEL).

Usage:
    python imp_rev.py <macho> <addr> [<addr> ...] [--window 0x4000]
"""
import argparse
import bisect
import sys

from clsprobe import Img, class_ro


def ml_entries(im, list_va):
    """Yield (sel_name, types, imp) for a method list (classic or relative)."""
    if not list_va:
        return
    hdr = im.u32(list_va)
    if hdr is None:
        return
    ents = hdr & 0xFFFF
    rel = bool(hdr & 0x80000000)
    cnt = im.u32(list_va + 4) or 0
    if ents not in (12, 24):
        return
    if rel:
        ents = 12
    for k in range(cnt):
        eo = list_va + 8 + ents * k
        if ents == 24:
            n, t, i = im.u64(eo), im.u64(eo + 8), im.u64(eo + 16)
            sel = im.cstr(n) if n else None
            yield sel, t, i, eo
        else:
            vn, vt, vi = im.i32(eo), im.i32(eo + 4), im.i32(eo + 8)
            tn = (eo + vn) & 0xFFFFFFFFFFFFFFFF
            tt = (eo + 4 + vt) & 0xFFFFFFFFFFFFFFFF
            ti = (eo + 8 + vi) & 0xFFFFFFFFFFFFFFFF
            sel = None
            if vn:
                raw = im.u64(tn)
                if raw:
                    sec = im.sect_of(tn)
                    if sec and "selrefs" in sec:
                        sel = im.cstr(raw & 0xFFFFFFFFFFFF)
                    else:
                        sel = im.cstr(tn)
            tstr = im.cstr(tt) if vt else None
            yield sel, tstr, (ti if vi else 0), eo


def collect(im):
    rows = []

    def add(kind, owner, list_va):
        for sel, t, imp, eo in ml_entries(im, list_va):
            if imp:
                rows.append((imp, kind, owner, sel, t, eo))

    cl = im.sect("__objc_classlist")
    if cl:
        for i in range(cl["size"] // 8):
            p = im.u64(cl["addr"] + 8 * i)
            if not p:
                continue
            ro, _ = class_ro(im, p)
            if not ro:
                continue
            nm = im.cstr(im.u64(ro + 24) or 0) or f"cls_{p:X}"
            add("class", nm, im.u64(ro + 32))
    cat = im.sect("__objc_catlist")
    if cat:
        # category_t: name(8) cls(8) instanceMethods(8) classMethods(8)
        for i in range(cat["size"] // 8):
            c = im.u64(cat["addr"] + 8 * i)
            if not c:
                continue
            nm = im.cstr(im.u64(c) or 0) or f"cat_{c:X}"
            cls = im.u64(c + 8) or 0
            cnm = None
            if cls:
                ro, _ = class_ro(im, cls)
                if ro:
                    cnm = im.cstr(im.u64(ro + 24) or 0)
            add("cat+", f"{cnm or hex(cls)}+{nm}", im.u64(c + 16))
            add("cat-", f"{cnm or hex(cls)}+{nm}", im.u64(c + 24))
    pr = im.sect("__objc_protolist")
    if pr:
        # protocol_t: isa(8) name(8) protocols(8) instanceMethods(8) classMethods(8)
        for i in range(pr["size"] // 8):
            p = im.u64(pr["addr"] + 8 * i)
            if not p:
                continue
            nm = im.cstr(im.u64(p + 8) or 0) or f"proto_{p:X}"
            add("proto", nm, im.u64(p + 24))
            add("proto", nm, im.u64(p + 32))
    rows.sort()
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("macho")
    ap.add_argument("addrs", nargs="+")
    ap.add_argument("--window", type=lambda x: int(x, 0), default=0x4000)
    a = ap.parse_args()
    im = Img(a.macho)
    rows = collect(im)
    print(f"# {len(rows)} methods with IMPs in {a.macho}")
    starts = [r[0] for r in rows]
    for s in a.addrs:
        addr = int(s, 0)
        print(f"\n=== 0x{addr:X}  [{im.sect_of(addr)}]")
        i = bisect.bisect_right(starts, addr) - 1
        if i >= 0:
            imp, kind, owner, sel, t, eo = rows[i]
            print(f"  nearest-before: {kind} {owner}  -[{sel}]  imp=0x{imp:X} (+0x{addr - imp:X})  types={t!r}")
        else:
            print("  nearest-before: none")
        j = bisect.bisect_left(starts, addr - a.window)
        while j < len(rows) and rows[j][0] <= addr + a.window:
            imp, kind, owner, sel, t, eo = rows[j]
            if imp != (rows[i][0] if i >= 0 else None):
                print(f"  near: {kind} {owner}  -[{sel}]  imp=0x{imp:X} ({imp - addr:+#x})")
            j += 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
