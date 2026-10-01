#!/usr/bin/env python3
"""Fit the relative-method-list offset convention.

For every method in every class of a Mach-O that uses relative method lists
(entsizeAndFlags 0x8000000C), test the three candidate bases (list start,
entry start, field address) for each of the three 32-bit fields and report how
often the target is a *valid C-string start* inside a plausible section.

Usage: python mlfit.py <macho>
"""
import struct
import sys

from clsprobe import Img, class_ro


def valid_start(im, va, want_sects, pred=None):
    s = im.sect_of(va)
    if s is None or s not in want_sects:
        return None
    prev = im.rd(va - 1, 1)
    if not prev or prev[0] != 0:
        return None
    txt = im.cstr(va)
    if not txt:
        return None
    if pred and not pred(txt):
        return None
    return txt


def main():
    path = sys.argv[1]
    im = Img(path)
    cl = im.sect("__objc_classlist")
    n = cl["size"] // 8
    name_sects = {"__TEXT,__objc_methname", "__TEXT,__cstring", "__TEXT,__objc_classname"}
    types_sects = {"__TEXT,__objc_methtype", "__TEXT,__cstring", "__TEXT,__objc_methname"}
    exec_sects = {"__TEXT,__text", "__TEXT,il2cpp", "__TEXT,__stubs", "__TEXT,__objc_stubs"}
    tally = {}
    examples = []
    nmeth = 0
    for i in range(n):
        p = im.u64(cl["addr"] + 8 * i)
        ro, _ = class_ro(im, p)
        if not ro:
            continue
        bm = im.u64(ro + 32)
        if not bm:
            continue
        fl = im.u32(bm)
        cnt = im.u32(bm + 4) or 0
        if fl is None or (fl & 0xFFFF) != 12:
            continue
        for k in range(cnt):
            eo = bm + 8 + k * 12
            vals = [im.i32(eo + 4 * j) for j in range(3)]
            if any(v is None for v in vals):
                continue
            nmeth += 1
            for lbl, v in zip(("name", "types", "imp"), vals):
                for bn, base in (("list", bm), ("entry", eo), ("field", eo + 4 * ("name", "types", "imp").index(lbl))):
                    tgt = (base + v) & 0xFFFFFFFFFFFFFFFF
                    key = (lbl, bn)
                    if lbl == "name":
                        r = valid_start(im, tgt, name_sects, lambda t: all(c.isalnum() or c in "_:" for c in t))
                    elif lbl == "types":
                        r = valid_start(im, tgt, types_sects, lambda t: t[0].isdigit() or t[0] in "@{([^" or t[0] in "vcislfBdq")
                    else:
                        r = im.sect_of(tgt) in exec_sects and im.sect_of(tgt)
                    if r:
                        tally[key] = tally.get(key, 0) + 1
                        if lbl == "name" and len(examples) < 6 and bn == "field":
                            examples.append((i, k, r, im.cstr(im.u64(ro + 24))))
    print(f"# {n} classes, {nmeth} methods with 12-byte entries")
    print("# valid resolutions by (field, base):")
    for lbl in ("name", "types", "imp"):
        row = "  ".join(f"{bn}={tally.get((lbl, bn), 0)}" for bn in ("list", "entry", "field"))
        print(f"#   {lbl:<6} {row}")
    print("# sample selectors decoded rel-to-field:", examples)
    return 0


if __name__ == "__main__":
    sys.exit(main())
