#!/usr/bin/env python3
"""Nail down the relative-method-list `name` offset convention by pairing the
same classes/methods in two builds of the same framework (classic 24-byte lists
vs relative 12-byte lists) and locating each known selector string.

Usage: python mlfit2.py <classic_macho> <relative_macho> [--limit N]
"""
import struct
import sys

from clsprobe import Img, class_ro


def lists(im):
    """{class_name: (ro, [method_list addresses])}"""
    out = {}
    cl = im.sect("__objc_classlist")
    if not cl:
        return out
    for i in range(cl["size"] // 8):
        p = im.u64(cl["addr"] + 8 * i)
        if not p:
            continue
        ro, _ = class_ro(im, p)
        if not ro:
            continue
        nm = im.cstr(im.u64(ro + 24) or 0)
        bm = im.u64(ro + 32)
        if nm and bm:
            out.setdefault(nm, (ro, bm))
    return out


def find_str(im, sect_name, s):
    sct = im.sect(sect_name)
    if not sct:
        return None
    blob = im.rd(sct["addr"], sct["size"])
    needle = s.encode() + b"\0"
    hits = []
    start = 0
    while True:
        j = blob.find(needle, start)
        if j < 0:
            break
        # must be a string start (preceded by NUL) and followed by NUL
        if j == 0 or blob[j - 1] == 0:
            hits.append(sct["addr"] + j)
        start = j + 1
    return hits


def main():
    a = sys.argv[1:2] + sys.argv[2:3]
    limit = 0
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])
    old = Img(a[0])
    new = Img(a[1])
    lo, ln = lists(old), lists(new)
    print(f"# classic {a[0]}: {len(lo)} classes ; relative {a[1]}: {len(ln)} classes")
    common = [k for k in ln if k in lo]
    print(f"# common class names: {len(common)}")
    offs = {"list": [], "entry": [], "field": []}
    imp_ok = {"list": 0, "entry": 0, "field": 0}
    show = 0
    pairs = 0
    skip = {"flags": 0, "count": 0, "nosel": 0, "common": len(common)}
    for cname in common:
        ro_old, bm_old = lo[cname]
        ro_new, bm_new = ln[cname]
        f_old, c_old = old.u32(bm_old), old.u32(bm_old + 4)
        f_new, c_new = new.u32(bm_new), new.u32(bm_new + 4)
        if (f_old & 0xFFFF) != 24 or (f_new & 0xFFFF) != 12:
            skip["flags"] += 1
            if skip["flags"] <= 2:
                print(f"#   skip {cname}: old flags=0x{f_old:08X} new flags=0x{f_new:08X}")
            continue
        if c_old != c_new:
            skip["count"] += 1
            continue
        for k in range(c_old):
            eo_old = bm_old + 8 + 24 * k
            eo_new = bm_new + 8 + 12 * k
            sel = old.cstr(old.u64(eo_old) or 0)
            types = old.cstr(old.u64(eo_old + 8) or 0)
            if not sel:
                skip["nosel"] += 1
                continue
            hits = find_str(new, "__objc_methname", sel) or []
            thits = find_str(new, "__objc_methtype", types) if types else []
            v = new.i32(eo_new)
            v2 = new.i32(eo_new + 4)
            pairs += 1
            if show < 6:
                show += 1
                print(f"  ex {cname}.{sel} list=0x{bm_new:X} entry=0x{eo_new:X} v_name=0x{v & 0xFFFFFFFF:08X} v_types=0x{v2 & 0xFFFFFFFF:08X}"
                      f" sel@{[hex(h) for h in hits[:2]]} types@{[hex(h) for h in (thits or [])[:2]]}")
                if hits:
                    print(f"      name offsets: sel-list=0x{hits[0]-bm_new:X} sel-entry=0x{hits[0]-eo_new:X} sel-v=0x{hits[0]-v:X}")
                if thits:
                    print(f"      types offsets: types-list=0x{thits[0]-bm_new:X} types-field=0x{thits[0]-(eo_new+4):X} types-v=0x{thits[0]-v2:X}")
            for bn, base in (("list", bm_new), ("entry", eo_new), ("field", eo_new)):
                if any(h - (base + v) == 0 for h in hits):
                    offs[bn].append(0)
                elif hits:
                    offs[bn].append((hits[0] - (base + v)))
            imp_v = new.i32(eo_new + 8)
            for bn, base in (("list", bm_new), ("entry", eo_new), ("field", eo_new + 8)):
                s = new.sect_of((base + imp_v) & 0xFFFFFFFFFFFFFFFF)
                if s in ("__TEXT,__text", "__TEXT,il2cpp", "__TEXT,__stubs", "__TEXT,__objc_stubs"):
                    imp_ok[bn] += 1
            if show < 4 and limit:
                show += 1
                print(f"  {cname}.{sel} v_name=0x{v & 0xFFFFFFFF:08X} methname_hits={[hex(h) for h in hits[:3]]}"
                      f" v_types={types!r}")
    print(f"# method pairs with a located selector: {pairs}")
    print("# skip reasons:", skip)
    for lbl in ("list", "entry", "field"):
        ex = offs[lbl]
        zero = sum(1 for x in ex if x == 0)
        others = sorted(set(x for x in ex if x != 0))[:4]
        print(f"#   name rel-to-{lbl:<6} exact hits {zero}/{pairs}  (other deltas {others})")
    print("#   imp lands in executable section:", imp_ok)
    return 0


if __name__ == "__main__":
    sys.exit(main())
