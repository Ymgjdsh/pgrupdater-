#!/usr/bin/env python3
"""Census of ObjC 2.0 ABI details that differ between an iOS-12-era build and an
iOS-13+ build of the same framework: method/ivar/property/protocol list formats.

Usage: python abi_census.py <macho> [<macho> ...]
"""
import struct
import sys

from clsprobe import Img, class_ro


def hdr(im, va):
    if not va:
        return None
    f = im.u32(va)
    c = im.u32(va + 4)
    if f is None:
        return None
    return (f, c, f & 0xFFFF, bool(f & 0x80000000))


def census(path):
    im = Img(path)
    print(f"\n===== {path}")
    cl = im.sect("__objc_classlist")
    tally = {}
    names = {}
    for i in range(cl["size"] // 8):
        p = im.u64(cl["addr"] + 8 * i)
        if not p:
            continue
        ro, _ = class_ro(im, p)
        if not ro:
            continue
        for lbl, off in (("baseMethods", 32), ("baseProtocols", 40), ("ivars", 48), ("baseProperties", 64)):
            h = hdr(im, im.u64(ro + off))
            if not h:
                continue
            key = (lbl, h[2], h[3])
            tally[key] = tally.get(key, 0) + 1
            names.setdefault(key, i)
    print("# class_ro_t list formats (field, entsize, relative) -> #classes")
    for k, v in sorted(tally.items()):
        print(f"#   {k[0]:<14} entsize={k[1]:<3} relative={k[2]}: {v}")

    for sec, fields in (("__objc_protolist", (("instanceMethods", 24), ("classMethods", 32), ("optInstanceMethods", 40), ("optClassMethods", 48))),
                        ("__objc_catlist", (("instanceMethods", 16), ("classMethods", 24)))):
        s = im.sect(sec)
        if not s:
            print(f"# {sec}: absent")
            continue
        tally2 = {}
        for i in range(s["size"] // 8):
            p = im.u64(s["addr"] + 8 * i)
            if not p:
                continue
            for lbl, off in fields:
                h = hdr(im, im.u64(p + off))
                if not h:
                    continue
                key = (lbl, h[2], h[3])
                tally2[key] = tally2.get(key, 0) + 1
        print(f"# {sec} ({s['size']//8} entries) list formats:")
        for k, v in sorted(tally2.items()):
            print(f"#   {k[0]:<20} entsize={k[1]:<3} relative={k[2]}: {v}")

    # do category/protocol lists that use the relative format point into __objc_methlist?
    ml = im.sect("__objc_methlist")
    if ml:
        lo, hi = ml["addr"], ml["addr"] + ml["size"]
        inside = 0
        outside = 0
        for sec, fields in (("__objc_catlist", (("instanceMethods", 16), ("classMethods", 24))),
                            ("__objc_protolist", (("instanceMethods", 24), ("classMethods", 32)))):
            s = im.sect(sec)
            if not s:
                continue
            for i in range(s["size"] // 8):
                p = im.u64(s["addr"] + 8 * i)
                if not p:
                    continue
                for lbl, off in fields:
                    tgt = im.u64(p + off)
                    if not tgt:
                        continue
                    if lo <= tgt < hi:
                        inside += 1
                    else:
                        outside += 1
        print(f"# lists referenced by categories/protocols: inside __objc_methlist {inside}, elsewhere {outside}")

    # every rebase/pointer slot pointing into __objc_methlist, by section
    if ml:
        lo, hi = ml["addr"], ml["addr"] + ml["size"]
        hits = {}
        for s in im.sects:
            if not s["size"] or s["offset"] == 0 or s["name"] in ("__mod_init_func",):
                continue
            if s["addr"] < lo or s["addr"] >= hi:
                pass
            blob = im.rd(s["addr"], min(s["size"], s["filesize"] if "filesize" in s else s["size"]))
            if not blob:
                continue
            for j in range(0, len(blob) - 7, 8):
                v = struct.unpack_from("<Q", blob, j)[0] & 0xFFFFFFFFFFFF
                if lo <= v < hi:
                    hits[f"{s['seg']},{s['name']}"] = hits.get(f"{s['seg']},{s['name']}", 0) + 1
        print("# 8-byte slots whose value points into __objc_methlist, by section:")
        for k, v in sorted(hits.items()):
            print(f"#   {k}: {v}")
    return 0


if __name__ == "__main__":
    for p in sys.argv[1:]:
        census(p)
