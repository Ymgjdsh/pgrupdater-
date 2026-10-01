#!/usr/bin/env python3
"""Verify the relative-method-list `name` field convention (expects an offset to
a __objc_selrefs slot that itself holds the selector pointer).

Usage: python check_rel.py <macho> [className] [count]
"""
import struct
import sys

from clsprobe import Img, class_ro


def main():
    im = Img(sys.argv[1])
    want = sys.argv[2] if len(sys.argv) > 2 else None
    lim = int(sys.argv[3]) if len(sys.argv) > 3 else 6
    cl = im.sect("__objc_classlist")
    done = 0
    for i in range(cl["size"] // 8):
        p = im.u64(cl["addr"] + 8 * i)
        ro, _ = class_ro(im, p)
        if not ro:
            continue
        nm = im.cstr(im.u64(ro + 24) or 0)
        if want and nm != want:
            continue
        bm = im.u64(ro + 32)
        f = im.u32(bm)
        cnt = im.u32(bm + 4)
        if (f & 0xFFFF) != 12:
            continue
        print(f"class {nm} ro=0x{ro:X} list=0x{bm:X} flags=0x{f:08X} count={cnt}")
        for k in range(cnt):
            eo = bm + 8 + 12 * k
            vn = im.i32(eo)
            vt = im.i32(eo + 4)
            vi = im.i32(eo + 8)
            tn = (eo + vn) & 0xFFFFFFFFFFFFFFFF
            tt = (eo + 4 + vt) & 0xFFFFFFFFFFFFFFFF
            ti = (eo + 8 + vi) & 0xFFFFFFFFFFFFFFFF
            raw = im.u64(tn)
            selptr = (raw & 0xFFFFFFFFFFFF) if raw else None
            sel = im.cstr(selptr) if selptr else None
            if done < lim:
                print(f"  m{k}: name_field=0x{eo:X} +0x{vn & 0xFFFFFFFF:X} -> 0x{tn:X} [{im.sect_of(tn)}] u64=0x{(raw or 0):X}"
                      f" sel={sel!r}")
                print(f"       types -> 0x{tt:X} [{im.sect_of(tt)}] = {im.cstr(tt)!r}")
                print(f"       imp   -> 0x{ti:X} [{im.sect_of(ti)}]")
                done += 1
        break
    return 0


if __name__ == "__main__":
    sys.exit(main())
