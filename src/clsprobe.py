#!/usr/bin/env python3
"""Inspect ObjC classes / class_ro_t / method lists in a Mach-O (classic or chained).

Usage:
    python clsprobe.py <macho> [--limit N] [--list 0xVA] [--json out.json]

Prints, for the first few classes in __objc_classlist:
    name, class_ro_t address, baseMethods address, and the method-list header
    (entsizeAndFlags / count / first entries raw).
Also reports the histogram of method-list header words over every class.
"""
import argparse
import json
import struct
import sys

SEG64 = 0x19
SECT = 80


def parse(path):
    buf = open(path, "rb").read()
    assert struct.unpack_from("<I", buf, 0)[0] == 0xFEEDFACF
    ncmds = struct.unpack_from("<I", buf, 16)[0]
    segs, sects = [], []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmd == SEG64:
            name = buf[off + 8:off + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", buf, off + 24)
            nsects = struct.unpack_from("<I", buf, off + 64)[0]
            segs.append(dict(name=name, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff, filesize=filesize))
            for k in range(nsects):
                so = off + 72 + k * SECT
                sname = buf[so:so + 16].split(b"\0")[0].decode()
                sseg = buf[so + 16:so + 32].split(b"\0")[0].decode()
                addr, size, o, align, reloff, nreloc, flg = struct.unpack_from("<QQIIIIIII", buf, so + 32)[:7]
                sects.append(dict(name=sname, seg=sseg, addr=addr, size=size, offset=o, flags=flg))
        off += cmdsize
    return buf, segs, sects


class Img:
    def __init__(self, path):
        self.path = path
        self.buf, self.segs, self.sects = parse(path)

    def foff(self, va):
        for s in self.segs:
            if s["vmaddr"] <= va < s["vmaddr"] + s["filesize"]:
                return s["fileoff"] + (va - s["vmaddr"])
        return None

    def rd(self, va, n):
        fo = self.foff(va)
        if fo is None:
            return None
        return self.buf[fo:fo + n]

    def u64(self, va):
        b = self.rd(va, 8)
        return None if b is None or len(b) < 8 else struct.unpack("<Q", b)[0]

    def u32(self, va):
        b = self.rd(va, 4)
        return None if b is None or len(b) < 4 else struct.unpack("<I", b)[0]

    def i32(self, va):
        b = self.rd(va, 4)
        return None if b is None or len(b) < 4 else struct.unpack("<i", b)[0]

    def cstr(self, va, maxlen=200):
        b = self.rd(va, maxlen)
        if b is None:
            return None
        e = b.find(b"\0")
        if e < 0:
            return None
        try:
            return b[:e].decode()
        except UnicodeDecodeError:
            return None

    def sect_of(self, va):
        for s in self.sects:
            if s["addr"] <= va < s["addr"] + s["size"]:
                return f"{s['seg']},{s['name']}"
        return None

    def sect(self, name, seg=None):
        for s in self.sects:
            if s["name"] == name and (seg is None or s["seg"] == seg):
                return s
        return None


def class_ro(im, cls_ptr):
    """class_t -> (ro_ptr, flags)"""
    data = im.u64(cls_ptr + 32)
    if data is None:
        return None, None
    return (data & ~0x7), (data & 0x7)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("macho")
    ap.add_argument("--limit", type=int, default=6)
    ap.add_argument("--list", default=None)
    ap.add_argument("--json")
    a = ap.parse_args()
    im = Img(a.macho)
    cl = im.sect("__objc_classlist")
    if not cl:
        raise SystemExit("no __objc_classlist")
    n = cl["size"] // 8
    print(f"# __objc_classlist {cl['seg']} 0x{cl['addr']:X} {n} classes")
    hist = {}
    rows = []
    for i in range(n):
        p = im.u64(cl["addr"] + 8 * i)
        if not p:
            continue
        ro, fl = class_ro(im, p)
        if not ro:
            continue
        name = im.cstr(im.u64(ro + 24) or 0)
        bm = im.u64(ro + 32)
        flags = im.u32(ro)
        hdr = None
        if bm:
            flags_ml = im.u32(bm)
            cnt = im.u32(bm + 4)
            hdr = (flags_ml, cnt)
            if flags_ml is not None:
                key = (flags_ml & 0xFFFF, bool(flags_ml & 0x80000000))
                hist[key] = hist.get(key, 0) + 1
        rows.append(dict(i=i, cls_va=p, ro_va=ro, ro_flags=flags, name=name, base_methods=bm, ml=hdr))
        if i < a.limit:
            print(f"\n[{i}] class 0x{p:X} ro=0x{ro:X} ro_flags=0x{flags:X} name={name!r} baseMethods=0x{(bm or 0):X}")
            if bm:
                ents = (hdr[0] or 0) & 0xFFFF
                print(f"    method_list flags=0x{hdr[0]:08X} entsize={ents} relative={bool(hdr[0] & 0x80000000)} count={hdr[1]}")
                for k in range(min(2, hdr[1] or 0)):
                    eo = bm + 8 + k * ents
                    if ents == 24:
                        print(f"      m{k} @0x{eo:X} name=0x{im.u64(eo) or 0:X} types=0x{im.u64(eo+8) or 0:X} imp=0x{im.u64(eo+16) or 0:X}"
                              f"  sel={im.cstr(im.u64(eo) or 0)!r}")
                    else:
                        f = [im.i32(eo + 4 * j) for j in range(ents // 4 if ents else 3)]
                        print(f"      m{k} @0x{eo:X} raw={[hex(x & 0xFFFFFFFF) for x in f]}")
    print("\n# method-list header histogram (entsize, relative) -> #classes")
    for k, v in sorted(hist.items()):
        print(f"#   entsize={k[0]} relative={k[1]}: {v}")
    if a.json:
        json.dump(rows, open(a.json, "w"), indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
