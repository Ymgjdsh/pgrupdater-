#!/usr/bin/env python3
"""Initializer census: where do __init_offsets / __mod_init_func targets land?

usage: python initmap.py <macho> [...]
"""
import struct, sys


def load(path):
    b = open(path, "rb").read()
    ncmds = struct.unpack_from("<I", b, 16)[0]
    off, segs, secs = 32, [], []
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from("<II", b, off)
        if cmd == 0x19:
            name = b[off + 8:off + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, foff, fsize = struct.unpack_from("<QQQQ", b, off + 24)
            maxprot, initprot, nsects, flags = struct.unpack_from("<IIII", b, off + 56)
            segs.append((name, vmaddr, vmsize, foff, fsize, initprot))
            so = off + 72
            for _ in range(nsects):
                sseg = b[so + 16:so + 32].split(b"\0")[0].decode()
                sname = b[so:so + 16].split(b"\0")[0].decode()
                addr, size = struct.unpack_from("<QQ", b, so + 32)
                s_off, align, reloff, nreloc, flags2 = struct.unpack_from("<IIIII", b, so + 48)
                secs.append(dict(seg=sseg, name=sname, addr=addr, size=size, off=s_off, type=flags2 & 0xFF))
                so += 80
        off += sz
    return b, segs, secs


def image_base(segs):
    for (n, va, vs, fo, fs, ip) in segs:
        if n != "__PAGEZERO":
            return va
    return 0


def where(secs, va):
    for s in secs:
        if s["addr"] <= va < s["addr"] + s["size"]:
            return f"{s['seg']},{s['name']}"
    for s in secs:
        pass
    return "??"


for path in sys.argv[1:]:
    b, segs, secs = load(path)
    base = image_base(segs)
    print(f"==== {path}  image_base=0x{base:x}")
    for s in secs:
        if s["type"] not in (9, 0x16) or not s["size"]:
            continue
        n = s["size"] // (8 if s["type"] == 9 else 4)
        print(f"  section {s['seg']},{s['name']} type={s['type']} n={n}")
        tgt = []
        for i in range(n):
            if s["type"] == 9:
                tgt.append(struct.unpack_from("<Q", b, s["off"] + 8 * i)[0])
            else:
                tgt.append(base + struct.unpack_from("<I", b, s["off"] + 4 * i)[0])
        hist = {}
        for t in tgt:
            hist[where(secs, t)] = hist.get(where(secs, t), 0) + 1
        print(f"    target sections: {hist}")
        print(f"    min=0x{min(tgt):x} max=0x{max(tgt):x}")
        for t in tgt[:8]:
            print(f"      first: 0x{t:x}  ({where(secs, t)})")
