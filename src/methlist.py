#!/usr/bin/env python3
"""Walk the ObjC method-list section of a Mach-O and characterise its format.

Usage:
    python methlist.py <macho> [--limit N] [--list 0xADDR] [--stats]

For each method_list_t it reports entsizeAndFlags / count, and -- for the first
few entries -- how each of the three 32-bit fields resolves under the candidate
bases (list base / entry address / field address).  That tells us whether the
image uses relative method lists (iOS 13+ ABI) or classic 24-byte absolute ones.
"""
import argparse
import struct
import sys

SEG64 = 0x19
SECT = 80


def parse(path):
    buf = open(path, "rb").read()
    magic = struct.unpack_from("<I", buf, 0)[0]
    assert magic == 0xFEEDFACF, hex(magic)
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


def foff(segs, va):
    for s in segs:
        if s["vmaddr"] <= va < s["vmaddr"] + s["filesize"]:
            return s["fileoff"] + (va - s["vmaddr"])
    return None


def sect_of(sects, va):
    for s in sects:
        if s["addr"] <= va < s["addr"] + s["size"]:
            return f"{s['seg']},{s['name']}"
    return None


def cstr_ok(buf, segs, va, maxlen=256):
    fo = foff(segs, va)
    if fo is None:
        return None
    end = buf.find(b"\0", fo, fo + maxlen)
    if end < 0:
        return None
    raw = buf[fo:end]
    if not raw or any(b < 9 or b > 126 for b in raw):
        return None
    return raw.decode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("macho")
    ap.add_argument("--limit", type=int, default=3)
    ap.add_argument("--list", default=None)
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--max-lists", type=int, default=0)
    a = ap.parse_args()
    buf, segs, sects = parse(a.macho)
    ml = [s for s in sects if s["name"] in ("__objc_methlist", "__objc_const", "__const") and s["seg"] == "__TEXT"]
    if not ml:
        ml = [s for s in sects if s["name"] == "__objc_methlist"]
    if not ml:
        raise SystemExit("no __objc_methlist section")
    sec = ml[0]
    print(f"# method lists in __TEXT,__objc_methlist: 0x{sec['addr']:X}..0x{sec['addr']+sec['size']:X} ({sec['size']} bytes)")
    stats = {}
    base = sec["addr"]
    end = sec["addr"] + sec["size"]
    cur = base
    nlists = 0
    while cur < end:
        fo = foff(segs, cur)
        flags, count = struct.unpack_from("<II", buf, fo)
        entsize = flags & 0xFFFF
        rel = bool(flags & 0x80000000)
        if entsize == 0:
            print(f"0x{cur:08X}: flags=0x{flags:08X} (entsize 0) -- stop")
            break
        size = 8 + count * entsize
        stats[(entsize, rel)] = stats.get((entsize, rel), 0) + 1
        nlists += 1
        if nlists <= a.limit:
            print(f"\nlist {nlists} @0x{cur:08X}: flags=0x{flags:08X} entsize={entsize} relative={rel} count={count} size={size}")
            for i in range(min(2, count)):
                eo = cur + 8 + i * entsize
                fo2 = foff(segs, eo)
                f = struct.unpack_from("<3i", buf, fo2)
                print(f"  entry{i} @0x{eo:08X}: raw={f[0] & 0xFFFFFFFF:08X},{f[1] & 0xFFFFFFFF:08X},{f[2] & 0xFFFFFFFF:08X}")
                for lbl, fld in zip(("name", "types", "imp"), f):
                    for bn, bb in (("list", cur), ("entry", eo), ("field", eo + ("name", "types", "imp").index(lbl) * 4)):
                        tgt = (bb + fld) & 0xFFFFFFFFFFFFFFFF
                        s = sect_of(sects, tgt)
                        c = cstr_ok(buf, segs, tgt) if s and ("cstring" in s or "methname" in s or "methtype" in s or "objc" in s) else None
                        if s:
                            stats.setdefault("hits", {}).setdefault((lbl, bn), 0)
                            stats["hits"][(lbl, bn)] += 1
                        if c:
                            stats.setdefault("cstr", {}).setdefault((lbl, bn), 0)
                            stats["cstr"][(lbl, bn)] = stats["cstr"].get((lbl, bn), 0) + 1
        cur += size
        cur = (cur + 7) & ~7
        if a.max_lists and nlists >= a.max_lists:
            break
    print(f"\n# {nlists} lists walked, final offset 0x{cur:08X} (section end 0x{end:08X}, {'EXACT' if cur == end else 'MISMATCH'})")
    print("# (entsize, relative) -> count:", stats.get(0) if 0 in stats else "")
    for k, v in stats.items():
        if k in ("hits", "cstr"):
            continue
        print(f"#   entsize={k[0]} relative={k[1]}: {v} lists")
    if a.stats:
        print("# field-base hit counts (field label, base) -> times target lands in some section:")
        for k, v in sorted(stats.get("hits", {}).items()):
            print(f"#   {k[0]:>5} rel-to-{k[1]:<6} {v}")
        print("# ...and times it lands on a printable C string in a string section:")
        for k, v in sorted(stats.get("cstr", {}).items()):
            print(f"#   {k[0]:>5} rel-to-{k[1]:<6} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
