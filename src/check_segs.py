import struct, sys, os

def segs(path):
    b = open(path, "rb").read()
    ncmds, sizeofcmds = struct.unpack_from("<II", b, 16)
    off = 32
    out = []
    info = {}
    for _ in range(ncmds):
        cmd, cs = struct.unpack_from("<II", b, off)
        base = cmd & 0x7FFFFFFF
        if base == 0x19:
            nm = b[off+8:off+24].rstrip(b"\0").decode()
            va, vs, fo, fs = struct.unpack_from("<QQQQ", b, off+24)
            flags = struct.unpack_from("<I", b, off+68)[0]
            out.append((nm, va, vs, fo, fs, flags))
        elif base == 0x22:
            f = struct.unpack_from("<IIIIIIIIII", b, off+8)
            info["dyld_info"] = dict(rebase=(f[0], f[1]), bind=(f[2], f[3]),
                                     weak=(f[4], f[5]), lazy=(f[6], f[7]),
                                     export=(f[8], f[9]))
        elif base == 0x2:
            f = struct.unpack_from("<IIIIII", b, off+8)
            info["symtab"] = f
        elif base == 0xb:
            info["dysymtab"] = struct.unpack_from("<IIIIIIIIIIIIIIIIIIII", b, off+8)
        elif base == 0x1d:
            info["codesig"] = struct.unpack_from("<II", b, off+8)
        elif base == 0x26:
            info["funcstarts"] = struct.unpack_from("<II", b, off+8)
        elif base == 0x29:
            info["dataincode"] = struct.unpack_from("<II", b, off+8)
        off += cs
    return b, out, info

def check(path):
    b, ss, info = segs(path)
    print(f"\n=== {path}  file={len(b)} (0x{len(b):X})")
    for nm, va, vs, fo, fs, fl in ss:
        marker = ""
        if nm == "__LINKEDIT":
            marker = f"   <-- file end of seg = 0x{fo+fs:X}"
        print(f"  {nm:14s} vm=0x{va:<10X} vsize=0x{vs:<8X} foff=0x{fo:<9X} fsize=0x{fs:<8X} "
              f"vend=0x{fo+fs:X}{marker}")
    link = [s for s in ss if s[0] == "__LINKEDIT"][0]
    lo, lsz = link[3], link[4]
    hi = lo + lsz
    print(f"  __LINKEDIT file range: 0x{lo:X} .. 0x{hi:X}")
    print(f"  file size vs linkedit end: {len(b)} vs {hi}  -> "
          f"{'file end == linkedit end' if len(b) == hi else ('file is %d (0x%X) bytes past linkedit end' % (len(b)-hi, len(b)-hi))}")
    for k, (o, s) in info.get("dyld_info", {}).items():
        if s == 0:
            print(f"    dyld_info.{k:7s} off={o} size=0 (unused)")
            continue
        ok = lo <= o and o + s <= hi
        print(f"    dyld_info.{k:7s} off=0x{o:X} size={s} end=0x{o+s:X} inside __LINKEDIT: {ok}")
    for k in ("symtab", "funcstarts", "dataincode", "codesig"):
        if k not in info:
            continue
        v = info[k]
        if k == "symtab":
            o, n, so, ns, io, isz = v
            for lbl, oo, ss2 in (("symoff", so, ns*16), ("stroff", io, isz)):
                print(f"    symtab.{lbl} off=0x{oo:X} size={ss2} inside __LINKEDIT: {lo <= oo and oo+ss2 <= hi}")
        else:
            o, s = v
            print(f"    {k:10s} off=0x{o:X} size={s} inside __LINKEDIT: {s == 0 or (lo <= o and o+s <= hi)}")

for p in sys.argv[1:]:
    check(p)
