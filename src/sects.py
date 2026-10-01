#!/usr/bin/env python3
"""Section-level dump + initializer census.

For each Mach-O argument print:
  * every segment: vmaddr vmsize fileoff filesize initprot maxprot flags
  * every section: seg/name addr size offset align flags/type
  * census of S_MOD_INIT_FUNC_POINTERS (0x9) and S_INIT_FUNC_OFFSETS (0x16)
    -> how many initializers, and their target vmaddrs
  * per-segment file slack: filesize - (max(section.offset+section.size) - fileoff)
"""
import struct, sys

SECT_TYPE = {0x0: "REGULAR", 0x1: "CSTRING", 0x2: "4BYTE_LITERALS", 0x3: "8BYTE_LITERALS",
             0x4: "LITERAL_PTR", 0x5: "NONLAZY_SYM_PTR(5)", 0x6: "NONLAZY_SYM_PTR(6)",
             0x7: "LAZY_SYM_PTR", 0x8: "SYM_STUBS", 0x9: "MOD_INIT_FUNC", 0xA: "MOD_TERM_FUNC",
             0xB: "COALESCED", 0xC: "GB_ZEROFILL", 0xD: "INTERPOSING", 0xE: "16BYTE_LITERALS",
             0xF: "DTrace_DOF", 0x10: "LAZY_DYLIB_SYM_PTR", 0x11: "THREAD_LOCAL_VARS",
             0x12: "THREAD_LOCAL_VAR_PTRS", 0x13: "THREAD_LOCAL_INIT_FUNC",
             0x14: "INIT_FUNC_OFFSETS(0x14)", 0x15: "THREAD_LOCAL_INIT_OFFSETS",
             0x16: "INIT_FUNC_OFFSETS"}
SEG_FLAG = {0x1: "HIGHVM", 0x2: "FVMLIB", 0x4: "NORELOC", 0x8: "PROTECTED_V1", 0x10: "READ_ONLY",
            0x20: "NORELOC_OVER", 0x40: "NORELOC_STRIP"}


def dump(path):
    b = open(path, "rb").read()
    magic = struct.unpack_from("<I", b, 0)[0]
    if magic != 0xFEEDFACF:
        print(f"{path}: not a 64-bit Mach-O (magic 0x{magic:08x})")
        return
    ncmds = struct.unpack_from("<I", b, 16)[0]
    off = 32
    segs, secs = [], []
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from("<II", b, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            name = b[off + 8:off + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, foff, fsize = struct.unpack_from("<QQQQ", b, off + 24)
            maxprot, initprot, nsects, flags = struct.unpack_from("<IIII", b, off + 56)
            segs.append((name, vmaddr, vmsize, foff, fsize, initprot, maxprot, flags))
            so = off + 72
            for _ in range(nsects):
                sname = b[so:so + 16].split(b"\0")[0].decode()
                sseg = b[so + 16:so + 32].split(b"\0")[0].decode()
                addr, size = struct.unpack_from("<QQ", b, so + 32)
                s_off, align, reloff, nreloc, flags2, r1, r2, r3 = struct.unpack_from("<IIIIIIII", b, so + 48)
                secs.append(dict(seg=sseg, name=sname, addr=addr, size=size, off=s_off, align=align,
                                 type=flags2 & 0xFF, attrs=flags2 & ~0xFF, r1=r1, r2=r2, r3=r3))
                so += 80
        off += sz

    print(f"==== {path}")
    print(f"  ncmds={ncmds}  sections={len(secs)}")
    for (n, va, vs, fo, fs, ip, mp, fl) in segs:
        inits = [s for s in secs if s["seg"] == n]
        end = max([s["off"] + s["size"] for s in inits], default=fo)
        slack = fo + fs - end
        fl_str = "|".join(v for k, v in SEG_FLAG.items() if fl & k) or "-"
        print(f"  SEG {n:<14} vmaddr=0x{va:x} vmsize=0x{vs:x} file=[0x{fo:x},0x{fo+fs:x}) "
              f"initprot={ip} maxprot={mp} flags=0x{fl:x}({fl_str}) nsects={len(inits)} fileslack={slack}")
    for s in secs:
        t = SECT_TYPE.get(s["type"], f"type{s['type']}")
        mark = ""
        cnt = ""
        if s["type"] == 9:
            cnt = f"  ** {s['size']//8} initializer pointers **"
        elif s["type"] == 0x16:
            cnt = f"  ** {s['size']//4} initializer offsets **"
        print(f"    {s['seg']},{s['name']:<22} addr=0x{s['addr']:x} size=0x{s['size']:x} "
              f"off=0x{s['off']:x} align=2^{s['align']} {t}{mark}{cnt}")

    # initializer targets
    for s in secs:
        if s["type"] == 9 and s["size"]:
            print(f"  -- __mod_init_func ({s['seg']},{s['name']}) targets (unslid):")
            for i in range(0, s["size"], 8):
                v = struct.unpack_from("<Q", b, s["off"] + i)[0]
                print(f"       0x{v:x}")
        if s["type"] == 0x16 and s["size"]:
            print(f"  -- __init_offsets ({s['seg']},{s['name']}) targets (mach_header+off):")
            for i in range(0, s["size"], 4):
                v = struct.unpack_from("<I", b, s["off"] + i)[0]
                print(f"       off=0x{v:x} -> va=0x{0x100000000 + v:x}")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        try:
            dump(p)
        except Exception as e:
            print(f"{p}: ERROR {type(e).__name__}: {e}")
        print()
