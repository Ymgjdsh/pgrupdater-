"""Acceptance check for the iOS-12 patched Mach-O files."""
import struct, sys

NAMES = {
    0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0x3: "LC_SYMSEG", 0x4: "LC_THREAD",
    0x5: "LC_UNIXTHREAD", 0x6: "LC_LOADFVMLIB", 0x7: "LC_IDFVMLIB",
    0x8: "LC_IDENT", 0x9: "LC_FVMFILE", 0xa: "LC_PREPAGE", 0xb: "LC_DYSYMTAB",
    0xc: "LC_LOAD_DYLIB", 0xd: "LC_ID_DYLIB", 0xe: "LC_LOAD_DYLINKER",
    0xf: "LC_ID_DYLINKER", 0x10: "LC_PREBOUND_DYLIB", 0x11: "LC_ROUTINES",
    0x12: "LC_SUB_FRAMEWORK", 0x13: "LC_SUB_UMBRELLA", 0x14: "LC_SUB_CLIENT",
    0x15: "LC_SUB_LIBRARY", 0x16: "LC_TWOLEVEL_HINTS", 0x17: "LC_PREBIND_CKSUM",
    0x18: "LC_LOAD_WEAK_DYLIB", 0x19: "LC_SEGMENT_64", 0x1a: "LC_ROUTINES_64",
    0x1b: "LC_UUID", 0x1c: "LC_RPATH", 0x1d: "LC_CODE_SIGNATURE",
    0x1e: "LC_SEGMENT_SPLIT_INFO", 0x1f: "LC_REEXPORT_DYLIB",
    0x20: "LC_LAZY_LOAD_DYLIB", 0x21: "LC_ENCRYPTION_INFO",
    0x22: "LC_DYLD_INFO", 0x23: "LC_LOAD_UPWARD_DYLIB", 0x24: "LC_VERSION_MIN_MACOSX",
    0x25: "LC_VERSION_MIN_IPHONEOS", 0x26: "LC_FUNCTION_STARTS",
    0x27: "LC_DYLD_ENVIRONMENT", 0x28: "LC_MAIN", 0x29: "LC_DATA_IN_CODE",
    0x2a: "LC_SOURCE_VERSION", 0x2b: "LC_DYLIB_CODE_SIGN_DRS",
    0x2c: "LC_ENCRYPTION_INFO_64", 0x2d: "LC_LINKER_OPTION",
    0x2e: "LC_LINKER_OPTIMIZATION_HINT", 0x2f: "LC_VERSION_MIN_TVOS",
    0x30: "LC_VERSION_MIN_WATCHOS", 0x31: "LC_NOTE", 0x32: "LC_BUILD_VERSION",
    0x33: "LC_DYLD_EXPORTS_TRIE", 0x34: "LC_DYLD_CHAINED_FIXUPS",
}
# commands dyld on iOS 12 knows about (only LC_REQ_DYLD ones matter for compat)
OLD_REQDYLD = {0x18, 0x1c, 0x1f, 0x23, 0x28}   # LOAD_WEAK_DYLIB, RPATH, REEXPORT_DYLIB, LOAD_UPWARD, MAIN
PLAT = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 6: "macCatalyst", 7: "iOS-sim"}


def vers(v):
    return f"{(v>>16)&0xFFFF}.{(v>>8)&0xFF}.{v&0xFF}"


def check(path):
    b = open(path, "rb").read()
    magic, cput, cpus, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from("<IiiIIIII", b, 0)
    print(f"\n=== {path}  ({len(b)} bytes)")
    print(f"  magic 0x{magic:X} cputype 0x{cput:X} cpusubtype 0x{cpus:X} filetype {ftype} "
          f"flags 0x{flags:X}")
    print(f"  ncmds {ncmds} sizeofcmds {sizeofcmds}")
    assert sizeofcmds <= 0x4000, "load commands overrun the first section!"
    off = 32
    bad = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", b, off)
        base = cmd & 0x7FFFFFFF
        nm = NAMES.get(base, f"??0x{base:X}")
        req = "REQ" if cmd & 0x80000000 else "   "
        extra = ""
        if base == 0x32:
            plat, minos, sdk, ntools = struct.unpack_from("<IIII", b, off+8)
            extra = f"  platform={PLAT.get(plat,plat)} minos={vers(minos)} sdk={vers(sdk)} ntools={ntools}"
        elif base == 0x25 or base == 0x2F or base == 0x30:
            v, s = struct.unpack_from("<II", b, off+8)
            extra = f"  minos={vers(v)} sdk={vers(s)}"
        elif base == 0x22 or base == 0x22 | 0x80000000:
            f2 = struct.unpack_from("<IIIIIIIIII", b, off+8)
            extra = (f"  rebase={f2[0]}/{f2[1]} bind={f2[2]}/{f2[3]} weak={f2[4]}/{f2[5]} "
                     f"lazy={f2[6]}/{f2[7]} export={f2[8]}/{f2[9]}")
        elif base in (0x1D, 0x33, 0x34):
            d, s = struct.unpack_from("<II", b, off+8)
            extra = f"  dataoff=0x{d:X} size={s}"
        elif base == 0x1B:
            extra = "  " + b[off+8:off+24].hex()
        elif base == 0x21 or base == 0x2C:
            ct, cs, cp = struct.unpack_from("<III", b, off+8)
            extra = f"  cryptoff={ct} cryptsize={cs} cryptid={cp}"
        elif base == 0x19:
            seg = b[off+8:off+24].rstrip(b"\0").decode()
            va, vs, fo, fs = struct.unpack_from("<QQQQ", b, off+24)
            extra = f"  {seg:14s} vm=0x{va:X} vsize=0x{vs:X} foff=0x{fo:X} fsize=0x{fs:X}"
        print(f"   {req} {nm:28s} size={cmdsize}{extra}")
        if cmd & 0x80000000 and base not in OLD_REQDYLD and base != 0x22:
            bad.append(nm)
        off += cmdsize
    if bad:
        print("  !!!! LOAD COMMANDS THAT iOS 12 dyld WILL REJECT:", bad)
    else:
        print("  OK: no unknown LC_REQ_DYLD commands")
    return b


for p in sys.argv[1:]:
    check(p)
