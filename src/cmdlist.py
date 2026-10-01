#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Print every load command (raw cmd value, name, offset, size) of a Mach-O file."""
import struct
import sys

NAMES = {
    0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0x3: "LC_SYMSEG", 0x4: "LC_THREAD", 0x5: "LC_UNIXTHREAD",
    0x6: "LC_LOADFVMLIB", 0x7: "LC_IDFVMLIB", 0x8: "LC_IDENT", 0x9: "LC_FVMFILE", 0xA: "LC_PREPAGE",
    0xB: "LC_DYSYMTAB", 0xC: "LC_LOAD_DYLIB", 0xD: "LC_ID_DYLIB", 0xE: "LC_LOAD_DYLINKER",
    0xF: "LC_ID_DYLINKER", 0x10: "LC_PREBOUND_DYLIB", 0x11: "LC_ROUTINES", 0x12: "LC_SUB_FRAMEWORK",
    0x13: "LC_SUB_UMBRELLA", 0x14: "LC_SUB_CLIENT", 0x15: "LC_SUB_LIBRARY", 0x16: "LC_TWOLEVEL_HINTS",
    0x17: "LC_PREBIND_CKSUM", 0x18: "LC_LOAD_WEAK_DYLIB", 0x19: "LC_SEGMENT_64", 0x1A: "LC_ROUTINES_64",
    0x1B: "LC_UUID", 0x1C: "LC_RPATH", 0x1D: "LC_CODE_SIGNATURE", 0x1E: "LC_SEGMENT_SPLIT_INFO",
    0x1F: "LC_REEXPORT_DYLIB", 0x20: "LC_LAZY_LOAD_DYLIB", 0x21: "LC_ENCRYPTION_INFO",
    0x22: "LC_DYLD_INFO", 0x23: "LC_DYLD_INFO_ONLY", 0x24: "LC_LOAD_UPWARD_DYLIB",
    0x25: "LC_VERSION_MIN_MACOSX", 0x26: "LC_VERSION_MIN_IPHONEOS", 0x27: "LC_FUNCTION_STARTS",
    0x28: "LC_DYLD_ENVIRONMENT", 0x29: "LC_MAIN", 0x2A: "LC_DATA_IN_CODE", 0x2B: "LC_SOURCE_VERSION",
    0x2C: "LC_DYLIB_CODE_SIGN_DRS", 0x2D: "LC_ENCRYPTION_INFO_64", 0x2E: "LC_LINKER_OPTION",
    0x2F: "LC_LINKER_OPTIMIZATION_HINT", 0x30: "LC_VERSION_MIN_TVOS", 0x31: "LC_VERSION_MIN_WATCHOS",
    0x32: "LC_NOTE", 0x33: "LC_BUILD_VERSION", 0x34: "LC_DYLD_EXPORTS_TRIE", 0x35: "LC_DYLD_CHAINED_FIXUPS",
    0x36: "LC_FILESET_ENTRY",
}
# correct the constants that differ between the 32/64-bit and old/new numbering:
NAMES[0x22] = "LC_DYLD_INFO"
NAMES[0x23] = "LC_DYLD_INFO_ONLY"
NAMES[0x2C] = "LC_ENCRYPTION_INFO_64"
NAMES[0x2D] = "LC_LOAD_DYLINKER?"
NAMES[0x2F] = "LC_VERSION_MIN_IPHONEOS?"
NAMES[0x32] = "LC_BUILD_VERSION?"
# definitive values used by the toolchain we care about:
FIX = {0x1B: "LC_UUID", 0x1D: "LC_CODE_SIGNATURE", 0x22: "LC_DYLD_INFO_ONLY", 0x24: "LC_VERSION_MIN_IPHONEOS",
       0x26: "LC_FUNCTION_STARTS", 0x29: "LC_DATA_IN_CODE", 0x2B: "LC_SOURCE_VERSION",
       0x2C: "LC_ENCRYPTION_INFO_64", 0x32: "LC_BUILD_VERSION", 0x33: "LC_DYLD_EXPORTS_TRIE",
       0x34: "LC_DYLD_CHAINED_FIXUPS", 0x80000018: "LC_LOAD_WEAK_DYLIB", 0x8000001C: "LC_REEXPORT_DYLIB",
       0x8000001F: "LC_LAZY_LOAD_DYLIB", 0x18: "LC_LOAD_WEAK_DYLIB", 0x1F: "LC_REEXPORT_DYLIB"}

for path in sys.argv[1:]:
    buf = open(path, "rb").read()
    magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from("<8I", buf, 0)
    print("== %s  %d bytes ncmds=%d sizeofcmds=%d" % (path, len(buf), ncmds, sizeofcmds))
    off = 32
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        nm = FIX.get(cmd) or NAMES.get(cmd & 0x7FFFFFFF) or NAMES.get(cmd) or "?"
        extra = ""
        if cmd == 0x32:
            plat, minos, sdk, nt = struct.unpack_from("<4I", buf, off + 8)
            extra = " platform=%d minos=%d.%d.%d sdk=%d.%d.%d" % (plat, minos >> 16, (minos >> 8) & 0xFF, minos & 0xFF, sdk >> 16, (sdk >> 8) & 0xFF, sdk & 0xFF)
        elif cmd == 0x24:
            ver, sdk = struct.unpack_from("<2I", buf, off + 8)
            extra = " version=%d.%d.%d sdk=%d.%d.%d" % (ver >> 16, (ver >> 8) & 0xFF, ver & 0xFF, sdk >> 16, (sdk >> 8) & 0xFF, sdk & 0xFF)
        elif cmd == 0x29:
            eo, ss, rs, _ = struct.unpack_from("<4Q", buf, off + 8)
            extra = " entryoff=0x%x stacksize=0x%x" % (eo, ss)
        print("   [%2d] off=0x%-6x cmd=0x%-8x %-24s size=%-6d%s" % (i, off, cmd, nm, cmdsize, extra))
        off += cmdsize
