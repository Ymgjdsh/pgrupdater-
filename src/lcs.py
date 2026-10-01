import struct, sys, glob

NAMES = {
    0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0x3: "LC_SYMSEG", 0x4: "LC_THREAD", 0x5: "LC_UNIXTHREAD",
    0xB: "LC_DYSYMTAB", 0xC: "LC_LOAD_DYLIB", 0xD: "LC_ID_DYLIB", 0xE: "LC_LOAD_DYLINKER",
    0xF: "LC_ID_DYLINKER", 0x18: "LC_LOAD_WEAK_DYLIB", 0x19: "LC_SEGMENT_64",
    0x1B: "LC_UUID", 0x1C: "LC_RPATH", 0x1D: "LC_CODE_SIGNATURE", 0x20: "LC_SEGMENT_SPLIT_INFO",
    0x21: "LC_REEXPORT_DYLIB", 0x22: "LC_LAZY_LOAD_DYLIB", 0x23: "LC_ENCRYPTION_INFO",
    0x24: "LC_DYLD_INFO", 0x25: "LC_VERSION_MIN_IPHONEOS", 0x26: "LC_FUNCTION_STARTS",
    0x29: "LC_DATA_IN_CODE", 0x2A: "LC_SOURCE_VERSION", 0x2B: "LC_DYLIB_CODE_SIGN_DRS",
    0x2C: "LC_ENCRYPTION_INFO_64", 0x2F: "LC_VERSION_MIN_MACOSX", 0x32: "LC_BUILD_VERSION",
    0x33: "LC_DYLD_EXPORTS_TRIE", 0x34: "LC_DYLD_CHAINED_FIXUPS", 0x80000018: "LC_LOAD_WEAK_DYLIB|REQ",
    0x8000001C: "LC_RPATH|REQ", 0x80000022: "LC_DYLD_INFO_ONLY", 0x80000028: "LC_MAIN|?",
    0x80000034: "LC_DYLD_EXPORTS_TRIE|?",
    0x28: "LC_MAIN",
}
# the high bit marks "required" for some commands; display raw too
def census(path):
    with open(path, "rb") as f:
        head = f.read(0x40000)
    magic = struct.unpack_from("<I", head, 0)[0]
    if magic != 0xFEEDFACF:
        print("%-32s not thin arm64 macho (0x%08X)" % (path, magic))
        return
    ncmds, sizeofcmds = struct.unpack_from("<II", head, 16)
    off = 32
    out = {}
    order = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", head, off)
        nm = NAMES.get(cmd, "0x%08X" % cmd)
        out[nm] = out.get(nm, 0) + 1
        order.append((hex(cmd), cmdsize, off))
        off += cmdsize
    print("%-32s ncmds=%d sizeofcmds=%d" % (path, ncmds, sizeofcmds))
    for k, v in out.items():
        print("      %-28s %d" % (k, v))
    if "LC_MAIN" in out or "0x80000028" in out:
        for cmd, cmdsize, o in order:
            if int(cmd, 16) & ~0x80000000 == 0x28:
                entryoff, stacksize = struct.unpack_from("<QQ", head, o + 8)
                print("      LC_MAIN entryoff=0x%X stacksize=0x%X (cmd 0x%s)" % (entryoff, stacksize, cmd))
    if "LC_UNIXTHREAD" in out:
        for cmd, cmdsize, o in order:
            if int(cmd, 16) == 0x5:
                print("      LC_UNIXTHREAD cmdsize=0x%X" % cmdsize)
    return out

for p in sys.argv[1:]:
    for f in glob.glob(p):
        census(f)
        print()
