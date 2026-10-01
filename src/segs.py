#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dump the segment table + dyld-info/code-signature commands of a Mach-O.

usage: python segs.py <macho> [<macho> ...]
"""
import struct
import sys

LC_NAMES = {
    0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0xB: "LC_DYSYMTAB", 0xC: "LC_LOAD_DYLIB",
    0xD: "LC_ID_DYLIB", 0x19: "LC_SEGMENT_64", 0x1B: "LC_UUID", 0x1D: "LC_CODE_SIGNATURE",
    0x1E: "LC_SEGMENT_SPLIT_INFO", 0x21: "LC_LAZY_LOAD_DYLIB", 0x22: "LC_ENCRYPTION_INFO",
    0x25: "LC_VERSION_MIN_MACOSX", 0x26: "LC_VERSION_MIN_IPHONEOS", 0x29: "LC_FUNCTION_STARTS",
    0x2A: "LC_DYLD_ENVIRONMENT", 0x2C: "LC_VERSION_MIN_TVOS", 0x2B: "LC_MAIN",
    0x2E: "LC_DATA_IN_CODE", 0x2F: "LC_SOURCE_VERSION", 0x32: "LC_BUILD_VERSION",
    0x33: "LC_DYLD_EXPORTS_TRIE", 0x34: "LC_DYLD_CHAINED_FIXUPS", 0x80000018: "LC_LOAD_WEAK_DYLIB",
    0x8000001C: "LC_REEXPORT_DYLIB", 0x8000001F: "LC_LOAD_UPWARD_DYLIB",
    0x80000022: "LC_DYLD_INFO_ONLY", 0x80000023: "LC_LOAD_DYLINKER?",
}


def main():
    for path in sys.argv[1:]:
        buf = open(path, "rb").read()
        magic, _ct, _cs, _ft, ncmds, sizeofcmds, _fl, _r = struct.unpack_from("<8I", buf, 0)
        print("== %s  size=%d (%s) magic=%s ncmds=%d sizeofcmds=%d"
              % (path, len(buf), hex(len(buf)), hex(magic), ncmds, sizeofcmds))
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", buf, off)
            name = LC_NAMES.get(cmd, hex(cmd))
            if cmd == 0x19:
                seg = bytes(buf[off + 8:off + 24]).rstrip(b"\0").decode(errors="replace")
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", buf, off + 24)
                print("   %-14s %-16s vmaddr=%#x vmsize=%#x fileoff=%#x filesize=%#x  end=%#x (EOF-diff %+d)"
                      % (name, seg, vmaddr, vmsize, fileoff, filesize, fileoff + filesize,
                         len(buf) - (fileoff + filesize)))
            elif cmd in (0x1D, 0x80000022):
                dataoff, datasize = struct.unpack_from("<II", buf, off + 8)
                print("   %-14s dataoff=%#x datasize=%#x end=%#x" % (name, dataoff, datasize,
                                                                     dataoff + datasize))
                if cmd == 0x80000022:
                    rb, rs, bo, bs, wo, ws, eo, es, lo, ls = struct.unpack_from("<10I", buf, off + 8)
                    print("        rebase=%#x/%#x bind=%#x/%#x weak=%#x/%#x export=%#x/%#x lazy=%#x/%#x"
                          % (rb, rs, bo, bs, wo, ws, eo, es, lo, ls))
            off += cmdsize


if __name__ == "__main__":
    main()
