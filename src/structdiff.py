#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Structural diff between two Mach-O images (segment/section/load-command level).

Usage: python structdiff.py <a> <b>

Both are printed; sections present in one and not the other are flagged with '<<'.
"""
import struct
import sys

SEG64 = 0x19
C = {0xC: "LOAD_DYLIB", 0xD: "ID_DYLIB", 0x18: "WEAK_DYLIB", 0x1F: "REEXPORT_DYLIB",
     0x20: "LAZY_LOAD_DYLIB", 0x23: "UPWARD_DYLIB", 0x1C: "RPATH", 0x22: "DYLD_INFO",
     0x80000022: "DYLD_INFO_ONLY", 0x2: "SYMTAB", 0xB: "DYSYMTAB", 0x1B: "UUID",
     0x32: "BUILD_VERSION", 0x25: "VERSION_MIN_IPHONEOS", 0x24: "VERSION_MIN_MACOSX",
     0x29: "DATA_IN_CODE", 0x26: "FUNCTION_STARTS", 0x1D: "CODE_SIGNATURE",
     0x2C: "ENCRYPTION_INFO_64", 0x21: "ENCRYPTION_INFO", 0x2A: "SOURCE_VERSION",
     0x80000028: "MAIN", 0x80000034: "DYLD_EXPORTS_TRIE", 0x80000033: "DYLD_CHAINED_FIXUPS",
     0x2B: "DYLIB_CODE_SIGN_DRS", 0x80000035: "DYLD_EXPORTS_TRIE", 0x1E: "SEGMENT_SPLIT_INFO",
     0x2E: "LINKER_OPTION", 0x80000018: "WEAK_DYLIB", 0x8000001C: "RPATH",
     0x8000001F: "REEXPORT_DYLIB", 0x80000023: "UPWARD_DYLIB", 0x8000001E: "SPLIT_INFO",
     0x2D: "CODE_SIGNATURE_DRS", 0x8000002B: "DYLIB_CODE_SIGN_DRS"}

SEC_NAMES = {"__text", "__stubs", "__stub_helper", "__got", "__nl_symbol_ptr",
             "__la_symbol_ptr", "__const", "__cstring", "__objc_classlist",
             "__objc_methname", "__objc_imageinfo", "__swift5_proto", "__swift5_types"}


def dump(path):
    buf = open(path, "rb").read()
    magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from("<8I", buf, 0)
    print("### %s" % path)
    print("   magic=0x%x cputype=%d cpusubtype=0x%x ftype=%d ncmds=%d sizeofcmds=%d flags=0x%x size=%d"
          % (magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, len(buf)))
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmd == SEG64:
            name = buf[off + 8:off + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", buf, off + 24)
            maxprot, initprot, nsects, sflags = struct.unpack_from("<4I", buf, off + 56)
            print("   SEG %-14s vmaddr=0x%09x vmsize=0x%08x fileoff=0x%08x filesize=0x%08x max=%d init=%d nsects=%d flags=0x%x"
                  % (name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, sflags))
            s = off + 72
            for _ in range(nsects):
                sn = buf[s:s + 16].split(b"\0")[0].decode()
                sg = buf[s + 16:s + 32].split(b"\0")[0].decode()
                addr, size = struct.unpack_from("<2Q", buf, s + 32)
                offset, align, reloff, nreloc, sfl = struct.unpack_from("<5I", buf, s + 48)
                segs.append(sn)
                if sn in SEC_NAMES:
                    print("        %-16s %-14s addr=0x%09x size=0x%-8x off=0x%-8x align=%d flags=0x%x"
                          % (sn, sg, addr, size, offset, align, sfl))
                s += 80
        elif cmd in (0x80000022, 0x22):
            f = struct.unpack_from("<10I", buf, off + 8)
            print("   %s rebase=(0x%x,%d) bind=(0x%x,%d) weak=(0x%x,%d) lazy=(0x%x,%d) export=(0x%x,%d)"
                  % (C[cmd], *f))
        elif cmd == 0x32:
            plat, minos, sdk, ntools = struct.unpack_from("<4I", buf, off + 8)
            print("   BUILD_VERSION platform=%d minos=%d.%d.%d sdk=%d.%d.%d ntools=%d"
                  % (plat, minos >> 16, (minos >> 8) & 0xFF, minos & 0xFF,
                     sdk >> 16, (sdk >> 8) & 0xFF, sdk & 0xFF, ntools))
        elif cmd == 0x25:
            v, sdk = struct.unpack_from("<2I", buf, off + 8)
            print("   VERSION_MIN_IPHONEOS version=%d.%d.%d sdk=%d.%d.%d"
                  % (v >> 16, (v >> 8) & 0xFF, v & 0xFF, sdk >> 16, (sdk >> 8) & 0xFF, sdk & 0xFF))
        elif cmd in (0x2C, 0x21):
            coff, csize, cid = struct.unpack_from("<3I", buf, off + 8)
            print("   ENCRYPTION_INFO cryptoff=0x%x cryptsize=0x%x cryptid=%d" % (coff, csize, cid))
        elif cmd == 0x1D:
            doff, dsize = struct.unpack_from("<2I", buf, off + 8)
            print("   CODE_SIGNATURE dataoff=0x%x datasize=0x%x" % (doff, dsize))
        elif cmd in (0x80000028,):
            eo, ss = struct.unpack_from("<2Q", buf, off + 8)
            print("   MAIN entryoff=0x%x stacksize=0x%x" % (eo, ss))
        elif cmd in (0x80000033, 0x80000034):
            doff, dsize = struct.unpack_from("<2I", buf, off + 8)
            print("   %s dataoff=0x%x datasize=0x%x" % (C[cmd], doff, dsize))
        off += cmdsize
    return segs, flags, cpusub


if __name__ == "__main__":
    a, b = sys.argv[1], sys.argv[2]
    sa, fa, ca = dump(a)
    print()
    sb, fb, cb = dump(b)
    print()
    print("sections only in %s: %s" % (a, sorted(set(sa) - set(sb))))
    print("sections only in %s: %s" % (b, sorted(set(sb) - set(sa))))
