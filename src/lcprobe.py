#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dump the load commands that matter for old-dyld compatibility, for one or more Mach-O files."""
import struct
import sys

CMDS = {
    0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0x4: "LC_THREAD", 0xB: "LC_LOAD_DYLIB",
    0xC: "LC_LOAD_DYLIB", 0x1B: "LC_UUID", 0x1D: "LC_CODE_SIGNATURE",
    0x21: "LC_ENCRYPTION_INFO_64", 0x22: "LC_DYLD_INFO_ONLY", 0x24: "LC_VERSION_MIN_IPHONEOS",
    0x26: "LC_FUNCTION_STARTS", 0x29: "LC_DATA_IN_CODE", 0x2B: "LC_SOURCE_VERSION",
    0x2F: "LC_BUILD_VERSION", 0x32: "LC_BUILD_VERSION", 0x33: "LC_DYLD_EXPORTS_TRIE",
    0x34: "LC_DYLD_CHAINED_FIXUPS", 0x80000018: "LC_LOAD_WEAK_DYLIB",
    0x8000001C: "LC_REEXPORT_DYLIB", 0x8000001F: "LC_LAZY_LOAD_DYLIB", 0x1E: "LC_SEGMENT_64",
    0x19: "LC_SEGMENT_64",
}


def name_of(buf, off, nameoff):
    s = buf[off + nameoff:off + nameoff + 200]
    return s.split(b"\0")[0].decode(errors="replace")


def dump(path):
    buf = open(path, "rb").read()
    magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from("<8I", buf, 0)
    print("== %s  %d bytes  magic=0x%08x cputype=%d ftype=%d ncmds=%d sizeofcmds=%d flags=0x%x"
          % (path, len(buf), magic, cputype, ftype, ncmds, sizeofcmds, flags))
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        c = cmd & 0x7FFFFFFF
        if c == 0x19:  # LC_SEGMENT_64
            segname = buf[off + 8:off + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", buf, off + 24)
            maxprot, initprot, nsects, sflags = struct.unpack_from("<4I", buf, off + 56)
            segs.append((segname, vmaddr, vmsize, fileoff, filesize, initprot, sflags))
            print("   %-16s vmaddr=0x%-9x vmsize=0x%-9x fileoff=0x%-9x filesize=0x%-9x initprot=%d flags=0x%x"
                  % (segname, vmaddr, vmsize, fileoff, filesize, initprot, sflags))
        elif c == 0xB or c == 0xC or cmd == 0x80000018 or cmd == 0x8000001C or cmd == 0x8000001F:
            no = struct.unpack_from("<I", buf, off + 8)[0]
            print("   %-22s %s" % (CMDS.get(cmd, hex(cmd)), name_of(buf, off, no)))
        elif c == 0x2C or c == 0x21:  # LC_ENCRYPTION_INFO_64 / LC_ENCRYPTION_INFO
            cryptoff, cryptsize, cryptid = struct.unpack_from("<3I", buf, off + 8)
            print("   LC_ENCRYPTION_INFO_64   cryptoff=0x%x cryptsize=0x%x cryptid=%d" % (cryptoff, cryptsize, cryptid))
        elif c == 0x22:  # LC_DYLD_INFO_ONLY
            r_off, r_sz, b_off, b_sz, wb_off, wb_sz, ly_off, ly_sz, ex_off, ex_sz = struct.unpack_from("<10I", buf, off + 8)
            print("   LC_DYLD_INFO_ONLY  rebase=(0x%x,%d) bind=(0x%x,%d) weak_bind=(0x%x,%d) lazy=(0x%x,%d) export=(0x%x,%d)"
                  % (r_off, r_sz, b_off, b_sz, wb_off, wb_sz, ly_off, ly_sz, ex_off, ex_sz))
        elif c == 0x2F:  # LC_BUILD_VERSION
            platform, minos, sdk, ntools = struct.unpack_from("<4I", buf, off + 8)
            print("   LC_BUILD_VERSION  platform=%d minos=%d.%d.%d sdk=%d.%d.%d"
                  % (platform, minos >> 16, (minos >> 8) & 0xFF, minos & 0xFF,
                     sdk >> 16, (sdk >> 8) & 0xFF, sdk & 0xFF))
        elif c == 0x24:  # LC_VERSION_MIN_IPHONEOS
            ver, sdk = struct.unpack_from("<2I", buf, off + 8)
            print("   LC_VERSION_MIN_IPHONEOS  version=%d.%d.%d sdk=%d.%d.%d"
                  % (ver >> 16, (ver >> 8) & 0xFF, ver & 0xFF, sdk >> 16, (sdk >> 8) & 0xFF, sdk & 0xFF))
        elif c == 0x1D:
            doff, dsz = struct.unpack_from("<2I", buf, off + 8)
            print("   LC_CODE_SIGNATURE  dataoff=0x%x datasize=0x%x" % (doff, dsz))
        off += cmdsize
    return segs


if __name__ == "__main__":
    for p in sys.argv[1:]:
        dump(p)
