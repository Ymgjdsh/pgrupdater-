#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compare the LC_LOAD_DYLIB closure of several Mach-O files.

Usage: python libdiff.py <macho> [<macho> ...]

Prints each image's dependency list (ordinal order = the order dyld assigns,
1-based, which is what bind ordinals refer to) and the set differences.
"""
import struct
import sys

SEG64 = 0x19
DYLIB_CMDS = {0xC: "LOAD", 0x18: "WEAK", 0x1F: "REEXPORT", 0x23: "LAZY",
              0x80000018: "WEAK", 0x8000001C: "REEXPORT", 0x8000001F: "LAZY",
              0x80000023: "LAZY", 0x20: "ID"}


def dylibs(path):
    buf = open(path, "rb").read()
    ncmds = struct.unpack_from("<I", buf, 16)[0]
    off = 32
    out = {}
    ordinal = 0
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmd in DYLIB_CMDS and DYLIB_CMDS[cmd] != "ID":
            nameoff = struct.unpack_from("<I", buf, off + 8)[0]
            name = buf[off + nameoff:buf.index(b"\0", off + nameoff)].decode(errors="replace")
            ordinal += 1
            out[ordinal] = (DYLIB_CMDS[cmd], name)
        off += cmdsize
    return out


if __name__ == "__main__":
    sets = {}
    for path in sys.argv[1:]:
        d = dylibs(path)
        sets[path] = d
        print("=== %s : %d dylib dependencies" % (path, len(d)))
        for k in sorted(d):
            print("   %2d  %-8s %s" % (k, d[k][0], d[k][1]))
        print()
    paths = sys.argv[1:]
    for i in range(len(paths)):
        for j in range(i + 1, len(paths)):
            a = {v[1] for v in sets[paths[i]].values()}
            b = {v[1] for v in sets[paths[j]].values()}
            print("--- only in %s:" % paths[i])
            for n in sorted(a - b):
                print("      %s" % n)
            print("--- only in %s:" % paths[j])
            for n in sorted(b - a):
                print("      %s" % n)
