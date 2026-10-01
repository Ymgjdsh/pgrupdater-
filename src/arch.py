#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Print the Mach-O header fields that decide whether a CPU can execute a binary."""
import struct
import sys

SUB = {
    (12, 0): "arm64 ALL", (12, 1): "arm64 v8", (12, 2): "arm64e",
    (12, 0x80000002): "arm64e (lib)", (12, 9): "arm64_32",
}
CPUT = {7: "x86", 12: "arm64", 16777228: "arm64"}

for path in sys.argv[1:]:
    buf = open(path, "rb").read(4096)
    magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from("<8I", buf, 0)
    if magic == 0xCAFEBABE or magic == 0xBEBAFECA:
        print("%-50s FAT/universal binary" % path)
        continue
    sub = cpusub & 0x00FFFFFF
    name = SUB.get((cputype & 0xFFFFFF, sub)) or SUB.get((cputype & 0xFFFFFF, cpusub)) or ("subtype %d" % sub)
    print("%-52s magic=0x%08x cputype=%-9s(0x%x) cpusubtype=%-16s ftype=%d flags=0x%x"
          % (path, magic, CPUT.get(cputype & 0xFFFFFF, "?"), cputype & 0xFFFFFF, name, ftype, flags))
