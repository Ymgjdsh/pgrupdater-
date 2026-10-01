#!/usr/bin/env python3
"""Repair the specific LC_BUILD_VERSION defect produced before v20.

Usage: fix_build_version.py <input Mach-O> <output Mach-O>

Older chained2dyld outputs kept the single linker build_tool_version record
and cmdsize=32, but set ntools=0. Restore ntools=1 without moving any bytes.
Only that known defect is repaired; other malformed inputs are rejected.
The resulting image must be re-signed before installation.
"""
import struct
import sys
from pathlib import Path


def repair(data):
    if len(data) < 32 or struct.unpack_from("<I", data)[0] != 0xFEEDFACF:
        raise ValueError("expected a thin 64-bit Mach-O")
    count, size = struct.unpack_from("<II", data, 16)
    end = 32 + size
    if end > len(data):
        raise ValueError("load commands extend beyond file")
    out = bytearray(data)
    changes = []
    off = 32
    builds = 0
    for _ in range(count):
        if off + 8 > end:
            raise ValueError("truncated load command header")
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8 or cmdsize % 8 or off + cmdsize > end:
            raise ValueError("invalid load command bounds")
        if cmd == 0x32:
            builds += 1
            if cmdsize < 24:
                raise ValueError("truncated LC_BUILD_VERSION")
            ntools = struct.unpack_from("<I", data, off + 20)[0]
            if cmdsize != 24 + ntools * 8:
                if cmdsize != 32 or ntools != 0:
                    raise ValueError("not the known cmdsize=32, ntools=0 defect")
                tool, version = struct.unpack_from("<II", data, off + 24)
                if tool != 3 or version == 0:
                    raise ValueError("expected the preserved TOOL_LD record")
                struct.pack_into("<I", out, off + 20, 1)
                changes.append({"command_offset": off, "field_offset": off + 20,
                                "old_ntools": 0, "new_ntools": 1,
                                "cmdsize": cmdsize, "tool": tool,
                                "tool_version": version})
        off += cmdsize
    if off != end or builds != 1:
        raise ValueError("expected exact load-command extent and one build-version command")
    return bytes(out), changes


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    src, dst = map(Path, sys.argv[1:])
    if src.resolve() == dst.resolve():
        raise SystemExit("refusing to overwrite input")
    data, changes = repair(src.read_bytes())
    dst.write_bytes(data)
    for change in changes:
        print("ntools 0 -> 1 at %#x; cmdsize=32, TOOL_LD=%#x preserved"
              % (change["field_offset"], change["tool_version"]))
    print("%s -> %s: %d bytes, %d corrected command(s); RE-SIGN REQUIRED"
          % (src, dst, len(data), len(changes)))


if __name__ == "__main__":
    main()
