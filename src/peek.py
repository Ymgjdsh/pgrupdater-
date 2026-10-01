#!/usr/bin/env python3
"""hexdump a slice of a Mach-O by *unslid vmaddr* (or --file offset).

Usage: python peek.py <macho> <addr> [length] [--file] [--str]
"""
import argparse
import struct
import sys

SEG64 = 0x19


def parse(path):
    buf = open(path, "rb").read()
    magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from("<8I", buf, 0)
    assert magic == 0xFEEDFACF, hex(magic)
    segs = []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmd == SEG64:
            name = buf[off + 8:off + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", buf, off + 24)
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        off += cmdsize
    return buf, segs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("macho")
    ap.add_argument("addr")
    ap.add_argument("length", nargs="?", type=lambda v: int(v, 0), default=0x40)
    ap.add_argument("--file", action="store_true", help="addr is a file offset")
    ap.add_argument("--str", action="store_true", help="also print NUL-terminated ascii")
    a = ap.parse_args()
    buf, segs = parse(a.macho)
    addr = int(a.addr, 0)
    fo = addr if a.file else None
    if fo is None:
        for name, vmaddr, vmsize, fileoff, filesize in segs:
            if vmaddr <= addr < vmaddr + filesize:
                fo = fileoff + (addr - vmaddr)
                break
    if fo is None:
        raise SystemExit(f"0x{addr:X} is not file-backed")
    blob = buf[fo:fo + a.length]
    for i in range(0, len(blob), 16):
        chunk = blob[i:i + 16]
        n = len(chunk) // 4
        words = " ".join(f"{w:08X}" for w in struct.unpack(f"<{n}I", chunk[:n * 4]))
        print(f"0x{addr + i:09X}  {chunk.hex(' '):<47} {words}")
    if a.str:
        end = buf.find(b"\0", fo)
        print("ascii:", repr(buf[fo:end if 0 < end < fo + 512 else fo + 512]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
