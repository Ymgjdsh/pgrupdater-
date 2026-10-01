#!/usr/bin/env python3
"""Print LC_UUID and dump/decode the classic LC_DYLD_INFO_ONLY rebase stream.

Usage: python tmp_uuid_rebase.py <macho> [...]
"""
import struct
import sys
import uuid as uuidlib

LC_UUID = 0x1B
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022

REBASE_OPCODES = {
    0x00: "DONE",
    0x10: "SET_TYPE_IMM",
    0x20: "SET_SEGMENT_AND_OFFSET_ULEB",
    0x30: "ADD_ADDR_ULEB",
    0x40: "ADD_ADDR_IMM_SCALED",
    0x50: "DO_REBASE_IMM_TIMES",
    0x60: "DO_REBASE_ULEB_TIMES",
    0x70: "DO_REBASE_ADD_ADDR_ULEB",
    0x80: "DO_REBASE_ULEB_TIMES_SKIPPING_ULEB",
}


def uleb(buf, off):
    result = 0
    shift = 0
    start = off
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, off, off - start


def main():
    for path in sys.argv[1:]:
        with open(path, "rb") as fh:
            buf = fh.read()
        magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from(
            "<IiiIIIII", buf, 0)
        off = 32
        print("=" * 80)
        print("%s  (%d bytes, magic 0x%08X, ncmds %d, sizeofcmds %d)" % (path, len(buf), magic, ncmds, sizeofcmds))
        segs = {}
        dylibinfo = None
        for i in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", buf, off)
            if cmd == LC_UUID:
                raw = buf[off + 8:off + 24]
                print("  [%2d] LC_UUID  %s" % (i, str(uuidlib.UUID(bytes=raw)).upper()))
            elif cmd == LC_DYLD_INFO or cmd == LC_DYLD_INFO_ONLY:
                reb_off, reb_size, bnd_off, bnd_size, wk_off, wk_size, lz_off, lz_size, ex_off, ex_size = \
                    struct.unpack_from("<10I", buf, off + 8)
                dylibinfo = (reb_off, reb_size, bnd_off, bnd_size, lz_off, lz_size)
                print("  [%2d] %s rebase(0x%X,%d) bind(0x%X,%d) weak(%d,%d) lazy(0x%X,%d) export(0x%X,%d)"
                      % (i, "LC_DYLD_INFO_ONLY" if cmd == LC_DYLD_INFO_ONLY else "LC_DYLD_INFO",
                         reb_off, reb_size, bnd_off, bnd_size, wk_off, wk_size, lz_off, lz_size, ex_off, ex_size))
            elif cmd & 0x7FFFFFFF == 0x1 and cmdsize >= 72:
                segname = buf[off + 8:off + 24].rstrip(b"\0").decode("ascii", "replace")
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", buf, off + 24)
                segs[segname] = (vmaddr, vmsize, fileoff, filesize)
                print("  [%2d] LC_SEGMENT_64 %-14s vmaddr 0x%X vmsize 0x%X fileoff 0x%X filesize 0x%X"
                      % (i, segname, vmaddr, vmsize, fileoff, filesize))
            off += cmdsize
        if dylibinfo is None:
            print("  !! no LC_DYLD_INFO_ONLY")
            continue
        reb_off, reb_size, bnd_off, bnd_size, lz_off, lz_size = dylibinfo
        data = buf[reb_off:reb_off + reb_size]
        print("  rebase stream @0x%X (%d bytes): %s" % (reb_off, reb_size, data.hex()))
        p = 0
        seg_index = 0
        seg_names = ["__TEXT", "__DATA_CONST", "__DATA"]
        # decode using the *segment order in the file*
        ordered = sorted(segs.items(), key=lambda kv: kv[1][0])
        first = 1 if "__PAGEZERO" in segs else 0
        while p < len(data):
            b = data[p]
            op = b & 0xF0
            imm = b & 0x0F
            name = REBASE_OPCODES.get(op)
            if name is None:
                print("    !! BAD OPCODE %d (0x%02X) at stream offset %d (file 0x%X)"
                      % (b, b, p, reb_off + p))
                break
            extra = ""
            p += 1
            if op == 0x20:
                val, p, n = uleb(data, p)
                si = first + imm
                extra = " seg_index=%d (%s) offset=0x%X" % (
                    si, ordered[si][0] if si < len(ordered) else "?", val)
            elif op == 0x30:
                val, p, n = uleb(data, p)
                extra = " uleb=%d" % val
            elif op == 0x60 or op == 0x80:
                val, p, n = uleb(data, p)
                extra = " count=%d" % val
                if op == 0x80:
                    val2, p, n = uleb(data, p)
                    extra += " skip=%d" % val2
            elif op == 0x50:
                extra = " times=%d" % imm
            elif op == 0x40:
                extra = " imm_scaled=%d" % imm
            elif op == 0x10:
                extra = " type=%d" % imm
            print("    @%2d 0x%02X %-34s%s" % (p - 1, b, name, extra))


if __name__ == "__main__":
    main()
