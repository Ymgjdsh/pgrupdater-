#!/usr/bin/env python3
"""Pack classic link-edit data in the order expected by iOS signers.

Usage: canonicalize_linkedit.py <in Mach-O> <out Mach-O>

The converter can leave a stale App Store SuperBlob between the symbol/string
tables and classic dyld streams. Some re-signers infer their output location
from that boundary instead of LC_CODE_SIGNATURE. Put every live link-edit
payload before that boundary, then put the signature slot at the new boundary.
"""
import struct
import sys

SEGMENT_64 = 0x19
SYMTAB = 0x2
DYSYMTAB = 0xB
CODE_SIGNATURE = 0x1D
DYLD_INFO = (0x22, 0x80000022)
FUNCTION_STARTS = 0x26
DATA_IN_CODE = 0x29
LINKEDIT_DATA = {0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x31,
                 0x80000033, 0x80000034}
STREAMS = ("rebase", "bind", "weak_bind", "lazy_bind", "export")


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def w32(b, o, v):
    struct.pack_into("<I", b, o, v)


def align8(v):
    return (v + 7) & ~7


def main(src, dst):
    b = bytearray(open(src, "rb").read())
    ncmds = u32(b, 16)
    cmds = []
    off = 32
    linkedit = None
    dyld = None
    symtab = None
    dysymtab = None
    sig = None
    for i in range(ncmds):
        cmd, size = struct.unpack_from("<II", b, off)
        c = {"index": i, "cmd": cmd, "size": size, "off": off}
        cmds.append(c)
        if cmd == SEGMENT_64:
            name = bytes(b[off + 8:off + 24]).rstrip(b"\0")
            if name == b"__LINKEDIT":
                fileoff, filesize = struct.unpack_from("<QQ", b, off + 40)
                linkedit = (off, fileoff, filesize)
        elif cmd in DYLD_INFO:
            dyld = c
        elif cmd == SYMTAB:
            symtab = c
        elif cmd == DYSYMTAB:
            dysymtab = c
        elif cmd == CODE_SIGNATURE:
            sig = c
        off += size
    if not (linkedit and dyld and symtab and dysymtab and sig):
        raise SystemExit("missing __LINKEDIT, dyld info, symbol, dynamic symbol, or signature command")
    le_cmd, le_start, le_size = linkedit
    le_end = le_start + le_size

    # Capture every live payload before clearing the old link-edit area.
    blobs = []
    d_off = dyld["off"] + 8
    for k, name in enumerate(STREAMS):
        o, s = u32(b, d_off + k * 8), u32(b, d_off + k * 8 + 4)
        if s:
            blobs.append(("stream:" + name, o, s, bytes(b[o:o + s]), "dyld", d_off + k * 8))

    # Other linkedit_data_command payloads keep their command-specific offsets.
    for c in cmds:
        if c["cmd"] in LINKEDIT_DATA and c["cmd"] != CODE_SIGNATURE:
            o, s = u32(b, c["off"] + 8), u32(b, c["off"] + 12)
            if s:
                blobs.append(("lc:%x" % c["cmd"], o, s, bytes(b[o:o + s]), "lc", c["off"] + 8))

    so = symtab["off"]
    symoff, nsyms, stroff, strsize = struct.unpack_from("<4I", b, so + 8)
    if nsyms:
        blobs.append(("symtab", symoff, nsyms * 16, bytes(b[symoff:symoff + nsyms * 16]), "symtab", so + 8))
    if dysymtab:
        yo = dysymtab["off"]
        # toc, modtab, extrefsym, indirectsym, extrel, locrel.
        for name, field, count_field, elem in (
                ("toc", 32, 36, 8),
                ("modtab", 40, 44, 4),
                ("extrefsym", 48, 52, 4),
                ("indirectsym", 56, 60, 4),
                ("extrel", 64, 68, 8),
                ("locrel", 72, 76, 8)):
            o = u32(b, yo + field)
            count = u32(b, yo + count_field)
            if o and count:
                blobs.append(("dysym:" + name, o, count * elem,
                              bytes(b[o:o + count * elem]), "dysym", yo + field))
    if strsize:
        blobs.append(("strtab", stroff, strsize, bytes(b[stroff:stroff + strsize]), "symtab", so + 16))

    # Deterministic Apple-like order: dyld streams, auxiliary linkedit data,
    # nlist, dynamic tables, then string table. Signature occupies the tail.
    rank = {"stream:rebase": 10, "stream:bind": 11, "stream:weak_bind": 12,
            "stream:lazy_bind": 13, "stream:export": 14}
    aux = {"lc:26": 20, "lc:29": 21, "lc:1e": 22, "lc:2b": 23,
           "lc:2e": 24, "lc:31": 25, "lc:80000033": 26, "lc:80000034": 27}
    rank.update(aux)
    rank.update({"symtab": 30, "dysym:toc": 31, "dysym:modtab": 32,
                 "dysym:extrefsym": 33, "dysym:indirectsym": 34,
                 "dysym:extrel": 35, "dysym:locrel": 36, "strtab": 40})
    blobs.sort(key=lambda x: (rank.get(x[0], 29), x[1]))
    if not blobs:
        raise SystemExit("no live link-edit payloads")

    # Preserve each payload byte-for-byte while assigning new offsets.
    cur = le_start
    placed = []
    for name, old, size, data, kind, field in blobs:
        cur = align8(cur)
        if cur + size > le_end:
            raise SystemExit("packed link-edit data exceeds __LINKEDIT")
        placed.append((name, old, size, data, kind, field, cur))
        cur += size
    sig_off = align8(cur)
    if sig_off > le_end:
        raise SystemExit("signature boundary exceeds __LINKEDIT")

    b[le_start:le_end] = bytes(le_size)
    for name, old, size, data, kind, field, new in placed:
        b[new:new + size] = data
        if kind == "dyld":
            w32(b, field, new)
        elif kind in ("lc", "symtab", "dysym"):
            w32(b, field, new)
    # The string-table field is in LC_SYMTAB and was included above; set the
    # signature slot after every live payload has been placed.
    w32(b, sig["off"] + 8, sig_off)
    w32(b, sig["off"] + 12, le_end - sig_off)

    print("source       %s  %d B" % (src, len(b)))
    print("__LINKEDIT   [%#x,%#x)" % (le_start, le_end))
    print("placement    " + ", ".join("%s@%#x+%#x" % (n, new, size)
                                     for n, old, size, data, kind, field, new in placed))
    print("codesig      dataoff %#x datasize %#x" % (sig_off, le_end - sig_off))
    open(dst, "wb").write(bytes(b))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        raise SystemExit(2)
    main(sys.argv[1], sys.argv[2])
