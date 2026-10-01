#!/usr/bin/env python3
"""Clear a stale embedded Mach-O signature while preserving a signer slot.

The converted image can retain an App Store SuperBlob even though its code has
changed.  Some sideloaders replace the slot named by LC_CODE_SIGNATURE, while
others discover the first SuperBlob in __LINKEDIT.  Keeping both locations
alive is unsafe: the stale blob can be parsed as the image signature or can
overlap data a signer intends to write.

The output keeps the file and segment sizes unchanged.  Every non-signature
link-edit payload is preserved byte-for-byte; bytes from the end of the last
live payload through __LINKEDIT's end become the zero-filled signing slot.
"""
import struct
import sys

SEGMENT_64 = 0x19
SYMTAB = 0x2
DYSYMTAB = 0xB
CODE_SIGNATURE = 0x1D
DYLD_INFO = (0x22, 0x80000022)
LINKEDIT_DATA = {0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x31,
                 0x80000033, 0x80000034}


def align8(value):
    return (value + 7) & ~7


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def main(src, dst):
    data = bytearray(open(src, "rb").read())
    ncmds = u32(data, 16)
    off = 32
    linkedit = None
    sig_cmd = None
    live_ends = []

    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == SEGMENT_64:
            name = bytes(data[off + 8:off + 24]).rstrip(b"\0")
            if name == b"__LINKEDIT":
                fileoff = u64(data, off + 40)
                filesize = u64(data, off + 48)
                linkedit = (fileoff, filesize)
        elif cmd == CODE_SIGNATURE:
            if sig_cmd is not None:
                raise SystemExit("multiple LC_CODE_SIGNATURE commands")
            sig_cmd = off
        elif cmd in DYLD_INFO:
            for i in range(5):
                size = u32(data, off + 12 + i * 8)
                if size:
                    start = u32(data, off + 8 + i * 8)
                    live_ends.append((start, start + size))
        elif cmd == SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<4I", data, off + 8)
            if nsyms:
                live_ends.append((symoff, symoff + nsyms * 16))
            if strsize:
                live_ends.append((stroff, stroff + strsize))
        elif cmd == DYSYMTAB:
            for field, count_field, elem in ((32, 36, 8), (40, 44, 4),
                                              (48, 52, 4), (56, 60, 4),
                                              (64, 68, 8), (72, 76, 8)):
                start = u32(data, off + field)
                count = u32(data, off + count_field)
                if start and count:
                    live_ends.append((start, start + count * elem))
        elif cmd in LINKEDIT_DATA:
            start, size = struct.unpack_from("<2I", data, off + 8)
            if start and size:
                live_ends.append((start, start + size))
        off += cmdsize

    if linkedit is None or sig_cmd is None:
        raise SystemExit("missing __LINKEDIT or LC_CODE_SIGNATURE")
    le_start, le_size = linkedit
    le_end = le_start + le_size
    if le_end > len(data):
        raise SystemExit("__LINKEDIT extends beyond the file")

    old_dataoff, old_datasize = struct.unpack_from("<2I", data, sig_cmd + 8)
    # Only payloads inside __LINKEDIT participate in the slot boundary.
    inside = [(max(le_start, a), min(le_end, b))
              for a, b in live_ends if a < le_end and b > le_start]
    content_end = align8(max((b for _, b in inside), default=le_start))
    if content_end > le_end:
        raise SystemExit("live link-edit payload exceeds __LINKEDIT")

    data[content_end:le_end] = b"\0" * (le_end - content_end)
    struct.pack_into("<2I", data, sig_cmd + 8, content_end, le_end - content_end)
    open(dst, "wb").write(data)
    print("%s -> %s: file=%d old-codesig=(0x%x,0x%x) new-codesig=(0x%x,0x%x)"
          % (src, dst, len(data), old_dataoff, old_datasize,
             content_end, le_end - content_end))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: clear_codesig.py <in Mach-O> <out Mach-O>")
        raise SystemExit(2)
    main(sys.argv[1], sys.argv[2])
