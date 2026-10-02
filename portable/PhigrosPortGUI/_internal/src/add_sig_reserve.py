#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Give a Mach-O a *plausible* code-signature region so third-party signing tools
do not mistake `LC_CODE_SIGNATURE.dataoff == 0` for "signature already at the front".

Some Windows signers (observed with i4Tools' IPA signing) navigate by
LC_CODE_SIGNATURE: when dataoff == 0 they treat the leading bytes of the file as an
existing signature, strip/copy them away and clobber the Mach-O header.  A decrypted
App Store IPA normally still has a non-zero dataoff pointing at the (stale) blob.

This tool appends a zero-filled, page-aligned reserve at the end of __LINKEDIT,
points LC_CODE_SIGNATURE at it, and grows __LINKEDIT to cover it — i.e. it makes the
file look exactly like an unsigned/stripped IPA whose signature slot lives at the tail.

usage: python add_sig_reserve.py <in Mach-O> <out Mach-O> [reserve bytes] [--verbose]
"""
import struct
import sys

LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT_64 = 0x19
MH_MAGIC_64 = 0xFEEDFACF


def align_up(v, a):
    return (v + a - 1) & ~(a - 1)


def main():
    inp, outp = sys.argv[1], sys.argv[2]
    reserve = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x10000
    verbose = "--verbose" in sys.argv
    buf = bytearray(open(inp, "rb").read())
    magic, cputype, _cs, ftype, ncmds, sizeofcmds, _fl, _r = struct.unpack_from("<8I", buf, 0)
    if magic != MH_MAGIC_64:
        raise SystemExit("not a 64-bit Mach-O: %s" % hex(magic))

    cs_cmd = None       # file offset of the LC_CODE_SIGNATURE command
    le_cmd = None       # file offset of the __LINKEDIT segment command
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmd == LC_CODE_SIGNATURE and cs_cmd is None:
            cs_cmd = off
        elif cmd == LC_SEGMENT_64:
            name = bytes(buf[off + 8:off + 24]).rstrip(b"\0").decode()
            if name == "__LINKEDIT" and le_cmd is None:
                le_cmd = off
        off += cmdsize
    if cs_cmd is None:
        raise SystemExit("no LC_CODE_SIGNATURE command (add one first)")
    if le_cmd is None:
        raise SystemExit("no __LINKEDIT segment")

    old_dataoff, old_datasize = struct.unpack_from("<II", buf, cs_cmd + 8)
    vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", buf, le_cmd + 24)
    old_size = len(buf)
    if verbose:
        print("old: file=%d cs=(%s,%s) linkedit vmaddr=%s vmsize=%s fileoff=%s filesize=%s"
              % (old_size, hex(old_dataoff), hex(old_datasize), hex(vmaddr), hex(vmsize),
                 hex(fileoff), hex(filesize)))
    if old_dataoff + old_datasize > old_size:
        print("warn: old signature region runs past EOF (%s + %s > %d)"
              % (hex(old_dataoff), hex(old_datasize), old_size))

    new_dataoff = align_up(old_size, 0x1000)
    buf += b"\0" * (new_dataoff - old_size)      # pad to page boundary
    buf += b"\0" * reserve                        # the signature slot itself
    new_size = len(buf)
    delta = new_size - old_size

    new_filesize = new_size - fileoff          # fileoff is unchanged; __LINKEDIT still ends at EOF
    # preserve the original page-slack of __LINKEDIT vmsize
    slack = vmsize - align_up(filesize, 0x1000)
    new_vmsize = align_up(new_filesize, 0x1000) + slack
    struct.pack_into("<II", buf, cs_cmd + 8, new_dataoff, reserve)
    struct.pack_into("<Q", buf, le_cmd + 32, new_vmsize)     # vmsize
    struct.pack_into("<Q", buf, le_cmd + 48, new_filesize)   # filesize (NOT fileoff)
    # keep __LINKEDIT filesize covering the new EOF
    assert fileoff + new_filesize == new_size, "linkedit must end at EOF"
    assert new_vmsize % 0x1000 == 0 and new_vmsize >= new_filesize, "vmsize geometry"

    open(outp, "wb").write(bytes(buf))
    print("%s -> %s: file %d -> %d (+%d), LC_CODE_SIGNATURE=(%s,%s), __LINKEDIT filesize=%s vmsize=%s"
          % (inp, outp, old_size, new_size, delta, hex(new_dataoff), hex(reserve),
             hex(new_filesize), hex(new_vmsize)))


if __name__ == "__main__":
    main()
