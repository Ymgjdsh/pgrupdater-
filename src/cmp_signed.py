#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compare a re-signed Mach-O inside an IPA against our reference build.

Checks: first differing byte offset, code-signature load command consistency,
__LINKEDIT geometry, and whether anything besides the signature blob changed.

Usage:  python cmp_signed.py <signed.ipa> <reference.ipa> <member-path>
"""
import struct
import sys
import zipfile

MH_MAGIC_64 = 0xFEEDFACF
LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT_64 = 0x19


def parse(buf: bytes):
    magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from("<8I", buf, 0)
    assert magic == MH_MAGIC_64, hex(magic)
    out = {"ncmds": ncmds, "sizeofcmds": sizeofcmds, "ftype": ftype, "flags": hex(flags),
           "segs": {}, "cs": None, "cmds": []}
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        out["cmds"].append((cmd, cmdsize))
        if cmd == LC_CODE_SIGNATURE:
            dataoff, datasize = struct.unpack_from("<II", buf, off + 8)
            out["cs"] = (dataoff, datasize)
        elif cmd == LC_SEGMENT_64:
            name = buf[off + 8:off + 24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", buf, off + 24)
            out["segs"][name] = (vmaddr, vmsize, fileoff, filesize)
        off += cmdsize
    return out


def first_diff(a: bytes, b: bytes):
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return n if len(a) != len(b) else -1


def main():
    signed_ipa, ref_ipa, member = sys.argv[1], sys.argv[2], sys.argv[3]
    za, zb = zipfile.ZipFile(signed_ipa), zipfile.ZipFile(ref_ipa)
    A, B = za.read(member), zb.read(member)
    print("member      : %s" % member)
    print("signed size : %d" % len(A))
    print("ref size    : %d  (delta %+d)" % (len(B), len(A) - len(B)))
    pa, pb = parse(A), parse(B)
    for tag, p, ln in (("signed", pa, len(A)), ("ref   ", pb, len(B))):
        cs = p["cs"]
        le = p["segs"].get("__LINKEDIT")
        print("-- %s: ncmds=%d sizeofcmds=%d ftype=%d flags=%s" % (tag, p["ncmds"], p["sizeofcmds"], p["ftype"], p["flags"]))
        print("   __LINKEDIT vmaddr=%s vmsize=%s fileoff=%s filesize=%s" % tuple(hex(x) for x in le) if le else "   no __LINKEDIT")
        if cs:
            dataoff, datasize = cs
            print("   LC_CODE_SIGNATURE dataoff=%s datasize=%s  end=%s  (file %s) %s"
                  % (hex(dataoff), hex(datasize), hex(dataoff + datasize), hex(ln),
                     "OK" if dataoff + datasize <= ln else "OUT OF FILE !!"))
            print("   sig blob magic=%s" % hex(struct.unpack_from("<I", A if tag.strip() == "signed" else B, dataoff)[0]))
            if le:
                print("   inside __LINKEDIT? %s" % (le[2] <= dataoff and dataoff + datasize <= le[2] + le[3]))
        else:
            print("   NO LC_CODE_SIGNATURE")
    d = first_diff(A, B)
    print("first differing byte offset: %s" % (hex(d) if d >= 0 else "NONE (identical)"))
    if pa["cs"] and pb["cs"]:
        print("ref sig dataoff=%s size=%s ; signed sig dataoff=%s size=%s"
              % (hex(pb["cs"][0]), hex(pb["cs"][1]), hex(pa["cs"][0]), hex(pa["cs"][1])))
    # compare the region before the signature blob
    if pa["cs"] and pb["cs"]:
        cut = min(pa["cs"][0], pb["cs"][0])
        same = A[:cut] == B[:cut]
        print("prefix up to first sig dataoff (%d bytes) identical: %s" % (cut, same))
        if not same:
            print("   first diff inside prefix: %s" % hex(first_diff(A[:cut], B[:cut])))
            for i in range(0, cut, 1):
                if A[i] != B[i]:
                    print("   ctx signed: %s" % A[max(0, i - 16):i + 16].hex())
                    print("   ctx ref   : %s" % B[max(0, i - 16):i + 16].hex())
                    break


if __name__ == "__main__":
    main()
