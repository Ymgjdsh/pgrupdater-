#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Investigate the layout a signing tool produced inside an IPA.

For each code member: locate the Mach-O magic, dump the prepended blob header,
parse LC_CODE_SIGNATURE / __LINKEDIT, and diff the Mach-O body against a reference.
"""
import struct
import sys
import zipfile

MH_MAGIC_64 = 0xFEEDFACF
LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT_64 = 0x19

MEMBERS = [
    "Payload/Phigros.app/Phigros",
    "Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework",
]


def parse_macho(buf, base=0):
    magic, _c, _s, ftype, ncmds, sizeofcmds, flags, _r = struct.unpack_from("<8I", buf, base)
    assert magic == MH_MAGIC_64, hex(magic)
    out = {"ftype": ftype, "ncmds": ncmds, "sizeofcmds": sizeofcmds, "flags": hex(flags),
           "cs": None, "segs": {}}
    off = base + 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmd == LC_CODE_SIGNATURE:
            out["cs"] = struct.unpack_from("<II", buf, off + 8)
        elif cmd == LC_SEGMENT_64:
            name = buf[off + 8:off + 24].rstrip(b"\0").decode()
            out["segs"][name] = struct.unpack_from("<4Q", buf, off + 24)
        off += cmdsize
    return out


def superblob(buf):
    magic, length, count = struct.unpack_from(">III", buf, 0)
    idx = []
    off = 12
    for _ in range(count):
        t, o = struct.unpack_from(">II", buf, off)
        idx.append((t, o))
        off += 8
    return magic, length, count, idx


def main():
    signed, ref = sys.argv[1], sys.argv[2]
    za, zb = zipfile.ZipFile(signed), zipfile.ZipFile(ref)
    for m in MEMBERS:
        A, B = za.read(m), zb.read(m)
        print("=" * 78)
        print("%s\n  signed us=%d  ref us=%d  delta=%+d" % (m, len(A), len(B), len(A) - len(B)))
        # where is the mach-o magic?
        pos = A.find(b"\xcf\xfa\xed\xfe")
        print("  first Mach-O magic at offset: %s" % (hex(pos) if pos >= 0 else "NOT FOUND"))
        print("  prepended blob header: magic=%s length=%s count=%s"
              % tuple([hex(x) for x in superblob(A)[:3]]))
        print("  blob index entries (type, offset): %s" % [(t, hex(o)) for t, o in superblob(A)[3]])
        for i, (t, o) in enumerate(superblob(A)[3]):
            if t == 5:
                print("  entitlements blob at %s: %s" % (hex(o), A[o + 8:o + 260].decode("utf-8", "replace").replace("\x00", " ")[:230]))
        if pos > 0:
            body = A[pos:]
            print("  body identical to reference? %s" % (body == B))
            if body != B:
                d = next((i for i in range(min(len(body), len(B))) if body[i] != B[i]), None)
                print("    first body diff at %s" % (hex(d) if d is not None else "length differs"))
            p = parse_macho(A, pos)
            print("  body Mach-O: ftype=%d ncmds=%d sizeofcmds=%d" % (p["ftype"], p["ncmds"], p["sizeofcmds"]))
            print("  body LC_CODE_SIGNATURE dataoff=%s datasize=%s"
                  % (tuple(hex(x) for x in p["cs"]) if p["cs"] else None))
            le = p["segs"].get("__LINKEDIT")
            print("  body __LINKEDIT vmaddr=%s vmsize=%s fileoff=%s filesize=%s"
                  % (tuple(hex(x) for x in le) if le else None))
            if p["cs"]:
                print("  file len=%s ; dataoff+datasize=%s" % (hex(len(A)), hex(p["cs"][0] + p["cs"][1])))
        q = parse_macho(B, 0)
        print("  ref LC_CODE_SIGNATURE dataoff=%s datasize=%s" % (tuple(hex(x) for x in q["cs"]) if q["cs"] else None))
        le = q["segs"].get("__LINKEDIT")
        print("  ref __LINKEDIT fileoff=%s filesize=%s (file %s)"
              % (hex(le[2]), hex(le[3]), hex(len(B))) if le else "  ref no __LINKEDIT")


if __name__ == "__main__":
    main()
