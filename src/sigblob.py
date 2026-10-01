#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Parse the embedded signature (SuperBlob) that LC_CODE_SIGNATURE points at.

usage: python sigblob.py <macho> [<macho> ...]
"""
import struct
import sys

BLOB_NAMES = {0: "CodeDirectory", 1: "Info.plist slot", 2: "Requirements", 3: "ResourceDir",
              4: "Application", 5: "Entitlements", 6: "DMG", 7: "DER entitlements",
              8: "LaunchConstraint", 9: "LibraryConstraint", 10: "CodeDirectory (alt)",
              11: "Info.plist (alt)", 12: "ResourceDir (alt)", 4096: "alt CodeDirectory",
              65536: "CMS signature"}


def parse(path):
    buf = open(path, "rb").read()
    magic, _ct, _cs, _ft, ncmds, _sc, _fl, _r = struct.unpack_from("<8I", buf, 0)
    dataoff = datasize = None
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmd == 0x1D:
            dataoff, datasize = struct.unpack_from("<II", buf, off + 8)
        off += cmdsize
    print("== %s  file=%d (0x%x)  LC_CODE_SIGNATURE=(0x%x,0x%x)"
          % (path, len(buf), len(buf), dataoff, datasize))
    b = buf[dataoff:dataoff + datasize]
    print("   first 8 bytes at dataoff: %s" % b[:8].hex(" "))
    if len(b) < 12 or b[:4] != b"\xfa\xde\x0c\xc0":
        nz = sum(1 for x in b if x)
        print("   NOT a SuperBlob (non-zero bytes in region: %d / %d)" % (nz, len(b)))
        return
    blen, count = struct.unpack_from(">II", b, 4)
    print("   SuperBlob magic ok, length=%d (0x%x), blobs=%d" % (blen, blen, count))
    for i in range(count):
        t, o = struct.unpack_from(">II", b, 12 + i * 8)
        name = BLOB_NAMES.get(t, hex(t))
        sub = b[o:o + 8]
        smagic = sub[:4]
        if smagic == b"\xfa\xde\x0c\x02":     # CodeDirectory
            slen = struct.unpack_from(">I", sub, 4)[0]
            ver = struct.unpack_from(">I", b, o + 8)[0]
            flags, hash_off, id_off, nspecial, ncode = struct.unpack_from(">5I", b, o + 12)
            code_limit = struct.unpack_from(">I", b, o + 32)[0]
            hash_size, hash_type, _plat, _page = struct.unpack_from(">4B", b, o + 36)
            ident = b[o + id_off:b.index(b"\0", o + id_off)].decode(errors="replace")
            print("     %-18s off=0x%-7x len=%-8d version=0x%x codeLimit=0x%x hashType=%d "
                  "codeSlots=%d id=%r" % (name, o, slen, ver, code_limit, hash_type, ncode, ident))
            print("     %-18s codeLimit==dataoff? %s   covered by region? %s"
                  % ("", code_limit == dataoff, o + slen <= len(b)))
        elif smagic == b"\xfa\xde\x0c\x01":   # Requirements
            print("     %-18s off=0x%-7x (Requirements set)" % (name, o))
        elif smagic in (b"\xfa\xde\x0c\x05", b"\xfa\xde\x71\x71"):   # Entitlements
            slen = struct.unpack_from(">I", sub, 4)[0]
            payload = b[o + 8:o + slen].replace(b"\0", b"")
            print("     %-18s off=0x%-7x len=%d %s" % (name, o, slen, payload.decode(errors="replace")))
        else:
            slen = struct.unpack_from(">I", sub, 4)[0] if len(sub) >= 8 else 0
            print("     %-18s off=0x%-7x magic=%s len=%d" % (name, o, smagic.hex(" "), slen))
    print("   trailing bytes after SuperBlob length: %d" % (len(b) - blen))


for p in sys.argv[1:]:
    parse(p)
