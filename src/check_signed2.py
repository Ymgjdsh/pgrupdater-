#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check whether a third-party-signed IPA still contains loadable Mach-O members.

usage: python check_signed2.py <ipa>
"""
import struct
import sys
import zipfile

MEMBERS = ["Payload/Phigros.app/Phigros",
           "Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework"]

ipa = sys.argv[1]
z = zipfile.ZipFile(ipa)
names = z.namelist()
sig = [n for n in names if "_CodeSignature" in n or n.endswith(".mobileprovision") or "SC_Info" in n]
print("== %s\n   entries=%d  signature artifacts=%d" % (ipa, len(names), len(sig)))
for n in sig:
    print("   %s (%d B)" % (n, z.getinfo(n).file_size))
for m in MEMBERS:
    b = z.read(m)
    head = b[:4]
    magic_ok = head == b"\xcf\xfa\xed\xfe"
    anywhere = b.find(b"\xcf\xfa\xed\xfe")
    line = "   %-62s %d B  head=%s  Mach-O-valid=%s" % (m.rsplit("/", 1)[-1], len(b), head.hex(" "), magic_ok)
    print(line)
    if not magic_ok:
        print("      -> CF FA ED FE found at offset %d (of %d)" % (anywhere, len(b)))
        if head == b"\xfa\xde\x0c\xc0":
            ln, cnt = struct.unpack_from(">II", b, 4)
            print("      -> stripped: file starts with Apple SuperBlob (len %#x, %d blobs)" % (ln, cnt))
    else:
        magic, _ct, _cs, _ft, ncmds, sizeofcmds, _fl, _r = struct.unpack_from("<8I", b, 0)
        print("      -> ncmds=%d sizeofcmds=%d" % (ncmds, sizeofcmds))
print("VERDICT: %s" % ("OK - executables are intact Mach-O files" if all(
    z.read(m)[:4] == b"\xcf\xfa\xed\xfe" for m in MEMBERS) else "BROKEN - at least one executable is not a Mach-O"))
