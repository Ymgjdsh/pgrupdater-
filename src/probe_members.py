#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dump the first bytes of key members in two IPAs to see what a signing tool did."""
import sys
import zipfile

MEMBERS = [
    "Payload/Phigros.app/Phigros",
    "Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework",
    "Payload/Phigros.app/Info.plist",
    "Payload/Phigros.app/embedded.mobileprovision",
    "Payload/Phigros.app/_CodeSignature/CodeResources",
]


def probe(path):
    print("=" * 78)
    print(path)
    zf = zipfile.ZipFile(path)
    names = set(zf.namelist())
    for m in MEMBERS:
        if m not in names:
            print("  %-70s <absent>" % m)
            continue
        i = zf.getinfo(m)
        data = zf.read(m)
        print("  %-70s method=%d us=%d cs=%d crc=%08X" % (m, i.compress_type, i.file_size, i.compress_size, i.CRC))
        print("      raw   : %s" % data[:40].hex())
        print("      ascii : %s" % "".join(chr(c) if 32 <= c < 127 else "." for c in data[:40]))


for p in sys.argv[1:]:
    probe(p)
