#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extract one or more members from a zip/IPA verbatim.

usage: python extract_members.py <archive> <member>=<outpath> [<member>=<outpath> ...]
"""
import sys
import zipfile

z = zipfile.ZipFile(sys.argv[1])
for spec in sys.argv[2:]:
    member, out = spec.split("=", 1)
    data = z.read(member)
    open(out, "wb").write(data)
    print("%s -> %s (%d bytes)" % (member, out, len(data)))
