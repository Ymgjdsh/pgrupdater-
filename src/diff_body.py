#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Diff the body of a signed member (after a prepended signature superblob) against our build."""
import sys
import zipfile

MEMBERS = [
    "Payload/Phigros.app/Phigros",
    "Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework",
]

signed, ref = sys.argv[1], sys.argv[2]
za, zb = zipfile.ZipFile(signed), zipfile.ZipFile(ref)
for m in MEMBERS:
    A, B = za.read(m), zb.read(m)
    print("=" * 78)
    print(m)
    # body = everything after the signature superblob (big-endian length at offset 4)
    import struct
    blob_len = struct.unpack_from(">I", A, 4)[0]
    body = A[blob_len:]
    print("  blob_len=%d  body_len=%d  ref_len=%d" % (blob_len, len(body), len(B)))
    print("  body[:64] = %s" % body[:64].hex())
    print("  ref [:64] = %s" % B[:64].hex())
    if len(body) == len(B):
        diffs = [i for i in range(len(body)) if body[i] != B[i]]
        print("  differing bytes: %d of %d (%.2f%%)" % (len(diffs), len(B), 100.0 * len(diffs) / len(B)))
        print("  first 20 diff offsets: %s" % [hex(i) for i in diffs[:20]])
        if diffs:
            print("  last diff offset: %s" % hex(diffs[-1]))
            # xored?
            x = bytes(a ^ b for a, b in zip(body[:256], B[:256]))
            print("  xor(body,ref)[:64] = %s" % x[:64].hex())
        else:
            print("  body == ref exactly")
