#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reveal the byte-level structure of the transformed body a signer wrote."""
import struct
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
    blob_len = struct.unpack_from(">I", A, 4)[0]
    body = A[blob_len:]
    print("=" * 78)
    print("%s\n  ref=%d body=%d blob=%d" % (m, len(B), len(body), blob_len))

    K = B.find(body[:64])
    print("  ref.find(body[:64]) = %s" % (hex(K) if K >= 0 else "NOT FOUND"))
    if K >= 0:
        n = len(B) - K
        seg = B[K:K + len(body)]
        # how far does the plain shift hold?
        cut = next((i for i in range(min(len(seg), len(body))) if seg[i] != body[i]), None)
        print("  shift K=%d matches for first %s bytes" % (K, hex(cut) if cut is not None else "ALL"))

    print("  --- needle mapping (body offset -> ref offset) ---")
    step = max(1, len(body) // 8)
    for p in list(range(0, len(body) - 64, step)) + [len(body) - 64]:
        r = B.find(body[p:p + 64])
        print("    body[%9d] found at ref[%s]  delta=%s"
              % (p, hex(r) if r >= 0 else "NOT FOUND", (r - p) if r >= 0 else "-"))

    print("  --- mismatch map (16 blocks) ---")
    blocks = 16
    bs = (len(body) + blocks - 1) // blocks
    for i in range(blocks):
        a = body[i * bs:(i + 1) * bs]
        b = B[i * bs:(i + 1) * bs]
        if not a:
            break
        if a == b:
            print("    block %2d  off %9d  IDENTICAL" % (i, i * bs))
            continue
        x = (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")
        bad = len(a) - x.count(0)
        print("    block %2d  off %9d  mismatched %8d / %8d  (%.1f%%)"
              % (i, i * bs, bad, len(a), 100.0 * bad / len(a)))
