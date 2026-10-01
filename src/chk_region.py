#!/usr/bin/env python3
"""chk_region.py -- compare the login-param table region between the pristine
framework (chained fixups) and the converted v9raw (classic dyld info), and
list any classic binds/rebase entries that fall inside it."""
import struct
import sys

import chained2dyld as C
import patch_v12 as P

LO, HI = 0x47A1C00, 0x47A1C80


def words(tag, path):
    m = C.MachO(open(path, "rb").read())
    fo = m.foff(LO)
    print("== %s (%s) fo=0x%x ==" % (tag, path, fo))
    for i in range(0, HI - LO, 8):
        w = struct.unpack_from("<Q", m.buf, fo + i)[0]
        s = ""
        if w and 0x100000000 <= w < 0x6000000:
            try:
                end = m.buf.index(b"\0", m.foff(w))
                s = m.buf[m.foff(w):end][:40].decode("utf-8", "replace")
            except Exception:
                s = "?"
        print("  0x%08x  %016x  %s" % (LO + i, w, s))


def fixups(path):
    m = C.MachO(open(path, "rb").read())
    dec = C.decode_fixups(m)
    print("== fixups in region (%s) ==" % path)
    for f in dec["fixups"]:
        if LO <= f["vmaddr"] < HI:
            print("  0x%08x %s name=%s lib=%s target=%s" %
                  (f["vmaddr"], f["kind"], f.get("name"), f.get("lib"), f.get("target")))


def binds(path):
    m = C.MachO(open(path, "rb").read())
    print("== classic binds in region (%s) ==" % path)
    for seg, vm, name, ordn, weak in P.decode_binds(m):
        if LO <= vm < HI:
            print("  0x%08x %s ord=%s weak=%s" % (vm, name, ordn, weak))


if __name__ == "__main__":
    words("pristine", r"work\UnityFramework")
    words("converted", r"out\UnityFramework.v9raw")
    fixups(r"work\UnityFramework")
    binds(r"out\UnityFramework.v9raw")
