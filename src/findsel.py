#!/usr/bin/env python3
"""findsel.py <macho> <sel-string-va>  -- find __objc_selrefs slots pointing at a selector string.

Handles both chained fixups and classic LC_DYLD_INFO rebase streams by asking
chained2dyld for the decoded fixups when available.
"""
import sys
import chained2dyld as C

def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    path = argv[1]
    want = int(argv[2], 0)
    buf = open(path, "rb").read()
    m = C.MachO(bytes(buf))
    try:
        dec = C.decode_fixups(m)
    except Exception as exc:                      # classic dyld info binary
        print("decode_fixups failed: %r" % (exc,))
        return 1
    fixups = dec["fixups"] if isinstance(dec, dict) else dec
    hits = []
    for f in fixups:
        t = f.get("target")
        if t is None:
            continue
        if (t & 0xFFFFFFFFFFFFFFFF) == want:
            hits.append(f)
    print("fixups=%d  slots whose target == 0x%x: %d" % (len(fixups), want, len(hits)))
    for f in hits:
        seg = m.seg_of(f["vmaddr"])
        segname = (seg.get("name") if isinstance(seg, dict) else getattr(seg, "name", None)) or "?"
        print("  slot 0x%08x  seg=%s  kind=%s" % (f["vmaddr"], segname, f.get("kind")))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
