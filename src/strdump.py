#!/usr/bin/env python3
"""strdump.py <macho> <start-va> <len> -- print NUL-separated C strings with addresses."""
import sys

import chained2dyld as C


def main(argv):
    if len(argv) != 4:
        print(__doc__)
        return 2
    path, va, n = argv[1], int(argv[2], 0), int(argv[3], 0)
    m = C.MachO(open(path, "rb").read())
    fo = m.foff(va)
    blob = bytes(m.buf[fo:fo + n])
    base, cur = va, b""
    for i, b in enumerate(blob):
        if b == 0:
            if cur:
                print("0x%08x  %s" % (base, cur.decode("utf-8", "replace")))
            base = va + i + 1
            cur = b""
        else:
            cur += bytes([b])
    if cur:
        print("0x%08x  %s  (unterminated)" % (base, cur.decode("utf-8", "replace")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
