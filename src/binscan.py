"""binscan.py <file> <needle> [--ctx N] [--utf16]

Search a (large) binary file for a UTF-8 or UTF-16LE needle and print every hit
with printable context on both sides. Read-only, memory-mapped.
"""
import sys
import mmap


def printable(b: bytes) -> str:
    out = []
    for c in b:
        out.append(chr(c) if 32 <= c < 127 else ".")
    return "".join(out)


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    path = argv[1]
    needle = argv[2].encode("utf-8")
    ctx = 64
    if "--ctx" in argv:
        ctx = int(argv[argv.index("--ctx") + 1])
    if "--utf16" in argv:
        needle = argv[2].encode("utf-16-le")
    with open(path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        total = mm.size()
        hits = []
        start = 0
        while True:
            i = mm.find(needle, start)
            if i < 0:
                break
            hits.append(i)
            start = i + 1
            if len(hits) >= 200:
                break
        print(f"{path}: {len(hits)} hit(s) for {argv[2]!r} (file size {total})")
        for off in hits:
            lo = max(0, off - ctx)
            hi = min(total, off + len(needle) + ctx)
            print(f"  @0x{off:x}")
            print(f"    {printable(mm[lo:hi])}")
        mm.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
