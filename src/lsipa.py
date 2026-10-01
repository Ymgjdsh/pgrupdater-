"""lsipa.py <ipa> [--frameworks] [--scan NEEDLE]

List IPA entries (optionally just Frameworks) and/or stream-scan selected
entries for a byte needle. Read-only.
"""
import sys
import zipfile


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    ipa = argv[1]
    scan = None
    if "--scan" in argv:
        scan = argv[argv.index("--scan") + 1].encode("utf-8")
    fw_only = "--frameworks" in argv
    with zipfile.ZipFile(ipa) as z:
        names = z.namelist()
        if fw_only:
            fw = sorted({n.split("/Frameworks/", 1)[1].split("/", 1)[0]
                         for n in names if "/Frameworks/" in n})
            print(f"{ipa}: {len(names)} entries, {len(fw)} frameworks")
            for f in fw:
                print("  ", f)
        else:
            print(f"{ipa}: {len(names)} entries")
            for n in names:
                if "Payload/Phigros.app/" in n and n.count("/") <= 3:
                    print("  ", n)
        if scan:
            print(f"-- scanning Frameworks members for {scan!r}")
            for n in names:
                if "/Frameworks/" not in n:
                    continue
                if n.endswith("/"):
                    continue
                if "/" in n.split("/Frameworks/", 1)[1]:
                    # nested file inside a framework bundle: only look at the binary itself
                    tail = n.split("/Frameworks/", 1)[1]
                    if tail.count("/") != 1:
                        continue
                data = z.read(n)
                if scan in data:
                    off = data.find(scan)
                    print(f"  HIT {n} (size {len(data)}) @0x{off:x}")
                    lo = max(0, off - 64)
                    hi = min(len(data), off + len(scan) + 64)
                    print("    ", "".join(chr(c) if 32 <= c < 127 else "." for c in data[lo:hi]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
