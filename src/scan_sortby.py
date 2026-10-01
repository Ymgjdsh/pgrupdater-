"""Scan both Phigros IPAs (entry by entry, streaming) for marker strings.

Markers tell us which build/data a run used:
  SortBySongBase  -> 4.0.0-only class (absent from 3.19.0 metadata)
  UnitySubsystems -> the Data/UnitySubsystems manifest 4.0.0 has (3.19.0 log lacks the
                     "[Subsystems] Discovering subsystems at path" line)
  OrientationManager / NotifyEventListener -> game scripts that printed in the Sep 30 log
Usage: python scan_sortby.py <ipa> [<ipa> ...]
"""
import sys, zipfile, io

MARKERS = [b"SortBySongBase", b"UnitySubsystems", b"OrientationManager",
           b"NotifyEventListener", b"GameInformation"]

def scan(path):
    print("=" * 70)
    print("IPA:", path)
    zf = zipfile.ZipFile(path)
    names = zf.namelist()
    print("entries:", len(names))
    hits = {m: [] for m in MARKERS}
    total = 0
    for i, n in enumerate(names):
        try:
            info = zf.getinfo(n)
        except KeyError:
            continue
        if info.file_size < 16:
            continue
        total += info.file_size
        try:
            with zf.open(n) as fh:
                counts = {m: 0 for m in MARKERS}
                first = {m: None for m in MARKERS}
                off = 0
                tail = b""
                while True:
                    chunk = fh.read(4 << 20)
                    if not chunk:
                        break
                    buf = tail + chunk
                    base = off - len(tail)
                    for m in MARKERS:
                        start = 0
                        while True:
                            j = buf.find(m, start)
                            if j < 0:
                                break
                            counts[m] += 1
                            if first[m] is None:
                                first[m] = base + j
                            start = j + 1
                    off += len(chunk)
                    tail = buf[-64:]
        except Exception as exc:                      # noqa: BLE001
            print("  !! %s: %s" % (n, exc))
            continue
        for m in MARKERS:
            if counts[m]:
                hits[m].append((n, counts[m], first[m]))
        if (i + 1) % 200 == 0:
            print("  ... %d/%d entries, %d MB scanned" % (i + 1, len(names), total >> 20))
    print("uncompressed bytes scanned: %d (%.1f GB)" % (total, total / 2**30))
    for m in MARKERS:
        print("- %s: %d entries" % (m.decode(), len(hits[m])))
        for n, c, fo in sorted(hits[m], key=lambda t: -t[1])[:12]:
            print("    %7d  first@0x%x  %s" % (c, fo, n))
    zf.close()

if __name__ == "__main__":
    for p in sys.argv[1:]:
        scan(p)
