#!/usr/bin/env python3
"""impscan.py <binds.json> <substr> [substr ...]

Print the import entries whose symbol name contains any of the given
substrings, with the dylib they bind to.  The json is the one written by
dylibinfo.py.  Accepts either the {name: ...} dict form or the list form.
"""
import json
import sys


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    data = json.load(open(argv[1], "r", encoding="utf-8"))
    pats = argv[2:]
    entries = []
    if isinstance(data, dict):
        for key, val in data.items():
            entries.append((key, val))
    else:
        for e in data:
            entries.append((e.get("name", ""), e))
    hits = []
    for key, val in entries:
        if any(p.lower() in key.lower() for p in pats):
            hits.append((key, val))
    for key, val in sorted(hits):
        if isinstance(val, dict):
            lib = val.get("lib")
            weak = val.get("weak")
        else:
            lib, weak = val, None
        print("%-60s lib=%-4s weak=%s" % (key, lib, weak))
    print("%d hit(s) for %s" % (len(hits), pats))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
