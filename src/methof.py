#!/usr/bin/env python3
"""List ObjC methods (owner, sel, imp) from a Mach-O, optionally filtered.

Usage:
    python methof.py <macho> [pattern] [--kind class|cat+|cat-|proto] [--json out]
Pattern is a case-insensitive substring matched against "owner -[sel]".
"""
import argparse
import json
import sys

from clsprobe import Img
from imp_rev import collect


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("macho")
    ap.add_argument("pattern", nargs="?", default="")
    ap.add_argument("--kind", default=None)
    ap.add_argument("--json", default=None)
    ap.add_argument("--sort", default="imp", choices=["imp", "name"])
    a = ap.parse_args()

    im = Img(a.macho)
    rows = collect(im)
    pat = a.pattern.lower()
    sel = []
    for imp, kind, owner, s, t, eo in rows:
        if a.kind and kind != a.kind:
            continue
        label = f"{owner} -[{s}]"
        if pat and pat not in label.lower():
            continue
        sel.append((imp, kind, owner, s, t))
    if a.sort == "imp":
        sel.sort()
    else:
        sel.sort(key=lambda r: r[3] or "")
    for imp, kind, owner, s, t in sel:
        print(f"0x{imp:08X}  {kind:5s} {owner}  -[{s}]")
    print(f"# {len(sel)} match(es) of {len(rows)} methods in {a.macho}")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump([dict(imp=imp, kind=k, owner=o, sel=s) for imp, k, o, s, t in sel], fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
