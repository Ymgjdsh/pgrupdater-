#!/usr/bin/env python3
"""Per-dylib import census from the .binds.json written by dylibinfo.py."""
import ast
import collections
import json
import sys


def load(path):
    d = json.load(open(path))
    per = collections.Counter()
    syms = collections.defaultdict(list)
    for k in d:
        name, lib, weak = ast.literal_eval(k)
        per[lib] += 1
        syms[lib].append((name, weak))
    return per, syms


def main(argv):
    json_path = argv[0]
    libs = json.load(open(json_path.rsplit(".binds.json", 1)[0] + ".dylibs.json")) if False else None
    per, syms = load(json_path)
    total = sum(per.values())
    print("%s: %d imports over %d dylib ordinals" % (json_path, total, len(per)))
    for lib, n in sorted(per.items()):
        print("  ord%-4s %4d imports" % (lib, n))
    if "--lib" in argv:
        want = set(int(x) for x in argv[argv.index("--lib") + 1].split(","))
        for lib in sorted(want):
            print("--- ord%s (%d imports) ---" % (lib, per.get(lib, 0)))
            for name, weak in sorted(syms[lib]):
                print("      %-55s weak=%s" % (name, weak))


if __name__ == "__main__":
    main(sys.argv[1:])
