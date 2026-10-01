"""tmp_badlist.py <a.c> [<b.c>]

List every LOAD_BADMACHO / LOAD_BADARCH site with its enclosing function plus the
preceding ~6 code lines (the guard condition), and optionally diff the two files'
site sets semantically (normalised text, function-scoped windows).

usage: python tmp_badlist.py dyldsrc\\xnu12_mach_loader.c dyldsrc\\xnu14_mach_loader.c
"""
import re
import sys


def norm(s):
    s = re.sub(r"//.*", "", s)
    s = re.sub(r"\s+", "", s)
    return s


def funcs(lines):
    """Return list of (line_idx, name) for function definitions, crude but good."""
    out = []
    for i, l in enumerate(lines):
        m = re.match(r"^(?:static\s+)?(?:inline\s+)?[A-Za-z_][A-Za-z0-9_ \t\*]*\b([A-Za-z_][A-Za-z0-9_]*)\s*\($", l)
        if m and not l.startswith(" ") and not l.startswith("\t"):
            out.append((i, m.group(1)))
    return out


def sites(path):
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    fns = funcs(lines)
    res = []
    for i, l in enumerate(lines):
        if "LOAD_BADMACHO" in l or "LOAD_BADARCH" in l:
            name = "?"
            for j, n in fns:
                if j < i:
                    name = n
                else:
                    break
            win = lines[max(0, i - 6):i + 1]
            res.append((i + 1, name, [x.strip() for x in win]))
    return res


def main():
    a = sys.argv[1]
    sa = sites(a)
    print("=== %s : %d sites ===" % (a, len(sa)))
    for ln, fn, win in sa:
        print("%5d %-32s | %s" % (ln, fn, " ".join(w for w in win if w)[:170]))
    if len(sys.argv) > 2:
        b = sys.argv[2]
        sb = sites(b)
        print()
        print("=== %s : %d sites ===" % (b, len(sb)))
        for ln, fn, win in sb:
            print("%5d %-32s | %s" % (ln, fn, " ".join(w for w in win if w)[:170]))
        # semantic set diff: compare normalised windows keyed by function
        ka = {}
        for ln, fn, win in sa:
            ka.setdefault(fn, set()).add(norm(" ".join(win)))
        kb = {}
        for ln, fn, win in sb:
            kb.setdefault(fn, set()).add(norm(" ".join(win)))
        print()
        print("=== windows only in %s ===" % a)
        for fn in sorted(ka):
            only = ka[fn] - kb.get(fn, set())
            for w in sorted(only):
                print("  %-32s %s" % (fn, w[:160]))
        print()
        print("=== windows only in %s ===" % b)
        for fn in sorted(kb):
            only = kb[fn] - ka.get(fn, set())
            for w in sorted(only):
                print("  %-32s %s" % (fn, w[:160]))


main()
