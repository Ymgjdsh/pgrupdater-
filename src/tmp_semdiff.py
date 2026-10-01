"""tmp_semdiff.py <old.c> <new.c> -- whitespace-insensitive multiset line diff (only code-ish lines)."""
import re, sys
from collections import Counter

old, new = sys.argv[1], sys.argv[2]


def norm(l):
    s = re.sub(r"\s+", "", l)
    while s.endswith("{"):
        s = s[:-1]
    return s


def load(p):
    out = []
    for i, l in enumerate(open(p, encoding="utf-8", errors="replace").read().splitlines(), 1):
        t = l.strip()
        if not t or t.startswith(("*", "/*", "//", "#")):
            continue
        out.append((i, t, norm(t)))
    return out


O, N = load(old), load(new)
oc, nc = Counter(x[2] for x in O), Counter(x[2] for x in N)
extra = nc - oc
print(f"old lines {len(O)}  new lines {len(N)}  distinctive new lines {sum(extra.values())}")
print("\n=== code lines only in NEW (deduped, source order) ===")
seen = set()
for i, t, n in N:
    if n in extra and n not in seen:
        seen.add(n)
        print(f"  :{i}  {t}")
