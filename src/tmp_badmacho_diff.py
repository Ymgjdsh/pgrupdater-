"""tmp_badmacho_diff.py <old.c> <new.c> [ctx]
Report LOAD_BADMACHO (and LOAD_FAILURE-like) sites whose local code context is new in <new.c>.
Context = up to `ctx` preceding non-blank lines + the match line, whitespace-collapsed.
"""
import re, sys

old, new = sys.argv[1], sys.argv[2]
CTX = int(sys.argv[3]) if len(sys.argv) > 3 else 4
PAT = re.compile(r"LOAD_BADMACHO|LOAD_BADARCH|LOAD_FAILURE|LOAD_PROTECT|LOAD_NOSPACE")


def sites(path):
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    out = []
    for i, ln in enumerate(lines):
        if "LOAD_BADMACHO" not in ln and "LOAD_BADARCH" not in ln:
            continue
        # walk back over preceding significant lines
        ctx = []
        j = i - 1
        while j >= 0 and len(ctx) < CTX:
            s = lines[j].strip()
            if s and not s.startswith(("*", "/*", "//")):
                ctx.insert(0, re.sub(r"\s+", " ", s))
            j -= 1
        sig = " | ".join(ctx)
        out.append((i + 1, sig, lines[i].strip()))
    return out


def by_sig(sites_):
    d = {}
    for ln, sig, txt in sites_:
        d.setdefault(sig, []).append((ln, txt))
    return d


o = by_sig(sites(old))
n = by_sig(sites(new))
print(f"old sites: {sum(len(v) for v in o.values())}  unique ctx: {len(o)}")
print(f"new sites: {sum(len(v) for v in n.values())}  unique ctx: {len(n)}")
print("\n=== contexts NEW in <new> (not in <old>) ===")
for sig, v in n.items():
    if sig not in o:
        for ln, txt in v:
            print(f"  :{ln}  {txt}")
            print(f"        ctx: {sig}")
print("\n=== contexts only in <old> ===")
for sig, v in o.items():
    if sig not in n:
        for ln, txt in v:
            print(f"  :{ln}  {txt}")
            print(f"        ctx: {sig}")
