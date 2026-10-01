#!/usr/bin/env python3
"""Extract thread stacks from legacy-text .ips reports and compare them.

Usage:
    python thrcmp.py <report.ips> [<report.ips> ...] [--thread N] [--all]

Frame lines look like:
    0   UnityFramework   0x000000010289a700 0x102000000 + 9021184
The third column is the slid address; the fourth the image base, so the
unslid image offset is addr - base (this is what lbl.py wants).
"""
import re
import sys

FRAME_RE = re.compile(
    r"^\s*(\d+)\s+(\S+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s*\+\s*(\d+)\s*$"
)
NAME_RE = re.compile(r"^Thread (\d+) name:\s*(.+?)\s*$")
HEAD_RE = re.compile(r"^Thread (\d+)(?:\s+Crashed)?:\s*$")


def parse(path):
    """-> dict(thread_index -> dict(name=str, frames=[(idx, module, va, base_off)]))"""
    out = {}
    cur = None
    for line in open(path, "r", encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        m = NAME_RE.match(line)
        if m:
            cur = int(m.group(1))
            out.setdefault(cur, {"name": m.group(2), "frames": []})["name"] = m.group(2)
            continue
        m = HEAD_RE.match(line)
        if m:
            cur = int(m.group(1))
            out.setdefault(cur, {"name": "", "frames": []})
            continue
        m = FRAME_RE.match(line)
        if m and cur is not None:
            idx = int(m.group(1))
            module = m.group(2)
            va = int(m.group(3), 16)
            base = int(m.group(4), 16)
            out[cur]["frames"].append((idx, module, va - base))
            continue
        if line.startswith("Thread State:") or line.startswith("Binary Images"):
            cur = None
    return out


def show(threads, want):
    for i in sorted(threads):
        if want is not None and i != want:
            continue
        t = threads[i]
        print(f"--- Thread {i} {t['name']}")
        for idx, module, off in t["frames"]:
            print(f"   {idx:3d} {module:24s} +0x{off:08X}")


def main(argv):
    want = None
    paths = []
    for a in argv:
        if a == "--all":
            want = "all"
        elif a.startswith("--thread"):
            want = int(a.split("=", 1)[1]) if "=" in a else None
        else:
            paths.append(a)
    if not paths:
        print(__doc__)
        return 2
    parsed = [(p, parse(p)) for p in paths]
    for p, t in parsed:
        print(f"===== {p}")
        if want == "all":
            show(t, None)
        else:
            show(t, want if want is not None else 0)
    if len(parsed) > 1:
        print("===== diff of thread 0 offsets")
        base = parsed[0][1]
        for p, t in parsed[1:]:
            b = base.get(0, {}).get("frames", [])
            o = t.get(0, {}).get("frames", [])
            print(f"  {parsed[0][0]} vs {p}: {len(b)} vs {len(o)} frames", end="")
            diffs = [i for i in range(min(len(b), len(o))) if b[i][2] != o[i][2]]
            print(f", differing frame indices: {diffs[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
