#!/usr/bin/env python3
"""Build an RVA -> il2cpp name index from an Il2CppDumper `dump.cs`.

Il2CppDumper prints, before every method/field:

    // RVA: 0x2E4144C Offset: 0x2E4144C VA: 0x2E4144C
    public int IndexOf(string value, int startIndex) { }

The RVA equals the file offset inside `__TEXT` of the shipped `UnityFramework`
(`__TEXT` has vmaddr 0 and fileoff 0), so a crash-report `imageOffset` can be
resolved straight to a method name.

Usage:
    python rvamap.py <dump.cs> [--out index.json] [--stats]
    python rvamap.py <dump.cs> --lookup 0x2E4144C [0x... ...]
"""
import argparse
import json
import os
import re
import sys

RVA_RE = re.compile(r"//\s*RVA:\s*0x([0-9A-Fa-f]+)\s+Offset:\s*0x([0-9A-Fa-f]+)\s+VA:\s*0x([0-9A-Fa-f]+)")
TYPE_RE = re.compile(r"^\s*(?:public|private|internal|protected|sealed|abstract|static|partial|readonly|\s)*"
                     r"(class|struct|interface|enum)\s+([A-Za-z_][\w`<>,.\[\]]*)")
NS_RE = re.compile(r"^\s*//\s*Namespace:\s*(\S+)")
# declarations we do not want as the "name" of an RVA entry
SKIP_RE = re.compile(r"^\s*(//|$|\}|\{)")


def clean_decl(line):
    s = line.strip()
    if s.endswith("{"):
        s = s[:-1].strip()
    if s.endswith(";"):
        s = s[:-1].strip()
    # drop modifiers
    for mod in ("public ", "private ", "protected ", "internal ", "static ", "readonly ", "sealed ",
                "abstract ", "virtual ", "override ", "extern ", "unsafe ", "const "):
        while s.startswith(mod):
            s = s[len(mod):]
    if "(" in s:
        s = s[: s.index("(")]
    return s.strip()


def build(path):
    entries = []
    cur_type = ""
    cur_ns = ""
    pending_rva = None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = NS_RE.match(line)
            if m:
                cur_ns = m.group(1)
            m = TYPE_RE.match(line)
            if m:
                cur_type = m.group(2)
                cur_ns = ""  # namespace lines come right after the type line in dump.cs
                pending_rva = None
                continue
            m = RVA_RE.search(line)
            if m:
                pending_rva = int(m.group(1), 16)
                continue
            if pending_rva is None:
                continue
            if SKIP_RE.match(line):
                continue
            name = clean_decl(line)
            if not name:
                pending_rva = None
                continue
            full = f"{cur_type}.{name}" if cur_type else name
            entries.append((pending_rva, full))
            pending_rva = None
    entries.sort()
    return entries


def stats(entries):
    print(f"entries: {len(entries)}")
    if entries:
        print(f"min RVA: 0x{entries[0][0]:X}  max RVA: 0x{entries[-1][0]:X}")
    # duplicate RVAs (overloads share the same address rarely, but generics do)
    dupes = 0
    for i in range(1, len(entries)):
        if entries[i][0] == entries[i - 1][0]:
            dupes += 1
    print(f"duplicate-RVA entries: {dupes}")


def lookup(entries, addr):
    import bisect
    i = bisect.bisect_right(entries, (addr, "\uffff"))
    if i == 0:
        return None, None
    rva, name = entries[i - 1]
    return rva, name


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--out")
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--lookup", nargs="*", default=None)
    a = ap.parse_args()

    cache = a.out or (os.path.splitext(a.dump)[0] + ".rvamap.json")
    if os.path.exists(cache) and os.path.getmtime(cache) > os.path.getmtime(a.dump) and a.lookup is None:
        entries = [(e[0], e[1]) for e in json.load(open(cache, encoding="utf-8"))]
        print(f"loaded {len(entries)} entries from {cache}")
    else:
        entries = build(a.dump)
        with open(cache, "w", encoding="utf-8") as fh:
            json.dump(entries, fh)
        print(f"built {len(entries)} entries -> {cache}")

    if a.stats:
        stats(entries)
    if a.lookup:
        for tok in a.lookup:
            addr = int(tok, 16) if tok.lower().startswith("0x") else int(tok, 16)
            rva, name = lookup(entries, addr)
            if rva is None:
                print(f"0x{addr:X}: before the first entry")
            else:
                print(f"0x{addr:X} (= {name} + 0x{addr - rva:X})  [RVA 0x{rva:X}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
