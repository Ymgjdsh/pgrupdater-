#!/usr/bin/env python3
"""Decode the dyld-3 export trie of a converted binary and compare it with the original
image's trie, proving the relocated copy still resolves every symbol.

    python verify_export.py <pristine macho> <converted macho> [symbol ...]
"""
import struct
import sys

LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_EXPORTS_TRIE = 0x80000033

FLAGS = {
    0x00: "REGULAR", 0x01: "WEAK_DEFINITION", 0x02: "THREAD_LOCAL", 0x03: "ABSOLUTE",
    0x04: "REEXPORT", 0x08: "STUB_AND_RESOLVER", 0x10: "WEAK_LOOKUP",
}


def uleb(b, i):
    r = s = 0
    while True:
        v = b[i]; i += 1
        r |= (v & 0x7F) << s
        if not (v & 0x80):
            return r, i
        s += 7


def cmds(b):
    ncmds, = struct.unpack_from("<I", b, 16)
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", b, off)
        yield cmd, cmdsize, off
        off += cmdsize


def trie_region(b):
    for cmd, cmdsize, off in cmds(b):
        if cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            f = struct.unpack_from("<10I", b, off + 8)
            return f[8], f[9], "LC_DYLD_INFO(.export)"
        if cmd == LC_DYLD_EXPORTS_TRIE:
            o, s = struct.unpack_from("<II", b, off + 8)
            return o, s, "LC_DYLD_EXPORTS_TRIE"
    raise SystemExit("no export trie command")


def walk(trie):
    """Return {name: (flags, addr_or_reexport)} from a dyld-3 export trie blob."""
    out = {}
    seen = set()

    def descend(node, prefix):
        if node in seen:
            return
        seen.add(node)
        i = node
        terminal, i = uleb(trie, i)
        end = i + terminal
        if terminal:
            flags, j = uleb(trie, i)
            if flags & 0x04:                       # REEXPORT
                _ord, j = uleb(trie, j)
                e = trie.index(b"\0", j)
                out[prefix] = ("REEXPORT->" + trie[j:e].decode(), None)
            else:
                addr, j = uleb(trie, j)
                out[prefix] = (FLAGS.get(flags, hex(flags)), addr)
        i = end
        nchild, i = uleb(trie, i)
        for _ in range(nchild):
            e = trie.index(b"\0", i)
            edge = trie[i:e].decode()
            child, i = uleb(trie, e + 1)
            descend(child, prefix + edge)

    descend(0, "")
    return out


def main(pristine, converted, want):
    grep = None
    if want and want[0] == "--grep":
        grep, want = want[1], []
    a = open(pristine, "rb").read()
    b = open(converted, "rb").read()
    ao, asz, ahow = trie_region(a)
    bo, bsz, bhow = trie_region(b)
    print(f"pristine  {pristine}: {ahow} off=0x{ao:X} size={asz}")
    print(f"converted {converted}: {bhow} off=0x{bo:X} size={bsz}")
    ta, tb = a[ao:ao + asz], b[bo:bo + bsz]
    print(f"  byte-identical trie payload: {ta == tb}")
    ea, eb = walk(ta), walk(tb)
    print(f"  exported symbols: pristine={len(ea)} converted={len(eb)} identical={ea == eb}")
    bad = [n for n in ea if ea[n] != eb.get(n)]
    if bad:
        print(f"  MISMATCHED: {bad[:10]}")
    if grep:
        hits = [n for n in sorted(ea) if grep.lower() in n.lower()]
        print(f"  names matching {grep!r} ({len(hits)}): {hits[:25]}")
    for s in want:
        print(f"  {s!r}: pristine={ea.get(s)} converted={eb.get(s)}")
    ok = (ta == tb) and (ea == eb) and all(s in eb for s in want)
    print("PASS: relocated export trie resolves the same symbols" if ok
          else "FAIL: export trie differs")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3:]))
