#!/usr/bin/env python3
"""Relocate the classic LC_DYLD_INFO streams of a converted Mach-O to the front of
__LINKEDIT and repack LC_CODE_SIGNATURE so the image matches the layout that
Apple's ld64/codesign_allocate produce -- the layout of the working 3.19.0
reference (work319/Phigros): streams at __LINKEDIT+0, then function_starts,
symtab, strtab, then the signature covering everything to the end of __LINKEDIT.

Only LC_DYLD_INFO offset/size fields, the stream bytes and the LC_CODE_SIGNATURE
dataoff/datasize change.  No load command is added, removed or resized; segment
geometry and file size are untouched.

usage: relocate_streams.py <in> <out> [--dry-run] [--require-zero]
"""
import struct, sys

SEG = 0x19
SYMTAB = 0x2
DYSYMTAB = 0xb
CODESIG = 0x1d
DYLDINFO = (0x22, 0x80000022)
SIZED = {0x1e, 0x26, 0x29, 0x2b, 0x2e, 0x31, 0x80000033, 0x80000034}
STREAMS = ("rebase", "bind", "weak_bind", "lazy_bind", "export")


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def w32(b, o, v):
    struct.pack_into("<I", b, o, v)


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def al8(x):
    return (x + 7) & ~7


def analyze(b):
    ncmds = u32(b, 16)
    so = 32
    L = Sz = None
    regs = []      # (off,size,name) of everything that must stay put or is data
    dyname = {}    # name -> (cmd_off + field offset of off, + of size)
    code = None
    for _ in range(ncmds):
        cmd = u32(b, so)
        cs = u32(b, so + 4)
        if cmd == SEG:
            if b[so + 8:so + 24].split(b"\0")[0] == b"__LINKEDIT":
                L = u64(b, so + 40)
                Sz = u64(b, so + 48)
        elif cmd in DYLDINFO:
            for k, nm in enumerate(STREAMS):
                o = u32(b, so + 8 + 8 * k)
                s = u32(b, so + 12 + 8 * k)
                dyname[nm] = (so + 8 + 8 * k, so + 12 + 8 * k)
                if s:
                    regs.append((o, s, "stream:" + nm))
        elif cmd == SYMTAB:
            sy, ns, st, ss = u32(b, so + 8), u32(b, so + 12), u32(b, so + 16), u32(b, so + 20)
            if ns:
                regs.append((sy, ns * 16, "symtab"))
            if ss:
                regs.append((st, ss, "strtab"))
        elif cmd in SIZED:
            o, s = u32(b, so + 8), u32(b, so + 12)
            if s:
                regs.append((o, s, "lc%x" % cmd))
        elif cmd == DYSYMTAB:
            # (field offset, element size or 0 when unknown) -- treat unknown as a
            # 4-byte marker so we never drop a stream on top of a real table
            for nm, o, el in (("toc", 8, 8), ("modtab", 24, 4), ("extref", 32, 4),
                              ("indirectsym", 56, 4), ("extrel", 40, 4), ("locrel", 48, 4)):
                v = u32(b, so + o)
                if v:
                    regs.append((v, el, "dysym:" + nm))
        elif cmd == CODESIG:
            code = so
        so += cs
    return dict(L=L, Sz=Sz, regs=regs, dyname=dyname, code=code, file=len(b))


def find_gap(blockers, lo, hi, need):
    """lowest offset in [lo,hi) with need bytes of room that no live region claims.
    The bytes themselves may be non-zero: anything inside __LINKEDIT that no load
    command points at is dead (e.g. the chained-fixups payload whose command the
    converter dropped), so overwriting it is safe."""
    cur = lo
    for o, e in sorted(blockers):
        if o > cur and o - cur >= need:
            return cur
        cur = max(cur, e)
    if hi - cur >= need:
        return cur
    return None


def main():
    argv = sys.argv[1:]
    flags = {a for a in argv if a.startswith("--")}
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 2:
        print(__doc__)
        return 2
    src, dst = args
    b = bytearray(open(src, "rb").read())
    a = analyze(bytes(b))
    L, Sz, regs, code = a["L"], a["Sz"], a["regs"], a["code"]
    if L is None or code is None or not a["dyname"]:
        print("ERROR: need __LINKEDIT + LC_DYLD_INFO(_ONLY) + LC_CODE_SIGNATURE")
        return 1
    streams = [r for r in regs if r[2].startswith("stream:")]
    streams.sort(key=lambda r: STREAMS.index(r[2].split(":")[1]))
    blobs = {r[2]: bytes(b[r[0]:r[0] + r[1]]) for r in streams}
    need = sum(al8(r[1]) for r in streams)
    lo, hi = L, min(len(b), L + Sz)
    print("source       %s  %d B" % (src, len(b)))
    print("__LINKEDIT   fileoff %#x filesize %#x  search [%#x,%#x)" % (L, Sz, lo, hi))
    print("old streams  " + ", ".join("%s@%#x+%#x" % (r[2].split(":")[1], r[0], r[1]) for r in streams))
    print("need         %#x B" % need)
    if not streams:
        print("ERROR: no non-empty dyld info stream")
        return 1
    blockers = [(r[0], r[0] + r[1]) for r in regs if not r[2].startswith("stream:")]
    tgt = find_gap(blockers, lo, hi, need)
    if tgt is None:
        print("ERROR: no free run of %#x B inside __LINKEDIT" % need)
        return 1
    oldfront = min(r[0] for r in streams)
    print("target       %#x" % tgt)
    if tgt == oldfront:
        print("already at the front of __LINKEDIT -- nothing to do")
        return 0
    dirty = sum(1 for x in b[tgt:tgt + need] if x)
    if dirty:
        if "--require-zero" in flags:
            print("ERROR: target holds %d non-zero bytes (dead space) and --require-zero was given" % dirty)
            return 1
        print("note         overwriting %d non-zero bytes of dead space at %#x "
              "(no load command points there)" % (dirty, tgt))
    old = {nm: o for nm, (o, _) in ((r[2], (r[0], r[1])) for r in streams)}
    cur = tgt
    placed = []
    for r in streams:                                   # compute every new offset first
        nm, s = r[2], r[1]
        fo = a["dyname"][r[2].split(":")[1]][0]
        w32(b, fo, cur)
        placed.append((cur, s, r[2]))
        cur = al8(cur + s)
    for _, s, nm in placed:                             # then copy the bytes
        nfo = a["dyname"][nm.split(":")[1]][0]
        off = u32(b, nfo)
        b[off:off + s] = blobs[nm]
    for nm, o in old.items():                           # vacate the old home
        b[o:o + len(blobs[nm])] = bytes(len(blobs[nm]))
    tail = al8(tgt + need)                              # clear the rest of the dead run
    nxt = min([o for o, e in blockers if o >= tail] or [hi])
    if nxt > tail:
        b[tail:nxt] = bytes(nxt - tail)
    finals = [(r[0], r[0] + r[1]) for r in regs if not r[2].startswith("stream:")]
    finals += [(o, o + s) for o, s, _ in placed]
    end = al8(max(e for _, e in finals))
    if not (L <= end < hi):
        print("ERROR: computed content end %#x outside __LINKEDIT" % end)
        return 1
    w32(b, code + 8, end)
    w32(b, code + 12, hi - end)
    print("placement    " + ", ".join("%s@%#x+%#x" % (nm.split(":")[1], o, s) for o, s, nm in placed))
    print("codesig      dataoff %#x datasize %#x  (content end %#x, linkedit end %#x)"
          % (end, hi - end, end, hi))
    if "--dry-run" not in flags:
        open(dst, "wb").write(bytes(b))
        c = analyze(bytes(b))
        chk = {r[2]: bytes(b[r[0]:r[0] + r[1]]) for r in c["regs"] if r[2].startswith("stream:")}
        ok = all(chk.get(k) == v for k, v in blobs.items())
        cd = u32(b, c["code"] + 8), u32(b, c["code"] + 12)
        print("wrote        %s  %d B   self-check streams==%s codesig=%#x/%#x"
              % (dst, len(b), ok, cd[0], cd[1]))
        return 0 if ok else 1
    print("dry run -- nothing written")
    return 0


sys.exit(main())
