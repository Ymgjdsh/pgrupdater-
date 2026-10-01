#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Walk the classic bind / weak-bind streams of a converted Mach-O and report linkage.

Usage: python bindscan.py <macho> [symbol ...]

Prints counts, the dylib ordinal histogram, and (given symbol names) whether each
symbol is bound strongly or weakly - which decides whether a missing iOS 12 symbol
causes a dyld abort at launch or merely a NULL value.
"""
import struct
import sys

SEG64 = 0x19
DYLD_INFO = 0x80000022


def parse(path):
    buf = open(path, "rb").read()
    magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from("<8I", buf, 0)
    off = 32
    segs = []
    info = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmd == SEG64:
            segname = buf[off + 8:off + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", buf, off + 24)
            segs.append((segname, vmaddr, vmsize, fileoff, filesize))
        elif cmd in (0x22, 0x23, DYLD_INFO):
            info = struct.unpack_from("<10I", buf, off + 8)
        off += cmdsize
    return buf, segs, info


def uleb(b, i):
    r = 0
    s = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7F) << s
        if not (x & 0x80):
            return r, i
        s += 7


def sleb(b, i):
    r = 0
    s = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7F) << s
        s += 7
        if not (x & 0x80):
            if x & 0x40:
                r |= -(1 << s)
            return r, i


def walk_bind(buf, base, size, weak):
    b = buf[base:base + size]
    seg_idx = 0
    seg_off = 0
    ordinal = 0
    sym = None
    flags = 0
    addend = 0
    out = []
    i = 0
    done = False
    while i < len(b) and not done:
        op = b[i] & 0xF0
        imm = b[i] & 0x0F
        i += 1
        if op == 0x00:  # DONE
            done = True
        elif op == 0x10:
            ordinal = imm
        elif op == 0x20:
            ordinal, i = uleb(b, i)
        elif op == 0x30:
            ordinal = imm | (-16 if imm else 0) if imm & 0x8 else imm
            if imm & 0x8:
                ordinal = imm - 16
        elif op == 0x40:
            end = b.index(b"\0", i)
            sym = b[i:end].decode(errors="replace")
            flags = imm
            i = end + 1
        elif op == 0x50:
            pass
        elif op == 0x60:
            addend, i = sleb(b, i)
        elif op == 0x70:
            seg_idx = imm
            seg_off, i = uleb(b, i)
        elif op == 0x80:
            v, i = uleb(b, i)
            seg_off += v
        elif op in (0x90, 0xA0, 0xB0, 0xC0):
            cnt = 1
            skip = 0
            if op == 0xA0:
                v, i = uleb(b, i)
                skip = v
            elif op == 0xB0:
                skip = imm * 8
            elif op == 0xC0:
                cnt, i = uleb(b, i)
                sk, i = uleb(b, i)
                skip = sk
            for k in range(cnt):
                segname = segs[seg_idx][0] if seg_idx < len(segs) else "?seg%d" % seg_idx
                addr = (segs[seg_idx][1] if seg_idx < len(segs) else 0) + seg_off
                out.append((sym, ordinal, weak or bool(flags & 0x1), segname, addr, addend))
                seg_off += skip if cnt > 1 else 0
            if op == 0x90:
                seg_off += 0
            elif op == 0xA0:
                seg_off += skip
            elif op == 0xB0:
                seg_off += skip
            elif op == 0xC0:
                seg_off += cnt * skip
        elif op == 0xD0:
            pass
        else:
            raise ValueError("unknown bind opcode 0x%02x at %d" % (b[i - 1], i - 1))
    return out, i, len(b)


if __name__ == "__main__":
    path = sys.argv[1]
    want = set(sys.argv[2:])
    buf, segs, info = parse(path)
    if info is None:
        raise SystemExit("no LC_DYLD_INFO(_ONLY)")
    r_off, r_sz, b_off, b_sz, wb_off, wb_sz, ly_off, ly_sz, ex_off, ex_sz = info
    print("segments: %s" % [s[0] for s in segs])
    print("bind stream   off=0x%x size=%d" % (b_off, b_sz))
    print("weak stream   off=0x%x size=%d" % (wb_off, wb_sz))
    from collections import Counter
    entries, ci, cl = walk_bind(buf, b_off, b_sz, weak=False)
    print("bind stream entries: %d  (consumed %d of %d bytes)" % (len(entries), ci, cl))
    # A regular bind stream may still carry BIND_SYMBOL_FLAGS_WEAK_IMPORT (0x1) per entry.
    flagged_strong = [e for e in entries if not e[2]]
    flagged_weak = [e for e in entries if e[2]]
    print("   of which weak-flagged (BIND_SYMBOL_FLAGS_WEAK_IMPORT): %d" % len(flagged_weak))
    print("   truly strong binds: %d" % len(flagged_strong))
    wb_entries = []
    if wb_sz:
        wb_entries, wi, wl = walk_bind(buf, wb_off, wb_sz, weak=True)
        print("weak_bind stream: %d entries  (consumed %d of %d bytes)" % (len(wb_entries), wi, wl))
    else:
        print("weak_bind stream: empty (off=0x0 size=0)")
    print("strong ordinal histogram: %s" % sorted(Counter(o for _, o, _, _, _, _ in entries).items()))
    if wb_entries:
        print("weak_bind ordinal histogram: %s" % sorted(Counter(o for _, o, _, _, _, _ in wb_entries).items()))
    # per-symbol: how many slots are strongly bound vs weakly bound
    st, wk = {}, {}
    for s, o, w, seg, addr, ad in entries:
        (wk if w else st).setdefault(s, []).append((o, seg, addr))
    for s, o, w, seg, addr, ad in wb_entries:
        wk.setdefault(s, []).append((o, seg, addr))
    print("distinct strongly-bound symbols: %d   distinct weakly-bound symbols: %d" % (len(st), len(wk)))
    if want:
        print("\nper-symbol linkage:")
        for s in sorted(want):
            a = st.get(s)
            c = wk.get(s)
            print("   %-40s STRONG=%s WEAK=%s" % (s, ("%d slot(s) ord=%s" % (len(a), sorted({x[0] for x in a}))) if a else "-",
                                                  ("%d slot(s) ord=%s" % (len(c), sorted({x[0] for x in c}))) if c else "-"))
    overlap = set(st) & set(wk)
    print("\nsymbols bound BOTH strongly and weakly: %d %s" % (len(overlap), sorted(overlap)[:10]))
    print("\nsample strongly-bound symbols: %s" % sorted(st)[:10])
    print("sample weakly-bound symbols:   %s" % sorted(wk)[:10])
    out = open(path + ".binds.txt", "w", encoding="utf-8")
    for s in sorted(st):
        out.write("STRONG %s %s\n" % (s, sorted({x[0] for x in st[s]})))
    for s in sorted(wk):
        out.write("WEAK   %s %s\n" % (s, sorted({x[0] for x in wk[s]})))
    out.close()
    print("\nfull per-symbol list written to %s" % (path + ".binds.txt"))
