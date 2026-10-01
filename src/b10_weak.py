#!/usr/bin/env python3
# Focused check: does the classic bind stream bind each slot to the SAME symbol, dylib ordinal
# and weak/strong disposition as the pristine chained-fixups bind for that slot?
import struct, collections

FW_PRISTINE = r"H:/file/phi/work/UnityFramework"
FW_PATCHED = r"H:/file/phi/out/UnityFramework.v4"
APP_PRISTINE = r"H:/file/phi/work/Phigros.main"
APP_PATCHED = r"H:/file/phi/out/Phigros.v4"


def rd(b, o, f):
    return struct.unpack_from(f, b, o)


class MO:
    def __init__(self, b):
        self.b = b
        m = rd(b, 0, "<I")[0]
        assert m in (0xfeedfacf, 0xfeedface), hex(m)
        self.ncmds = rd(b, 16, "<I")[0]
        self.cmds = []
        o = 32
        for _ in range(self.ncmds):
            c, cs = rd(b, o, "<II")
            self.cmds.append((c, cs, o))
            o += cs
        self.segs = []
        for c, cs, o in self.cmds:
            if c == 0x19:
                nm = b[o + 8:o + 24].split(b"\0")[0].decode()
                va, vs, fo, fs = rd(b, o + 24, "<QQQQ")
                self.segs.append(dict(name=nm, vmaddr=va, vmsize=vs, fileoff=fo, filesize=fs))
        self.chained = None
        self.info = None
        self.symtab = None
        for c, cs, o in self.cmds:
            if c == 0x80000034:
                self.chained = rd(b, o + 8, "<IIII")
            elif c == 0x80000022:
                self.info = rd(b, o + 8, "<12I")
            elif c == 0x2:
                self.symtab = rd(b, o + 8, "<IIII")

    def sym_name(self, idx):
        symoff, nsyms, stroff, strsize = self.symtab
        n_strx = rd(self.b, symoff + 16 * idx, "<I")[0]
        e = self.b.find(b"\0", stroff + n_strx)
        return self.b[stroff + n_strx:e].decode("utf-8", "replace")


def decode_chained(m):
    """returns (imports, binds) ; binds = list of dict(loc, ordinal, name, weak)"""
    base, size = m.chained[0], m.chained[1]
    h = rd(m.b, base, "<IIIII")
    version, starts, imports_off, symbols_off, imports_count = h
    imports_format, sym_format = rd(m.b, base + 20, "<II")
    print("  chained header @0x%x version=%d starts=0x%x imports=0x%x symbols=0x%x count=%d fmt=%d symfmt=%d"
          % (base, version, starts, imports_off, symbols_off, imports_count, imports_format, sym_format))
    assert imports_format == 1, "only DYLD_CHAINED_IMPORT"
    imports = []
    for i in range(imports_count):
        v = rd(m.b, base + imports_off + 4 * i, "<I")[0]
        lib_ord = v & 0xFF
        weak = (v >> 8) & 1
        noff = v >> 9
        e = m.b.find(b"\0", base + symbols_off + noff)
        nm = m.b[base + symbols_off + noff:e].decode("utf-8", "replace")
        imports.append(dict(ord=lib_ord, weak=weak, name=nm))
    seg_count = rd(m.b, base + starts, "<I")[0]
    print("  starts_in_image seg_count=%d" % seg_count)
    binds = []
    for si in range(seg_count):
        so = rd(m.b, base + starts + 4 + 4 * si, "<I")[0]
        if so == 0:
            continue
        sz, page_size, ptr_fmt, seg_off, max_valid, page_count = rd(m.b, base + starts + so, "<IHH Q I H")
        # note: struct is size(u32) page_size(u16) pointer_format(u16) segment_offset(u64) max_valid(u32) page_count(u16)
        starts_off = base + starts + so + 22
        start_arr = rd(m.b, starts_off, "<%dH" % page_count)
        seg = [s for s in m.segs if s["vmaddr"] == seg_off]
        segname = seg[0]["name"] if seg else "?"
        ncd = 0
        for pg in range(page_count):
            ps = start_arr[pg]
            if ps == 0xFFFF:
                continue
            offs = []
            if ps & 0x8000:
                j = starts_off + 2 * page_count + 2 * (ps & 0x7FFF)
                cnt = rd(m.b, j, "<H")[0]
                offs = list(rd(m.b, j + 2, "<%dH" % cnt))
            else:
                offs = [ps]
            for o0 in offs:
                loc = seg_off + pg * page_size + o0
                fo = loc  # vmaddr==fileoff in this binary
                raw = rd(m.b, fo, "<Q")[0]
                nxt = (raw >> 51) & 0xFFF
                guard = 0
                while True:
                    is_bind = (raw >> 63) & 1
                    if ptr_fmt in (2, 6):
                        if is_bind:
                            ordn = raw & 0xFFFFFF
                            addend = (raw >> 24) & 0xFF
                            nm = imports[ordn - 1]["name"] if 1 <= ordn <= len(imports) else "<ord %d>" % ordn
                            binds.append(dict(loc=loc, ord=ordn, name=nm, addend=addend,
                                              weak=imports[ordn - 1]["weak"] if 1 <= ordn <= len(imports) else -1))
                        else:
                            pass
                    if nxt == 0:
                        break
                    loc += nxt * 4
                    raw = rd(m.b, loc, "<Q")[0]
                    nxt = (raw >> 51) & 0xFFF
                    guard += 1
                    if guard > 100000:
                        raise RuntimeError("chain runaway")
                ncd += 1
        print("    seg[%d] %-12s ptr_fmt=%d seg_off=0x%x pages=%d chains=%d" % (si, segname, ptr_fmt, seg_off, page_count, ncd))
    return imports, binds


def decode_classic_bind(m):
    """walk LC_DYLD_INFO_ONLY weak_bind and bind streams; return list of dict(loc, ord, name, weak)"""
    f = m.info
    # 10 fields: rebase_off, rebase_size, bind_off, bind_size, weak_bind_off, weak_bind_size,
    #           lazy_bind_off, lazy_bind_size, export_off, export_size
    reb_off, reb_sz, bind_off, bind_sz, wb_off, wb_sz, lb_off, lb_sz, exp_off, exp_sz = f[:10]
    print("  LC_DYLD_INFO_ONLY rebase=0x%x/%d bind=0x%x/%d weak=0x%x/%d lazy=0x%x/%d export=0x%x/%d"
          % (reb_off, reb_sz, bind_off, bind_sz, wb_off, wb_sz, lb_off, lb_sz, exp_off, exp_sz))
    symoff, nsyms, stroff, strsize = m.symtab
    # map symbol name -> symtab index (undefined ones)
    name2idx = {}
    for i in range(nsyms):
        n_type = rd(m.b, symoff + 16 * i + 4, "<B")[0]
        if n_type & 0x0e:
            continue
        nm = m.sym_name(i)
        name2idx.setdefault(nm, i)

    def walk(off, size, label):
        seg_idx = None
        seg_off = 0
        sym = None
        sym_flags = 0
        ordn = None
        typ = None
        addend = 0
        out = []
        p = off
        end = off + size
        segs = m.segs

        def L():
            return (segs[seg_idx]["vmaddr"] if seg_idx is not None else 0) + seg_off

        def rec():
            return dict(loc=L(), ord=ordn, name=sym, flags=sym_flags, addend=addend)
        while p < end:
            b0 = m.b[p]
            op, imm = b0 & 0xF0, b0 & 0x0F
            p += 1
            if op == 0x00:
                print("    %s: DONE at 0x%x (consumed %d/%d)" % (label, p, p - off, size))
                return out
            elif op == 0x10:
                ordn = imm if imm != 0 else None
            elif op == 0x20:
                ordn, p = uleb(m.b, p)
            elif op == 0x30:
                ordn = 0 if imm == 0 else (imm | 0xFFFFFFF0) - 0x100000000
            elif op == 0x40:
                sym_flags = imm
                e = m.b.find(b"\0", p, end)
                sym = m.b[p:e].decode("utf-8", "replace")
                p = e + 1
            elif op == 0x50:
                typ = imm
            elif op == 0x60:
                addend, p = sleb(m.b, p)
            elif op == 0x70:
                seg_idx = imm
                seg_off, p = uleb(m.b, p)
            elif op == 0x80:
                d, p = uleb(m.b, p)
                seg_off += d
            elif op == 0x90:
                out.append(rec())
            elif op == 0xA0:
                out.append(rec())
                d, p = uleb(m.b, p)
                seg_off += d
            elif op == 0xB0:
                out.append(rec())
                seg_off += imm * 8
            elif op == 0xC0:
                cnt, p = uleb(m.b, p)
                skip, p = uleb(m.b, p)
                for _ in range(cnt):
                    out.append(rec())
                    seg_off += skip
            else:
                raise RuntimeError("bad bind opcode 0x%02x at 0x%x" % (b0, p - 1))
        print("    %s: stream END at 0x%x = declared end (%d/%d)" % (label, p, p - off, size))
        return out

    out = []
    if wb_sz:
        out += walk(wb_off, wb_sz, "weak_bind")
    if bind_sz:
        out += walk(bind_off, bind_sz, "bind")
    return out


def uleb(b, p):
    r = 0
    s = 0
    while True:
        x = b[p]
        p += 1
        r |= (x & 0x7F) << s
        if not (x & 0x80):
            return r, p
        s += 7


def sleb(b, p):
    r = 0
    s = 0
    while True:
        x = b[p]
        p += 1
        r |= (x & 0x7F) << s
        s += 7
        if not (x & 0x80):
            if x & 0x40:
                r |= -(1 << s)
            return r, p


def compare(tag, pfile, cfile):
    print("=" * 100)
    print("## %s : pristine %s  vs  patched %s" % (tag, pfile, cfile))
    pb = open(pfile, "rb").read()
    cb = open(cfile, "rb").read()
    pm = MO(pb)
    cm = MO(cb)
    print("-- pristine chained")
    imports, pbinds = decode_chained(pm)
    print("   pristine chained BINDS: %d ; distinct import names %d ; weak imports %d (distinct weak %d)"
          % (len(pbinds), len({i['name'] for i in imports}),
             sum(1 for i in imports if i['weak']), len({i['name'] for i in imports if i['weak']})))
    print("-- patched classic")
    cbinds = decode_classic_bind(cm)
    cweak = [x for x in cbinds if x['flags'] & 1]
    print("   patched binds: %d ; with WEAK_IMPORT flag %d ; distinct names %d ; distinct weak names %d"
          % (len(cbinds), len(cweak), len({x['name'] for x in cbinds}), len({x['name'] for x in cweak})))
    # ordinal presence check
    ords = collections.Counter(x['ord'] for x in cbinds)
    print("   patched bind ordinals used: %s" % sorted(ords))
    bad = [x for x in cbinds if x['name'] not in {i['name'] for i in imports}]
    print("   patched bind names NOT in pristine imports table: %d %s" % (len(bad), sorted({x['name'] for x in bad})[:10]))
    # per-symbol weak disposition
    pw = {i['name']: i['weak'] for i in imports}
    cw = collections.defaultdict(set)
    for x in cbinds:
        cw[x['name']].add(1 if x['flags'] & 1 else 0)
    noweak = sorted(n for n, v in cw.items() if 0 in v and 1 in v and pw.get(n) is not None)
    print("   symbols bound BOTH weak and strong in patched stream: %d %s" % (len(noweak), noweak[:10]))
    strong_in_pristine_weak_in_patched = sorted(n for n, v in cw.items() if pw.get(n) == 0 and v == {1})
    weak_in_pristine_strong_in_patched = sorted(n for n, v in cw.items() if pw.get(n) == 1 and v == {0})
    print("   pristine STRONG but patched WEAK: %d" % len(strong_in_pristine_weak_in_patched))
    for n in strong_in_pristine_weak_in_patched[:60]:
        print("        %s" % n)
    print("   pristine WEAK but patched STRONG: %d" % len(weak_in_pristine_strong_in_patched))
    for n in weak_in_pristine_strong_in_patched[:60]:
        print("        %s" % n)
    # per-slot comparison: patched bind loc (vmaddr) -> pristine chained bind loc
    psl = {x['loc']: x for x in pbinds}
    csl = {x['loc']: x for x in cbinds}
    both = sorted(set(psl) & set(csl))
    onlyp = sorted(set(psl) - set(csl))
    onlyc = sorted(set(csl) - set(psl))
    print("   slots: pristine %d patched %d both %d only-pristine %d only-patched %d"
          % (len(psl), len(csl), len(both), len(onlyp), len(onlyc)))
    if onlyp:
        print("      only-pristine slots (first 20): %s" % [hex(x) for x in onlyp[:20]])
        for x in onlyp[:20]:
            print("        0x%x -> %s (ord %s, weak %s)" % (x, psl[x]['name'], psl[x]['ord'], psl[x]['weak']))
    if onlyc:
        print("      only-patched slots (first 20): %s" % [hex(x) for x in onlyc[:20]])
        for x in onlyc[:20]:
            print("        0x%x -> %s (ord %s, flags 0x%x)" % (x, csl[x]['name'], csl[x]['ord'], csl[x]['flags']))
    nmis = [l for l in both if psl[l]['name'] != csl[l]['name']]
    print("   SLOT NAME MISMATCHES: %d" % len(nmis))
    for l in nmis[:40]:
        print("      0x%x pristine %s (ord %s) vs patched %s (ord %s)" % (l, psl[l]['name'], psl[l]['ord'], csl[l]['name'], csl[l]['ord']))
    ordmis = [l for l in both if psl[l]['ord'] != csl[l]['ord']]
    print("   SLOT ORDINAL MISMATCHES: %d" % len(ordmis))
    for l in ordmis[:40]:
        print("      0x%x %s pristine ord %s vs patched ord %s" % (l, psl[l]['name'], psl[l]['ord'], csl[l]['ord']))
    wmis = [l for l in both if (psl[l]['weak'] == 1) != bool(csl[l]['flags'] & 1)]
    print("   SLOT WEAK-FLAG MISMATCHES: %d" % len(wmis))
    for l in wmis[:40]:
        print("      0x%x %s pristine weak=%s patched flags=0x%x" % (l, psl[l]['name'], psl[l]['weak'], csl[l]['flags']))


def main():
    import sys
    out = open(r"H:/file/phi/b10_weak.txt", "w", encoding="utf-8")
    old = sys.stdout

    class T:
        def write(self, s):
            old.write(s)
            out.write(s)

        def flush(self):
            old.flush()

    sys.stdout = T()
    for tag, pf, cf in (("UnityFramework", FW_PRISTINE, FW_PATCHED), ("Phigros app", APP_PRISTINE, APP_PATCHED)):
        try:
            compare(tag, pf, cf)
        except Exception as e:
            print("ERROR comparing %s: %r" % (tag, e))
            import traceback
            traceback.print_exc()
    sys.stdout = old
    out.close()
    print("written H:/file/phi/b10_weak.txt")


if __name__ == "__main__":
    main()
