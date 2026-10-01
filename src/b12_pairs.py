#!/usr/bin/env python3
"""b12: decisive slot->symbol comparison.
pristine chained fixups  vs  patched classic bind stream, correct pointer strides.
"""
import struct, sys, collections

CASES = [
    ("UnityFramework",
     r"H:/file/phi/work/UnityFramework",
     r"H:/file/phi/out/UnityFramework.v4"),
    ("Phigros app",
     r"H:/file/phi/work/Phigros.main",
     r"H:/file/phi/out/Phigros.v4"),
]


def rd(b, o, f):
    return struct.unpack_from(f, b, o)


def uleb(b, p):
    r = s = 0
    while True:
        x = b[p]; p += 1
        r |= (x & 0x7F) << s
        if not (x & 0x80):
            return r, p
        s += 7


def sleb(b, p):
    r = s = 0
    while True:
        x = b[p]; p += 1
        r |= (x & 0x7F) << s
        s += 7
        if not (x & 0x80):
            if x & 0x40:
                r |= -(1 << s)
            return r, p


def parse(path):
    b = open(path, "rb").read()
    magic, = rd(b, 0, "<I")
    ncmds, = rd(b, 16, "<I")
    o = 32
    cmds = []
    for _ in range(ncmds):
        c, cs = rd(b, o, "<II")
        cmds.append((c, cs, o))
        o += cs
    segs, sects, dylibs = [], [], []
    symoff = nsyms = stroff = 0
    chained = None
    info = None
    for c, cs, o in cmds:
        if c == 0x19:
            nm = b[o + 8:o + 24].split(b"\0")[0].decode()
            va, vs, fo, fs = rd(b, o + 24, "<QQQQ")
            segs.append(dict(name=nm, vmaddr=va, vmsize=vs, fileoff=fo, filesize=fs))
            nsec, = rd(b, o + 64, "<I")
            so = o + 72
            for _ in range(nsec):
                sn = b[so:so + 16].split(b"\0")[0].decode()
                sa, ss = rd(b, so + 32, "<QQ")
                soff, = rd(b, so + 48, "<I")
                sects.append(dict(seg=nm, name=sn, addr=sa, size=ss, offset=soff))
                so += 80
        elif c == 0x2:
            symoff, nsyms, stroff, strsize = rd(b, o + 8, "<IIII")
        elif c == 0xC or c == 0x80000018 or c == 0x8000001F:
            no, = rd(b, o + 8, "<I")
            dylibs.append(dict(weak=(c == 0x80000018), name=b[o + 24:o + 24 + no].split(b"\0")[0].decode()))
        elif c == 0x80000034:
            do, ds = rd(b, o + 8, "<II")
            chained = (do, ds)
        elif c == 0x80000022:
            info = rd(b, o + 8, "<10I")
        elif c == 0x25 or c == 0x32:
            pass
    return dict(b=b, segs=segs, sects=sects, dylibs=dylibs, symoff=symoff, nsyms=nsyms,
                stroff=stroff, chained=chained, info=info, ncmds=ncmds)


def symname(m, i):
    b = m["b"]
    xs, = rd(b, m["symoff"] + 16 * i, "<I")
    if xs == 0:
        return ""
    e = b.find(b"\0", m["stroff"] + xs)
    return b[m["stroff"] + xs:e].decode("utf-8", "replace")


def pristine_chained(path):
    m = parse(path)
    b = m["b"]
    ib = m["segs"][0]["vmaddr"]
    do, ds = m["chained"]
    ver, starts, imports_off, symbols_off, imp_count, imp_fmt, sym_fmt = rd(b, do, "<7I")
    imports = []
    for i in range(imp_count):
        raw, = rd(b, do + imports_off + 4 * i, "<I")
        lib_ord = raw & 0xFF
        weak = (raw >> 8) & 1
        name_off = raw >> 9
        e = b.find(b"\0", do + symbols_off + name_off)
        nm = b[do + symbols_off + name_off:e].decode("utf-8", "replace")
        imports.append((nm, lib_ord, weak))
    scount, = rd(b, do + starts, "<I")
    seg_info = [rd(b, do + starts + 4 + 4 * i, "<I")[0] for i in range(scount)]
    out = {}
    for si, sio in enumerate(seg_info):
        if sio == 0:
            continue
        p = do + starts + sio
        size, page_size, ptr_fmt, seg_off = rd(b, p, "<IHHQ")
        maxv, page_count = rd(b, p + 16, "<IH")
        base = p + 22
        for pg in range(page_count):
            ps, = rd(b, base + 2 * pg, "<H")
            if ps == 0xFFFF:
                continue
            offs = []
            if ps & 0x8000:
                c, = rd(b, base + 2 * pg, "<H")
                cnt = c & 0x7FFF
                j = base + 2 * page_count
                offs = [rd(b, j + 2 * k, "<H")[0] for k in range(cnt)]
            else:
                offs = [ps]
            for o0 in offs:
                loc = ib + seg_off + pg * page_size + o0
                while True:
                    fo = loc - ib
                    if fo < 0 or fo + 8 > len(b):
                        break
                    raw, = rd(b, fo, "<Q")
                    nxt = (raw >> 51) & 0xFFF
                    isbind = (raw >> 63) & 1
                    if isbind:
                        ordn = raw & 0xFFFFFF
                        nm, lib_ord, weak = imports[ordn] if 0 <= ordn < len(imports) else ("<ord %d>" % ordn, -1, -1)
                        out[loc] = dict(kind="bind", name=nm, lib=lib_ord, weak=weak, ordn=ordn)
                    else:
                        tgt = raw & 0xFFFFFFFFF
                        out[loc] = dict(kind="rebase", name="", lib=-1, weak=-1, tgt=ib + tgt if (raw >> 36) & 0xFF == 0 else None,
                                        raw=raw)
                    if nxt == 0:
                        break
                    loc += nxt * 4
    return m, ib, imports, out


def patched_binds(path):
    m = parse(path)
    b = m["b"]
    reb_off, reb_sz, bind_off, bind_sz = m["info"][:4]
    p = bind_off
    end = bind_off + bind_sz
    seg_idx = None
    seg_off = 0
    sym = None
    flags = 0
    ordn = None
    out = collections.OrderedDict()
    dups = []
    while p < end:
        b0 = b[p]
        op, imm = b0 & 0xF0, b0 & 0x0F
        p += 1

        def L():
            return (m["segs"][seg_idx]["vmaddr"] if seg_idx is not None else 0) + seg_off

        def rec():
            nonlocal seg_off
            s = L()
            if s in out:
                dups.append(s)
            out[s] = dict(kind="bind", name=sym, ordn=ordn, flags=flags, seg=m["segs"][seg_idx]["name"] if seg_idx is not None else "?")
            seg_off += 8

        if op == 0x00:
            break
        elif op == 0x10:
            ordn = imm
        elif op == 0x20:
            ordn, p = uleb(b, p)
        elif op == 0x30:
            ordn = 0 if imm == 0 else imm - 16
        elif op == 0x40:
            flags = imm
            e = b.find(b"\0", p, end)
            sym = b[p:e].decode("utf-8", "replace")
            p = e + 1
        elif op == 0x50:
            pass
        elif op == 0x60:
            _, p = sleb(b, p)
        elif op == 0x70:
            seg_idx = imm
            seg_off, p = uleb(b, p)
        elif op == 0x80:
            d, p = uleb(b, p)
            seg_off += d
        elif op == 0x90:
            rec()
        elif op == 0xA0:
            rec()
            d, p = uleb(b, p)
            seg_off += d
        elif op == 0xB0:
            rec()
            seg_off += imm * 8
        elif op == 0xC0:
            cnt, p = uleb(b, p)
            skip, p = uleb(b, p)
            for _ in range(cnt):
                rec()
                seg_off += skip
        else:
            raise SystemExit("unknown bind opcode 0x%02x at 0x%x" % (b0, p - 1))
    return m, out, dups


def rebase_entries(path):
    m = parse(path)
    b = m["b"]
    reb_off, reb_sz = m["info"][0], m["info"][1]
    p = reb_off
    end = reb_off + reb_sz
    seg_idx = None
    seg_off = 0
    out = {}
    while p < end:
        b0 = b[p]
        op, imm = b0 & 0xF0, b0 & 0x0F
        p += 1

        def L():
            return (m["segs"][seg_idx]["vmaddr"] if seg_idx is not None else 0) + seg_off

        def rec():
            nonlocal seg_off
            out[L()] = True
            seg_off += 8

        if op == 0x00:
            break
        elif op == 0x10:
            pass
        elif op == 0x20:
            seg_idx = imm
            seg_off, p = uleb(b, p)
        elif op == 0x30:
            d, p = uleb(b, p)
            seg_off += d
        elif op == 0x40:
            seg_off += imm * 8
        elif op == 0x50:
            for _ in range(imm):
                rec()
        elif op == 0x60:
            c, p = uleb(b, p)
            for _ in range(c):
                rec()
        elif op == 0x70:
            rec()
            d, p = uleb(b, p)
            seg_off += d
        elif op == 0x80:
            c, p = uleb(b, p)
            skip, p = uleb(b, p)
            for _ in range(c):
                rec()
                seg_off += skip
        else:
            raise SystemExit("unknown rebase opcode 0x%02x at 0x%x" % (b0, p - 1))
    return m, out


for label, pth, qth in CASES:
    print("=" * 100)
    print("## %s" % label)
    pm, ib, imports, pfix = pristine_chained(pth)
    qm, qbinds, dups = patched_binds(qth)
    qreb_m, qreb = rebase_entries(qth)
    print("-- pristine chained @ image_base 0x%x : fixups %d (binds %d, rebases %d), import names %d"
          % (ib, len(pfix), sum(1 for v in pfix.values() if v["kind"] == "bind"),
             sum(1 for v in pfix.values() if v["kind"] == "rebase"), len(imports)))
    print("-- patched : binds %d (dup slots %d), rebases %d, sections %s"
          % (len(qbinds), len(dups), len(qreb),
             [(sg, nm, hex(a), hex(sz)) for sg, nm, a, sz in
              ((s["seg"], s["name"], s["addr"], s["size"]) for s in qm["sects"] if s["name"] == "__got")]))

    pbind = {k: v for k, v in pfix.items() if v["kind"] == "bind"}
    preb = {k: v for k, v in pfix.items() if v["kind"] == "rebase"}
    both = set(pbind) & set(qbinds)
    print("   slots in BOTH pristine-bind and patched-bind : %d" % len(both))
    print("   pristine bind slots NOT in patched bind stream: %d" % len(set(pbind) - set(qbinds)))
    print("   patched bind slots NOT in pristine binds      : %d" % len(set(qbinds) - set(pbind)))
    name_mm = []
    for s in sorted(both):
        a = pbind[s]["name"]
        c = qbinds[s]["name"]
        if a != c:
            name_mm.append((s, a, c, pbind[s]["lib"], pbind[s]["weak"], qbinds[s]["ordn"], qbinds[s]["flags"]))
    print("   SLOT NAME MISMATCHES: %d" % len(name_mm))
    for s, a, c, pl, pw, qo, qf in name_mm[:25]:
        print("      0x%08x pristine %s (lib_ord %d weak %d)  vs  patched %s (ord %s flags 0x%x)" % (s, a, pl, pw, c, qo, qf))
    weak_mm = [(s, pbind[s]["name"], pbind[s]["weak"], qbinds[s]["flags"] & 1) for s in sorted(both)
               if (pbind[s]["weak"] == 1) != bool(qbinds[s]["flags"] & 1)]
    strong_to_weak = [x for x in weak_mm if x[2] == 0]
    print("   SLOT WEAK-FLAG MISMATCHES: %d (of which pristine-strong->patched-weak %d)" % (len(weak_mm), len(strong_to_weak)))
    for s, n, pw, qw in weak_mm[:20]:
        print("      0x%08x %s pristine weak=%d patched flags&1=%d" % (s, n, pw, qw))
    # direction-of-change census by NAME (not slot)
    pstrong = {v["name"] for v in pbind.values() if v["weak"] == 0}
    pweak = {v["name"] for v in pbind.values() if v["weak"] == 1}
    qstrong = {v["name"] for v in qbinds.values() if not (v["flags"] & 1)}
    qweak = {v["name"] for v in qbinds.values() if (v["flags"] & 1)}
    s2w = sorted(pstrong & qweak)
    print("   NAME-level: pristine-strong names now weak: %d" % len(s2w))
    for n in s2w[:30]:
        print("      %s" % n)
    print("   NAME-level: pristine-weak names now strong: %d %s" % (len(sorted(pweak & qstrong)), sorted(pweak & qstrong)[:10]))
    print("   pristine names total %d (strong %d weak %d); patched names total %d (strong %d weak %d)"
          % (len(pstrong | pweak), len(pstrong), len(pweak), len(qstrong | qweak), len(qstrong), len(qweak)))
    got = [s for s in qm["sects"] if s["name"] == "__got"]
    if got:
        g = got[0]
        lo, hi = g["addr"], g["addr"] + g["size"]
        inb = sum(1 for s in qbinds if lo <= s < hi)
        print("   __got range 0x%x..0x%x : patched binds inside %d ; pristine binds inside %d"
              % (lo, hi, inb, sum(1 for s in pbind if lo <= s < hi)))
    pref = {s for s in preb}
    print("   patched bind slots that pristine had as REBASE: %d ; patched rebase slots pristine had as BIND: %d"
          % (len(set(qbinds) & pref), len(set(qreb) & set(pbind))))
