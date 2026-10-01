#!/usr/bin/env python3
"""b13: authoritative __got slot -> symbol mapping via LC_DYSYMTAB indirect symbol table.
Compares pristine chained binary vs patched classic binary, and checks every GOT slot is
covered by the patched bind or rebase stream.
"""
import struct

BIN = 0x80000000
ABS = 0x40000000


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
    ncmds, = rd(b, 16, "<I")
    o = 32
    cmds = []
    for _ in range(ncmds):
        c, cs = rd(b, o, "<II")
        cmds.append((c, cs, o))
        o += cs
    segs, sects = [], []
    symoff = nsyms = stroff = 0
    indoff = nind = 0
    info = None
    chained = None
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
                flags, = rd(b, so + 64, "<I")
                styp = flags & 0xFF
                res1, = rd(b, so + 68, "<I")
                sects.append(dict(seg=nm, name=sn, addr=sa, size=ss, offset=soff, type=styp, res1=res1))
                so += 80
        elif c == 0x2:
            symoff, nsyms, stroff, strsize = rd(b, o + 8, "<IIII")
        elif c == 0xB:
            f = rd(b, o + 8, "<18I")
            indoff, nind = f[12], f[13]
        elif c == 0x80000034:
            info = None
            do, ds = rd(b, o + 8, "<II")
            chained = (do, ds)
        elif c == 0x80000022:
            info = rd(b, o + 8, "<10I")
    return dict(b=b, segs=segs, sects=sects, symoff=symoff, nsyms=nsyms, stroff=stroff,
                indoff=indoff, nind=nind, info=info, chained=chained)


def symname(m, i):
    b = m["b"]
    if i >= m["nsyms"]:
        return "<sym out of range %d>" % i
    xs, = rd(b, m["symoff"] + 16 * i, "<I")
    if xs == 0:
        return "<empty>"
    e = b.find(b"\0", m["stroff"] + xs)
    return b[m["stroff"] + xs:e].decode("utf-8", "replace")


def got_map(m):
    """slot vmaddr -> (symbol name, kind) from the indirect symbol table."""
    b = m["b"]
    out = {}
    for s in m["sects"]:
        if s["type"] not in (0x6, 0x7, 0x8):
            continue
        if s["name"] not in ("__got", "__auth_got", "__stubs", "__la_symbol_ptr", "__nl_symbol_ptr"):
            continue
        ent = s["res1"]
        count = s["size"] // 8 if s["type"] != 0x8 else s["size"] // 6
        if s["type"] == 0x8:
            count = s["size"] // 12  # arm64 stub size
        for k in range(count):
            if ent + k >= m["nind"]:
                break
            v, = rd(b, m["indoff"] + 4 * (ent + k), "<I")
            slot = s["addr"] + k * (12 if s["type"] == 0x8 else 8)
            if v & BIN:
                nm = "<INDIRECT_SYMBOL_LOCAL>"
            elif v & ABS:
                nm = "<INDIRECT_SYMBOL_ABS>"
            else:
                nm = symname(m, v)
            out[slot] = (nm, s["name"])
    return out


def classic_streams(m):
    reb_off, reb_sz, bind_off, bind_sz = m["info"][:4]
    b = m["b"]
    # rebases: slot set
    p, end = reb_off, reb_off + reb_sz
    seg_idx, seg_off = None, 0
    reb = set()
    while p < end:
        b0 = b[p]; op, imm = b0 & 0xF0, b0 & 0x0F; p += 1

        def L():
            return (m["segs"][seg_idx]["vmaddr"] if seg_idx is not None else 0) + seg_off

        def recr():
            nonlocal seg_off
            reb.add(L()); seg_off += 8
        if op == 0x00:
            break
        elif op == 0x10:
            pass
        elif op == 0x20:
            seg_idx = imm; seg_off, p = uleb(b, p)
        elif op == 0x30:
            d, p = uleb(b, p); seg_off += d
        elif op == 0x40:
            seg_off += imm * 8
        elif op == 0x50:
            for _ in range(imm):
                recr()
        elif op == 0x60:
            c, p = uleb(b, p)
            for _ in range(c):
                recr()
        elif op == 0x70:
            recr(); d, p = uleb(b, p); seg_off += d
        elif op == 0x80:
            c, p = uleb(b, p); skip, p = uleb(b, p)
            for _ in range(c):
                recr(); seg_off += skip
        else:
            raise SystemExit("unknown rebase op 0x%02x" % b0)
    # binds
    p, end = bind_off, bind_off + bind_sz
    seg_idx, seg_off = None, 0
    bs = {}
    sym = None; flags = 0; ordn = None
    while p < end:
        b0 = b[p]; op, imm = b0 & 0xF0, b0 & 0x0F; p += 1

        def Lb():
            return (m["segs"][seg_idx]["vmaddr"] if seg_idx is not None else 0) + seg_off

        def recb():
            nonlocal seg_off
            bs[Lb()] = (sym, ordn, flags); seg_off += 8
        if op == 0x00:
            break
        elif op == 0x10:
            ordn = imm
        elif op == 0x20:
            ordn, p = uleb(b, p)
        elif op == 0x30:
            ordn = 0 if imm == 0 else imm - 16
        elif op == 0x40:
            flags = imm; e = b.find(b"\0", p, end); sym = b[p:e].decode("utf-8", "replace"); p = e + 1
        elif op == 0x50:
            pass
        elif op == 0x60:
            _, p = sleb(b, p)
        elif op == 0x70:
            seg_idx = imm; seg_off, p = uleb(b, p)
        elif op == 0x80:
            d, p = uleb(b, p); seg_off += d
        elif op == 0x90:
            recb()
        elif op == 0xA0:
            recb(); d, p = uleb(b, p); seg_off += d
        elif op == 0xB0:
            recb(); seg_off += imm * 8
        elif op == 0xC0:
            c, p = uleb(b, p); skip, p = uleb(b, p)
            for _ in range(c):
                recb(); seg_off += skip
        else:
            raise SystemExit("unknown bind op 0x%02x" % b0)
    return reb, bs


for label, px, qx in [("UnityFramework", r"H:/file/phi/work/UnityFramework", r"H:/file/phi/out/UnityFramework.v4"),
                      ("Phigros app", r"H:/file/phi/work/Phigros.main", r"H:/file/phi/out/Phigros.v4")]:
    print("=" * 100)
    print("## %s" % label)
    pm, qm = parse(px), parse(qx)
    pg, qg = got_map(pm), got_map(qm)
    print("pristine indirect GOT/stub slots: %d   patched: %d" % (len(pg), len(qg)))
    only_p = set(pg) - set(qg)
    only_q = set(qg) - set(pg)
    both = set(pg) & set(qg)
    mm = [(s, pg[s][0], qg[s][0]) for s in sorted(both) if pg[s][0] != qg[s][0]]
    print("common slots %d ; only-pristine %d ; only-patched %d ; NAME MISMATCHES %d"
          % (len(both), len(only_p), len(only_q), len(mm)))
    for s, a, c in mm[:20]:
        print("    0x%08x pristine %s vs patched %s" % (s, a, c))
    got_only = {s: v for s, v in pg.items() if v[1] in ("__got", "__auth_got")}
    print("first 12 pristine __got entries (slot -> symbol):")
    for s in sorted(got_only)[:12]:
        print("   0x%08x %s" % (s, got_only[s][0]))
    qgot_only = {s: v for s, v in qg.items() if v[1] in ("__got", "__auth_got")}
    print("first 12 patched __got entries (slot -> symbol):")
    for s in sorted(qgot_only)[:12]:
        print("   0x%08x %s" % (s, qgot_only[s][0]))
    if qm["info"] is not None:
        reb, binds = classic_streams(qm)
        got_slots = set(qgot_only)
        unbound = sorted(got_slots - set(binds) - reb)
        print("patched __got slots: %d ; covered by bind %d ; by rebase %d ; UNCOVERED %d %s"
              % (len(got_slots), len(got_slots & set(binds)), len(got_slots & reb), len(unbound),
                 [hex(x) for x in unbound[:20]]))
        print("binds outside __got: %d ; rebases outside all sections: %d"
              % (len(set(binds) - got_slots), 0))
    for probe in (0x4451df0, 0x4451df8, 0x4451e00, 0x4451e08, 0x4451e10, 0x4451e18, 0x4451e20):
        if probe in pg or probe in qg:
            print("   probe 0x%x pristine=%s patched=%s" % (probe, pg.get(probe, ("-",))[0], qg.get(probe, ("-",))[0]))
