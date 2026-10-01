#!/usr/bin/env python3
# Probe: where does the patched bind stream put slots? (stream order, per-segment ranges, probes)
import struct, collections

FW = r"H:/file/phi/out/UnityFramework.v4"
PB = r"H:/file/phi/work/UnityFramework"


def rd(b, o, f):
    return struct.unpack_from(f, b, o)


def parse(path):
    b = open(path, "rb").read()
    ncmds = rd(b, 16, "<I")[0]
    o = 32
    cmds = []
    for _ in range(ncmds):
        c, cs = rd(b, o, "<II")
        cmds.append((c, cs, o))
        o += cs
    segs = []
    sects = []
    for c, cs, o in cmds:
        if c == 0x19:
            nm = b[o + 8:o + 24].split(b"\0")[0].decode()
            va, vs, fo, fs = rd(b, o + 24, "<QQQQ")
            segs.append(dict(name=nm, vmaddr=va, vmsize=vs, fileoff=fo, filesize=fs))
            ns = rd(b, o + 64, "<I")[0]
            so = o + 72
            for _ in range(ns):
                sn = b[so:so + 16].split(b"\0")[0].decode()
                sa, ss = rd(b, so + 32, "<QQ")
                soff = rd(b, so + 48, "<I")[0]
                sects.append(dict(seg=nm, name=sn, addr=sa, size=ss, offset=soff))
                so += 80
    info = None
    for c, cs, o in cmds:
        if c == 0x80000022:
            info = rd(b, o + 8, "<10I")
    return b, segs, sects, info


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


b, segs, sects, info = parse(FW)
print("segments:", [(s['name'], hex(s['vmaddr']), hex(s['vmsize']), hex(s['fileoff'], ) if False else hex(s['fileoff'])) for s in segs])
print("sections of interest:", [(x['seg'], x['name'], hex(x['addr']), hex(x['size']), hex(x['offset'])) for x in sects if x['name'] in ('__got', '__const', '__data', '__bss', '__objc_data', '__cfstring')])
reb_off, reb_sz, bind_off, bind_sz, wb_off, wb_sz, lb_off, lb_sz, exp_off, exp_sz = info[:10]
# symbol names
symoff = nsyms = stroff = None
for c, cs, o in parse(FW)[0] and []:
    pass
ncmds = rd(b, 16, "<I")[0]
o = 32
for _ in range(ncmds):
    c, cs = rd(b, o, "<II")
    if c == 0x2:
        symoff, nsyms, stroff, strsize = rd(b, o + 8, "<IIII")
    o += cs


def sname(i):
    xs = rd(b, symoff + 16 * i, "<I")[0]
    e = b.find(b"\0", stroff + xs)
    return b[stroff + xs:e].decode("utf-8", "replace")


p = bind_off
end = bind_off + bind_sz
seg_idx = None
seg_off = 0
sym = None
flags = 0
ordn = None
entries = []
while p < end:
    b0 = b[p]
    op, imm = b0 & 0xF0, b0 & 0x0F
    p += 1
    if op == 0x00:
        break
    elif op == 0x10:
        ordn = imm if imm else None
    elif op == 0x20:
        ordn, p = uleb(b, p)
    elif op == 0x30:
        ordn = 0 if imm == 0 else (imm | 0xFFFFFFF0) - 0x100000000
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

    def L():
        return (segs[seg_idx]["vmaddr"] if seg_idx is not None else 0) + seg_off
    if op == 0x90:
        entries.append((L(), sym, ordn, flags, seg_idx, "DO_BIND"))
    elif op == 0xA0:
        entries.append((L(), sym, ordn, flags, seg_idx, "DO_BIND_ADD_ADDR_ULEB"))
        d, p = uleb(b, p)
        seg_off += d
    elif op == 0xB0:
        entries.append((L(), sym, ordn, flags, seg_idx, "DO_BIND_ADD_ADDR_IMM_SCALED"))
        seg_off += imm * 8
    elif op == 0xC0:
        cnt, p = uleb(b, p)
        skip, p = uleb(b, p)
        for _ in range(cnt):
            entries.append((L(), sym, ordn, flags, seg_idx, "DO_BIND_ULEB_TIMES_SKIPPING_ULEB"))
            seg_off += skip

print("bind entries decoded: %d ; distinct slots %d" % (len(entries), len({e[0] for e in entries})))
print("first 25 in stream order:")
for e in entries[:25]:
    print("   0x%08x  %-9s ord=%-4s flags=0x%x seg=%s  %s" % (e[0], e[5][:9], e[2], e[3], e[4], e[1]))
print("slot min=0x%x max=0x%x" % (min(e[0] for e in entries), max(e[0] for e in entries)))
per = collections.Counter()
for e in entries:
    si = e[4]
    per[segs[si]["name"] if si is not None else "?"] += 1
print("per segment:", dict(per))
dup = [s for s, c in collections.Counter(e[0] for e in entries).items() if c > 1]
print("duplicated slots: %d (first 10 %s)" % (len(dup), [hex(x) for x in sorted(dup)[:10]]))
probe = [0x4451df0, 0x4451df8, 0x4451e00, 0x4451e08, 0x4451e10, 0x4451e18, 0x4451e20, 0x4450020, 0x4450018, 0x4452fa8]
m = {e[0]: e for e in entries}
for q in probe:
    if q in m:
        print("   probe 0x%x -> %s (ord %s, flags 0x%x, %s)" % (q, m[q][1], m[q][2], m[q][3], m[q][5]))
    else:
        print("   probe 0x%x -> NOT in bind stream" % q)
# which slots does the original bind there?
pb, psegs, psects, pinfo = parse(PB)
print("pristine segments:", [(s['name'], hex(s['vmaddr']), hex(s['fileoff'])) for s in psegs])
py = pb.find(b"bplist")
print("pristine raw words at probe slots:")
for q in probe:
    fo = q  # vmaddr == fileoff for this binary
    if fo + 8 <= len(pb):
        print("   pristine 0x%x raw=0x%016x" % (q, rd(pb, fo, "<Q")[0]))
