#!/usr/bin/env python3
"""Independently check that `chained2dyld.py` turned the 12-byte *relative*
method lists of the 4.0.0 UnityFramework into classic 24-byte absolute lists:

 1. walk the pristine `__TEXT,__objc_methlist` with the relative convention;
 2. walk the new `__DATA_METHLIST,__objc_methlist` of the converted image as a
    classic list and require every (SEL, types, IMP) triple to be bit-identical
    to the pristine one;
 3. require all 3*N new pointer slots to be listed in the classic rebase stream;
 4. require every rebase slot that used to point into the old relative section
    to hold (and rebase to) the new list address instead;
 5. require the new segment to obey dyld's file-order rules.

usage: python verify_relmeth.py <pristine macho> <converted macho>
"""
import struct
import sys
import chained2dyld as C

N_PASS = N_FAIL = 0


def ok(name, cond, detail=""):
    global N_PASS, N_FAIL
    if cond:
        N_PASS += 1
        print(f"  PASS {name}" + (f"  [{detail}]" if detail else ""))
    else:
        N_FAIL += 1
        print(f"  FAIL {name}  {detail}")


def decode_rel(m, fixups):
    """All relative lists: [(list_va, [(sel_va, types_va, imp_va)])]"""
    s = next(x for x in m.sections if x["name"] == "__objc_methlist" and x["size"]
             and x["seg"] == "__TEXT")
    by_va = {f["vmaddr"]: f for f in fixups if f["foff"] is not None}
    out, cur = [], s["addr"]
    while cur + 8 <= s["addr"] + s["size"]:
        hdr, cnt = C.rd(m.buf, m.foff(cur), "II")
        if not (hdr & 0x80000000) or (hdr & ~C.METH_FLAG_MASK) != C.METHOD_ENTSIZE_REL:
            raise SystemExit(f"pristine list 0x{cur:x} is not a relative list: 0x{hdr:08x}")
        ents = []
        for i in range(cnt):
            fva = cur + 8 + 12 * i
            rn, rt, ri = C.rd(m.buf, m.foff(fva), "iii")
            if rn == 0:
                sel = 0
            else:
                f = by_va.get(fva + rn)
                if f is None:
                    raise SystemExit(f"no fixup for name slot 0x{fva + rn:x}")
                sel = f["target"]
            ents.append((sel, 0 if rt == 0 else fva + 4 + rt,
                         0 if ri == 0 else fva + 8 + ri))
        out.append((cur, ents))
        cur = C.round_up(cur + 8 + 12 * cnt, 8)
    return s, out


def main(ppath, cpath):
    pm = C.MachO(open(ppath, "rb").read())
    pf = C.decode_fixups(pm)["fixups"]
    oldsect, old = decode_rel(pm, pf)
    n_meth = sum(len(e) for _, e in old)
    print(f"pristine {ppath}: {len(old)} relative list(s), {n_meth} method(s) "
          f"in {oldsect['seg']},{oldsect['name']} 0x{oldsect['addr']:x}+0x{oldsect['size']:x}")

    cm = C.MachO(open(cpath, "rb").read())
    cbuf = cm.buf
    new = [x for x in cm.sections if x["name"] == "__objc_methlist" and x["size"]]
    ok("exactly one new methlist section",
       len([x for x in new if x["seg"] == C.REL_METH_SEG]) == 1
       and not [x for x in new if x["seg"] == "__TEXT" and x["addr"] != oldsect["addr"]],
       f"{len(new)} found: {[(x['seg'], hex(x['addr'])) for x in new]}")
    ns = [x for x in new if x["seg"] == C.REL_METH_SEG][0]
    ok("it lives in the new segment", ns["seg"] == C.REL_METH_SEG, ns["seg"])
    ms = cm.seg_by_name[C.REL_METH_SEG]

    # --- walk the new section as classic 24-byte lists
    lists, cur = [], ns["addr"]
    end = ns["addr"] + ns["size"]
    while cur + 8 <= end:
        hdr, cnt = C.rd(cbuf, cm.foff(cur), "II")
        ents = []
        for i in range(cnt):
            ents.append(struct.unpack_from("<QQQ", cbuf, cm.foff(cur) + 8 + 24 * i))
        lists.append((cur, hdr, cnt, ents))
        cur += 8 + 24 * cnt
    ok("new list count == pristine", (len(lists), sum(l[2] for l in lists)) == (len(old), n_meth),
       f"{len(lists)} list(s) / {sum(l[2] for l in lists)} method(s) vs "
       f"{len(old)} / {n_meth}")
    ok("classic entsize 24, flags 0",
       all(h == 24 for _, h, _, _ in lists),
       repr(sorted({h for _, h, _, _ in lists})[:4]))
    ok("no padding between lists", cur == end, f"walk ended 0x{cur:x} vs 0x{end:x}")

    # --- every method triple must be identical to the pristine decode
    bad, checked = [], 0
    for (ova, oents), (nva, hdr, cnt, nents) in zip(old, lists):
        if len(oents) != cnt:
            bad.append((hex(ova), "count", len(oents), cnt))
            continue
        for j, (o, n) in enumerate(zip(oents, nents)):
            checked += 1
            if tuple(o) != tuple(n):
                bad.append((hex(ova), j, [hex(v) for v in o], [hex(v) for v in n]))
    ok("all (SEL, types, IMP) triples identical", not bad, f"{len(bad)} bad of {checked}")

    # --- every pointer of every list must be rebased
    di = cm.lc(C.LC_DYLD_INFO_ONLY) or cm.lc(C.LC_DYLD_INFO)
    rb_off, rb_sz = struct.unpack_from("<II", cbuf, di[0]["off"] + 8)
    slots = set(C.verify_classic(cpath, verbose=False)["rebase"])
    segidx = [s["name"] for s in cm.segments].index(C.REL_METH_SEG)
    want = set()
    for nva, hdr, cnt, nents in lists:
        base = nva - ns["addr"]
        for j in range(cnt):
            for k in range(3):
                want.add((segidx, base + 8 + 24 * j + 8 * k))
    missing = sorted(want - slots)
    ok("all new pointer slots are rebase slots", not missing,
       f"{len(want)} wanted, {len(missing)} missing"
       + (f" e.g. {missing[0]}" if missing else ""))

    # --- the old references must now point at the new lists
    old_lo, old_hi = oldsect["addr"], oldsect["addr"] + oldsect["size"]
    refs = [f for f in pf if f["kind"] == "rebase" and f["foff"] is not None
            and old_lo <= f["target"] < old_hi]
    nv_by_old = {ova: nva for (ova, _), (nva, _, _, _) in zip(old, lists)}
    segidx_of_name = {s["name"]: i for i, s in enumerate(cm.segments)}
    stale = []
    for f in refs:
        nv = nv_by_old.get(f["target"])
        got = struct.unpack_from("<Q", cbuf, f["foff"])[0]
        slot = (f["seg"], f["vmaddr"] - cm.segments[f["seg"]]["vmaddr"])
        if nv is None or got != nv or slot not in slots:
            stale.append((hex(f["vmaddr"]), hex(got), hex(nv) if nv else "?", slot in slots))
    ok("all old list references repointed", not stale,
       f"{len(refs)} reference(s), {len(stale)} stale"
       + (f" e.g. {stale[0]}" if stale else ""))

    # --- no rebase slot anywhere may still hold a pointer into the dead section
    live = []
    for seg_i, off in sorted(slots):
        sg = cm.segments[seg_i]
        fo = sg["fileoff"] + off
        if off + 8 > sg["filesize"]:
            continue
        v = struct.unpack_from("<Q", cbuf, fo)[0]
        if old_lo <= v < old_hi:
            live.append((hex(sg["vmaddr"] + off), hex(v)))
    ok("no rebase slot targets the dead section", not live,
       f"{len(live)} slot(s)" + (f" e.g. {live[0]}" if live else ""))

    # --- dyld file-order rules for the new segment
    le = cm.seg_by_name["__LINKEDIT"]
    ms = cm.seg_by_name[C.REL_METH_SEG]
    ok("new segment precedes __LINKEDIT in the file",
       ms["fileoff"] + ms["filesize"] == le["fileoff"],
       f"0x{ms['fileoff']:x}+0x{ms['filesize']:x} vs 0x{le['fileoff']:x}")
    ok("__LINKEDIT still has the largest fileoff",
       le["fileoff"] == max(s["fileoff"] for s in cm.segments),
       hex(le["fileoff"]))
    ok("new segment vm/filesize match and are page sized",
       ms["vmsize"] == ms["filesize"] and ms["filesize"] % 0x4000 == 0,
       f"vm=0x{ms['vmsize']:x} file=0x{ms['filesize']:x}")
    ok("new segment is writable (rebasable)",
       ms["initprot"] & 0x2 == 0x2 and ms["maxprot"] & 0x2 == 0x2,
       f"initprot={ms['initprot']} maxprot={ms['maxprot']}")
    others = [s for s in cm.segments if s["name"] not in (C.REL_METH_SEG,)]
    ok("new segment vm range does not overlap __LINKEDIT",
       ms["vmaddr"] >= C.round_up(le["vmaddr"] + le["vmsize"], 0x4000),
       f"new 0x{ms['vmaddr']:x} vs linkedit end 0x{le['vmaddr'] + le['vmsize']:x}")
    ok("section is inside the segment file range",
       ms["fileoff"] <= ns["offset"] and ns["offset"] + ns["size"] <= ms["fileoff"] + ms["filesize"],
       f"offset=0x{ns['offset']:x} size=0x{ns['size']:x}")

    # --- spot check: decode a few selectors from the converted file
    spots = []
    for nva, hdr, cnt, nents in lists[:2]:
        for sel, types, imp in nents[:2]:
            s = bytes(cbuf[cm.foff(sel):cm.foff(sel) + 32]).split(b"\0")[0].decode("latin-1")
            t = bytes(cbuf[cm.foff(types):cm.foff(types) + 32]).split(b"\0")[0].decode("latin-1")
            spots.append(f"{s} {t} imp={cm.sect_of(imp)['name']}@{imp:#x}")
    print("  spot check: " + " | ".join(spots))

    print(f"\n{N_PASS} passed, {N_FAIL} failed")
    return 1 if N_FAIL else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
