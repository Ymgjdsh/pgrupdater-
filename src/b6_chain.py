# -*- coding: utf-8 -*-
"""Decode the pristine LC_DYLD_CHAINED_FIXUPS of 4.0.0 UnityFramework and compare
it with the classic streams the converter wrote into out/UnityFramework.v4."""
import struct, zipfile, hashlib

BASE = "H:/file/phi/"
IPA4 = BASE + "games.Pigeon.Phigros_4.0.0_und3fined.ipa"
FW_MEMBER = "Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework"

OUT = open(BASE + "b6_chain.txt", "w", encoding="utf-8")
def w(*a):
    s = " ".join(str(x) for x in a); print(s); OUT.write(s + "\n"); OUT.flush()

def rd(b, o, f): return struct.unpack_from("<" + f, b, o)

# ---------- chained fixups decoder ----------
def parse_chained(b, base, hdr_off):
    fv, starts_off, imports_off, symbols_off, imports_count, imports_format, symbols_format = \
        rd(b, hdr_off, "7I")
    w("dyld_chained_fixups_header @%#x: version=%d starts=%#x imports=%#x symbols=%#x "
      "imports_count=%d imports_format=%d symbols_format=%d"
      % (hdr_off, fv, starts_off, imports_off, symbols_off, imports_count, imports_format,
         symbols_format))
    so = hdr_off + starts_off
    seg_count = rd(b, so, "I")[0]
    seg_off = list(rd(b, so+4, "%dI" % seg_count))
    w("starts_in_image @%#x seg_count=%d seg_info_offset=%s" % (so, seg_count, seg_off))
    # imports
    imports = []
    io_ = hdr_off + imports_off
    wpool = hdr_off + symbols_off
    for k in range(imports_count):
        if imports_format == 1:               # dyld_chained_import (4 bytes)
            v = rd(b, io_+4*k, "I")[0]
            lib_ord = v & 0xFF
            weak_imp = (v >> 8) & 1
            name_off = v >> 9
            addend = 0
        elif imports_format == 2:             # dyld_chained_import_addend (8 bytes)
            v = rd(b, io_+8*k, "I")[0]
            lib_ord = v & 0xFF
            weak_imp = (v >> 8) & 1
            name_off = v >> 9
            addend = rd(b, io_+8*k+4, "i")[0]
        else:                                 # dyld_chained_import_addend64 (16 bytes)
            v1, v2 = rd(b, io_+16*k, "QQ")
            lib_ord = v1 & 0xFFFF
            weak_imp = (v1 >> 16) & 1
            name_off = (v1 >> 32) & 0xFFFFFFFF
            addend = v2
        imports.append(dict(ord=lib_ord, weak=weak_imp, name_off=name_off, addend=addend))
    for im in imports:
        e = b.index(b"\0", wpool + im["name_off"])
        im["name"] = b[wpool+im["name_off"]:e].decode("utf-8", "replace")
    w("imports decoded=%d  first 3: %s" % (len(imports), [(i["ord"], i["name"], i["weak"]) for i in imports[:3]]))
    total = 0; binds = []; rebases = []; fmt_seen = set()
    for si in range(seg_count):
        if seg_off[si] == 0: continue
        off = so + seg_off[si]
        size, page_size, ptr_fmt = rd(b, off, "IHH")
        seg_offset = rd(b, off+8, "Q")[0]
        max_valid, page_count = rd(b, off+16, "IH")
        fmt_seen.add(ptr_fmt)
        w("  seg[%d] struct_size=%d page_size=%#x ptr_fmt=%d seg_offset=%#x max_valid=%#x page_count=%d"
          % (si, size, page_size, ptr_fmt, seg_offset, max_valid, page_count))
        starts = list(rd(b, off+22, "%dH" % page_count))
        n_page = 0; n_seg = 0
        for pg in range(page_count):
            ps = starts[pg]
            if ps == 0xFFFF: continue
            n_page += 1
            offs = []
            if ps & 0x8000:
                j = off + 22 + 2*page_count
                while True:
                    v = rd(b, j, "H")[0]; j += 2
                    if v == 0: break
                    offs.append(v)
            else:
                offs.append(ps)
            for o0 in offs:
                loc = seg_offset + pg*page_size + o0
                f = base + loc
                while True:
                    raw = rd(b, f, "Q")[0]
                    total += 1; n_seg += 1
                    if ptr_fmt in (1, 9, 12, 7, 10):
                        if raw & (1 << 63):
                            auth = (raw >> 62) & 1
                            nxt = (raw >> 51) & 0x7FF
                            if auth:
                                ordn = raw & 0xFFFF
                                binds.append(dict(loc=loc, ord=ordn, addend=None, auth=True))
                            else:
                                ordn = raw & 0xFFFF
                                binds.append(dict(loc=loc, ord=ordn, addend=(raw >> 32) & 0x7FFFF, auth=False))
                        else:
                            tgt = raw & ((1 << 43)-1)
                            nxt = (raw >> 51) & 0x7FF
                            rebases.append(dict(loc=loc, target=tgt))
                    else:  # PTR_64 (2) / PTR_64_OFFSET (6)
                        if raw & (1 << 63):
                            ordn = raw & 0xFFFFFF
                            addend = (raw >> 24) & 0xFF
                            nxt = (raw >> 51) & 0xFFF
                            binds.append(dict(loc=loc, ord=ordn, addend=addend, auth=False))
                        else:
                            tgt = raw & ((1 << 36)-1)
                            high8 = (raw >> 36) & 0xFF
                            nxt = (raw >> 51) & 0xFFF
                            rebases.append(dict(loc=loc, target=tgt, high8=high8))
                    if nxt == 0: break
                    f += 4*nxt
        w("  seg[%d] ptr_fmt=%d page_size=%#x page_count=%d pages_used=%d pointers=%d"
          % (si, ptr_fmt, page_size, page_count, n_page, n_seg))
    w("TOTAL chained pointers=%d  binds=%d  rebases=%d  ptr_formats=%s"
      % (total, len(binds), len(rebases), fmt_seen))
    return dict(imports=imports, binds=binds, rebases=rebases, fmt_seen=fmt_seen)

# ---------- patched binary: reuse the walkers from b5_streams ----------
import importlib.util
spec = importlib.util.spec_from_file_location("b5", BASE + "b5_streams.py")
# b5 runs its whole analysis on import; avoid that by re-implementing the two walkers here.
def uleb(b, i):
    r = 0; s = 0
    while True:
        x = b[i]; i += 1; r |= (x & 0x7F) << s
        if not (x & 0x80): return r, i
        s += 7
def sleb(b, i):
    r = 0; s = 0
    while True:
        x = b[i]; i += 1; r |= (x & 0x7F) << s; s += 7
        if not (x & 0x80):
            if x & 0x40: r -= (1 << s)
            return r, i
def walk_bind(b, off, size):
    end = off+size; i = off; ordi = 0; nm = None; fl = 0; ty = 0; ad = 0; segi = 0; segoff = 0
    ent = []; done = None
    while i < end:
        o = b[i] & 0xF0; imm = b[i] & 0x0F; i += 1
        if o == 0x00: done = i; break
        elif o == 0x10: ordi = imm
        elif o == 0x20: ordi, i = uleb(b, i)
        elif o == 0x30: ordi = 0 if imm == 0 else -((~imm & 0xF)+1)
        elif o == 0x40:
            fl = imm; e = b.index(b"\0", i); nm = b[i:e].decode("utf-8", "replace"); i = e+1
        elif o == 0x50: ty = imm
        elif o == 0x60: ad, i = sleb(b, i)
        elif o == 0x70: segi = imm; segoff, i = uleb(b, i)
        elif o == 0x80: v, i = uleb(b, i); segoff += v
        elif o == 0x90: ent.append((ordi, nm, fl, segi, segoff)); segoff += 8
        elif o == 0xA0:
            ent.append((ordi, nm, fl, segi, segoff)); v, i = uleb(b, i); segoff += 8+v
        elif o == 0xB0:
            ent.append((ordi, nm, fl, segi, segoff)); segoff += 8+imm*8
        elif o == 0xC0:
            cnt, i = uleb(b, i); sk, i = uleb(b, i)
            for _ in range(cnt):
                ent.append((ordi, nm, fl, segi, segoff)); segoff += 8+sk
        else:
            raise ValueError("bind opcode %#x @%#x" % (b[i-1], i-1))
    return ent, done

def segs_of(b):
    magic, ct, cs, ft, ncmds, sc, fl, _ = rd(b, 0, "IiiIIIII")
    o = 32; segs = []; info = None; dylibs = []
    for _ in range(ncmds):
        cmd, size = rd(b, o, "II")
        if cmd == 0x19:
            nm = b[o+8:o+24].rstrip(b"\0").decode()
            vma, vms, fo, fs = rd(b, o+24, "QQQQ")
            segs.append(dict(name=nm, vmaddr=vma, vmsize=vms, fileoff=fo, filesize=fs))
        elif cmd == 0x80000022:
            info = rd(b, o+8, "10I")
        elif cmd in (0xC, 0x80000018, 0x8000001F, 0x21, 0x80000023):
            noff = rd(b, o+8, "I")[0]; e = b.index(b"\0", o+noff)
            dylibs.append(b[o+noff:e].decode())
        elif cmd == 0x80000034:
            w("(unexpected) chained fixups in patched binary")
        o += size
    return segs, info, dylibs

pristine = zipfile.ZipFile(IPA4).read(FW_MEMBER)
w("pristine fw size=%d sha256=%s" % (len(pristine), hashlib.sha256(pristine).hexdigest()[:16]))
# find LC_DYLD_CHAINED_FIXUPS
magic, ct, cs, ft, ncmds, sc, fl, _ = rd(pristine, 0, "IiiIIIII")
o = 32; hdr = None
for _ in range(ncmds):
    cmd, size = rd(pristine, o, "II")
    if cmd == 0x80000034:
        hdr = rd(pristine, o+8, "II")
    o += size
w("pristine LC_DYLD_CHAINED_FIXUPS dataoff=%#x datasize=%#x" % hdr)
pc = parse_chained(pristine, 0, hdr[0])

patched = open(BASE + "out/UnityFramework.v4", "rb").read()
segs, info, dylibs = segs_of(patched)
ro, rs, bo, bs, wo, ws, lo, ls, eo, es = info
ent, done = walk_bind(patched, bo, bs)
w("")
w("patched: rebase_size=%d bind entries=%d dylibs=%d" % (rs, len(ent), len(dylibs)))
w("pristine: chained pointers=%d (binds=%d rebases=%d)" % (len(pc["binds"])+len(pc["rebases"]),
                                                           len(pc["binds"]), len(pc["rebases"])))
# rebases: chained rebases + chained binds that the shim turned into rebases should equal 514487
w("")
w("== rebase count check: patched rebase entries vs pristine chained rebases")
w("   pristine rebases            = %d" % len(pc["rebases"]))
# bins of chained rebase targets rounded down: compare multisets of (unslid target)
pr = sorted(r["target"] + (r.get("high8", 0) << 36) for r in pc["rebases"])
w("   pristine rebase targets: min=%#x max=%#x" % (pr[0], pr[-1]))
# patched rebase entries -> walk rebase stream to get them
def walk_rebase(b, off, size):
    end = off+size; i = off; ty = 0; segi = 0; segoff = 0; ent = []; done = None
    while i < end:
        o = b[i] & 0xF0; imm = b[i] & 0x0F; i += 1
        if o == 0x00: done = i; break
        elif o == 0x10: ty = imm
        elif o == 0x20: segi = imm; segoff, i = uleb(b, i)
        elif o == 0x30: v, i = uleb(b, i); segoff += v
        elif o == 0x40: segoff += imm*8
        elif o == 0x50:
            for _ in range(imm): ent.append((segi, segoff, ty)); segoff += 8
        elif o == 0x60:
            v, i = uleb(b, i)
            for _ in range(v): ent.append((segi, segoff, ty)); segoff += 8
        elif o == 0x70:
            v, i = uleb(b, i); ent.append((segi, segoff, ty)); segoff += 8+v
        elif o == 0x80:
            v, i = uleb(b, i); sk, i = uleb(b, i)
            for _ in range(v): ent.append((segi, segoff, ty)); segoff += 8+sk
        else: raise ValueError("rebase opcode %#x" % b[i-1])
    return ent, done
rbe, _d = walk_rebase(patched, ro, rs)
w("   patched rebase entries      = %d  (delta vs pristine = %d)"
  % (len(rbe), len(rbe)-len(pc["rebases"])))
pvals = {}
for (si, so, ty) in rbe:
    vm = segs[si]["vmaddr"] + so
    fo = segs[si]["fileoff"] + so
    if so + 8 <= segs[si]["filesize"]:
        pvals[vm] = rd(patched, fo, "Q")[0]
# pristine rebase slot locations (vmaddr) using pristine segment layout
pmagic, pct, pcs, pft, pncmds, psc, pfl, _ = rd(pristine, 0, "IiiIIIII")
o = 32; psegs = []
for _ in range(pncmds):
    cmd, size = rd(pristine, o, "II")
    if cmd == 0x19:
        nm = pristine[o+8:o+24].rstrip(b"\0").decode()
        vma, vms, fo_, fs = rd(pristine, o+24, "QQQQ")
        psegs.append(dict(name=nm, vmaddr=vma, vmsize=vms, fileoff=fo_, filesize=fs))
    o += size
def pfile2vm(loc):
    for s in psegs:
        if s["fileoff"] <= loc < s["fileoff"]+s["filesize"]:
            return s["vmaddr"] + (loc - s["fileoff"])
    return None
pslots = {pfile2vm(r["loc"]): (r["target"] + (r.get("high8", 0) << 36)) for r in pc["rebases"]}
w("   pristine rebase slot vmaddrs: %d (unique file-loc->vm mapped=%d)"
  % (len(pc["rebases"]), sum(1 for x in pslots if x is not None)))
matched = sum(1 for vm, v in pvals.items() if vm in pslots and pslots[vm] == v)
w("   patched rebase slots whose stored value equals the pristine chained target: %d / %d"
  % (matched, len(pvals)))
w("   patched slots NOT present as pristine chained rebases: %s"
  % sorted("%#x" % vm for vm in pvals if vm not in pslots))
mism = [(vm, v, pslots.get(vm)) for vm, v in pvals.items() if vm in pslots and pslots[vm] != v]
w("   value mismatches: %d %s" % (len(mism), [("%#x" % a, "%#x" % b, ("%#x" % c) if c else None) for a, b, c in mism[:10]]))
# binds comparison
w("")
w("== bind symbol/ordinal/weak comparison")
from collections import Counter
imp_by_ord = Counter()
for im in pc["imports"]:
    imp_by_ord[(im["ord"], im["name"], im["weak"])] += 1
chained_binds = Counter()
for bd in pc["binds"]:
    ordn = bd["ord"]
    # chained ordinal is 1-based index into imports
    if 1 <= ordn <= len(pc["imports"]):
        im = pc["imports"][ordn-1]
        chained_binds[(im["ord"], im["name"], im["weak"])] += 1
    else:
        chained_binds[("<bad ord %d>" % ordn, "", 0)] += 1
patched_binds = Counter()
for (ordi, nm, fl, segi, segoff) in ent:
    patched_binds[(ordi, nm, 1 if (fl & 1) else 0)] += 1
# chained binds use dylib ordinal from the import record; patched uses stream ordinal.
cb = Counter((k[0], k[1]) for k in chained_binds.elements())
pb = Counter((k[0], k[1]) for k in patched_binds.elements())
w("   chained bind import-records (distinct ord,name): %d ; patched binds: %d" % (len(cb), len(pb)))
w("   chained only: %s" % list((cb - pb).items())[:15])
w("   patched only: %s" % list((pb - cb).items())[:15])
cweak = sum(v for k, v in chained_binds.items() if k[2])
pweak = sum(v for k, v in patched_binds.items() if k[2])
w("   weak-flagged entries: chained=%d patched=%d" % (cweak, pweak))
w("   total binds: chained=%d patched=%d" % (sum(chained_binds.values()), sum(patched_binds.values())))
badord = [k for k in chained_binds if isinstance(k[0], str)]
w("   chained binds with out-of-range import ordinal: %d %s" % (len(badord), badord[:5]))
# are the 538 unknown names present in the pristine imports?
unknown = set()
for (ordi, nm, fl, segi, segoff) in ent:
    if nm and nm not in {i["name"] for i in pc["imports"]}:
        unknown.add(nm)
w("   patched bind names absent from pristine imports table: %d  e.g. %s"
  % (len(unknown), sorted(unknown)[:8]))
OUT.close(); print("written b6_chain.txt")
