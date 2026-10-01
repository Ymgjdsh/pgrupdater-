# -*- coding: utf-8 -*-
"""Independent classic-dyld stream validator + load-command hygiene.

Standalone: does not import chained2dyld.  Mach-O sources can be files or
members of an .ipa (zipfile) so the untouched originals are compared in place.
"""
import struct, hashlib, zipfile, sys, io

BASE = "H:/file/phi/"
IPA4 = BASE + "games.Pigeon.Phigros_4.0.0_und3fined.ipa"
IPA319 = BASE + "games.Pigeon.Phigros_3.19.0_und3fined.ipa"

TARGETS = [
    ("4.0.0_ORIG_app", ("ipa", IPA4, "Payload/Phigros.app/Phigros")),
    ("4.0.0_ORIG_fw",  ("ipa", IPA4, "Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework")),
    ("4.0.0_PATCHED_app", ("file", BASE + "out/Phigros.v4")),
    ("4.0.0_PATCHED_fw",  ("file", BASE + "out/UnityFramework.v4")),
    ("3.19.0_ORIG_app", ("ipa", IPA319, "Payload/Phigros.app/Phigros")),
    ("3.19.0_ORIG_fw",  ("ipa", IPA319, "Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework")),
    ("4.0.0_BUILT_app", ("file", BASE + "out/Phigros")),
]

# --- real mach-o loader.h values -------------------------------------------------
LCNAMES = {
    0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0x3: "LC_SYMSEG", 0x4: "LC_THREAD",
    0x5: "LC_UNIXTHREAD", 0xB: "LC_DYSYMTAB", 0xC: "LC_LOAD_DYLIB", 0xD: "LC_ID_DYLIB",
    0xE: "LC_LOAD_DYLINKER", 0xF: "LC_ID_DYLINKER", 0x10: "LC_PREBOUND_DYLIB",
    0x11: "LC_ROUTINES", 0x12: "LC_SUB_FRAMEWORK", 0x13: "LC_SUB_UMBRELLA",
    0x14: "LC_SUB_CLIENT", 0x15: "LC_SUB_LIBRARY", 0x16: "LC_TWOLEVEL_HINTS",
    0x17: "LC_PREBIND_CKSUM", 0x18: "LC_LOAD_WEAK_DYLIB", 0x19: "LC_SEGMENT_64",
    0x1A: "LC_ROUTINES_64", 0x1B: "LC_UUID", 0x1C: "LC_RPATH", 0x1D: "LC_CODE_SIGNATURE",
    0x1E: "LC_SEGMENT_SPLIT_INFO", 0x1F: "LC_REEXPORT_DYLIB", 0x20: "LC_LAZY_LOAD_DYLIB",
    0x21: "LC_ENCRYPTION_INFO", 0x22: "LC_DYLD_INFO", 0x23: "LC_LOAD_UPWARD_DYLIB",
    0x24: "LC_VERSION_MIN_MACOSX", 0x25: "LC_VERSION_MIN_IPHONEOS", 0x26: "LC_FUNCTION_STARTS",
    0x27: "LC_DYLD_ENVIRONMENT", 0x28: "LC_MAIN", 0x29: "LC_DATA_IN_CODE",
    0x2A: "LC_SOURCE_VERSION", 0x2B: "LC_DYLIB_CODE_SIGN_DRS", 0x2C: "LC_ENCRYPTION_INFO_64",
    0x2D: "LC_LINKER_OPTION", 0x2E: "LC_LINKER_OPTIMIZATION_HINT",
    0x2F: "LC_VERSION_MIN_TVOS", 0x30: "LC_VERSION_MIN_WATCHOS", 0x31: "LC_NOTE",
    0x32: "LC_BUILD_VERSION", 0x33: "LC_DYLD_EXPORTS_TRIE", 0x34: "LC_DYLD_CHAINED_FIXUPS",
    0x35: "LC_LINKER_OPTIMIZATION_HINT2"}
DYLIB_RAWS = (0xC, 0x80000018, 0x1F | 0x80000000, 0x23 | 0x80000000, 0x20)
RPATH_RAW = 0x8000001C
PLATFORMS = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 5: "bridgeOS",
             6: "macCatalyst", 7: "iOSSimulator", 8: "tvOSSimulator",
             9: "watchOSSimulator", 10: "DriverKit", 11: "visionOS"}
TOOLS = {1: "clang", 2: "swift", 3: "ld", 4: "lld", 5: "metal", 6: "airnt",
         7: "airp", 8: "air-lld", 9: "air-nt", 10: "air-ptx"}

def rd(b, o, f):
    return struct.unpack_from("<" + f, b, o)

def uleb(b, i):
    r = 0; s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7F) << s
        if not (x & 0x80):
            return r, i
        s += 7

def sleb(b, i):
    r = 0; s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7F) << s
        s += 7
        if not (x & 0x80):
            if x & 0x40:
                r -= (1 << s)
            return r, i

class MO:
    def __init__(self, data, name):
        self.buf = data; self.name = name
        self.magic, self.cputype, self.cpusub, self.ftype, self.ncmds, self.sizeofcmds, \
            self.flags, _r = rd(data, 0, "IiiIIIII")
        assert self.magic == 0xFEEDFACF, hex(self.magic)
        self.cmds = []
        o = 32
        for _ in range(self.ncmds):
            cmd, size = rd(data, o, "II")
            self.cmds.append((cmd, size, o))
            o += size
        self.segs, self.sects, self.dylibs, self.rpaths = [], [], [], []
        for raw, size, o in self.cmds:
            if raw == 0x19:
                nm = data[o+8:o+24].rstrip(b"\0").decode()
                vma, vms, fo, fs = rd(data, o+24, "QQQQ")
                maxp, initp, nsect, sfl = rd(data, o+56, "iiII")
                si = len(self.segs)
                self.segs.append(dict(i=si, name=nm, vmaddr=vma, vmsize=vms,
                                      fileoff=fo, filesize=fs, initprot=initp,
                                      maxprot=maxp, flags=sfl))
                so = o + 72
                for _j in range(nsect):
                    sn = data[so:so+16].rstrip(b"\0").decode()
                    sg = data[so+16:so+32].rstrip(b"\0").decode()
                    addr, sz = rd(data, so+32, "QQ")
                    off, align, reloff, nrel, flg = rd(data, so+48, "IIIII")
                    self.sects.append(dict(name=sn, seg=sg, addr=addr, size=sz,
                                           offset=off, flags=flg))
                    so += 80
            elif raw in DYLIB_RAWS:
                noff = rd(data, o+8, "I")[0]
                e = data.index(b"\0", o+noff)
                self.dylibs.append(dict(raw=raw, name=data[o+noff:e].decode()))
            elif raw == RPATH_RAW:
                noff = rd(data, o+8, "I")[0]
                e = data.index(b"\0", o+noff)
                self.rpaths.append(data[o+noff:e].decode())
        self.by_raw = {}
        for raw, size, o in self.cmds:
            self.by_raw.setdefault(raw, []).append(o)

    def seg_of(self, vm):
        for s in self.segs:
            if s["vmaddr"] <= vm < s["vmaddr"] + s["vmsize"]:
                return s
        return None

    def foff(self, vm):
        s = self.seg_of(vm)
        if s is None:
            return None
        d = vm - s["vmaddr"]
        return s["fileoff"] + d if d < s["filesize"] else None

    def symtab(self):
        if 0x2 not in self.by_raw:
            return [], 0
        o = self.by_raw[0x2][0]
        symoff, nsyms, stroff, strsize = rd(self.buf, o+8, "IIII")
        out = []
        for i in range(nsyms):
            n_strx, n_type, n_sect, n_desc, n_value = rd(self.buf, symoff+16*i, "IBBHQ")
            nm = ""
            if n_strx < strsize:
                e = self.buf.index(b"\0", stroff+n_strx)
                nm = self.buf[stroff+n_strx:e].decode("utf-8", "replace")
            out.append(dict(i=i, name=nm, type=n_type, sect=n_sect, desc=n_desc))
        return out, nsyms

def walk_rebase(b, off, size):
    end = off + size; i = off
    ty = 0; segi = 0; segoff = 0; ent = []; ops = 0; done = None
    while i < end:
        o = b[i] & 0xF0; imm = b[i] & 0x0F; i += 1; ops += 1
        if o == 0x00:
            done = i; break
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
        else:
            raise ValueError("rebase bad opcode %#x @ %#x" % (b[i-1], i-1))
    return ent, done, ops

def walk_bind(b, off, size):
    end = off + size; i = off
    ordi = 0; nm = None; fl = 0; ty = 0; ad = 0; segi = 0; segoff = 0
    ent = []; ops = 0; done = None
    while i < end:
        o = b[i] & 0xF0; imm = b[i] & 0x0F; cur = i; i += 1; ops += 1
        if o == 0x00: done = i; break
        elif o == 0x10: ordi = imm
        elif o == 0x20: ordi, i = uleb(b, i)
        elif o == 0x30: ordi = 0 if imm == 0 else -((~imm & 0xF) + 1)
        elif o == 0x40:
            fl = imm; e = b.index(b"\0", i); nm = b[i:e].decode("utf-8", "replace"); i = e+1
        elif o == 0x50: ty = imm
        elif o == 0x60: ad, i = sleb(b, i)
        elif o == 0x70: segi = imm; segoff, i = uleb(b, i)
        elif o == 0x80: v, i = uleb(b, i); segoff += v
        elif o == 0x90:
            ent.append((ordi, nm, fl, ty, ad, segi, segoff, cur)); segoff += 8
        elif o == 0xA0:
            ent.append((ordi, nm, fl, ty, ad, segi, segoff, cur))
            v, i = uleb(b, i); segoff += 8+v
        elif o == 0xB0:
            ent.append((ordi, nm, fl, ty, ad, segi, segoff, cur)); segoff += 8+imm*8
        elif o == 0xC0:
            cnt, i = uleb(b, i); sk, i = uleb(b, i)
            for _ in range(cnt):
                ent.append((ordi, nm, fl, ty, ad, segi, segoff, cur)); segoff += 8+sk
        else:
            raise ValueError("bind bad opcode %#x @ %#x" % (b[cur], cur))
    return ent, done, ops

W = 0x2
OUT = open(BASE + "b5_streams.txt", "w", encoding="utf-8")
def w(*a):
    s = " ".join(str(x) for x in a)
    print(s); OUT.write(s + "\n"); OUT.flush()

def load(kind):
    if kind[0] == "file":
        return open(kind[1], "rb").read()
    z = zipfile.ZipFile(kind[1])
    return z.read(kind[2])

# slots we specifically care about (fw v4): the 4 __got slots that were chained
# binds to _objc_opt_* and the 4 __objc_selrefs slots the thunks read.
GOT_SLOTS = {"_objc_opt_class": 0x4451e08, "_objc_opt_isKindOfClass": 0x4451e10,
             "_objc_opt_new": 0x4451e18, "_objc_opt_respondsToSelector": 0x4451e20}
SEL_SLOTS = {"class": 0x47cc030, "isKindOfClass:": 0x47cd940,
             "new": 0x47ce138, "respondsToSelector:": 0x47ceb60}

summary = {}
def analyze(label, kind):
    data = load(kind)
    m = MO(data, label)
    w("=" * 78)
    w("### %s   %s   size=%d sha256=%s" % (label, kind[1] if kind[0] == "file" else kind[1] + " :: " + kind[2],
                                           len(data), hashlib.sha256(data).hexdigest()[:16]))
    w("   magic=%#x filetype=%d ncmds=%d sizeofcmds=%d flags=%#x  chained=%s dyninfo=%s"
      % (m.magic, m.ftype, m.ncmds, m.sizeofcmds, m.flags,
         bool(m.by_raw.get(0x34)), bool(m.by_raw.get(0x80000022))))
    # ---- load commands (only the security/platform relevant ones inline)
    w("   -- load commands:")
    for raw, size, o in m.cmds:
        nm = LCNAMES.get(raw, "UNKNOWN(%#x)" % raw)
        ex = ""
        if raw == 0x32:
            plat, mn, sdk, nt = rd(m.buf, o+8, "IIII")
            ex = "platform=%d(%s) minos=%d.%d.%d sdk=%d.%d.%d ntools=%d" % (
                plat, PLATFORMS.get(plat, "?"), mn >> 16, (mn >> 8) & 0xFF, mn & 0xFF,
                sdk >> 16, (sdk >> 8) & 0xFF, sdk & 0xFF, nt)
            for t in range(nt):
                tv, tver = rd(m.buf, o+24+8*t, "II")
                ex += " | tool=%s(%d) ver=%d.%d.%d" % (TOOLS.get(tv, "?"), tv,
                                                       tver >> 16, (tver >> 8) & 0xFF, tver & 0xFF)
        elif raw in (0x24, 0x25, 0x2F, 0x30):
            v, s = rd(m.buf, o+8, "II")
            ex = "version=%d.%d.%d sdk=%d.%d.%d" % (v >> 16, (v >> 8) & 0xFF, v & 0xFF,
                                                    s >> 16, (s >> 8) & 0xFF, s & 0xFF)
        elif raw == 0x2A:
            v = rd(m.buf, o+8, "Q")[0]
            ex = "source_version=%d.%d.%d.%d.%d" % (v >> 40, (v >> 30) & 0x3FF,
                                                    (v >> 20) & 0x3FF, (v >> 10) & 0x3FF, v & 0x3FF)
        elif raw == 0x80000028:
            eo, ss = rd(m.buf, o+8, "QQ")
            ex = "entryoff=%#x stacksize=%#x" % (eo, ss)
        elif raw in (0x21, 0x2C):
            co, cs, cid = rd(m.buf, o+8, "III")
            ex = "cryptoff=%#x cryptsize=%#x cryptid=%d" % (co, cs, cid)
        elif raw == 0x1D:
            do, ds = rd(m.buf, o+8, "II")
            ex = "dataoff=%#x datasize=%#x end=%#x filesize=%#x" % (do, ds, do+ds, len(data))
        elif raw == 0x80000022:
            v = rd(m.buf, o+8, "10I")
            ex = "rebase=%#x/%d bind=%#x/%d weak=%#x/%d export=%#x/%d lazy=%#x/%d" % tuple(v)
        elif raw in (0x8000001C,):
            noff = rd(m.buf, o+8, "I")[0]; e = m.buf.index(b"\0", o+noff)
            ex = "path=%r" % m.buf[o+noff:e].decode()
        elif raw == 0x80000034:
            do, ds = rd(m.buf, o+8, "II")
            ex = "dataoff=%#x datasize=%#x" % (do, ds)
        elif raw == 0x80000033:
            do, ds = rd(m.buf, o+8, "II")
            ex = "dataoff=%#x datasize=%#x" % (do, ds)
        elif raw == 0x26:
            do, ds = rd(m.buf, o+8, "II")
            ex = "dataoff=%#x datasize=%#x" % (do, ds)
        w("      %-26s size=%-5d off=%#-8x %s" % (nm, size, o, ex))
    w("   -- dylibs=%d  rpaths=%s" % (len(m.dylibs), m.rpaths))
    for k, d in enumerate(m.dylibs, 1):
        w("      [%d] %-52s %s" % (k, d["name"], LCNAMES.get(d["raw"], d["raw"])))
    syms, nsym = m.symtab()
    undef = [s for s in syms if (s["type"] & 0x0E) == 0 and s["name"]]
    weakref = [s for s in undef if s["desc"] & 0x40]
    w("   -- symtab=%d undefined=%d of which N_WEAK_REF=%d" % (nsym, len(undef), len(weakref)))
    rec = dict(nsym=nsym, nundef=len(undef), nweakref=len(weakref),
               dylibs=[d["name"] for d in m.dylibs], cmds={})
    for raw, size, o in m.cmds:
        rec["cmds"].setdefault(LCNAMES.get(raw, hex(raw)), 0)
        rec["cmds"][LCNAMES.get(raw, hex(raw))] += 1
    # ---- classic streams
    if 0x80000022 in m.by_raw:
        o = m.by_raw[0x80000022][0]
        ro, rs, bo, bs, wo, ws, eo, es, lo, ls = rd(m.buf, o+8, "10I")
        reb, done, ops = walk_rebase(m.buf, ro, rs)
        w("   -- REBASE stream off=%#x size=%d : opcodes=%d entries=%d DONE@%s consumed=%s/%d"
          % (ro, rs, ops, len(reb), ("%#x" % done) if done else "NONE",
             (done-ro) if done else "NONE", rs))
        if done is None:
            w("      !! NO DONE opcode")
        else:
            tail = m.buf[done:ro+rs]
            w("      trailing=%d allzero=%s ; declared end=%#x next stream off=%#x"
              % (len(tail), all(x == 0 for x in tail), ro+rs, bo))
        an = []; perseg = {}
        for k, (si, so, ty) in enumerate(reb):
            if si >= len(m.segs):
                an.append("reb[%d] bad segidx %d" % (k, si)); continue
            s = m.segs[si]; vm = s["vmaddr"] + so
            perseg[s["name"]] = perseg.get(s["name"], 0) + 1
            if so >= s["vmsize"]:
                an.append("reb[%d] slot %#x off %#x >= vmsize %s" % (k, vm, so, s["name"]))
            if so+8 > s["filesize"]:
                an.append("reb[%d] slot %#x not file-backed in %s" % (k, vm, s["name"]))
            if not (s["initprot"] & W):
                an.append("reb[%d] slot %#x in NON-WRITABLE %s initprot=%d" % (k, vm, s["name"], s["initprot"]))
            fo = m.foff(vm)
            if fo is not None:
                val = rd(m.buf, fo, "Q")[0]
                if val != 0 and m.seg_of(val) is None:
                    an.append("reb[%d] slot %#x holds %#x NOT in any segment" % (k, vm, val))
        w("      per-segment: %s" % perseg)
        w("      ANOMALIES=%d" % len(an))
        for a in an[:25]: w("        " + a)
        # weak-flag census over all bind streams
        nbind = 0; nweakflag = 0; badord = []; badeg = []; nosym = 0; names = {}
        allent = []
        for kind, off_, size_ in (("bind", bo, bs), ("weak", wo, ws), ("lazy", lo, ls)):
            if size_ == 0:
                w("   -- %s stream EMPTY" % kind); continue
            e2, d2, o2 = walk_bind(m.buf, off_, size_)
            w("   -- %s stream off=%#x size=%d opcodes=%d entries=%d DONE@%s consumed=%s/%d trailing=%s"
              % (kind, off_, size_, o2, len(e2), ("%#x" % d2) if d2 else "NONE",
                 (d2-off_) if d2 else "NONE", size_,
                 (all(x == 0 for x in m.buf[d2:off_+size_]) if d2 else None)))
            if d2 is None:
                w("      !! NO DONE opcode in %s stream" % kind)
            for e in e2:
                allent.append((kind,) + e)
        nameset = {s["name"] for s in undef}
        for (kind, ordi, nm, fl, ty, ad, si, so, opat) in allent:
            nbind += 1
            if fl & 0x1: nweakflag += 1
            elif fl & 0x2: pass
            if nm is None or nm == "":
                nosym += 1; continue
            names[nm] = names.get(nm, 0) + 1
            if ordi < 0:
                pass
            elif ordi == 0:
                badord.append("%s @%#x sym=%s ordinal 0 (self)" % (kind, opat, nm))
            elif ordi > len(m.dylibs):
                badord.append("%s @%#x sym=%s ordinal %d > %d dylibs" % (kind, opat, nm, ordi, len(m.dylibs)))
            if nm not in nameset:
                badord.append("%s @%#x sym=%s not an undefined symtab symbol" % (kind, opat, nm))
            if si >= len(m.segs):
                badeg.append("%s @%#x sym=%s bad segidx %d" % (kind, opat, nm, si)); continue
            s = m.segs[si]; vm = s["vmaddr"] + so
            if so+8 > s["filesize"]:
                badeg.append("%s @%#x sym=%s slot %#x not file-backed in %s" % (kind, opat, nm, vm, s["name"]))
            if not (s["initprot"] & W):
                badeg.append("%s @%#x sym=%s slot %#x NON-WRITABLE %s" % (kind, opat, nm, vm, s["name"]))
        w("      bind entries total=%d (weak-flagged=%d, flat/weak-ordinal=%d) distinct syms=%d"
          % (nbind, nweakflag, nosym, len(names)))
        w("      ordinal/sym anomalies=%d" % len(badord))
        for a in badord[:25]: w("        " + a)
        w("      slot anomalies=%d" % len(badeg))
        for a in badeg[:25]: w("        " + a)
        # slots of interest
        slotmap = {}
        for k, (si, so, ty) in enumerate(reb):
            if si < len(m.segs):
                slotmap[m.segs[si]["vmaddr"] + so] = ("rebase", k, ty)
        for (kind, ordi, nm, fl, ty, ad, si, so, opat) in allent:
            if si < len(m.segs):
                slotmap[m.segs[si]["vmaddr"] + so] = ("bind:" + kind, nm, fl)
        w("   -- slots of interest:")
        for nm, vm in list(GOT_SLOTS.items()) + [("sel:" + k, v) for k, v in SEL_SLOTS.items()]:
            fo = m.foff(vm)
            val = rd(m.buf, fo, "Q")[0] if fo is not None else None
            w("      %#x %-28s entry=%-24s fileval=%s" % (vm, nm, slotmap.get(vm, "-"),
                                                         ("%#x" % val) if val is not None else "n/a"))
        rec["rebase"] = len(reb); rec["bind"] = nbind; rec["weakflag"] = nweakflag
    elif 0x34 in m.by_raw:
        o = m.by_raw[0x34][0]
        do, ds = rd(m.buf, o+8, "II")
        w("   -- LC_DYLD_CHAINED_FIXUPS dataoff=%#x datasize=%#x (iOS12 dyld2 CANNOT process this)"
          % (do, ds))
        if do and do+ds <= len(m.buf):
            ver, starts_in_image, starts_in_seg, starts_count, imports_off, imports_count, syms_off, strs_off = \
                rd(m.buf, do, "IIIIIIII")
            w("      dyld_chained_fixups_header: version=%d starts_in_image=%d seg_count=%d "
              "imports_count=%d" % (ver, starts_in_image, starts_count, imports_count))
    summary[label] = rec
    del data, m

for label, kind in TARGETS:
    try:
        analyze(label, kind)
    except Exception as e:
        import traceback
        w("!! TARGET %s FAILED: %r" % (label, e))
        w(traceback.format_exc())

w("")
w("=" * 78)
w("### LOAD-COMMAND DIFFS")
w("=" * 78)
for a, b in (("4.0.0_ORIG_fw", "4.0.0_PATCHED_fw"), ("4.0.0_ORIG_app", "4.0.0_PATCHED_app"),
             ("3.19.0_ORIG_fw", "4.0.0_PATCHED_fw")):
    if a not in summary or b not in summary: continue
    ka, kb = summary[a]["cmds"], summary[b]["cmds"]
    w("-- %s vs %s" % (a, b))
    for k in sorted(set(ka) | set(kb)):
        if ka.get(k, 0) != kb.get(k, 0):
            w("   %-28s %s=%d  %s=%d" % (k, a, ka.get(k, 0), b, kb.get(k, 0)))
    da = set(summary[a]["dylibs"]); db = set(summary[b]["dylibs"])
    if da != db:
        w("   dylibs only in %s: %s" % (a, sorted(da-db)))
        w("   dylibs only in %s: %s" % (b, sorted(db-da)))
    w("   symtab: %s nsym=%d undef=%d weakref=%d | %s nsym=%d undef=%d weakref=%d"
      % (a, summary[a]["nsym"], summary[a]["nundef"], summary[a]["nweakref"],
         b, summary[b]["nsym"], summary[b]["nundef"], summary[b]["nweakref"]))
OUT.close()
print("written b5_streams.txt")
