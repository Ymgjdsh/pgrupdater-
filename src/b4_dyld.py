# -*- coding: utf-8 -*-
"""Task 3: independent classic-dyld stream walker + load-command hygiene.

Standalone Mach-O reader; does not import chained2dyld.
"""
import struct, hashlib

BASE = "H:/file/phi/"
FILES = [("app_v4", BASE + "out/Phigros.v4"),
         ("fw_v4", BASE + "out/UnityFramework.v4"),
         ("app_v3b", BASE + "out/Phigros.v3b"),
         ("fw_pristine", BASE + "work/UnityFramework"),
         ("app_pristine", BASE + "work/Phigros.main")]
OUT = open(BASE + "b4_dyld.txt", "w", encoding="utf-8")
def w(*a):
    s = " ".join(str(x) for x in a)
    print(s)
    OUT.write(s + "\n")

MH_MAGIC_64 = 0xFEEDFACF
LC = {0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0xB: "LC_DYSYMTAB", 0xC: "LC_LOAD_DYLIB",
      0xD: "LC_ID_DYLIB", 0xE: "LC_LOAD_DYLINKER", 0x19: "LC_SEGMENT_64", 0x1B: "LC_UUID",
      0x1D: "LC_CODE_SIGNATURE", 0x1E: "LC_SEGMENT_SPLIT_INFO", 0x21: "LC_LAZY_LOAD_DYLIB",
      0x22: "LC_ENCRYPTION_INFO", 0x23: "LC_DYLD_INFO", 0x24: "LC_ENCRYPTION_INFO_64",
      0x25: "LC_VERSION_MIN_MACOSX", 0x26: "LC_VERSION_MIN_IPHONEOS", 0x29: "LC_FUNCTION_STARTS",
      0x2A: "LC_DYLD_ENVIRONMENT", 0x2B: "LC_MAIN", 0x2C: "LC_VERSION_MIN_TVOS",
      0x2D: "LC_VERSION_MIN_WATCHOS", 0x2E: "LC_DATA_IN_CODE", 0x2F: "LC_SOURCE_VERSION",
      0x30: "LC_DYLIB_CODE_SIGN_DRS", 0x31: "LC_ENCRYPTION_INFO_64b",
      0x32: "LC_BUILD_VERSION", 0x33: "LC_DYLD_EXPORTS_TRIE", 0x34: "LC_DYLD_CHAINED_FIXUPS",
      0x35: "LC_LINKER_OPTIMIZATION_HINT", 0x36: "LC_NOTE", 0x37: "LC_BUILD_VERSION2",
      0x80000018: "LC_LOAD_WEAK_DYLIB", 0x8000001C: "LC_REEXPORT_DYLIB",
      0x8000001F: "LC_LOAD_UPWARD_DYLIB", 0x80000022: "LC_DYLD_INFO_ONLY",
      0x80000023: "LC_LOAD_DYLINKER2", 0x80000028: "LC_MAIN2", 0x80000029: "LC_MAIN3"}
DYLIB_CMDS = (0xC, 0x80000018, 0x8000001C, 0x8000001F, 0x21)

PLATFORMS = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 5: "bridgeOS", 6: "macCatalyst",
             7: "iOSSimulator", 8: "tvOSSimulator", 9: "watchOSSimulator", 10: "DriverKit",
             11: "visionOS", 12: "visionOSSimulator"}

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
    r = 0; s = 0; x = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7F) << s
        s += 7
        if not (x & 0x80):
            if x & 0x40:
                r -= (1 << s)
            return r, i

class MO:
    def __init__(self, path):
        self.path = path
        self.buf = open(path, "rb").read(); b = self.buf
        self.magic, self.cputype, self.cpusub, self.ftype, self.ncmds, self.sizeofcmds, \
            self.flags, _r = rd(b, 0, "IiiIIIII")
        self.cmds = []
        o = 32
        for _ in range(self.ncmds):
            cmd, size = rd(b, o, "II")
            self.cmds.append((cmd & 0x7FFFFFFF, size, o, cmd))
            o += size
        self.segs, self.sects = [], []
        self.dylibs = []
        for cmd, size, o, raw in self.cmds:
            if cmd == 0x19:
                nm = b[o+8:o+24].rstrip(b"\0").decode()
                vma, vms, fo, fs = rd(b, o+24, "QQQQ")
                maxp, initp, nsect, sfl = rd(b, o+56, "iiII")
                si = len(self.segs)
                self.segs.append(dict(i=si, name=nm, vmaddr=vma, vmsize=vms, fileoff=fo,
                                      filesize=fs, initprot=initp, maxprot=maxp, nsects=nsect,
                                      flags=sfl))
                so = o + 72
                for _j in range(nsect):
                    sn = b[so:so+16].rstrip(b"\0").decode()
                    sg = b[so+16:so+32].rstrip(b"\0").decode()
                    addr, sz = rd(b, so+32, "QQ")
                    off, align, reloff, nrel, flg = rd(b, so+48, "IIIII")
                    self.sects.append(dict(name=sn, seg=sg, addr=addr, size=sz, offset=off,
                                           flags=flg))
                    so += 80
            elif raw in DYLIB_CMDS or cmd in (0xC, 0x21):
                noff = rd(b, o+8, "I")[0]
                e = b.index(b"\0", o+noff)
                self.dylibs.append(dict(name=b[o+noff:e].decode(), cmd=raw,
                                        ts=rd(b, o+16, "III"), csz=size))
        self.lc_bv = [c for c in self.cmds if c[0] == 0x32]
        self.lc_vm = [c for c in self.cmds if c[0] in (0x26, 0x25, 0x2C, 0x2D)]
        self.lc_info = [c for c in self.cmds if c[0] == 0x80000022 or c[0] == 0x23]
        self.lc_sym = [c for c in self.cmds if c[0] == 0x2]
        self.lc_dysym = [c for c in self.cmds if c[0] == 0xB]
        self.lc_main = [c for c in self.cmds if c[0] == 0x2B or c[0] == 0x80000028]
        self.lc_enc = [c for c in self.cmds if c[0] in (0x21, 0x22, 0x24)]
        self.lc_cs = [c for c in self.cmds if c[0] == 0x1D]
        self.lc_chain = [c for c in self.cmds if c[0] == 0x34]

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
        if not self.lc_sym:
            return []
        o = self.lc_sym[0][2]
        symoff, nsyms, stroff, strsize = rd(self.buf, o + 8, "IIII")
        out = []
        for i in range(nsyms):
            n_strx, n_type, n_sect, n_desc, n_value = rd(self.buf, symoff + 16*i, "IBBHQ")
            if n_strx >= strsize:
                out.append(dict(i=i, name="<badstrx>", type=n_type, sect=n_sect,
                                desc=n_desc, value=n_value)); continue
            e = self.buf.index(b"\0", stroff + n_strx)
            out.append(dict(i=i, name=self.buf[stroff+n_strx:e].decode("utf-8", "replace"),
                            type=n_type, sect=n_sect, desc=n_desc, value=n_value))
        return out


def walk_rebase(m, off, size):
    b = m.buf
    end = off + size
    i = off
    type_ = 0; segi = 0; segoff = 0
    entries = []; ops = 0
    done_at = None
    while i < end:
        op = b[i] & 0xF0; imm = b[i] & 0x0F; i += 1
        ops += 1
        if op == 0x00:
            done_at = i
            break
        elif op == 0x10:
            type_ = imm
        elif op == 0x20:
            segi = imm
            segoff, i = uleb(b, i)
        elif op == 0x30:
            v, i = uleb(b, i); segoff += v
        elif op == 0x40:
            segoff += imm * 8
        elif op == 0x50:
            for _ in range(imm):
                entries.append((segi, segoff, type_)); segoff += 8
        elif op == 0x60:
            v, i = uleb(b, i)
            for _ in range(v):
                entries.append((segi, segoff, type_)); segoff += 8
        elif op == 0x70:
            v, i = uleb(b, i)
            entries.append((segi, segoff, type_)); segoff += 8 + v
        elif op == 0x80:
            v, i = uleb(b, i); sk, i = uleb(b, i)
            for _ in range(v):
                entries.append((segi, segoff, type_)); segoff += 8 + sk
        else:
            raise ValueError("bad rebase opcode %#x at %#x" % (b[i-1], i-1))
    return entries, done_at, i, ops


def walk_bind(m, off, size, kind):
    b = m.buf
    end = off + size
    i = off
    ordinal = 0; symname = None; symflags = 0; type_ = 0; addend = 0
    segi = 0; segoff = 0
    entries = []; ops = 0; done_at = None
    while i < end:
        op = b[i] & 0xF0; imm = b[i] & 0x0F; cur = i; i += 1
        ops += 1
        if op == 0x00:
            done_at = i
            break
        elif op == 0x10:
            ordinal = imm
        elif op == 0x20:
            ordinal, i = uleb(b, i)
        elif op == 0x30:
            ordinal = 0 if imm == 0 else (imm | 0xF0) - 0x100
        elif op == 0x40:
            symflags = imm
            e = b.index(b"\0", i)
            symname = b[i:e].decode("utf-8", "replace")
            i = e + 1
        elif op == 0x50:
            type_ = imm
        elif op == 0x60:
            addend, i = sleb(b, i)
        elif op == 0x70:
            segi = imm
            segoff, i = uleb(b, i)
        elif op == 0x80:
            v, i = uleb(b, i); segoff += v
        elif op == 0x90:
            entries.append(dict(ordinal=ordinal, name=symname, flags=symflags, type=type_,
                                addend=addend, segi=segi, segoff=segoff, opat=cur))
            segoff += 8
        elif op == 0xA0:
            entries.append(dict(ordinal=ordinal, name=symname, flags=symflags, type=type_,
                                addend=addend, segi=segi, segoff=segoff, opat=cur))
            v, i = uleb(b, i); segoff += 8 + v
        elif op == 0xB0:
            entries.append(dict(ordinal=ordinal, name=symname, flags=symflags, type=type_,
                                addend=addend, segi=segi, segoff=segoff, opat=cur))
            segoff += 8 + imm * 8
        elif op == 0xC0:
            cnt, i = uleb(b, i); skip, i = uleb(b, i)
            for _ in range(cnt):
                entries.append(dict(ordinal=ordinal, name=symname, flags=symflags, type=type_,
                                    addend=addend, segi=segi, segoff=segoff, opat=cur))
                segoff += 8 + skip
        else:
            raise ValueError("bad bind opcode %#x at %#x (%s)" % (b[cur], cur, kind))
    return entries, done_at, i, ops


W_PROT = 0x2
for label, path in FILES:
    m = MO(path)
    w("=" * 78)
    w("### %s  %s  size=%d sha256=%s" % (label, path, len(m.buf),
                                         hashlib.sha256(m.buf).hexdigest()[:16]))
    w("=" * 78)
    w("header: magic=%#x cputype=%#x cpusub=%#x filetype=%d ncmds=%d sizeofcmds=%d flags=%#x"
      % (m.magic, m.cputype, m.cpusub, m.ftype, m.ncmds, m.sizeofcmds, m.flags))
    # ---- load-command hygiene
    w("-- commands:")
    for cmd, size, o, raw in m.cmds:
        nm = LC.get(raw, LC.get(cmd, hex(raw)))
        extra = ""
        if cmd == 0x32:
            plat, minos, sdk, ntools = rd(m.buf, o+8, "IIII")
            extra = ("platform=%d(%s) minos=%d.%d.%d sdk=%d.%d.%d ntools=%d"
                     % (plat, PLATFORMS.get(plat, "?"), minos >> 16, (minos >> 8) & 0xFF, minos & 0xFF,
                        sdk >> 16, (sdk >> 8) & 0xFF, sdk & 0xFF, ntools))
            for t in range(ntools):
                tv, tt = rd(m.buf, o + 24 + 8*t, "II")
                extra += " tool[%d]=%s(%d)" % (t, PLATFORMS.get(tv, tv), tt)
        elif cmd in (0x26, 0x25, 0x2C, 0x2D):
            v, s = rd(m.buf, o+8, "II")
            extra = "version=%d.%d.%d sdk=%d.%d.%d" % (v >> 16, (v >> 8) & 0xFF, v & 0xFF,
                                                       s >> 16, (s >> 8) & 0xFF, s & 0xFF)
        elif cmd == 0x2B:
            eo, ss, _p = rd(m.buf, o+8, "QQQ")
            extra = "entryoff=%#x stacksize=%#x" % (eo, ss)
        elif cmd in (0x22, 0x24):
            coff, csize, cid = rd(m.buf, o+8, "III")
            extra = "cryptoff=%#x cryptsize=%#x cryptid=%d" % (coff, csize, cid)
        elif cmd == 0x1D:
            do, ds = rd(m.buf, o+8, "II")
            extra = "dataoff=%#x datasize=%#x end=%#x (filesize=%#x)" % (do, ds, do+ds, len(m.buf))
        elif cmd == 0x80000022:
            vals = rd(m.buf, o+8, "10I")
            extra = ("rebase=%#x/%d bind=%#x/%d weak=%#x/%d export=%#x/%d lazy=%#x/%d"
                     % (vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7],
                        vals[8], vals[9]))
        elif raw in DYLIB_CMDS or cmd in (0xC, 0x21):
            noff = rd(m.buf, o+8, "I")[0]
            e = m.buf.index(b"\0", o+noff)
            extra = "name=%r ts=%d.%d.%d" % (m.buf[o+noff:e].decode(), *rd(m.buf, o+16, "III"))
        w("   %-24s size=%-4d off=%#-8x %s" % (nm, size, o, extra))
    w("-- CHAINED FIXUPS present: %s (must be ABSENT for iOS12)"
      % (bool(m.lc_chain) if True else False))
    # ---- segments
    w("-- segments:")
    for s in m.segs:
        w("   %-16s vmaddr=%#011x vmsize=%#09x fileoff=%#09x filesize=%#09x initprot=%d maxprot=%d"
          % (s["name"], s["vmaddr"], s["vmsize"], s["fileoff"], s["filesize"], s["initprot"], s["maxprot"]))
    # ---- symtab sanity
    syms = m.symtab()
    undef = [s for s in syms if (s["type"] & 0x0E) == 0 and s["name"]]
    w("-- symtab: %d symbols, %d undefined" % (len(syms), len(undef)))
    w("-- dylibs (%d):" % len(m.dylibs))
    for k, d in enumerate(m.dylibs, 1):
        w("   [%d] %-48s cmd=%s" % (k, d["name"], LC.get(d["cmd"], d["cmd"])))
    ndyl = len(m.dylibs)
    nameset = {s["name"] for s in undef}
    # ---- streams
    if not m.lc_info:
        w("!! NO LC_DYLD_INFO_ONLY")
        continue
    o = m.lc_info[0][2]
    ro, rs, bo, bs, wo, ws, eo, es, lo, ls = rd(m.buf, o+8, "10I")
    w("-- rebase stream off=%#x size=%d" % (ro, rs))
    reb, done, i, ops = walk_rebase(m, ro, rs)
    w("   opcodes=%d entries=%d  DONE at fileoff=%#x (consumed %d of %d declared bytes)"
      % (ops, len(reb), done, (done - ro) if done else -1, rs))
    if done is None:
        w("   !! NO DONE OPCODE - stream ran off the declared end")
    else:
        tail = m.buf[done:ro+rs]
        w("   trailing bytes after DONE: %d, all-zero=%s" % (len(tail), all(x == 0 for x in tail)))
        w("   declared end=%#x  next command stream starts at=%#x" % (ro+rs, bo))
    if ro + rs > len(m.buf):
        w("   !! rebase stream exceeds file size")
    anom = []
    rw = {}
    for k, (si, so, ty) in enumerate(reb):
        if si >= len(m.segs):
            anom.append("rebase[%d] bad segindex %d (nsegs=%d)" % (k, si, len(m.segs))); continue
        seg = m.segs[si]
        vm = seg["vmaddr"] + so
        if so >= seg["vmsize"]:
            anom.append("rebase[%d] offset %#x outside %s vmsize %#x" % (k, so, seg["name"], seg["vmsize"]))
        if so + 8 > seg["filesize"]:
            anom.append("rebase[%d] slot %#x not file-backed in %s" % (k, vm, seg["name"]))
        if not (seg["initprot"] & W_PROT):
            anom.append("rebase[%d] slot %#x in NON-WRITABLE segment %s initprot=%d"
                        % (k, vm, seg["name"], seg["initprot"]))
        fo = m.foff(vm)
        if fo is not None:
            val = rd(m.buf, fo, "Q")[0]
            tgt = m.seg_of(val)
            if val != 0 and tgt is None:
                anom.append("rebase[%d] slot %#x holds %#x which is NOT in any mapped segment"
                            % (k, vm, val))
            rw.setdefault(seg["name"], 0)
            rw[seg["name"]] += 1
    w("   rebases per segment: %s" % rw)
    w("   ANOMALIES: %d" % len(anom))
    for a in anom[:40]:
        w("     " + a)

    for kind, off_, size_ in (("bind", bo, bs), ("weak", wo, ws), ("lazy", lo, ls)):
        if size_ == 0:
            w("-- %s stream: EMPTY (off=%#x size=0)" % (kind, off_))
            continue
        w("-- %s stream off=%#x size=%d" % (kind, off_, size_))
        ent, done2, i2, ops2 = walk_bind(m, off_, size_, kind)
        w("   opcodes=%d entries=%d DONE at fileoff=%#x (consumed %d of %d)"
          % (ops2, len(ent), done2, (done2 - off_) if done2 else -1, size_))
        if done2 is None:
            w("   !! NO DONE OPCODE in %s stream" % kind)
        elif kind in ("lazy",):
            pass
        else:
            tail = m.buf[done2:off_+size_]
            w("   trailing bytes after DONE: %d, all-zero=%s" % (len(tail), all(x == 0 for x in tail)))
        if off_ + size_ > len(m.buf):
            w("   !! %s stream exceeds file size" % kind)
        an2 = []
        sset = {}
        ordc = {}
        segc = {}
        for k, e in enumerate(ent):
            nm = e["name"]
            sset[nm] = sset.get(nm, 0) + 1
            ordc[e["ordinal"]] = ordc.get(e["ordinal"], 0) + 1
            if nm is None:
                an2.append("%s[%d] no symbol name set before bind" % (kind, k)); continue
            if not nm:
                an2.append("%s[%d] EMPTY symbol name" % (kind, k))
            if nm not in nameset:
                an2.append("%s[%d] symbol %r is NOT an undefined external in the symtab" % (kind, k, nm))
            if kind != "weak":
                if e["ordinal"] < 0:
                    pass  # special (flat/weak) lookup
                elif e["ordinal"] == 0:
                    an2.append("%s[%d] symbol %r uses ordinal 0 (self) - suspicious" % (kind, k, nm))
                elif e["ordinal"] > ndyl:
                    an2.append("%s[%d] symbol %r ordinal %d OUT OF RANGE (ndylibs=%d)"
                               % (kind, k, nm, e["ordinal"], ndyl))
            if e["segi"] >= len(m.segs):
                an2.append("%s[%d] symbol %r bad segindex %d" % (kind, k, nm, e["segi"])); continue
            seg = m.segs[e["segi"]]
            vm = seg["vmaddr"] + e["segoff"]
            if e["segoff"] + 8 > seg["filesize"]:
                an2.append("%s[%d] symbol %r slot %#x not file-backed in %s"
                           % (kind, k, nm, vm, seg["name"]))
            if not (seg["initprot"] & W_PROT):
                an2.append("%s[%d] symbol %r slot %#x in NON-WRITABLE segment %s initprot=%d"
                           % (kind, k, nm, vm, seg["name"], seg["initprot"]))
            segc[seg["name"]] = segc.get(seg["name"], 0) + 1
        w("   distinct symbols=%d ; per-segment: %s" % (len(sset), segc))
        w("   ordinals used: %s" % dict(sorted(ordc.items())))
        w("   ANOMALIES: %d" % len(an2))
        for a in an2[:40]:
            w("     " + a)
    # ---- weak-import count from symtab/indirect table
    w("-- undefined symbols with N_WEAK_REF (desc & 0x40): %d ; with N_WEAK_DEF (0x80): %d"
      % (sum(1 for s in undef if s["desc"] & 0x40), sum(1 for s in undef if s["desc"] & 0x80)))
    # ---- LC_MAIN entry file offset sanity
    if m.lc_main:
        eo2 = rd(m.buf, m.lc_main[0][2] + 8, "Q")[0]
        seg = m.segs[0]
        w("-- entryoff=%#x -> vmaddr=%#x in %s ; first word=%08X"
          % (eo2, seg["vmaddr"] + eo2, seg["name"], rd(m.buf, eo2, "I")[0]))
OUT.close()
print("\nwritten b4_dyld.txt")
