# -*- coding: utf-8 -*-
"""Task 2: independent verification of the four _objc_opt_* GOT thunks.

Standalone Mach-O reader (no chained2dyld import) so nothing is re-derived from
the same code that wrote the patch.
"""
import struct, sys, hashlib

BASE = "H:/file/phi/"
OUT = open(BASE + "b3_thunks.txt", "w", encoding="utf-8")
def w(*a):
    s = " ".join(str(x) for x in a)
    print(s)
    OUT.write(s + "\n")

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_DYLD_INFO_ONLY = 0x80000022
S_NONLAZY = 0x6
S_LAZY = 0x7
S_NONLAZY_16 = 0x8

def rd(b, o, f):
    return struct.unpack_from("<" + f, b, o)

class MO:
    def __init__(self, path):
        self.path = path
        self.buf = open(path, "rb").read()
        b = self.buf
        self.magic, self.cputype, _cs, self.ftype, self.ncmds, self.sizeofcmds, _fl, _r = \
            rd(b, 0, "IiiIIIII")
        assert self.magic == MH_MAGIC_64, hex(self.magic)
        self.cmds = []
        o = 32
        for _ in range(self.ncmds):
            cmd, size = rd(b, o, "II")
            self.cmds.append((cmd, size, o))
            o += size
        self.segs, self.sects = [], []
        for cmd, size, o in self.cmds:
            if cmd != LC_SEGMENT_64:
                continue
            nm = b[o+8:o+24].rstrip(b"\0").decode()
            vma, vms, fo, fs = rd(b, o+24, "QQQQ")
            maxp, initp, nsect, sfl = rd(b, o+56, "iiII")
            si = len(self.segs)
            self.segs.append(dict(i=si, name=nm, vmaddr=vma, vmsize=vms, fileoff=fo,
                                  filesize=fs, initprot=initp, maxprot=maxp, nsects=nsect))
            so = o + 72
            for _j in range(nsect):
                sn = b[so:so+16].rstrip(b"\0").decode()
                sg = b[so+16:so+32].rstrip(b"\0").decode()
                addr, sz = rd(b, so+32, "QQ")
                off, align, reloff, nrel, flg = rd(b, so+48, "IIIII")
                res1, res2, res3 = rd(b, so+68, "III")
                self.sects.append(dict(name=sn, seg=sg, addr=addr, size=sz, offset=off,
                                       flags=flg, reserved1=res1, reserved2=res2,
                                       reserved3=res3, segi=si))
                so += 80
        self.by_name = {s["name"]: s for s in self.segs}

    def sect(self, seg, name):
        for s in self.sects:
            if s["seg"] == seg and s["name"] == name:
                return s
        return None

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
        if d >= s["filesize"]:
            return None
        return s["fileoff"] + d

    def symtab(self):
        c = [x for x in self.cmds if x[0] == LC_SYMTAB]
        if not c:
            return []
        o = c[0][2]
        symoff, nsyms, stroff, strsize = rd(self.buf, o + 8, "IIII")
        out = []
        for i in range(nsyms):
            n_strx, n_type, n_sect, n_desc, n_value = rd(self.buf, symoff + 16*i, "IBBHQ")
            e = self.buf.index(b"\0", stroff + n_strx)
            nm = self.buf[stroff + n_strx:e].decode("utf-8", "replace")
            out.append(dict(i=i, name=nm, type=n_type, sect=n_sect, desc=n_desc, value=n_value))
        return out

    def dysym(self):
        c = [x for x in self.cmds if x[0] == LC_DYSYMTAB]
        if not c:
            return None
        o = c[0][2]
        (iloc, niloc, iext, niext, iund, nund, toc, ntoc, mext, nmext,
         extref, nextref, indsymoff, nindsym) = rd(self.buf, o + 8, "IIIIIIIIIIIIII")
        return dict(indsymoff=indsymoff, nindsym=nindsym, iund=iund, nund=nund,
                    nextref=nextref, extref=extref)

    def indsym(self, idx):
        d = self.dysym()
        return rd(self.buf, d["indsymoff"] + 4*idx, "I")[0]

def dis_thunk(m, t):
    """decode 6 instructions at vmaddr t"""
    fo = m.foff(t)
    if fo is None:
        return dict(addr=t, words=[], error="vmaddr not file-backed")
    ins = [rd(m.buf, fo + 4*i, "I")[0] for i in range(6)]
    res = dict(addr=t, words=ins)
    p = 0
    if ins[0] == 0xAA0103E2:
        res["mov_x2_x1"] = True
        p = 1
    else:
        res["mov_x2_x1"] = False
    a = ins[p]
    res["adrp"] = a
    immhi = (a >> 5) & 0x7FFFF
    immlo = (a >> 29) & 3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    pc = t + 4*p
    page = ((pc & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
    res["adrp_page"] = page
    res["adrp_rd"] = a & 0x1F
    l = ins[p+1]
    res["ldr"] = l
    res["ldr_rt"] = l & 0x1F
    res["ldr_rn"] = (l >> 5) & 0x1F
    off = ((l >> 10) & 0xFFF) * 8
    res["ldr_off"] = off
    res["slot_addr"] = page + off
    res["mov_x1_x16"] = (ins[p+2] == 0xAA1003E1)
    br = ins[p+3]
    res["branch"] = br
    d = br & 0x3FFFFFF
    if d & (1 << 25):
        d -= (1 << 26)
    res["branch_pc"] = t + 4*(p+3)
    res["branch_target"] = t + 4*(p+3) + d*4
    res["n_insn"] = p + 4
    return res

WANT = [("_objc_opt_class", b"class", False),
        ("_objc_opt_isKindOfClass", b"isKindOfClass:", True),
        ("_objc_opt_new", b"new", False),
        ("_objc_opt_respondsToSelector", b"respondsToSelector:", True)]

def check(m, label, expect_thunks):
    w("=" * 78)
    w("### %s  %s  size=%d sha256=%s" % (label, m.path, len(m.buf),
                                         hashlib.sha256(m.buf).hexdigest()[:16]))
    w("=" * 78)
    syms = m.symtab()
    bys = {}
    for s in syms:
        bys.setdefault(s["name"], []).append(s)
    dy = m.dysym()
    w("symtab: %d symbols; dysymtab indsymoff=%#x nindirect=%d" % (len(syms), dy["indsymoff"], dy["nindsym"]))
    got_slots = {}
    for s in m.sects:
        if s["name"] not in ("__got", "__la_symbol_ptr", "__nl_symbol_ptr", "__auth_got"):
            continue
        if s["flags"] & 0xFF in (S_NONLAZY, S_LAZY, S_NONLAZY_16):
            kind = {S_NONLAZY: "nl", S_LAZY: "lz", S_NONLAZY_16: "nl16"}[s["flags"] & 0xFF]
            n = s["size"] // 8
            for k in range(n):
                idx = m.indsym(s["reserved1"] + k)
                if idx & 0x80000000 or idx >= len(syms):
                    continue
                nm = syms[idx]["name"]
                isl = bool(idx & 0x40000000) if False else False
                got_slots.setdefault(nm, []).append(
                    dict(seg=s["seg"], sect=s["name"], kind=kind,
                         vmaddr=s["addr"] + 8*k, offset=s["offset"] + 8*k,
                         indsym_idx=s["reserved1"] + k, symidx=idx,
                         value=rd(m.buf, s["offset"] + 8*k, "Q")[0],
                         symval=syms[idx]["value"], symtype=syms[idx]["type"]))
    for sym, sel, has_arg in WANT:
        w("--- %s (expected selector %r, arg-shuffle=%s)" % (sym, sel, has_arg))
        e = bys.get(sym)
        if not e:
            w("    !! symbol NOT in symtab")
            continue
        for s in e:
            w("    nlist: index=%d type=%#x (N_UNDF=%s N_EXT=%s) sect=%d desc=%#x value=%#x"
              % (s["i"], s["type"], hex(s["type"] & 0x0E), bool(s["type"] & 1), s["sect"], s["desc"], s["value"]))
        slots = got_slots.get(sym)
        if not slots:
            w("    !! no __got/__la_symbol_ptr slot bound to this symbol")
            continue
        for sl in slots:
            w("    slot %s,%s vmaddr=%#x fileoff=%#x indsym_idx=%d -> nlist#%d content=0x%016X"
              % (sl["seg"], sl["sect"], sl["vmaddr"], sl["offset"], sl["indsym_idx"],
                 sl["symidx"], sl["value"]))
            t = sl["value"]
            in_txt = m.by_name["__TEXT"]
            inseg = in_txt["vmaddr"] <= t < in_txt["vmaddr"] + in_txt["vmsize"]
            insec = [x["name"] for x in m.sects if x["addr"] <= t < x["addr"] + x["size"]]
            w("    thunk inside __TEXT=%s ; inside sections=%s" % (inseg, insec or "NONE (padding)"))
            r = dis_thunk(m, t)
            if "error" in r:
                w("    !! disassembly impossible: %s" % r["error"])
                continue
            w("    raw words: %s" % " ".join("%08X" % x for x in r["words"]))
            w("    decoded  : mov x2,x1=%s adrp x%d,#%#x ldr x%d,[x%d,#%#x] mov x1,x16=%s b->%#x"
              % (r["mov_x2_x1"], r["adrp_rd"], r["adrp_page"], r["ldr_rt"], r["ldr_rn"],
                 r["ldr_off"], r["mov_x1_x16"], r["branch_target"]))
            w("    slot it loads = %#x" % r["slot_addr"])
            sfo = m.foff(r["slot_addr"])
            if sfo is None:
                w("    !! slot not in file")
                continue
            ptr = rd(m.buf, sfo, "Q")[0]
            w("    selref slot content = 0x%016X" % ptr)
            cfo = m.foff(ptr)
            if cfo is None:
                w("    !! selref target not mapped in file (not a rebased pointer?)")
                continue
            z = m.buf.index(b"\0", cfo, cfo + 256)
            name = m.buf[cfo:z]
            ss = m.sect_of(ptr) if hasattr(m, "sect_of") else None
            w("    selector string at %#x = %r   ---> %s"
              % (ptr, name, "MATCH" if name == sel else "*** MISMATCH, expected %r ***" % sel))
        # expected-thunk cross-check
        if expect_thunks and sym in expect_thunks:
            w("    (pristine GOT slot value was %#x)" % expect_thunks[sym][0]["value"])
    # objc_msgSend stub
    msg = got_slots.get("_objc_msgSend")
    w("--- _objc_msgSend got slots: %s" % ([hex(x["vmaddr"]) for x in msg] if msg else "NONE"))
    stub = None
    if msg:
        target_vm = msg[0]["vmaddr"]
        st = m.sect("__TEXT", "__stubs")
        if st:
            for k in range(st["size"] // 12):
                a = st["addr"] + 12*k
                fo = st["offset"] + 12*k
                i0, i1, i2 = rd(m.buf, fo, "III")
                if i0 & 0x9F000000 != 0x90000000 or (i0 & 0x1F) != 16:
                    continue
                immhi = (i0 >> 5) & 0x7FFFF
                immlo = (i0 >> 29) & 3
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= (1 << 21)
                page = (a & ~0xFFF) + (imm << 12)
                slot = page + (((i1 >> 10) & 0xFFF) * 8)
                if slot == target_vm:
                    stub = a
                    w("objc_msgSend stub: vmaddr=%#x words=%08X %08X %08X  (ads slot %#x, br x16)"
                      % (a, i0, i1, i2, slot))
                    break
    if stub is None:
        w("!! objc_msgSend stub NOT FOUND")
    return got_slots, stub


mp = MO(BASE + "work/UnityFramework")
ms = MO(BASE + "out/UnityFramework.v4")
_, _ = check(mp, "PRISTINE", None)
gs, stub = check(ms, "PATCHED v4", None)

# cross-check each patched thunk's branch target == pristine objc_msgSend stub
w("")
w("### branch-target cross check")
for sym, sel, has_arg in WANT:
    v = gs.get(sym)
    if not v:
        w("  %s: no slot" % sym)
        continue
    r = dis_thunk(ms, v[0]["value"])
    w("  %-30s branch->0x%X  == objc_msgSend stub 0x%X ? %s"
      % (sym, r["branch_target"], stub, r["branch_target"] == stub))
OUT.close()
print("\nwritten b3_thunks.txt")
