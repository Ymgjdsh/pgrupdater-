#!/usr/bin/env python3
"""
chained2dyld.py -- convert a Mach-O that uses LC_DYLD_CHAINED_FIXUPS (dyld-852+,
iOS 15+) into the classic LC_DYLD_INFO_ONLY form that ancient dyld (iOS 12)
understands, and lower the platform min-OS to 12.0.

Why: chained fixups *replace* LC_DYLD_INFO and delete __DATA,__la_symbol_ptr.
dyld-655 (iOS 12) has no code for them, so it never rebases/binds __DATA and the
image dies on first pointer dereference.  We decode the chained tables ourselves
and re-emit equivalent classic rebase/bind opcode streams, and pre-clean the
slots so old dyld's "read 8 bytes, add slide" semantics see sane values.

Usage:
  python chained2dyld.py <in> <out> [--weak-file NAMES.txt] [--dry-run]
  python chained2dyld.py <in> --verify
"""
import struct, sys, os, json, argparse

MH_MAGIC_64 = 0xFEEDFACF
# load commands
LC_SEGMENT_64              = 0x19
LC_SYMTAB                  = 0x02
LC_DYSYMTAB                = 0x0B
LC_CODE_SIGNATURE          = 0x1D
LC_VERSION_MIN_IPHONEOS    = 0x25
LC_BUILD_VERSION           = 0x32
LC_DYLD_INFO               = 0x22
LC_DYLD_INFO_ONLY          = 0x80000022
LC_DYLD_EXPORTS_TRIE       = 0x80000033
LC_DYLD_CHAINED_FIXUPS     = 0x80000034

# rebase opcodes
REBASE_OPCODE_DONE                             = 0x00
REBASE_OPCODE_SET_TYPE_IMM                     = 0x10
REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB      = 0x20
REBASE_OPCODE_ADD_ADDR_ULEB                    = 0x30
REBASE_OPCODE_ADD_ADDR_IMM_SCALED              = 0x40
REBASE_OPCODE_DO_REBASE_IMM_TIMES              = 0x50
REBASE_OPCODE_DO_REBASE_ULEB_TIMES             = 0x60
REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB          = 0x70
REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80
REBASE_TYPE_POINTER                            = 1

# bind opcodes
BIND_OPCODE_DONE                               = 0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM              = 0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB             = 0x20
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM              = 0x30
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM      = 0x40
BIND_OPCODE_SET_TYPE_IMM                       = 0x50
BIND_OPCODE_SET_ADDEND_SLEB                    = 0x60
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB        = 0x70
BIND_OPCODE_ADD_ADDR_ULEB                      = 0x80
BIND_OPCODE_DO_BIND                            = 0x90
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB              = 0xA0
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED        = 0xB0
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB   = 0xC0
BIND_TYPE_POINTER                              = 1
BIND_SYMBOL_FLAGS_WEAK_IMPORT                  = 0x01
BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION          = 0x08

CHAINED_PTR_64_OFFSET = 6
CHAINED_PTR_64        = 2

def rd(buf, off, fmt):  return struct.unpack_from("<" + fmt, buf, off)
def uleb(n):
    n &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: out.append(b | 0x80)
        else: out.append(b); return bytes(out)
def sleb(n):
    out = bytearray(); more = True
    while more:
        b = n & 0x7F; n >>= 7
        if (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40)): more = False
        else: b |= 0x80
        out.append(b)
    return bytes(out)
def round_up(v, a): return (v + a - 1) // a * a


class MachO:
    def __init__(self, data):
        self.buf = bytearray(data)
        b = self.buf
        magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = rd(b, 0, "IiiIIIII")
        assert magic == MH_MAGIC_64, hex(magic)
        self.cputype, self.ftype, self.flags, self.ncmds = cputype, ftype, flags, ncmds
        self.sizeofcmds = sizeofcmds
        self.cmds = []
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = rd(b, off, "II")
            self.cmds.append(dict(cmd=cmd, size=cmdsize, off=off, raw=bytes(b[off:off+cmdsize])))
            off += cmdsize
        self.segments, self.sections, self.seg_by_name = [], [], {}
        for c in self.cmds:
            if c["cmd"] != LC_SEGMENT_64: continue
            co = c["off"]
            name = bytes(b[co+8:co+24]).rstrip(b"\0").decode("utf-8", "replace")
            vmaddr, vmsize, fileoff, filesize = rd(b, co+24, "QQQQ")
            maxprot, initprot, nsects, segflags = rd(b, co+56, "iiII")
            si = len(self.segments)
            seg = dict(idx=si, name=name, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff,
                       filesize=filesize, maxprot=maxprot, initprot=initprot, nsects=nsects,
                       flags=segflags, lc_off=co, lc_size=c["size"])
            self.segments.append(seg); self.seg_by_name[name] = seg
            so = co + 72
            for _j in range(nsects):
                sn = bytes(b[so:so+16]).rstrip(b"\0").decode("utf-8", "replace")
                sg = bytes(b[so+16:so+32]).rstrip(b"\0").decode("utf-8", "replace")
                addr, size = rd(b, so+32, "QQ")
                offset, align, reloff, nreloc, sflags = rd(b, so+48, "IIIII")
                self.sections.append(dict(seg=sg, name=sn, addr=addr, size=size,
                                          offset=offset, flags=sflags, segidx=si))
                so += 80
        t = self.seg_by_name.get("__TEXT")
        self.image_base = t["vmaddr"] if t else 0

    def lc(self, cmd): return [c for c in self.cmds if c["cmd"] == cmd]
    def sect_of(self, vmaddr):
        best = None
        for s in self.sections:
            if s["addr"] <= vmaddr < s["addr"] + s["size"]:
                if best is None or s["addr"] > best["addr"]: best = s
        return best
    def seg_of(self, vmaddr):
        for s in self.segments:
            if s["vmaddr"] <= vmaddr < s["vmaddr"] + s["vmsize"]: return s
        return None
    def foff(self, vmaddr):
        s = self.seg_of(vmaddr)
        if s is None: return None
        fo = s["fileoff"] + (vmaddr - s["vmaddr"])
        if vmaddr - s["vmaddr"] >= s["filesize"]: return None     # in __bss -> not in file
        return fo


# ---------------------------------------------------------------- fixups decode
def decode_fixups(m):
    """returns dict(imports=[...], fixups=[{seg,vmaddr,foff,kind,target|ordinal,addend,high8}])
    file offsets and vmaddrs are both correct (they are NOT the same for stub exes)."""
    b = m.buf
    cf = m.lc(LC_DYLD_CHAINED_FIXUPS)
    if not cf: return None
    co = cf[0]["off"]
    dataoff, datasize = rd(b, co+8, "II")
    base = dataoff
    (fv, starts_off, imports_off, symbols_off, imports_count,
     imports_format, symbols_format) = rd(b, base, "IIIIIII")
    imports = []
    stride = {1: 4, 2: 8, 3: 16}[imports_format]
    for i in range(imports_count):
        eo = base + imports_off + i*stride
        if imports_format == 1:
            v = rd(b, eo, "I")[0]
            lib_ord, weak, name_off = v & 0xFF, (v >> 8) & 1, (v >> 9) & 0x7FFFFF
            addend = 0
        elif imports_format == 2:
            v0, v1 = rd(b, eo, "Ii")
            lib_ord, weak, name_off = v0 & 0xFF, (v0 >> 8) & 1, (v0 >> 9) & 0x7FFFFF
            addend = v1
        else:
            v0, v1 = rd(b, eo, "QQ")
            lib_ord, weak, name_off = v0 & 0xFFFF, (v0 >> 16) & 1, (v0 >> 17) & 0x7FFFFFFF
            addend = struct.unpack("<q", struct.pack("<Q", v1))[0]
        so = base + symbols_off + name_off
        e = b.index(b"\0", so)
        imports.append(dict(idx=i, lib_ordinal=lib_ord, weak=weak,
                            name=b[so:e].decode("utf-8", "replace"), addend=addend))

    sc = rd(b, base + starts_off, "I")[0]
    seg_info_off = [rd(b, base + starts_off + 4 + 4*i, "I")[0] for i in range(sc)]
    fixups = []
    ptr_formats = {}
    for si, sio in enumerate(seg_info_off):
        if sio == 0: continue
        sp = base + starts_off + sio
        size, page_size, pointer_format, segment_offset, max_valid, page_count = \
            rd(b, sp, "IHHQIH")
        if si < len(m.segments):
            ptr_formats[m.segments[si]["name"]] = pointer_format
        # page starts -- must mirror dyld MachOLoaded.cpp:867-890 exactly:
        # 0xFFFF = START_NONE, 0x8000 = START_MULTI on the page entry and
        # START_LAST on each overflow entry; the overflow list is just more
        # uint16 entries appended to the SAME page_start[] array (2-byte stride).
        def ps_at(idx): return rd(b, sp + 22 + 2*idx, "H")[0]
        starts = []
        for pi in range(page_count):
            v = ps_at(pi)
            if v == 0xFFFF: continue
            if v & 0x8000:
                oi = v & 0x7FFF
                while True:
                    w = ps_at(oi)
                    starts.append((pi, w & 0x7FFF))
                    if w & 0x8000: break
                    oi += 1
            else:
                starts.append((pi, v))
        raw_base = segment_offset
        seg = m.segments[si] if si < len(m.segments) else None
        for pi, ps in starts:
            # dyld: pageContent = (uint8_t*)this + segInfo->segment_offset + pageIndex*page_size
            # i.e. segment_offset is relative to the MACH HEADER (= image_base), not absolute vmaddr
            raw_addr = raw_base + pi*page_size + ps
            fo_of_chain = raw_addr                        # file offset (fileoff==vmaddr-image_base here)
            while True:
                if fo_of_chain + 8 > len(b): break
                raw = rd(b, fo_of_chain, "Q")[0]
                is_bind = (raw >> 63) & 1
                nxt = (raw >> 51) & 0xFFF
                vmaddr = m.image_base + raw_addr
                fo = m.foff(vmaddr)
                if is_bind:
                    ordinal = raw & 0xFFFFFF
                    a8 = (raw >> 24) & 0xFF
                    sa = (a8 - 256) if (a8 >= 128 and pointer_format in (CHAINED_PTR_64, CHAINED_PTR_64_OFFSET)) else a8
                    imp = imports[ordinal] if ordinal < len(imports) else None
                    fixups.append(dict(seg=si, vmaddr=vmaddr, foff=fo, kind="bind",
                                       ordinal=ordinal, addend=sa,
                                       name=imp["name"] if imp else None,
                                       lib=imp["lib_ordinal"] if imp else None,
                                       weak=imp["weak"] if imp else None))
                else:
                    target = raw & 0xFFFFFFFFF
                    high8 = (raw >> 36) & 0xFF
                    fixups.append(dict(seg=si, vmaddr=vmaddr, foff=fo, kind="rebase",
                                       target=m.image_base + target, high8=high8))
                if nxt == 0: break
                raw_addr += nxt * 4
                fo_of_chain += nxt * 4
    return dict(imports=imports, fixups=fixups, ptr_formats=ptr_formats,
                exports=None, fixups_dataoff=dataoff, fixups_datasize=datasize)


# ------------------------------------------------ objc_opt_* shims (iOS < 13 only)
# iOS 12's libobjc has no objc_opt_class / objc_opt_isKindOfClass / objc_opt_new /
# objc_opt_respondsToSelector: they appeared in iOS 13, yet clang emits a call to them
# for every [obj class] / isKindOfClass: / respondsToSelector: / +new fast path, so a
# binary built against a newer SDK cannot launch while they are unresolved.  Instead of
# leaving the import weak (a guaranteed NULL call), point each __got slot at a small
# arm64 thunk written into the zero padding at the end of __TEXT; the thunk loads the
# matching selector from __objc_selrefs and tail-calls objc_msgSend, which is what the
# real fast paths do.
OBJC_OPT_SHIMS = [
    # symbol, selector, does the fast path pass an extra Class/SEL argument (x1 -> x2)?
    ("_objc_opt_class", b"class", False),
    ("_objc_opt_isKindOfClass", b"isKindOfClass:", True),
    ("_objc_opt_respondsToSelector", b"respondsToSelector:", True),
    ("_objc_opt_new", b"new", False),
]


def _enc_adrp(rd, target, pc):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    assert -(1 << 20) <= imm < (1 << 20), f"adrp out of range: {imm}"
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def _enc_ldr64(rt, rn, off):
    assert off % 8 == 0 and 0 <= off < 0x8000, f"ldr offset bad: {off}"
    return 0xF9400000 | ((off // 8) << 10) | (rn << 5) | rt


def _enc_mov(rd, rm):                       # ORR Xd, XZR, Xm
    return 0xAA0003E0 | (rm << 16) | rd


def _enc_b(target, pc):
    d = target - pc
    assert d % 4 == 0 and -(1 << 27) <= d < (1 << 27), f"b out of range: {d}"
    return 0x14000000 | ((d >> 2) & 0x3FFFFFF)


def _dec_adrp(insn, pc):
    imm = ((((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 3))
    if imm & (1 << 20): imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)


def _enc_sub_sp(imm):
    assert imm % 16 == 0 and 0 < imm < 0x1000, f"sub sp bad: {imm}"
    return 0xD1000000 | (imm << 10) | (31 << 5) | 31


def _enc_add_sp(imm):
    assert imm % 16 == 0 and 0 < imm < 0x1000, f"add sp bad: {imm}"
    return 0x91000000 | (imm << 10) | (31 << 5) | 31


def _enc_stp_x(rt, rt2, rn, off):           # STP Xt, Xt2, [Xn|SP, #off]
    assert off % 8 == 0 and -512 <= off <= 504, f"stp x bad: {off}"
    return 0xA9000000 | (((off // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def _enc_ldp_x(rt, rt2, rn, off):
    assert off % 8 == 0 and -512 <= off <= 504, f"ldp x bad: {off}"
    return 0xA9400000 | (((off // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def _enc_stp_q(rt, rt2, rn, off):           # STP Qt, Qt2, [Xn|SP, #off]  (opc=10, V=1)
    assert off % 16 == 0 and -1024 <= off <= 1008, f"stp q bad: {off}"
    return 0xAD000000 | (((off // 16) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def _enc_ldp_q(rt, rt2, rn, off):
    assert off % 16 == 0 and -1024 <= off <= 1008, f"ldp q bad: {off}"
    return 0xAD400000 | (((off // 16) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def _enc_str_x(rt, rn, off):                # STR Xt, [Xn|SP, #off]
    assert off % 8 == 0 and 0 <= off < 0x8000, f"str x bad: {off}"
    return 0xF9000000 | ((off // 8) << 10) | (rn << 5) | rt


def _enc_cbz_x(rt, target, pc):
    d = target - pc
    assert d % 4 == 0 and -(1 << 20) <= d < (1 << 20), f"cbz x out of range: {d}"
    return 0xB4000000 | (((d >> 2) & 0x7FFFF) << 5) | rt


def _enc_cbz_w(rt, target, pc):
    d = target - pc
    assert d % 4 == 0 and -(1 << 20) <= d < (1 << 20), f"cbz w out of range: {d}"
    return 0x34000000 | (((d >> 2) & 0x7FFFF) << 5) | rt


def _enc_movz_x(rd, imm):
    assert 0 <= imm < 0x10000
    return 0xD2800000 | (imm << 5) | rd


def _enc_movz_w(rd, imm):
    assert 0 <= imm < 0x10000
    return 0x52800000 | (imm << 5) | rd


def _enc_movi_v0_zero():                    # MOVI V0.16B, #0
    return 0x4F00E400


def _enc_bl(target, pc):
    d = target - pc
    assert d % 4 == 0 and -(1 << 27) <= d < (1 << 27), f"bl out of range: {d}"
    return 0x94000000 | ((d >> 2) & 0x3FFFFFF)


def _enc_br(rt):
    return 0xD61F0000 | (rt << 5)


def _enc_blr(rt):
    return 0xD63F0000 | (rt << 5)


_ENC_RET = 0xD65F03C0


def _words(*ins):
    return b"".join(struct.pack("<I", x) for x in ins)


def find_objc_msgSend_stub(m, buf, fixups):
    """first __TEXT,__stubs entry that jumps through the __got slot of _objc_msgSend"""
    got2name = {f["vmaddr"]: f["name"] for f in fixups if f["kind"] == "bind"}
    for st in m.sections:
        if st["seg"] != "__TEXT" or st["name"] != "__stubs": continue
        for i in range(st["size"] // 12):
            a, o = st["addr"] + i * 12, st["offset"] + i * 12
            i0, i1, i2 = rd(buf, o, "III")
            if i0 & 0x9F000000 != 0x90000000: continue
            if i1 & 0xFFC00000 != 0xF9400000 or i2 != 0xD61F0200: continue
            if got2name.get(_dec_adrp(i0, a) + ((i1 >> 10) & 0xFFF) * 8) == "_objc_msgSend":
                return a
    return None


def find_selref_slots(m, buf, fixups):
    """{selector bytes -> vmaddr of a __objc_selrefs slot holding that selector}"""
    sl = next((s for s in m.sections if s["name"] == "__objc_selrefs"), None)
    if sl is None: return {}
    reb_t = {f["vmaddr"]: f["target"] for f in fixups if f["kind"] == "rebase"}
    out = {}
    for off in range(0, sl["size"], 8):
        va = sl["addr"] + off
        tgt = reb_t.get(va)
        if tgt is None: continue
        fo = m.foff(tgt)
        if fo is None: continue
        z = buf.find(b"\0", fo, fo + 200)
        if z < 0: continue
        nm = bytes(buf[fo:z])
        if nm not in out: out[nm] = va
    return out


def plan_objc_opt_shims(m, buf, fixups, verbose=True):
    """rewrite the __got slots of the objc_opt_* fast paths into internal rebases that
    point at freshly written thunks; returns {symbol: thunk vmaddr} or None if unused"""
    sites = {sym: [f for f in fixups if f["kind"] == "bind" and f["name"] == sym]
             for sym, _sel, _a in OBJC_OPT_SHIMS}
    if not any(sites.values()):
        return None
    msg_stub = find_objc_msgSend_stub(m, buf, fixups)
    if msg_stub is None:
        raise SystemExit("shim: no objc_msgSend stub found")
    slots = find_selref_slots(m, buf, fixups)
    for _sym, sel, _a in OBJC_OPT_SHIMS:
        if sel not in slots:
            raise SystemExit(f"shim: selector {sel!r} not found in __objc_selrefs")
    txt = m.seg_by_name["__TEXT"]
    end = max(s["addr"] + s["size"] for s in m.sections if s["seg"] == "__TEXT")
    code_va = (end + 15) & ~15
    size = 0x20 * len(OBJC_OPT_SHIMS)
    if code_va + size > txt["vmaddr"] + txt["vmsize"]:
        raise SystemExit("shim: no free room at the end of __TEXT")
    code_fo = m.foff(code_va)
    if code_fo is None or any(buf[code_fo:code_fo + size]):
        raise SystemExit("shim: __TEXT tail is not free/zero-filled")
    plan = {}
    for i, (sym, sel, has_arg) in enumerate(OBJC_OPT_SHIMS):
        va = code_va + i * 0x20
        slot = slots[sel]
        page, off = slot & ~0xFFF, slot & 0xFFF
        ins, pc = [], va
        if has_arg:                          # the Class/SEL in x1 becomes argument 2
            ins.append(_enc_mov(2, 1)); pc += 4
        ins.append(_enc_adrp(16, page, pc)); pc += 4
        ins.append(_enc_ldr64(16, 16, off)); pc += 4
        ins.append(_enc_mov(1, 16)); pc += 4
        ins.append(_enc_b(msg_stub, pc))
        code = b"".join(struct.pack("<I", x) for x in ins)
        buf[code_fo + i * 0x20: code_fo + i * 0x20 + len(code)] = code
        plan[sym] = va
    n = 0
    for sym, va in plan.items():
        for f in sites[sym]:
            f["kind"] = "rebase"; f["target"] = va; f["high8"] = 0
            n += 1
    if verbose:
        print(f"  objc_opt shim: {n} got slot(s) -> {len(plan)} thunk(s) @0x{code_va:X}, "
              f"objc_msgSend stub 0x{msg_stub:X}, "
              f"selrefs {[hex(slots[s]) for _x, s, _a in OBJC_OPT_SHIMS]}")
    return dict(plan=plan, next_va=code_va + size, msg_stub=msg_stub)


# ------------------------------------------- iOS 12: @available() guards are gone
# 4.0.0 was linked with a deployment target of iOS 15, so every
# `if #available(iOS 13/14/15, *)` of the Unity engine was constant-folded to true:
# the chained binary imports no availability helper at all, while the 3.19.0 engine
# (deployment target 12, runs on this iPad) still calls its own helper 69 times.
# The first folded guard that bites on iOS 12 is
#     [UIApplication connectedScenes]        (v7: __objc_stubs call at 0xF914, in
# UnityAppController -initUnityWithApplication:+0x78) -- the very next thing the code
# does is follow the returned set.  iOS 12 raises NSInvalidArgumentException for the
# unknown selector, nobody catches it, and the 20 s launch watchdog then kills the
# process (0x8badf00d / "scene-create" / 17.96 s allowance).
#
# Enumerating and patching the folded guards is not viable: the guarded blocks found
# in 3.19.0 mention ~29 selectors, but that list includes plain iOS 2 APIs (init,
# isEqual:, addSubview:), i.e. a static audit cannot tell a guarded iOS 13 call from
# ordinary code that happens to sit in the same basic block.  So interpose
# objc_msgSend itself instead.  Every ObjC send of this image leaves through a
# __TEXT,__objc_stubs entry, and every one of those (2885 of them) loads objc_msgSend
# from a single __got slot, so retargeting that slot covers every send -- including
# the objc_opt_* fast paths:
#     respondsToSelector: -> tail call the real objc_msgSend (behaviour unchanged)
#     otherwise           -> return 0/nil, exactly what messaging nil does
# The dispatcher can therefore only differ from the original where the original would
# have raised.  Known caveat: selectors served dynamically by
# +resolveInstanceMethod: / forwardingTargetForSelector: answer NO to the probe.
AVAIL_DISPATCH_FRAME = 0x100


def build_avail_dispatcher(disp_va, selref_slot, msg_slot):
    """arm64 "availability-aware objc_msgSend" (position independent).
    selref_slot / msg_slot are absolute (unslid) vmaddrs: the __objc_selrefs slot
    holding respondsToSelector: and the __got slot of the *real* objc_msgSend.
    Everything the caller passed in x0-x8/q0-q7 must survive the probe, and the nil
    answer has to clear q0 too so float/vector results read as zero."""
    ins, pc = [], disp_va

    def emit(w):
        nonlocal pc
        ins.append(w); pc += 4

    def ldr_slot(rt, va):
        emit(_enc_adrp(rt, va & ~0xFFF, pc))
        emit(_enc_ldr64(rt, rt, va & 0xFFF))

    emit(_enc_sub_sp(AVAIL_DISPATCH_FRAME))
    emit(_enc_stp_x(29, 30, 31, 0xD0))
    for rt, off in ((0, 0x00), (2, 0x10), (4, 0x20), (6, 0x30)):
        emit(_enc_stp_x(rt, rt + 1, 31, off))
    emit(_enc_str_x(8, 31, 0x40))                     # x8 = indirect struct result ptr
    for rt, off in ((0, 0x50), (2, 0x70), (4, 0x90), (6, 0xB0)):
        emit(_enc_stp_q(rt, rt + 1, 31, off))         # d0..d31 as q0..q7
    nil_ref = len(ins); emit(0)                       # cbz x0, .Lnil
    emit(_enc_mov(2, 1))                              # receiver, _cmd, sel -> x0,x1,x2
    ldr_slot(1, selref_slot)
    ldr_slot(16, msg_slot)
    emit(_enc_blr(16))                                # [recv respondsToSelector:sel]
    nil2_ref = len(ins); emit(0)                      # cbz w0, .Lnil
    for rt, off in ((0, 0x00), (2, 0x10), (4, 0x20), (6, 0x30)):
        emit(_enc_ldp_x(rt, rt + 1, 31, off))
    emit(_enc_ldr64(8, 31, 0x40))
    for rt, off in ((0, 0x50), (2, 0x70), (4, 0x90), (6, 0xB0)):
        emit(_enc_ldp_q(rt, rt + 1, 31, off))
    emit(_enc_ldp_x(29, 30, 31, 0xD0))
    emit(_enc_add_sp(AVAIL_DISPATCH_FRAME))
    ldr_slot(16, msg_slot)
    emit(_enc_br(16))                                 # tail call the real objc_msgSend
    nil_va = pc                                       # .Lnil
    emit(_enc_ldp_x(29, 30, 31, 0xD0))
    emit(_enc_add_sp(AVAIL_DISPATCH_FRAME))
    emit(_enc_movz_x(0, 0))
    emit(_enc_movi_v0_zero())
    emit(_ENC_RET)
    ins[nil_ref] = _enc_cbz_x(0, nil_va, disp_va + 4 * nil_ref)
    ins[nil2_ref] = _enc_cbz_w(0, nil_va, disp_va + 4 * nil2_ref)
    return _words(*ins)


def text_code_va(m, buf, after_va=None):
    """first free 16-byte-aligned address in the zero padding at the end of __TEXT"""
    txt = m.seg_by_name["__TEXT"]
    end = max(s["addr"] + s["size"] for s in m.sections if s["seg"] == "__TEXT")
    va = round_up(end, 16)
    if after_va and after_va > va:
        va = round_up(after_va, 16)
    if va >= txt["vmaddr"] + txt["vmsize"]:
        raise SystemExit("no free room left at the end of __TEXT")
    return va


def place_code(m, buf, va, code, what):
    txt = m.seg_by_name["__TEXT"]
    fo = m.foff(va)
    if fo is None or va + len(code) > txt["vmaddr"] + txt["vmsize"]:
        raise SystemExit(f"{what}: does not fit in __TEXT at 0x{va:X}")
    if any(buf[fo:fo + len(code)]):
        raise SystemExit(f"{what}: __TEXT tail at 0x{va:X} is not free/zero filled")
    buf[fo:fo + len(code)] = code
    return fo


def count_slot_refs(m, buf, slot_vas):
    """{slot vmaddr: number of __objc_stubs / __stubs entries loading it} (diagnostic)"""
    n = {}
    for st in m.sections:
        if st["seg"] != "__TEXT" or st["name"] not in ("__objc_stubs", "__stubs"):
            continue
        step = 32 if st["name"] == "__objc_stubs" else 12
        extra = 8 if st["name"] == "__objc_stubs" else 0
        for i in range(st["size"] // step):
            a, o = st["addr"] + i * step, st["offset"] + i * step + extra
            i0, i1 = rd(buf, o, "II")
            if i0 & 0x9F000000 != 0x90000000 or i1 & 0xFFC00000 != 0xF9400000:
                continue
            va = _dec_adrp(i0, a + extra) + ((i1 >> 10) & 0xFFF) * 8
            if va in slot_vas:
                n[va] = n.get(va, 0) + 1
    return n


def plan_avail_dispatch(m, buf, fixups, rel, after_va=None, verbose=True):
    """Retarget every _objc_msgSend __got slot at the availability dispatcher.
    Returns dict(code_va, next_va, retargeted, real_slot_va, new_binds=[fixup]) or None."""
    msg_fix = [f for f in fixups if f["kind"] == "bind" and f["name"] == "_objc_msgSend"]
    if not msg_fix:
        if verbose:
            print("  avail_dispatch: no _objc_msgSend import -> skipped")
        return None
    if rel is None:
        raise SystemExit("avail_dispatch: needs __DATA_METHLIST (run without --no-rel-methlist)")
    slots = find_selref_slots(m, buf, fixups)
    if b"respondsToSelector:" not in slots:
        raise SystemExit("avail_dispatch: no respondsToSelector: selref slot")
    # The real objc_msgSend needs a slot of its own; allocate it in the slack of the
    # new segment so that nothing the dispatcher calls can be retargeted back at it.
    slack = len(rel["blob"])
    if slack + 8 > rel["ins"]:
        raise SystemExit("avail_dispatch: no slack in __DATA_METHLIST for the real slot")
    f0 = msg_fix[0]
    real = dict(seg=rel["segidx"], vmaddr=rel["region_vm"] + slack,
                foff=rel["region_fo"] + slack, kind="bind", name="_objc_msgSend",
                lib=f0["lib"], addend=0, weak=False, high8=0)
    code_va = text_code_va(m, buf, after_va)
    code = build_avail_dispatcher(code_va, slots[b"respondsToSelector:"], real["vmaddr"])
    place_code(m, buf, code_va, code, "avail_dispatch")
    refs = count_slot_refs(m, buf, {f["vmaddr"] for f in msg_fix})
    for f in msg_fix:
        f["kind"] = "rebase"; f["target"] = code_va; f["high8"] = 0
    if verbose:
        print(f"  avail_dispatch: objc_msgSend@{code_va:X} ({len(code)} bytes)"
              f" <- {len(msg_fix)} got slot(s) {[hex(f['vmaddr']) for f in msg_fix]}"
              f", stub refs { {hex(k): v for k, v in refs.items()} }"
              f", real slot 0x{real['vmaddr']:X} (seg {rel['segidx']})")
    return dict(code_va=code_va, next_va=code_va + len(code), retargeted=len(msg_fix),
                real_slot_va=real["vmaddr"], new_binds=[real], refs=refs)


# Missing iOS-13+ *functions*: they are imported weakly, so iOS 12 binds a NULL slot
# and the first call is a jump to address 0.  ("First present in SDK" is from the
# sampled SDK symbol dumps.)  Each stub answers what the platform did before the API
# existed, which is what a binary built on the older SDK would have compiled to.
AVAIL_FUNC_STUBS = [
    # symbol,                             answer
    ("_CAFrameRateRangeMake",             "hfa0"),   # CAFrameRateRange{0,0,0} in s0-s2
    ("___darwin_check_fd_set_overflow",   "one"),    # pre-13.7 code did the fd_set maths
    ("__availability_version_check",      "zero"),   # "not available" is the safe answer
]


def build_func_stub(kind):
    if kind == "hfa0":  return _words(_enc_movi_v0_zero(), _ENC_RET)
    if kind == "one":   return _words(_enc_movz_w(0, 1), _ENC_RET)
    if kind == "zero":  return _words(_enc_movz_w(0, 0), _ENC_RET)
    raise AssertionError(kind)


def plan_func_stubs(m, buf, fixups, after_va=None, verbose=True):
    """Point the __got slots of missing iOS-13+ functions at two-instruction answers."""
    va = round_up(after_va or text_code_va(m, buf), 16)
    plan = {}
    for sym, kind in AVAIL_FUNC_STUBS:
        site = [f for f in fixups if f["kind"] == "bind" and f["name"] == sym]
        if not site:
            continue
        code = build_func_stub(kind)
        place_code(m, buf, va, code, f"func stub {sym}")
        for f in site:
            f["kind"] = "rebase"; f["target"] = va; f["high8"] = 0
        plan[sym] = (va, len(site), kind)
        va += 16
    if verbose:
        if plan:
            print("  avail_stubs: " + ", ".join(
                f"{s} -> 0x{v:X} ({n} slot(s), {k})" for s, (v, n, k) in plan.items()))
        else:
            print("  avail_stubs: none of the missing functions are referenced")
    return dict(plan=plan, next_va=va)


def find_objc_stub_for_selref(m, buf, slot):
    """vmaddr of the __TEXT,__objc_stubs entry loading selector slot `slot` (or None)
    (each entry is 32 bytes: adrp x1,selref-page / ldr x1,[x1,#off] / adrp x16 / ...)"""
    for st in m.sections:
        if st["seg"] != "__TEXT" or st["name"] != "__objc_stubs":
            continue
        for i in range(st["size"] // 32):
            a, o = st["addr"] + i * 32, st["offset"] + i * 32
            i0, i1 = rd(buf, o, "II")
            if i0 & 0x9F000000 != 0x90000000 or i1 & 0xFFC00000 != 0xF9400000:
                continue
            if (i0 & 0x1F) != (i1 & 0x1F):
                continue
            if _dec_adrp(i0, a) + ((i1 >> 10) & 0xFFF) * 8 == slot:
                return a
    return None


# ------------------------------------------------- iOS 12: nobody builds the UIWindow
# -[UnityAppController initUnityWithApplication:] only ever creates the window through
# the iOS 13 scene API:
#     _window = [[UIWindow alloc] initWithWindowScene:
#                    [self pickStartupWindowScene: application.connectedScenes]];
# The pre-13 branch (`[[UIWindow alloc] initWithFrame: [UIScreen mainScreen].bounds]`)
# was constant-folded away for the same reason as AVAIL_DISPATCH above.  On iOS 12 the
# dispatcher answers nil for -connectedScenes and (selectors being absent) for
# -initWithWindowScene:, so _window stays nil and -[UnityAppController createUI] trips
# its own assertion -- UnityAppController+ViewHandling.mm:137
# "_window should be inited at this point" -- leaving a black screen until
# SpringBoard's scene-create watchdog kills the process (0x8badf00d, ~18 s).
#
# There is exactly one call site (0xF944): x0 = the freshly alloc'ed UIWindow,
# x2 = the (nil) UIScene, x20 = self (the store `str x0,[x20,#0x18]` follows at
# 0xF94C).  So the stub for -initWithWindowScene: is redirected at a shim that runs
# the dropped else-branch and leaves the window in x0.  Notes on the ABI:
#   * CGRect travels in d0-d3 (HFA of 4 doubles), both out of -bounds and into
#     -initWithFrame:, so the two sends chain with no register juggling -- confirmed
#     against 26 in-binary call sites of -initWithFrame: (`fmov d0, xzr` ... ).
#   * a __objc_stubs entry only clobbers x1 and x16, which is why the shim can call
#     those stubs directly; x19-x28 are left alone because the caller still releases
#     the x21/x22 (-connectedScenes / -pickStartupWindowScene:) results at 0xF958.
WINDOW_SEL = b"initWithWindowScene:"
WINDOW_SEL_SUPPORT = (b"mainScreen", b"bounds", b"initWithFrame:")


def build_window_shim(va, screen_classref, main_stub, bounds_stub, init_stub):
    ins, pc = [], va

    def emit(w):
        nonlocal pc
        ins.append(w); pc += 4

    emit(_enc_sub_sp(0x20))
    emit(_enc_stp_x(29, 30, 31, 0))
    emit(_enc_str_x(0, 31, 0x10))                      # [sp+0x10] = the alloc'ed UIWindow
    emit(_enc_adrp(8, screen_classref, pc))
    emit(_enc_ldr64(8, 8, screen_classref & 0xFFF))    # x8 = _OBJC_CLASS_$_UIScreen
    emit(_enc_mov(0, 8))
    emit(_enc_bl(main_stub, pc))                       # [UIScreen mainScreen]
    emit(_enc_bl(bounds_stub, pc))                     # [screen bounds] -> d0-d3
    emit(_enc_ldr64(0, 31, 0x10))                      # window
    emit(_enc_bl(init_stub, pc))                       # [window initWithFrame: rect]
    emit(_enc_ldp_x(29, 30, 31, 0))
    emit(_enc_add_sp(0x20))
    emit(_ENC_RET)
    return _words(*ins)


def plan_window_shim(m, buf, fixups, after_va=None, verbose=True):
    """Redirect -[UIWindow initWithWindowScene:]'s stub to the iOS 12 window creation."""
    slots = find_selref_slots(m, buf, fixups)
    if WINDOW_SEL not in slots:
        if verbose: print("  window_shim: -initWithWindowScene: not referenced -> skipped")
        return None
    stub = find_objc_stub_for_selref(m, buf, slots[WINDOW_SEL])
    if stub is None:
        raise SystemExit("window_shim: no __objc_stubs entry for initWithWindowScene:")
    cres = [f for f in fixups if f["kind"] == "bind" and f["name"] == "_OBJC_CLASS_$_UIScreen"]
    if not cres:
        raise SystemExit("window_shim: no _OBJC_CLASS_$_UIScreen reference")
    screen_classref = cres[0]["vmaddr"]
    stubs = {}
    for sel in WINDOW_SEL_SUPPORT:
        if sel not in slots:
            raise SystemExit(f"window_shim: selector {sel!r} not in __objc_selrefs")
        s = find_objc_stub_for_selref(m, buf, slots[sel])
        if s is None:
            raise SystemExit(f"window_shim: no __objc_stubs entry for {sel!r}")
        stubs[sel] = s
    code_va = text_code_va(m, buf, after_va)
    code = build_window_shim(code_va, screen_classref, stubs[b"mainScreen"],
                             stubs[b"bounds"], stubs[b"initWithFrame:"])
    place_code(m, buf, code_va, code, "window_shim")
    fo = m.foff(stub) + 0x10                            # the entry's final `br x16`
    cur = rd(buf, fo, "I")[0]
    if cur != 0xD61F0200:
        raise SystemExit(f"window_shim: stub 0x{stub:X}+0x10 is 0x{cur:08X}, not `br x16`")
    struct.pack_into("<I", buf, fo, _enc_b(code_va, stub + 0x10))
    if verbose:
        print(f"  window_shim: -initWithWindowScene: stub 0x{stub:X} -> 0x{code_va:X}"
              f" ({len(code)} bytes): [[UIWindow alloc] initWithFrame:"
              f"[[UIScreen classref 0x{screen_classref:X}] mainScreen].bounds]"
              f" (stubs { {s.decode(): hex(v) for s, v in stubs.items()} })")
    return dict(code_va=code_va, next_va=code_va + len(code), stub_va=stub)


# --------------------------------------------------------------- stream builders
# --------------------------------------------------- iOS 12 static initializers
# dyld-655.1.1 (iOS 12.x) knows only S_MOD_INIT_FUNC_POINTERS (0x9): its
# ImageLoaderMachO::doModInitFunctions walks the section table for that type and
# calls each 8-byte pointer.  The chained-fixups toolchain replaced it with
# S_INIT_FUNC_OFFSETS (0x16, a uint32 array of mach_header-relative offsets) and
# dyld only learnt about that in 732.8 (iOS 13: "else if ( type ==
# S_INIT_FUNC_OFFSETS )").  Verified in the Apple sources: dyld-635.2 and
# dyld-655.1.1 have zero occurrences of init_offsets; dyld-732.8/852.2 have the
# handler.  So on iOS 12 every static initializer of a chained-fixups image is
# silently skipped -- we materialise the offsets as a real __mod_init_func
# pointer array in the tail of a writable segment, and blank the old section so
# iOS 13+ dynld does not run the same functions twice.
S_INIT_FUNC_OFFSETS = 0x16
S_MOD_INIT_FUNC_POINTERS = 0x9
SECT_TYPE_MASK = 0xFF
ZEROFILL_SECT_TYPES = (0x1, 0xC, 0x12)     # S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL


def _cmd_for_seg(m, seg):
    return next((c for c in m.cmds
                 if c["cmd"] == LC_SEGMENT_64 and c["off"] == seg["lc_off"]), None)


def _pack_section(sectname, segname, addr, size, offset, align, flags):
    return struct.pack("<16s16sQQIIIIIIII", sectname.encode()[:16], segname.encode()[:16],
                       addr, size, offset, align, 0, 0, flags, 0, 0, 0)


def plan_mod_init(m, buf, verbose=True):
    """Turn S_INIT_FUNC_OFFSETS into a classic __mod_init_func pointer array.
    Returns [(segidx, offset_in_seg, target_vmaddr)] rebase slots to emit."""
    slots = []
    inits = [s for s in m.sections
             if (s["flags"] & SECT_TYPE_MASK) == S_INIT_FUNC_OFFSETS and s["size"]]
    if not inits:
        if verbose:
            print("  mod_init: no S_INIT_FUNC_OFFSETS section (nothing to do)")
        return slots
    text = m.seg_by_name.get("__TEXT")
    for s in inits:
        n = s["size"] // 4
        targets = [m.image_base + rd(buf, s["offset"] + 4 * i, "I")[0] for i in range(n)]
        bad = [t for t in targets if m.seg_of(t) is None]
        if bad:
            raise SystemExit(f"__init_offsets: {len(bad)} target(s) outside the image,"
                             f" e.g. 0x{bad[0]:x}")
        notext = [t for t in targets
                  if not (text["vmaddr"] <= t < text["vmaddr"] + text["filesize"])]
        if notext:
            raise SystemExit(f"__init_offsets: {len(notext)} target(s) outside __TEXT,"
                             f" e.g. 0x{notext[0]:x}")
        need = 8 * n
        host = addr = None
        for name in ("__DATA_CONST", "__DATA"):
            seg = m.seg_by_name.get(name)
            if seg is None or not (seg["initprot"] & 0x2):
                continue                                  # must be writable for the rebase
            secs = [x for x in m.sections if x["segidx"] == seg["idx"]]
            backed = [x for x in secs if (x["flags"] & SECT_TYPE_MASK) not in ZEROFILL_SECT_TYPES]
            cand = round_up(max([x["addr"] + x["size"] for x in backed], default=seg["vmaddr"]), 8)
            clash = [x for x in secs if x["addr"] < cand + need and cand < x["addr"] + x["size"]]
            if clash:
                if verbose:
                    print(f"  mod_init: {name} file tail is claimed by {clash[0]['name']}"
                          f" at 0x{clash[0]['addr']:x} -- trying next segment")
                continue
            if cand + need > seg["vmaddr"] + seg["vmsize"]:
                continue
            fo = seg["fileoff"] + (cand - seg["vmaddr"])
            if fo + need > seg["fileoff"] + seg["filesize"]:
                continue
            if any(buf[fo:fo + need]):
                if verbose:
                    print(f"  mod_init: {name} tail is not zero-filled -- skipping")
                continue
            host, addr = seg, cand
            break
        if host is None:
            raise SystemExit("__init_offsets: no writable segment has room for __mod_init_func")
        fo = host["fileoff"] + (addr - host["vmaddr"])
        for i, t in enumerate(targets):
            struct.pack_into("<Q", buf, fo + 8 * i, t)
            slots.append((host["idx"], addr - host["vmaddr"] + 8 * i, t))
        # add the new section entry to the host segment command
        c = _cmd_for_seg(m, host)
        raw = bytearray(c["raw"])
        struct.pack_into("<I", raw, 4, len(raw) + 80)                     # cmdsize
        struct.pack_into("<I", raw, 64, host["nsects"] + 1)               # nsects
        raw += _pack_section("__mod_init_func", host["name"], addr, need, fo, 3,
                             S_MOD_INIT_FUNC_POINTERS)
        c["raw"] = bytes(raw)
        host["nsects"] += 1
        m.sections.append(dict(seg=host["name"], name="__mod_init_func", addr=addr, size=need,
                               offset=fo, flags=S_MOD_INIT_FUNC_POINTERS, segidx=host["idx"]))
        # blank the old section entry so iOS 13+ dyld does not run them twice
        k = [x for x in m.sections if x["segidx"] == s["segidx"]].index(s)
        pc = _cmd_for_seg(m, m.segments[s["segidx"]])
        praw = bytearray(pc["raw"])
        ent = 72 + k * 80
        praw[ent:ent + 80] = _pack_section("__init_offsets", m.segments[s["segidx"]]["name"],
                                           0, 0, 0, 2, 0x0)
        pc["raw"] = bytes(praw)
        s.update(size=0, addr=0, offset=0, flags=0)
        if verbose:
            print(f"  mod_init: {n} initializer(s) -> {host['name']},__mod_init_func"
                  f" @0x{addr:x} (file 0x{fo:x}, {need} bytes); old section blanked")
    return slots


# ------------------------------------------- relative method lists (iOS 13+ ABI)
# The chained-fixups linker emits every Objective-C method list with a 12-byte
# stride and three int32 fields that are relative to the field's *own* address,
# and tags the header word with 0x80000000.  objc4 only learnt that layout in the
# iOS 13 era: iOS 12's libobjc reads the header word as an entsize and then walks
# count * 24 bytes per entry, i.e. it treats our 12-byte entries as absolute
# method_t{name,types,imp} records and dereferences garbage.  That is exactly the
# real-device crash (EXC_BAD_ACCESS inside libobjc.A.dylib with x0 = the list
# itself = class_ro_t.baseMethods).  We therefore rebuild every list in the
# classic 24-byte absolute layout inside a fresh file-backed RW segment -- which
# is what makes the pointers rebasable -- and repoint the list references at it.
METHOD_ENTSIZE_REL = 12
METH_FLAG_MASK = 0xffff0003
REL_METH_SEG = "__DATA_METHLIST"
SEG_CUSHION = 0x200000      # keep the new segment clear of __LINKEDIT's own growth

LC_FUNCTION_STARTS         = 0x26
LC_DATA_IN_CODE            = 0x29
LC_ENCRYPTION_INFO         = 0x21
LC_ENCRYPTION_INFO_64      = 0x2C

# file-offset fields (at these command-relative positions) that live in __LINKEDIT
LINKEDIT_OFFSET_FIELDS = {
    LC_SYMTAB:              (8, 16),                  # symoff, stroff
    LC_DYSYMTAB:            (32, 40, 48, 56, 64, 72),  # tocoff, modtaboff, extrefsymoff,
                                                       # indirectsymoff, extreloff, locreloff
    LC_DYLD_INFO:           (8, 16, 24, 32, 40),       # rebase/bind/weak_bind/lazy_bind/export
    LC_DYLD_INFO_ONLY:      (8, 16, 24, 32, 40),
    LC_FUNCTION_STARTS:     (8,),
    LC_DATA_IN_CODE:        (8,),
    LC_DYLD_EXPORTS_TRIE:   (8,),
    LC_DYLD_CHAINED_FIXUPS: (8,),
    LC_CODE_SIGNATURE:      (8,),
    LC_ENCRYPTION_INFO:     (8,),
    LC_ENCRYPTION_INFO_64:  (8,),
}


def _add_segment(m, name, vmaddr, size, fileoff, sect_size):
    """Append a file-backed RW segment holding one section (needs to be rebasable)."""
    raw = bytearray(72)
    struct.pack_into("<II", raw, 0, LC_SEGMENT_64, 72 + 80)
    raw[8:24] = name.encode()[:16].ljust(16, b"\0")
    struct.pack_into("<QQQQ", raw, 24, vmaddr, size, fileoff, size)
    struct.pack_into("<iiII", raw, 56, 3, 3, 1, 0)     # maxprot, initprot, nsects, flags
    raw += _pack_section("__objc_methlist", name, vmaddr, sect_size, fileoff, 3, 0)
    key = ("new-segment", name)
    m.cmds.append(dict(cmd=LC_SEGMENT_64, size=len(raw), off=key, raw=bytes(raw)))
    seg = dict(idx=len(m.segments), name=name, vmaddr=vmaddr, vmsize=size, fileoff=fileoff,
               filesize=size, maxprot=3, initprot=3, nsects=1, flags=0, lc_off=key,
               lc_size=len(raw))
    m.segments.append(seg)
    m.seg_by_name[name] = seg
    m.sections.append(dict(seg=name, name="__objc_methlist", addr=vmaddr, size=sect_size,
                           offset=fileoff, flags=0, segidx=seg["idx"]))
    return seg


def plan_rel_methlists(m, buf, fixups, verbose=True):
    """Rewrite the relative (iOS 13 ABI) method lists as classic 24-byte lists.
    Returns dict(ins, region_fo, blob, writes, slots, ...) or None if not needed."""
    s = next((x for x in m.sections
              if x["name"] == "__objc_methlist" and x["size"] and x["seg"] == "__TEXT"), None)
    if s is None:
        if verbose:
            print("  rel_method_lists: no __TEXT,__objc_methlist section (nothing to do)")
        return None
    base, end = s["addr"], s["addr"] + s["size"]

    # 1. walk the section: [u32 entsizeAndFlags][u32 count][count * 12 bytes], padded to 8
    lists, cur = [], base
    while cur + 8 <= end:
        hdr = rd(buf, m.foff(cur), "I")[0]
        if hdr == 0:
            break
        if not (hdr & 0x80000000) or (hdr & ~METH_FLAG_MASK) != METHOD_ENTSIZE_REL:
            raise SystemExit(f"__objc_methlist: unexpected header 0x{hdr:08x} at 0x{cur:x}")
        count = rd(buf, m.foff(cur) + 4, "I")[0]
        lists.append((cur, count))
        cur = round_up(cur + 8 + METHOD_ENTSIZE_REL * count, 8)
    if not lists:
        return None

    # 2. decode every entry into absolute (SEL, types, IMP) - all still unslid
    by_va = {f["vmaddr"]: f for f in fixups if f["foff"] is not None}
    decoded, n_meth = [], 0
    for lva, count in lists:
        ents = []
        for i in range(count):
            fva = lva + 8 + 12 * i
            rel_name, rel_type, rel_imp = rd(buf, m.foff(fva), "iii")
            # A relative pointer of 0 means NULL (a self reference is meaningless:
            # in the classic 3.19.0 build the *protocol* method lists carry
            # imp = 0x0 for every entry -- verified by protocheck319.py).
            if rel_name == 0:
                sel = 0
            else:
                # `name` is relative to a __objc_selrefs slot that itself holds the SEL
                tgt = fva + rel_name
                sec = m.sect_of(tgt)
                if sec is None:
                    raise SystemExit(f"method name 0x{tgt:x} is outside every section"
                                     f" (list 0x{lva:x} entry {i})")
                if sec["name"] == "__objc_selrefs":
                    f = by_va.get(tgt)
                    if f is None or f["kind"] != "rebase":
                        raise SystemExit(f"method name 0x{tgt:x} is not a rebase slot")
                    sel = f["target"]
                elif sec["name"] == "__objc_methname":
                    sel = tgt                             # already the SEL string itself
                else:
                    raise SystemExit(f"method name 0x{tgt:x} sits in {sec['seg']},{sec['name']}"
                                     f" (list 0x{lva:x})")
            if rel_type == 0:
                types = 0
            else:
                types = fva + 4 + rel_type
                tsec = m.sect_of(types)
                if tsec is None or tsec["seg"] != "__TEXT":
                    raise SystemExit(f"method types 0x{types:x} sits in"
                                     f" {tsec['name'] if tsec else 'no section'} (list 0x{lva:x})")
                # ld64 de-duplicates identical strings, so a type encoding may live in
                # __cstring instead of __objc_methtype (both are fine for the runtime)
                enc = bytes(buf[m.foff(types):m.foff(types) + 128]).split(b"\0")[0]
                if len(enc) < 2 or not all(32 <= ch < 127 for ch in enc):
                    raise SystemExit(f"method types 0x{types:x} is not a type encoding:"
                                     f" {enc[:40]!r} (list 0x{lva:x}, section {tsec['name']})")
            if rel_imp == 0:
                imp = 0
            else:
                imp = fva + 8 + rel_imp
                isec = m.sect_of(imp)
                if isec is None or isec["seg"] != "__TEXT" or imp % 4:
                    raise SystemExit(f"method imp 0x{imp:x} sits in"
                                     f" {isec['seg'] if isec else 'no segment'}"
                                     f" (list 0x{lva:x})")
            ents.append((sel, types, imp))
            n_meth += 1
        decoded.append((lva, ents))

    # 3. lay the classic lists out, and give the new segment room at the end of the file
    dt, le = m.seg_by_name["__DATA"], m.seg_by_name["__LINKEDIT"]
    if dt["fileoff"] + dt["filesize"] != le["fileoff"]:
        raise SystemExit("rel_method_lists: __DATA does not end where __LINKEDIT starts")
    # __LINKEDIT still has its *original* vmsize here: the rebase/bind/export
    # streams appended later grow it, so leave a cushion above it.
    seg_vm = round_up(le["vmaddr"] + le["vmsize"], 0x4000) + SEG_CUSHION
    region_fo = le["fileoff"]
    blob, new_va, plan_writes = bytearray(), {}, []
    for lva, ents in decoded:
        new_va[lva] = seg_vm + len(blob)
        blob += struct.pack("<II", 24, len(ents))
        for sel, types, imp in ents:
            for v in (sel, types, imp):
                plan_writes.append((len(blob), v))
                blob += b"\0" * 8
    ins = round_up(len(blob), 0x4000)
    assert seg_vm % 0x4000 == 0, hex(seg_vm)

    # 4. repoint every rebase slot that pointed into the old relative section
    repointed, seen = 0, set()
    for f in fixups:
        if f["kind"] != "rebase" or f["foff"] is None:
            continue
        if base <= f["target"] < end:
            nv = new_va.get(f["target"])
            if nv is None:
                raise SystemExit(f"rebase slot 0x{f['vmaddr']:x} points at 0x{f['target']:x}"
                                 f" inside __objc_methlist but not at a list start")
            f["target"] = nv
            repointed += 1
            seen.add(nv)
    dead = [hex(v) for v in new_va.values() if v not in seen][:4]

    # 5. the new segment, plus rebase slots for all 3 pointers of every method
    seg = _add_segment(m, REL_METH_SEG, seg_vm, ins, region_fo, len(blob))
    slots = [(seg["idx"], o, v) for o, v in plan_writes]
    writes = [(region_fo + o, v) for o, v in plan_writes]
    if verbose:
        print(f"  rel_method_lists: {len(lists)} list(s) / {n_meth} method(s)"
              f" -> {REL_METH_SEG},__objc_methlist @0x{seg_vm:x} (file 0x{region_fo:x},"
              f" {len(blob)} bytes in {ins} reserved); {repointed} reference(s) repointed"
              + (f"; {len(dead)} list(s) unreferenced e.g. {dead}" if dead else ""))
    return dict(ins=ins, region_fo=region_fo, region_vm=seg_vm, blob=bytes(blob),
                writes=writes, slots=slots, n_lists=len(lists), n_methods=n_meth,
                repointed=repointed, segidx=seg["idx"])


def build_rebase_stream(rebs):
    """rebs: [(segidx, offset_in_seg, target_vmaddr)] sorted by (seg, off)"""
    out = bytearray()
    out.append(REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER)
    cur_seg, cur_off = -1, 0
    i = 0
    while i < len(rebs):
        seg, off, _ = rebs[i]
        j = i
        while j + 1 < len(rebs) and rebs[j+1][0] == seg and rebs[j+1][1] == off + 8*(j+1-i):
            j += 1
        cnt = j - i + 1
        if seg != cur_seg:
            out.append(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | (seg & 0xF))
            out += uleb(off)
            cur_seg, cur_off = seg, off
        else:
            delta = off - cur_off
            if delta:
                out.append(REBASE_OPCODE_ADD_ADDR_ULEB); out += uleb(delta); cur_off = off
        if cnt > 1:
            out.append(REBASE_OPCODE_DO_REBASE_ULEB_TIMES); out += uleb(cnt)
        else:
            out.append(REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1)
        cur_off += 8*cnt
        i = j + 1
    out.append(REBASE_OPCODE_DONE)
    return bytes(out)


def enc_ordinal(n):
    if n == 0:    return bytes([BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 0])
    if n == 0xFF: return bytes([BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | 0xF])
    if n == 0xFE: return bytes([BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | 0xE])
    if n == 0xFD: return bytes([BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | 0xD])
    if n <= 15:   return bytes([BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | n])
    return bytes([BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB]) + uleb(n)


def build_bind_stream(binds):
    """binds: [(segidx, off, ordinal, name, addend, weakflag)] sorted by (seg, off)"""
    out = bytearray()
    out.append(BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER)
    st_ord = st_name = None; st_add = 0; cur_seg = -1; cur_off = 0
    for seg, off, ordinal, name, addend, weak in binds:
        if ordinal != st_ord:
            out += enc_ordinal(ordinal); st_ord = ordinal
        if name != st_name or weak:
            flags = BIND_SYMBOL_FLAGS_WEAK_IMPORT if weak else 0
            out.append(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | flags)
            out += name.encode() + b"\0"
            st_name = name
        if addend != st_add:
            out.append(BIND_OPCODE_SET_ADDEND_SLEB); out += sleb(addend); st_add = addend
        if seg != cur_seg:
            out.append(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | (seg & 0xF))
            out += uleb(off); cur_seg, cur_off = seg, off
        else:
            d = off - cur_off
            if d:
                out.append(BIND_OPCODE_ADD_ADDR_ULEB); out += uleb(d); cur_off = off
        out.append(BIND_OPCODE_DO_BIND); cur_off += 8
    out.append(BIND_OPCODE_DONE)
    return bytes(out)


# ------------------------------------------------------------------ converters
def convert(inpath, outpath, weak_names=frozenset(), weak_all_missing=False,
            minos=(12, 0, 0), sdk=(12, 4, 0), quit_patches=(), verbose=True,
            ptr_offset=True, shim_objc_opt=True, mod_init=True, rel_methlist=True,
            avail_dispatch=True, avail_stubs=True, window_shim=True):
    m = MachO(open(inpath, "rb").read())
    dec = decode_fixups(m)
    assert dec is not None, "no LC_DYLD_CHAINED_FIXUPS in " + inpath
    buf = m.buf
    fixups = dec["fixups"]
    n_bad = sum(1 for f in fixups if f["foff"] is None)
    if n_bad: print(f"  !! {n_bad} fixups outside file (bss?) -- skipped")

    # 1. code patches (Application.Quit -> RET)
    for off in quit_patches:
        old = bytes(buf[off:off+4])
        buf[off:off+4] = b"\xC0\x03\x5F\xD6"
        if verbose: print(f"  patch 0x{off:X}: {old.hex()} -> c0035fd6 (RET)")

    # 1b. iOS 12 has no objc_opt_* symbols -> rebase their __got slots onto local thunks
    shim = plan_objc_opt_shims(m, buf, fixups, verbose=verbose) if shim_objc_opt else None
    shim_next = shim["next_va"] if shim else None

    # 1c. iOS 12 dyld has no S_INIT_FUNC_OFFSETS -> real __mod_init_func array
    mod_init_slots = plan_mod_init(m, buf, verbose=verbose) if mod_init else []

    # 1d. iOS 12 libobjc has no relative (12-byte) method lists -> classic 24-byte ones
    rel = plan_rel_methlists(m, buf, fixups, verbose=verbose) if rel_methlist else None
    ins = rel["ins"] if rel else 0

    # 1e. the engine's @available(iOS 13+) guards were folded away by a deployment
    #     target of 15 -> interpose objc_msgSend so those sends answer nil on iOS 12
    avail = plan_avail_dispatch(m, buf, fixups, rel, after_va=shim_next,
                               verbose=verbose) if avail_dispatch else None

    # 1f. missing iOS-13+ *functions* (weakly imported -> NULL slot) get an answer
    fstub = plan_func_stubs(m, buf, fixups,
                            after_va=(avail["next_va"] if avail else shim_next),
                            verbose=verbose) if avail_stubs else None

    # 1g. the only UIWindow creation is the iOS 13 scene one -> run the dropped
    #     pre-13 branch instead ([[UIWindow alloc] initWithFrame:screen.bounds])
    win = plan_window_shim(m, buf, fixups,
                           after_va=(fstub["next_va"] if fstub
                                     else (avail["next_va"] if avail else shim_next)),
                           verbose=verbose) if window_shim else None

    # 2. clean chained bits out of the slots
    #    dyld (MachOLoaded.cpp:818) does:  newValue = (uintptr_t)this + unpackedTarget()
    #    i.e. for PTR_64_OFFSET the 8-bit "high8" field is NOT part of the answer -- verified
    #    empirically: the 87 entries with high8==0x80 point at real __TEXT C++ typeinfo name
    #    strings (0x3D8FA93 -> "St9exception"), which are wrong if high8 were ORed in.
    nz_high8 = 0
    for f in fixups:
        if f["foff"] is None: continue
        if f["kind"] == "rebase":
            if f["high8"]: nz_high8 += 1
            struct.pack_into("<Q", buf, f["foff"], f["target"])
        else:
            struct.pack_into("<Q", buf, f["foff"], 0)
    if nz_high8 and verbose:
        print(f"  note: {nz_high8} rebases had high8!=0 -> ignored for PTR_64_OFFSET")

    # 2b. binds synthesised by 1e live inside the region step 7 inserts, so they are
    #     appended *after* the chained-bit wipe above (which must not touch them)
    if avail and avail["new_binds"]:
        fixups.extend(avail["new_binds"])

    # 3. build classic streams
    rebs, binds = [], []
    n_forced = 0
    for f in fixups:
        if f["foff"] is None: continue
        seg = f["seg"]; off = f["vmaddr"] - m.segments[seg]["vmaddr"]
        if f["kind"] == "rebase":
            rebs.append((seg, off, f["target"]))
        else:
            name = f["name"] or ""
            weak = bool(f["weak"]) or weak_all_missing or (name in weak_names)
            if weak and not f["weak"]: n_forced += 1
            binds.append((seg, off, f["lib"] or 0, name, f["addend"], weak))
    rebs.extend(mod_init_slots)          # __mod_init_func pointers (1c) need rebasing too
    if rel:
        rebs.extend(rel["slots"])        # 3 pointers per classic method_t (1d)
    rebs.sort(key=lambda t: (t[0], t[1]))
    binds.sort(key=lambda t: (t[0], t[1]))
    reb_stream = build_rebase_stream(rebs)
    bind_stream = build_bind_stream(binds)
    if verbose:
        print(f"  rebases {len(rebs)} -> {len(reb_stream)} bytes"
              f"   binds {len(binds)} -> {len(bind_stream)} bytes"
              f"   weak binds {sum(1 for x in binds if x[5])} ({n_forced} forced weak)")

    # export trie: iOS 12's dyld walks the link-edit chunks strictly in the order
    # rebase <= bind <= weak_bind <= lazy_bind <= export and throws
    # "malformed mach-o image: dyld export info overlaps lazy bind info" otherwise
    # (ImageLoaderMachO.cpp:454-502 in dyld-635.2/655.1.1).  The original trie payload
    # lives before the symbol table, i.e. *before* the streams we append, so it has to be
    # copied to the tail; a trie's internal offsets are relative to its own start, so a
    # verbatim copy is safe.  The stale copy stays behind as dead bytes.
    exp_off = exp_size = 0
    old_exp_off = 0
    et = m.lc(LC_DYLD_EXPORTS_TRIE)
    if et:
        old_exp_off, exp_size = rd(buf, et[0]["off"] + 8, "II")

    # 4. append the streams at end of file, in dyld's required order
    base_end = len(buf)
    pad = (-base_end) % 8
    buf += b"\0" * pad
    reb_off = len(buf); buf += reb_stream
    if len(buf) % 8: buf += b"\0" * ((-len(buf)) % 8)
    bind_off = len(buf); buf += bind_stream
    if len(buf) % 8: buf += b"\0" * ((-len(buf)) % 8)
    if exp_size:
        trie = bytes(buf[old_exp_off:old_exp_off + exp_size])
        exp_off = len(buf)
        buf += trie
        if len(buf) % 8: buf += b"\0" * ((-len(buf)) % 8)
    new_end = len(buf)
    if verbose and exp_size:
        print(f"  export trie moved 0x{old_exp_off:X} -> 0x{exp_off:X} ({exp_size} bytes)")

    # 5. grow __LINKEDIT to cover the appended data
    le = m.seg_by_name["__LINKEDIT"]
    le["filesize"] = new_end - le["fileoff"]
    le["vmsize"] = round_up(le["filesize"], 0x4000)
    le_fo_old = le["fileoff"]
    if ins:                                  # 5b. lift __LINKEDIT to make room for 1d
        le["fileoff"] = le_fo_old + ins
        ms = m.seg_by_name.get(REL_METH_SEG)
        if ms is None or round_up(le["vmaddr"] + le["vmsize"], 0x4000) > ms["vmaddr"]:
            raise SystemExit(f"{REL_METH_SEG} at 0x{ms['vmaddr']:X} overlaps __LINKEDIT vm range"
                             f" ending at 0x{round_up(le['vmaddr'] + le['vmsize'], 0x4000):X}")

    # 6. rebuild load commands
    minos_enc = (minos[0] << 16) | (minos[1] << 8) | minos[2]
    sdk_enc   = (sdk[0] << 16) | (sdk[1] << 8) | sdk[2]
    new_cmds = []
    for c in m.cmds:
        cmd = c["cmd"]
        if cmd in (LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE):
            continue
        r = bytearray(c["raw"])
        if cmd == LC_BUILD_VERSION:
            # build_version_command: cmd,cmdsize,platform,minos,sdk,ntools
            # Tool records are retained in r. dyld3 requires the command size
            # to equal 24 + ntools * 8; zeroing ntools alone corrupts the LC.
            ntools = struct.unpack_from("<I", r, 20)[0]
            if len(r) != 24 + ntools * 8:
                raise SystemExit("invalid source LC_BUILD_VERSION size/ntools")
            struct.pack_into("<II", r, 12, minos_enc, sdk_enc)
        elif cmd == LC_CODE_SIGNATURE:
            struct.pack_into("<II", r, 8, 0, 0)           # signer adds a fresh one
        elif cmd == LC_SEGMENT_64:
            seg = next((s for s in m.segments if s["lc_off"] == c["off"]), None)
            if seg:
                struct.pack_into("<QQQQ", r, 24, seg["vmaddr"], seg["vmsize"],
                                 seg["fileoff"], seg["filesize"])
        elif ins and cmd in LINKEDIT_OFFSET_FIELDS:
            for fo in LINKEDIT_OFFSET_FIELDS[cmd]:      # everything in __LINKEDIT moved up
                v = struct.unpack_from("<I", r, fo)[0]
                if v and v >= le_fo_old:
                    struct.pack_into("<I", r, fo, v + ins)
        new_cmds.append((cmd, bytes(r)))
    # add LC_VERSION_MIN_IPHONEOS (16) + LC_DYLD_INFO_ONLY (48)
    vmin = struct.pack("<IIII", LC_VERSION_MIN_IPHONEOS, 16,
                       (minos[0]<<16)|(minos[1]<<8)|minos[2], (sdk[0]<<16)|(sdk[1]<<8)|sdk[2])
    dinfo = struct.pack("<IIIIIIIIIIII", LC_DYLD_INFO_ONLY, 48,
                        reb_off + ins, len(reb_stream),
                        bind_off + ins, len(bind_stream),
                        0, 0, 0, 0,
                        exp_off + ins if exp_off else 0, exp_size)
    cmds_blob = b"".join(r for _, r in new_cmds) + vmin + dinfo
    hdr_end = 32 + len(cmds_blob)
    first_sect = min((s["offset"] for s in m.sections if s["offset"]), default=0x4000)
    if hdr_end > first_sect:
        raise SystemExit(f"load commands ({hdr_end}) would overrun first section (0x{first_sect:X})")
    out = bytearray(buf)
    struct.pack_into("<II", out, 16, len(new_cmds) + 2, len(cmds_blob))
    out[32:hdr_end] = cmds_blob
    out[hdr_end:first_sect] = b"\0" * (first_sect - hdr_end)
    if rel:                                   # 7. slide the new method lists into place
        fo = rel["region_fo"]
        assert len(out) > fo + rel["ins"], (hex(len(out)), hex(fo))
        out[fo:fo] = b"\0" * rel["ins"]       # tail of __DATA == head of the new segment
        out[fo:fo + len(rel["blob"])] = rel["blob"]
        for wfo, v in rel["writes"]:
            struct.pack_into("<Q", out, wfo, v)
    # Construction above uses original segment indices. Normalize only after
    # every helper has finished, then remap the public result to final indices.
    # dyld3 rejects any fixup segment at or beyond the LINKEDIT segment index.
    from fix_classic_segments import repair as repair_segments
    out, segment_report = repair_segments(out)
    segment_map = segment_report["segment_map"]
    rebs = [(segment_map[t[0]], *t[1:]) for t in rebs]
    binds = [(segment_map[t[0]], *t[1:]) for t in binds]
    open(outpath, "wb").write(out)
    if verbose:
        print(f"  __LINKEDIT filesize 0x{le['filesize']:X} vmsize 0x{le['vmsize']:X};"
              f" file {len(out)} bytes; cmds {len(new_cmds)+2} ({len(cmds_blob)} bytes)")
    return dict(rebs=rebs, binds=binds, out=outpath, size=len(out))


# --------------------------------------------------------------------- verifier
def verify_classic(path, slide=0x100000000, verbose=True):
    """Independently interpret the classic streams of `path` and report what a
    dyld would do; also cross-check against a decode of the ORIGINAL chained
    tables when given the original path."""
    m = MachO(open(path, "rb").read())
    from fix_classic_segments import validate as validate_segments
    validate_segments(m)
    b = m.buf
    di = m.lc(LC_DYLD_INFO_ONLY) or m.lc(LC_DYLD_INFO)
    assert di, "no LC_DYLD_INFO in output"
    co = di[0]["off"]
    rb_off, rb_sz, bd_off, bd_sz, wb_off, wb_sz, lb_off, lb_sz, ex_off, ex_sz = rd(b, co+8, "IIIIIIIIII")
    res = dict(rebase=[], bind=[])
    # ---- rebase stream
    seg_i, seg_off, i = 0, 0, 0
    p = b[rb_off:rb_off+rb_sz]
    while i < len(p):
        op, imm = p[i] & 0xF0, p[i] & 0x0F; i += 1
        if op == REBASE_OPCODE_DONE: break
        elif op == REBASE_OPCODE_SET_TYPE_IMM: pass
        elif op == REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_i = imm; seg_off, i = read_uleb(p, i)
        elif op == REBASE_OPCODE_ADD_ADDR_ULEB:
            d, i = read_uleb(p, i); seg_off += d
        elif op == REBASE_OPCODE_ADD_ADDR_IMM_SCALED: seg_off += imm*8
        elif op == REBASE_OPCODE_DO_REBASE_IMM_TIMES:
            for _ in range(imm):
                res["rebase"].append((seg_i, seg_off)); seg_off += 8
        elif op == REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
            n, i = read_uleb(p, i)
            for _ in range(n):
                res["rebase"].append((seg_i, seg_off)); seg_off += 8
        elif op == REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
            d, i = read_uleb(p, i)
            res["rebase"].append((seg_i, seg_off)); seg_off += 8 + d
        elif op == REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
            n, i = read_uleb(p, i); s, i = read_uleb(p, i)
            for _ in range(n):
                res["rebase"].append((seg_i, seg_off)); seg_off += 8 + s
        else: raise SystemExit(f"bad rebase opcode 0x{op:X} at {i}")
    # ---- bind stream
    seg_i, seg_off, i = 0, 0, 0
    ordv, name, addend, flags = 0, None, 0, 0
    p = b[bd_off:bd_off+bd_sz]
    while i < len(p):
        op, imm = p[i] & 0xF0, p[i] & 0x0F; i += 1
        if op == BIND_OPCODE_DONE: break
        elif op == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: ordv = imm
        elif op == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            ordv, i = read_uleb(p, i)
        elif op == BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            ordv = {0xF: 0xFF, 0xE: 0xFE, 0xD: 0xFD}.get(imm, imm)
        elif op == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            flags = imm; e = p.index(b"\0", i); name = p[i:e].decode(); i = e+1
        elif op == BIND_OPCODE_SET_TYPE_IMM: pass
        elif op == BIND_OPCODE_SET_ADDEND_SLEB:
            addend, i = read_sleb(p, i)
        elif op == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_i = imm; seg_off, i = read_uleb(p, i)
        elif op == BIND_OPCODE_ADD_ADDR_ULEB:
            d, i = read_uleb(p, i); seg_off += d
        elif op == BIND_OPCODE_DO_BIND:
            res["bind"].append((seg_i, seg_off, ordv, name, addend, flags)); seg_off += 8
        elif op == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            d, i = read_uleb(p, i)
            res["bind"].append((seg_i, seg_off, ordv, name, addend, flags)); seg_off += 8 + d
        elif op == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            res["bind"].append((seg_i, seg_off, ordv, name, addend, flags)); seg_off += 8 + imm*8
        else: raise SystemExit(f"bad bind opcode 0x{op:X} at {i}")
    if verbose:
        print(f"VERIFY {path}: classic rebases={len(res['rebase'])} binds={len(res['bind'])} "
              f"export_off=0x{ex_off:X} size={ex_sz} wx={wb_sz}/{lb_sz}")
    # ---- replay iOS 12 dyld's link-edit validation (ImageLoaderMachO.cpp:454-502).
    # This is the check that made the device log say
    # "malformed mach-o image: dyld export info overlaps lazy bind info".
    le = m.seg_by_name["__LINKEDIT"]
    dyld_off = le["fileoff"]
    dyld_end = le["fileoff"] + le["filesize"]
    _lit = {"rebase": "dyld rebase info", "bind": "dyld bind info",
            "weak_bind": "dyld weak bind info", "lazy_bind": "dyld lazy bind info",
            "export": "dyld export info"}
    _ovl = {"bind": "dyld bind info overlaps rebase info",
            "weak_bind": "dyld weak bind info overlaps bind info",
            "lazy_bind": "dyld lazy bind info overlaps weak bind info",
            "export": "dyld export info overlaps lazy bind info"}
    for _n, _o, _s in (("rebase", rb_off, rb_sz), ("bind", bd_off, bd_sz),
                       ("weak_bind", wb_off, wb_sz), ("lazy_bind", lb_off, lb_sz),
                       ("export", ex_off, ex_sz)):
        if not _s:
            continue
        if _o < dyld_off:
            _why = ("malformed mach-o image: dyld rebase info underruns __LINKEDIT"
                    if _n == "rebase" else "malformed mach-o image: " + _ovl[_n])
            raise SystemExit(f"VERIFY FAIL {path}: {_why} (0x{_o:X} < 0x{dyld_off:X})")
        dyld_off = _o + _s
        if dyld_off > dyld_end:
            raise SystemExit(f"VERIFY FAIL {path}: malformed mach-o image: "
                             f"{_lit[_n]} overruns __LINKEDIT")
    if verbose:
        print(f"  dyld-order check: rebase < bind < export inside __LINKEDIT "
              f"[0x{le['fileoff']:X},0x{dyld_end:X}) -> implemented checks passed")
    res["export_off"] = ex_off
    res["export_size"] = ex_sz
    return res


def read_uleb(p, i):
    r = 0; s = 0
    while True:
        v = p[i]; i += 1; r |= (v & 0x7F) << s
        if not (v & 0x80): return r, i
        s += 7
def read_sleb(p, i):
    r = 0; s = 0
    while True:
        v = p[i]; i += 1; r |= (v & 0x7F) << s; s += 7
        if not (v & 0x80):
            if s < 64 and (v & 0x40): r |= -(1 << s)
            return r, i


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inp"); ap.add_argument("out", nargs="?")
    ap.add_argument("--weak-file"); ap.add_argument("--weak-all", action="store_true")
    ap.add_argument("--minos", default="12.0.0"); ap.add_argument("--sdk", default="12.4.0")
    ap.add_argument("--patch-quit", action="store_true")
    ap.add_argument("--no-shim-objc-opt", action="store_true")
    ap.add_argument("--no-mod-init", action="store_true")
    ap.add_argument("--no-rel-methlist", action="store_true")
    ap.add_argument("--no-avail-dispatch", action="store_true")
    ap.add_argument("--no-avail-stubs", action="store_true")
    ap.add_argument("--no-window-shim", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    mi = tuple(int(x) for x in a.minos.split(".")); sd = tuple(int(x) for x in a.sdk.split("."))
    wk = set()
    if a.weak_file and os.path.exists(a.weak_file):
        wk = {l.strip() for l in open(a.weak_file) if l.strip()}
    if a.verify:
        verify_classic(a.inp); return
    print(f"== {a.inp}")
    qp = (0x38E8964, 0x38E89B4) if a.patch_quit else ()
    out = a.out or (a.inp + ".dyldinfo")
    convert(a.inp, out, weak_names=wk, weak_all_missing=a.weak_all,
            minos=mi, sdk=sd, quit_patches=qp,
            shim_objc_opt=not a.no_shim_objc_opt,
            mod_init=not a.no_mod_init,
            rel_methlist=not a.no_rel_methlist,
            avail_dispatch=not a.no_avail_dispatch,
            avail_stubs=not a.no_avail_stubs,
            window_shim=not a.no_window_shim)
    verify_classic(out)


if __name__ == "__main__":
    main()
