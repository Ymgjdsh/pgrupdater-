#!/usr/bin/env python3
"""Label Mach-O addresses: stubs -> selector/import, slots -> SEL/class/string,
data -> pointed-to object, plus an annotated disassembler mode.

Usage:
    python lbl.py <macho> 0xADDR [0xADDR ...]
    python lbl.py <macho> --dis 0xADDR [len]      # annotated disassembly
"""
import argparse
import bisect
import struct
import sys

import capstone

MD = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
MD.detail = True

SEG64 = 0x19
S_SYMBOL_STUBS = 0x8
S_NON_LAZY = 0x6
S_LAZY = 0x7
SECT = 80


def parse(path):
    buf = open(path, "rb").read()
    assert struct.unpack_from("<I", buf, 0)[0] == 0xFEEDFACF
    ncmds = struct.unpack_from("<I", buf, 16)[0]
    segs, sects, lcs = [], [], []
    symtab = dysym = None
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        lcs.append((cmd, cmdsize, off))
        if cmd == SEG64:
            name = buf[off + 8:off + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", buf, off + 24)
            segs.append(dict(name=name, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff,
                             filesize=filesize))
            nsects = struct.unpack_from("<I", buf, off + 64)[0]
            for k in range(nsects):
                so = off + 72 + k * SECT
                sname = buf[so:so + 16].split(b"\0")[0].decode()
                sseg = buf[so + 16:so + 32].split(b"\0")[0].decode()
                addr, size, o, align, reloff, nreloc, flg, r1, r2 = \
                    struct.unpack_from("<QQIIIIIII", buf, so + 32)
                sects.append(dict(name=sname, seg=sseg, addr=addr, size=size, offset=o,
                                  align=align, flags=flg, r1=r1, r2=r2))
        elif cmd == 0x2:
            symtab = dict(symoff=struct.unpack_from("<I", buf, off + 8)[0],
                          nsyms=struct.unpack_from("<I", buf, off + 12)[0],
                          stroff=struct.unpack_from("<I", buf, off + 16)[0],
                          strsize=struct.unpack_from("<I", buf, off + 20)[0])
        elif cmd == 0xB:
            dysym = dict(indirectsymoff=struct.unpack_from("<I", buf, off + 56)[0],
                         nindirectsyms=struct.unpack_from("<I", buf, off + 60)[0])
        off += cmdsize
    return dict(buf=buf, segs=segs, sects=sects, lcs=lcs, symtab=symtab, dysym=dysym)


class Img:
    def __init__(self, path):
        self.__dict__.update(parse(path))
        self._symnames = None
        self._indirect = None

    # --- basic access
    def foff(self, va):
        for s in self.segs:
            if s["vmaddr"] <= va < s["vmaddr"] + s["filesize"]:
                return s["fileoff"] + (va - s["vmaddr"])
        return None

    def rd(self, va, n):
        fo = self.foff(va)
        return None if fo is None else self.buf[fo:fo + n]

    def u64(self, va):
        b = self.rd(va, 8)
        return None if b is None or len(b) < 8 else struct.unpack("<Q", b)[0]

    def i64(self, va):
        b = self.rd(va, 8)
        return None if b is None or len(b) < 8 else struct.unpack("<q", b)[0]

    def u32(self, va):
        b = self.rd(va, 4)
        return None if b is None or len(b) < 4 else struct.unpack("<I", b)[0]

    def cstr(self, va, maxlen=300):
        b = self.rd(va, maxlen)
        if b is None:
            return None
        e = b.find(b"\0")
        if e < 0:
            return None
        try:
            return b[:e].decode()
        except UnicodeDecodeError:
            return None

    def sect_of(self, va):
        for s in self.sects:
            if s["addr"] <= va < s["addr"] + s["size"]:
                return f"{s['seg']},{s['name']}"
        return None

    def sect(self, name, seg=None):
        for s in self.sects:
            if s["name"] == name and (seg is None or s["seg"] == seg):
                return s
        return None

    def seg_of(self, va):
        for s in self.segs:
            if s["vmaddr"] <= va < s["vmaddr"] + s["vmsize"]:
                return s
        return None

    # --- symbols
    def symname(self, symidx):
        st = self.symtab
        if not st:
            return None
        fo = st["symoff"] + 16 * symidx
        nx = struct.unpack_from("<I", self.buf, fo)[0]
        if nx == 0 or nx >= st["strsize"]:
            return None
        so = st["stroff"] + nx
        e = self.buf.find(b"\0", so)
        return self.buf[so:e].decode("utf-8", "replace")

    def indirect(self):
        """slot va -> imported symbol name"""
        if self._indirect is not None:
            return self._indirect
        out = {}
        if self.dysym:
            for s in self.sects:
                kind = s["flags"] & 0xFF
                if kind not in (S_SYMBOL_STUBS, S_NON_LAZY, S_LAZY):
                    continue
                ents = s["r2"] if kind == S_SYMBOL_STUBS else 8
                if not ents:
                    ents = 12
                n = s["size"] // ents
                for k in range(n):
                    idx = s["r1"] + k
                    if idx >= self.dysym["nindirectsyms"]:
                        break
                    fio = self.dysym["indirectsymoff"] + 4 * idx
                    symidx = struct.unpack_from("<I", self.buf, fio)[0]
                    if symidx & 0xC0000000:
                        continue
                    nm = self.symname(symidx)
                    if nm:
                        out[s["addr"] + k * ents] = nm
        self._indirect = out
        return out

    # --- objc
    def class_name(self, cls_ptr):
        if not cls_ptr:
            return None
        data = self.u64(cls_ptr + 32)
        if data is None:
            return None
        ro = data & ~0x7
        p = self.u64(ro + 24)
        return self.cstr(p) if p else None

    def class_list(self):
        out = {}
        cl = self.sect("__objc_classlist")
        if cl:
            for i in range(cl["size"] // 8):
                p = self.u64(cl["addr"] + 8 * i)
                if p:
                    out[p] = self.class_name(p)
        return out

    def cfstring(self, va):
        """If va looks like a __CFConstantString, return its C string."""
        p, ln = self.u64(va + 16), self.u64(va + 24)
        fl = self.u64(va + 8)
        if p and ln is not None and fl == 0x7C8 and 0 < ln < 400:
            s = self.cstr(p, 400)
            if s is not None and len(s) == ln:
                return s
        return None

    # --- labels
    def stub_target(self, va):
        """For a stub/bl-thunk address: (slot_va, kind) where kind='sel'|'imp'"""
        fo = self.foff(va)
        if fo is None:
            return None, None
        code = self.buf[fo:fo + 64]
        page = None
        pageoff = None
        for ins in MD.disasm(code, va):
            if ins.mnemonic == "adrp":
                page = int(ins.op_str.split(",")[-1].strip().lstrip("#"), 16)
                continue
            if ins.mnemonic == "add" and page is not None:
                try:
                    pageoff = int(ins.op_str.split(",")[-1].strip().lstrip("#"), 16)
                except ValueError:
                    pass
                continue
            if ins.mnemonic == "ldr":
                try:
                    disp = ins.operands[1].mem.disp
                except Exception:
                    return None, None
                if page is not None:
                    slot = page + (pageoff or 0) + disp
                    return slot, "sel" if self.sect_of(slot) and "selrefs" in self.sect_of(slot) else "imp"
            if ins.mnemonic in ("br", "b"):
                return None, None
        return None, None

    def label(self, va, depth=0, seen=None):
        seen = seen or set()
        if va is None or va in seen or depth > 3:
            return ""
        seen = seen | {va}
        sec = self.sect_of(va)
        if sec is None:
            if 0 < va < 0x10000000000:
                return ""
            return ""
        ind = self.indirect()
        tag = f"[{sec}]"
        # stubs
        if sec.endswith("stub") or sec.endswith("stubs") or "__stubs" in sec:
            slot, kind = self.stub_target(va)
            if slot is not None:
                if kind == "sel":
                    p = self.u64(slot)
                    s = self.cstr(p) if p else None
                    return f"{tag} stub#{va:X} -> sel {s!r}"
                nm = ind.get(slot)
                return f"{tag} stub#{va:X} -> import {nm} (slot 0x{slot:X})"
            nm = ind.get(va)
            return f"{tag} stub#{va:X} -> {nm}"
        # slots
        if "selrefs" in sec:
            p = self.u64(va)
            return f"{tag} selref 0x{va:X} -> {self.cstr(p)!r}" if p else f"{tag} selref 0x{va:X} -> (null)"
        if "classrefs" in sec:
            p = self.u64(va)
            nm = self.class_name(p) if p else None
            return f"{tag} classref 0x{va:X} -> class {nm or hex(p or 0)}"
        if "__objc_classlist" in sec:
            nm = self.class_name(va)
            return f"{tag} class 0x{va:X} -> {nm}"
        if "__objc_methname" in sec or "__objc_classname" in sec or "__cstring" in sec \
                or "__objc_methtype" in sec:
            return f"{tag} str 0x{va:X} -> {self.cstr(va)!r}"
        if "cfstring" in sec:
            s = self.cfstring(va)
            return f"{tag} CFString 0x{va:X} -> {s!r}" if s else f"{tag} 0x{va:X}"
        # data pointers
        if sec.startswith("__DATA") and depth < 3:
            v = self.u64(va)
            if v and self.sect_of(v):
                extra = self.label(v, depth + 1, seen)
                nm = ind.get(va)
                lead = f"{tag} slot 0x{va:X} -> 0x{v:X}"
                if nm:
                    lead += f" (import {nm})"
                return f"{lead}  {extra}" if extra else lead
            nm = ind.get(va)
            if nm:
                return f"{tag} import-slot 0x{va:X} -> {nm}"
            if v:
                return f"{tag} 0x{va:X} -> 0x{v:X}"
            return f"{tag} 0x{va:X} -> 0"
        return f"{tag} 0x{va:X}"


def method_index(im):
    try:
        from imp_rev import collect
        rows = collect(im)
        starts = [r[0] for r in rows]
        return rows, starts
    except Exception as e:  # pragma: no cover
        print(f"# (no method index: {e})", file=sys.stderr)
        return [], []


def annotated_dis(im, addr, length, rows, starts):
    code = im.rd(addr, length)
    if code is None:
        raise SystemExit(f"0x{addr:X} not in file")
    adrp = {}
    for ins in MD.disasm(code, addr):
        note = ""
        m, ops = ins.mnemonic, ins.op_str
        # track adrp pages
        if m == "adrp":
            try:
                page = int(ops.split(",")[-1].strip().lstrip("#"), 16)
                adrp[ins.reg_name(ins.operands[0].reg)] = page
            except Exception:
                pass
        tgt = None
        if m in ("bl", "b", "br", "blr", "cbz", "cbnz", "tbz", "tbnz", "b.eq", "b.ne",
                 "b.lt", "b.gt", "b.le", "b.ge", "b.hi", "b.ls", "b.cc", "b.cs") or m.startswith("b."):
            if ops.startswith("#"):
                try:
                    tgt = int(ops.lstrip("#"), 16)
                except ValueError:
                    pass
        if m in ("ldr", "ldrb", "ldrsw", "str", "ldur"):
            try:
                base = ins.reg_name(ins.operands[1].mem.base)
                disp = ins.operands[1].mem.disp
                if base in adrp:
                    va = adrp[base] + disp
                    lb = im.label(va)
                    if lb:
                        note = lb
            except Exception:
                pass
        elif m == "add":
            try:
                base = ins.reg_name(ins.operands[1].reg)
                imm = int(ins.op_str.split(",")[-1].strip().lstrip("#"), 16)
                if base in adrp:
                    va = adrp[base] + imm
                    lb = im.label(va)
                    if lb:
                        note = lb
            except Exception:
                pass
        if m in ("bl", "blr") and ops.startswith("#"):
            try:
                t = int(ops.lstrip("#"), 16)
                note = im.label(t)
            except ValueError:
                pass
        if tgt is not None and rows:
            i = bisect.bisect_right(starts, tgt) - 1
            if i >= 0:
                imp, kind, owner, sel, t, eo = rows[i]
                if 0 <= tgt - imp < 0x800:
                    note = f"{note} | {owner} -[{sel}]+0x{tgt - imp:X}" if note else \
                        f"{owner} -[{sel}]+0x{tgt - imp:X}"
        line = f"0x{ins.address:06X}  {m:8s} {ops}"
        print(f"{line:<52s} ; {note}" if note else line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("macho")
    ap.add_argument("addrs", nargs="*")
    ap.add_argument("--dis", action="store_true")
    ap.add_argument("--len", type=lambda x: int(x, 0), default=0x100)
    a = ap.parse_args()
    im = Img(a.macho)
    if a.dis:
        rows, starts = method_index(im)
        annotated_dis(im, int(a.addrs[0], 0), a.len, rows, starts)
        return 0
    for s in a.addrs:
        va = int(s, 0)
        print(im.label(va))
    return 0


if __name__ == "__main__":
    sys.exit(main())
