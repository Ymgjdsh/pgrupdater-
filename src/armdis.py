#!/usr/bin/env python3
"""Disassemble a slice of a Mach-O and annotate calls/stubs with symbol names.

Usage:
    python dis.py <macho> <addr> [length] [--dump dump.cs] [--u] [--raw]
        <addr>      hex (0x...) or decimal; interpreted as the *unslid* vmaddr
                    (what Il2CppDumper calls RVA) -- use --file for a file offset
    --u             in the UnityFramework `UnityFramework` (default: auto)
    --raw           do not annotate, plain instructions
    --follow N      also disassemble N bytes at the target of the first `bl`

Annotations:
    * `bl`/`b` into `__stubs`          -> resolved import symbol
    * `adrp+ldr` into `__got`/lazy ptr -> import symbol
    * any target inside `__text`       -> nearest il2cpp method (from dump.cs)
"""
import argparse
import bisect
import json
import os
import struct
import sys

import capstone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

SEG64 = 0x19
SECT_SIZE = 80
SEG_CMD = 72


def parse_macho(path):
    buf = open(path, "rb").read()
    magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from("<8I", buf, 0)
    assert magic == 0xFEEDFACF, hex(magic)
    segs, sects, info, symtab, dysym, csig = [], [], None, None, None, None
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmd == SEG64:
            segname = buf[off + 8:off + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", buf, off + 24)
            initprot, maxprot, nsects, fl = struct.unpack_from("<4I", buf, off + 56)
            seg = dict(name=segname, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff,
                       filesize=filesize, initprot=initprot, nsects=nsects, i=len(segs))
            segs.append(seg)
            for k in range(nsects):
                so = off + SEG_CMD + k * SECT_SIZE
                sname = buf[so:so + 16].split(b"\0")[0].decode()
                sseg = buf[so + 16:so + 32].split(b"\0")[0].decode()
                addr, size, offset, align, reloff, nreloc, flg, _r1, _r2, _r3 = struct.unpack_from(
                    "<QQIIIIIIII", buf, so + 32)
                sects.append(dict(name=sname, seg=sseg, addr=addr, size=size, offset=offset, flags=flg))
        elif cmd in (0x22, 0x23):
            info = struct.unpack_from("<10I", buf, off + 8)
        elif cmd == 0x2:
            symtab = struct.unpack_from("<4I", buf, off + 8)
        elif cmd == 0xB:
            dysym = struct.unpack_from("<18I", buf, off + 8)
        elif cmd == 0x1D:
            csig = struct.unpack_from("<2I", buf, off + 8)
        off += cmdsize
    return buf, segs, sects, info, symtab, dysym, csig


def bind_map(path):
    """addr -> symbol name for every classic-bind slot in the image."""
    import bindscan
    buf, segs, info = bindscan.parse(path)
    if info is None:
        return {}
    bindscan.segs = segs
    r_off, r_sz, b_off, b_sz, wb_off, wb_sz, ly_off, ly_sz, ex_off, ex_sz = info
    out = {}
    for base, size, weak in ((b_off, b_sz, False), (ly_off, ly_sz, False), (wb_off, wb_sz, True)):
        if not base or not size:
            continue
        try:
            entries, used, total = bindscan.walk_bind(buf, base, size, weak)
        except Exception as e:
            print(f"# warning: bind walk failed ({e})", file=sys.stderr)
            continue
        for sym, ordinal, isweak, segname, addr, addend in entries:
            out.setdefault(addr, (sym, ordinal, isweak))
    return out


def load_dump(path):
    if not path or not os.path.exists(path):
        return []
    cache = os.path.splitext(path)[0] + ".rvamap.json"
    if os.path.exists(cache) and os.path.getmtime(cache) > os.path.getmtime(path):
        return [(e[0], e[1]) for e in json.load(open(cache, encoding="utf-8"))]
    import rvamap
    ent = rvamap.build(path)
    json.dump(ent, open(cache, "w", encoding="utf-8"))
    return ent


def nearest(entries, addr):
    i = bisect.bisect_right(entries, (addr, "\uffff"))
    if i == 0:
        return None
    return entries[i - 1]


class Dis:
    def __init__(self, path, dump=None):
        self.path = path
        self.buf, self.segs, self.sects, self.info, self.symtab, self.dysym, self.csig = parse_macho(path)
        self.binds = bind_map(path)
        self.dump = load_dump(dump) if dump else []
        self.md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        self.md.detail = True

    def sect_of(self, addr):
        for s in self.sects:
            if s["addr"] <= addr < s["addr"] + s["size"]:
                return s
        return None

    def seg_of(self, addr):
        for s in self.segs:
            if s["vmaddr"] <= addr < s["vmaddr"] + s["vmsize"]:
                return s
        return None

    def foff(self, addr):
        for s in self.segs:
            if s["vmaddr"] <= addr < s["vmaddr"] + s["filesize"]:
                return s["fileoff"] + (addr - s["vmaddr"])
        return None

    def stub_target(self, addr):
        """If `addr` is the first instruction of a __stubs entry, return the got slot."""
        s = self.sect_of(addr)
        if not s or s["name"] != "__stubs":
            return None
        fo = self.foff(addr)
        if fo is None:
            return None
        code = self.buf[fo:fo + 12]
        # decode manually: adrp x16, page ; ldr x16, [x16, #imm] ; br x16
        w0, w1 = struct.unpack_from("<2I", code, 0)
        if (w0 & 0x9F000000) != 0x90000000 or (w1 & 0xFFC00000) != 0xF9400000:
            return None
        immhi = (w0 >> 5) & 0x7FFFF
        immlo = (w0 >> 29) & 0x3
        imm = ((immhi << 2) | immlo)
        if imm & (1 << 20):
            imm -= 1 << 21
        page = (addr & ~0xFFF) + (imm << 12)
        return page + ((w1 >> 10) & 0xFFF) * 8

    def label(self, addr, cur=None):
        """human annotation for an address used as a branch/call target"""
        st = self.sect_of(addr)
        if st and st["name"] in ("__stubs", "__auth_stubs"):
            slot = self.stub_target(addr - (addr % 12) if False else addr)
            if slot is None:
                # may be called mid-entry; align down to a 12-byte boundary within the section
                base = st["addr"]
                slot = self.stub_target(base + ((addr - base) // 12) * 12)
            if slot is not None and slot in self.binds:
                sym, ordinal, weak = self.binds[slot]
                return f"stub -> {sym}{' (weak)' if weak else ''} [ord {ordinal}]"
            if slot is not None:
                return f"stub -> slot 0x{slot:X} (unbound)"
            return "stub"
        if addr in self.binds:
            sym, ordinal, weak = self.binds[addr]
            return f"{sym}{' (weak)' if weak else ''}"
        if self.dump:
            hit = nearest(self.dump, addr)
            if hit and hit[0] <= addr:
                return f"{hit[1]} + 0x{addr - hit[0]:X}"
        s = self.seg_of(addr)
        if s:
            return f"<{s['name']}+0x{addr - s['vmaddr']:X}>"
        return "?"

    def dis(self, addr, length, annotate=True, prefix=""):
        fo = self.foff(addr)
        if fo is None:
            print(f"{prefix}0x{addr:X}: not file-backed")
            return []
        code = self.buf[fo:fo + length]
        lines = []
        for ins in self.md.disasm(code, addr):
            note = ""
            if annotate:
                if ins.mnemonic in ("bl", "b", "b.eq", "b.ne", "cbz", "cbnz", "tbz", "tbnz"):
                    try:
                        t = ins.operands[0].imm
                    except Exception:
                        t = None
                    if t:
                        note = "  ; -> " + self.label(t)
                elif ins.mnemonic == "adrp":
                    try:
                        t = ins.operands[1].imm
                    except Exception:
                        t = None
                    if t:
                        note = f"  ; page 0x{t:X}"
            lines.append((ins.address, ins.mnemonic, ins.op_str, note))
            print(f"{prefix}0x{ins.address:09X}  {ins.bytes.hex():<8} {ins.mnemonic:<8} {ins.op_str}{note}")
        return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("macho")
    ap.add_argument("addr", nargs="?", default=None)
    ap.add_argument("length", nargs="?", type=lambda v: int(v, 0), default=0x80)
    ap.add_argument("--dump")
    ap.add_argument("--sections", action="store_true")
    ap.add_argument("--bind", nargs="*", default=None)
    a = ap.parse_args()

    if not a.dump:
        cand = os.path.join(HERE, "tools", "Il2CppDumper", "dump.cs")
        a.dump = cand if os.path.exists(cand) else None

    d = Dis(a.macho, a.dump)
    if a.sections:
        for s in d.sects:
            print(f"  {s['seg']},{s['name']:<22} addr=0x{s['addr']:08X} size=0x{s['size']:X} off=0x{s['offset']:X} flags=0x{s['flags']:X}")
        return 0
    if a.bind is not None:
        for addr, (sym, ordv, weak) in sorted(d.binds.items()):
            if not a.bind or any(w.lower() in sym.lower() for w in a.bind):
                print(f"0x{addr:09X} {'WEAK' if weak else '    '} {sym} [ord {ordv}]")
        return 0
    if a.addr is None:
        raise SystemExit("need an address (use --sections/--bind otherwise)")
    addr = int(a.addr, 0)
    d.dis(addr, a.length)
    return 0


if __name__ == "__main__":
    sys.exit(main())
