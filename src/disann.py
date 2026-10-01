#!/usr/bin/env python3
"""disann.py -- disassemble an arm64 Mach-O range and annotate calls into
__objc_stubs (with the ObjC selector) and __stubs (with the imported symbol).

Usage: python disann.py <macho> <start-va-hex> [len-hex] [--pristine P]
"""
import sys, struct, chained2dyld as C
import capstone

def u64(buf, off): return struct.unpack_from("<Q", buf, off)[0]

path = sys.argv[1]
start = int(sys.argv[2], 16)
rest = sys.argv[3:]
ln = 0x100
if rest and not rest[0].startswith("--"):
    ln = int(rest[0], 16); rest = rest[1:]
pristine = path
if "--pristine" in rest:
    pristine = rest[rest.index("--pristine") + 1]

buf = open(path, "rb").read()
m = C.MachO(buf)
pbuf = open(pristine, "rb").read()
pm = C.MachO(pbuf)

# slot VA -> imported symbol name (from the pristine chained binary)
slot2name = {}
try:
    for f in C.decode_fixups(pm)["fixups"]:
        n = f.get("name")
        v = f.get("vmaddr")
        if n and v is not None: slot2name[v] = n
except Exception as e:
    print("// fixup decode failed:", e)

def section(seg, name):
    for s in m.sections:
        if s["seg"] == seg and s["name"] == name: return s
    return None

objc_stubs = section("__TEXT", "__objc_stubs")
stubs = section("__TEXT", "__stubs")
selrefs = section("__DATA_CONST", "__objc_selrefs") or section("__DATA", "__objc_selrefs")

def cstr(va):
    fo = m.foff(va)
    if fo is None: return None
    end = buf.find(b"\0", fo)
    return buf[fo:end].decode("utf-8", "replace")

def selref_name(slot_va):
    fo = m.foff(slot_va)
    if fo is None: return None
    tgt = u64(buf, fo)
    return cstr(tgt)

def annot_call(target):
    if objc_stubs and objc_stubs["addr"] <= target < objc_stubs["addr"] + objc_stubs["size"]:
        e = objc_stubs["addr"] + ((target - objc_stubs["addr"]) // 32) * 32
        fo = m.foff(e)
        i0 = struct.unpack_from("<I", buf, fo)[0]
        if i0 & 0x9F000000 == 0x90000000:
            immhi = (i0 >> 5) & 0x7FFFF; immlo = (i0 >> 29) & 3
            imm = (immhi << 2) | immlo
            if imm & (1 << 20): imm -= 1 << 21
            page = ((e & ~0xFFF) + (imm << 12)) & ((1 << 64) - 1)
            i1 = struct.unpack_from("<I", buf, fo + 4)[0]
            if i1 & 0xFFC00000 == 0xF9400000:
                off = ((i1 >> 10) & 0xFFF) * 8
                return "objc_msgSend sel=%r" % (selref_name(page + off),)
    if stubs and stubs["addr"] <= target < stubs["addr"] + stubs["size"]:
        e = stubs["addr"] + ((target - stubs["addr"]) // 12) * 12
        fo = m.foff(e)
        i0 = struct.unpack_from("<I", buf, fo)[0]
        if i0 & 0x9F000000 == 0x90000000:
            immhi = (i0 >> 5) & 0x7FFFF; immlo = (i0 >> 29) & 3
            imm = (immhi << 2) | immlo
            if imm & (1 << 20): imm -= 1 << 21
            page = ((e & ~0xFFF) + (imm << 12)) & ((1 << 64) - 1)
            i1 = struct.unpack_from("<I", buf, fo + 4)[0]
            if i1 & 0xFFC00000 == 0xF9400000:
                off = ((i1 >> 10) & 0xFFF) * 8
                return "CALL %s" % (slot2name.get(page + off, hex(page + off)),)
    return None

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True
fo = m.foff(start)
if fo is None:
    print("bad va"); sys.exit(1)
code = buf[fo:fo + ln]
last_adrp = {}
for ins in md.disasm(code, start):
    note = ""
    mn, ops = ins.mnemonic, ins.op_str
    if mn == "adrp":
        try:
            rd = ops.split(",")[0].strip()
            target = int(ops.split("#")[1], 0)
            last_adrp[rd] = (ins.address, target)
        except Exception:
            pass
    if mn in ("bl", "b") and ops.startswith("#"):
        t = int(ops[1:], 0)
        a = annot_call(t)
        if a: note = a
    if mn == "ldr" and "[" in ops and "#" in ops:
        try:
            rd = ops.split(",")[0].strip()
            base = ops.split("[")[1].split("]")[0].split(",")[0].strip()
            off = int(ops.split("#")[1].split("]")[0], 0)
            if base in last_adrp:
                slot = last_adrp[base][1] + off
                if slot in slot2name:
                    note = "slot -> %s" % slot2name[slot]
        except Exception:
            pass
    print("0x%08X  %-8s %-40s %s" % (ins.address, ins.bytes.hex(), mn + " " + ops, note))
