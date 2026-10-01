"""Show, for each missing-on-iOS-12 symbol, the __got slot(s) it occupies in the
pristine chained-fixup UnityFramework, the value that slot holds in a converted
file, and the first instructions at that target.

usage: python shimpeek.py out\\UnityFramework.v11 work\\UnityFramework
"""
import sys
import capstone
import chained2dyld as C

conv = sys.argv[1] if len(sys.argv) > 1 else r"out\UnityFramework.v11"
pris = sys.argv[2] if len(sys.argv) > 2 else r"work\UnityFramework"

m = C.MachO(open(conv, "rb").read())
mp = C.MachO(open(pris, "rb").read())
dec = C.decode_fixups(mp)

NAMES = sys.argv[3].split(",") if len(sys.argv) > 3 else [
    "_objc_opt_class", "_objc_opt_isKindOfClass", "_objc_opt_respondsToSelector",
    "_objc_opt_self", "_CAFrameRateRangeMake", "_OBJC_CLASS_$_UIWindowScene",
    "___NSDictionary0__struct", "___kCFBooleanTrue",
    "_OBJC_CLASS_$_NSConstantArray", "_OBJC_CLASS_$_NSConstantIntegerNumber",
]

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)


def u64(va):
    return C.rd(m.buf, m.foff(va), "Q")[0]


def dump(va, n=8):
    fo = m.foff(va)
    out = []
    for i in md.disasm(bytes(m.buf[fo:fo + n * 4]), va):
        out.append(f"{i.address:x}: {i.bytes.hex()}  {i.mnemonic}\t{i.op_str}")
    return out


for name in NAMES:
    slots = [f["vmaddr"] for f in dec["fixups"]
             if f["kind"] == "bind" and f["name"] == name]
    if not slots:
        print(f"{name}: no slot in pristine")
        continue
    vals = sorted({u64(s) for s in slots})
    print(f"{name}: {len(slots)} slot(s) {[hex(s) for s in slots]}")
    for v in vals:
        print(f"    -> {v:#x}", "(ZERO)" if v == 0 else "")
        if v:
            for line in dump(v, 6):
                print("       " + line)
