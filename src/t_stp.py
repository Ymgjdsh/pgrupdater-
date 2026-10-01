"""find the exact LDP/STP (SIMD&FP) opcode bases by asking capstone to decode candidates"""
import capstone, struct

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)


def dec(w):
    out = [f"{i.mnemonic} {i.op_str}" for i in md.disasm(struct.pack("<I", w), 0x1000)]
    return out[0] if out else "?"


for opc in range(4):
    for L in (0, 1):
        for wb in (0b010, 0b011, 0b001):
            base = (opc << 30) | (0b101 << 27) | (1 << 26) | (wb << 23) | (L << 22)
            off = 0x50
            scale = 16 if (opc & 2) else 8 if opc == 1 else 4
            imm7 = off // scale
            insn = base | ((imm7 & 0x7F) << 15) | (1 << 10) | (31 << 5) | 0
            print(f"base=0x{base:08X} (opc={opc} L={L} wb={wb:03b}) "
                  f"off=0x{off:x} -> 0x{insn:08X}  {dec(insn)}")
