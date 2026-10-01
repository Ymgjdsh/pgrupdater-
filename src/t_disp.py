"""unit-test the v8 objc_msgSend dispatcher emitter (disassemble it)"""
import capstone
from chained2dyld import (build_avail_dispatcher, build_func_stub, AVAIL_FUNC_STUBS,
                          _enc_bl, _enc_adrp, _dec_adrp, _enc_ldr64)

DISP = 0x444CE00          # like the free __TEXT tail of the framework
SELREF = 0x47CC1E8        # a real __objc_selrefs slot (connectedScenes) for the layout
MSG = 0x52923A8           # the synthesised real-objc_msgSend slot in __DATA_METHLIST

code = build_avail_dispatcher(DISP, SELREF, MSG)
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = False
print(f"dispatcher: {len(code)} bytes")
for i in md.disasm(code, DISP):
    print(f"  {i.address:x}: {i.bytes.hex()}  {i.mnemonic}\t{i.op_str}")

for sym, kind in AVAIL_FUNC_STUBS:
    c = build_func_stub(kind)
    print(f"stub {sym} ({kind}): {c.hex()}")
    for i in md.disasm(c, 0x444D000):
        print(f"   {i.mnemonic}\t{i.op_str}")

# sanity: every emitted word decodes (capstone must not answer ".byte")
n_bad = sum(1 for i in md.disasm(code, DISP) if i.mnemonic == ".byte")
print("undecodable words:", n_bad)
