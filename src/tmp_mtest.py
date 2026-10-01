import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN
uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
uc.mem_map(0x7000000, 0x2000)
print("mapped ok")
try:
    uc.mem_write(0x70000030, struct.pack("<I", 0xD65F03C0))
    print("write ok", uc.mem_read(0x70000030, 4).hex())
except Exception as e:
    print("write failed:", e)
uc2 = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
uc2.mem_map(0x3BF4000, 0x1000); uc2.mem_map(0x444C000, 0x1000)
uc2.mem_map(0x4450000, 0x3000); uc2.mem_map(0x47CB000, 0x1000)
uc2.mem_map(0x52B3000, 0x1000); uc2.mem_map(0x7000000, 0x2000)
try:
    uc2.mem_write(0x70000030, struct.pack("<I", 0xD65F03C0)); print("combo write ok")
except Exception as e:
    print("combo write failed:", e)
