import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN
def t(addr, size, waddr):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    try:
        uc.mem_map(addr, size)
    except Exception as e:
        print("map 0x%x+0x%x failed: %s" % (addr, size, e)); return
    try:
        uc.mem_write(waddr, b"\x01\x02\x03\x04"); print("map 0x%x+0x%x write 0x%x ok" % (addr, size, waddr))
    except Exception as e:
        print("map 0x%x+0x%x write 0x%x FAILED: %s" % (addr, size, waddr, e))
t(0x7000000, 0x1000, 0x7000000)
t(0x7000000, 0x1000, 0x7000030)
t(0x7000000, 0x2000, 0x7000030)
t(0x7000000, 0x2000, 0x70001030)
t(0x7000000, 0x10000, 0x7000030)
t(0x7000000, 0x10000, 0x70008030)
t(0x7000000, 0x10000, 0x7000F030)
t(0x7000000, 0x20000, 0x70010030)
