import struct
import chained2dyld as C
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN
DATA_VA = 0x52B3000
buf = open(r"out\UnityFramework.v13raw", "rb").read()
m = C.MachO(buf)
uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
for va, size, src in ((0x3BF4000, 0x1000, 0x3BF4000),
                      (0x444C000, 0x1000, 0x444C000),
                      (0x4450000, 0x3000, 0x4450000),
                      (0x47CB000, 0x1000, 0x47CB000),
                      (DATA_VA, 0x1000, m.foff(DATA_VA)),
                      (0x7000000, 0x2000, None)):
    uc.mem_map(va, size)
    if src is not None:
        uc.mem_write(va, buf[src:src + size])
print("regions:", [(hex(a), hex(b - a + 1)) for a, b, p in uc.mem_regions()])
def w(addr, data, tag):
    try:
        uc.mem_write(addr, data); print("  %-16s 0x%x ok" % (tag, addr))
    except Exception as e:
        print("  %-16s 0x%x FAILED" % (tag, addr))
w(0x4451DF8, struct.pack("<Q", 0x70000010), "MSGSEND_SLOT")
w(0x44520B0, struct.pack("<Q", 0x70000020), "CF_SLOT")
w(0x47CBDB8, struct.pack("<Q", 0x11111111), "SELREF")
w(0x70000030, struct.pack("<I", 0xD65F03C0), "CALLER")
w(0x70000010, b"\x01\x02\x03\x04", "FAKE1")
w(0x70000020, b"\x01\x02\x03\x04", "FAKE2")
