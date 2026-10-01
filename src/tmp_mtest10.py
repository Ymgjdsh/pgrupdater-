import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN
MAPS = [(0x3BF4000, 0x1000), (0x444C000, 0x1000), (0x4450000, 0x3000),
        (0x47CB000, 0x1000), (0x52B3000, 0x1000)]
def trial(extra, note):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    for a, s in extra:
        uc.mem_map(a, s)
    uc.mem_map(0x7000000, 0x2000)
    try:
        uc.mem_write(0x70000030, b"\x01\x02\x03\x04"); print("ok   %s" % note)
    except Exception:
        print("FAIL %s" % note)
trial([], "none first")
for i, mp in enumerate(MAPS):
    trial([mp], "after %s" % hex(mp[0]))
trial(MAPS[:2], "after first two")
trial(MAPS[:4], "after first four")
trial(MAPS, "after all five")
