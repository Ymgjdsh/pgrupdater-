from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN
import sys
if len(sys.argv) > 1 and sys.argv[1] == "big":
    data = open(r"out\UnityFramework.v13raw", "rb").read()
    print("read %d bytes" % len(data))
for a in (0x3BF4000, 0x444C000, 0x4450000, 0x47CB000, 0x52B3000, 0x7000000):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(a, 0x1000)
    try:
        uc.mem_write(a + 0x30, b"\x01\x02\x03\x04"); print("0x%09x ok" % a)
    except Exception:
        print("0x%09x FAILED" % a)
