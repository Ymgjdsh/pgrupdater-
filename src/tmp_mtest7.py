from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN
for a in (0x2000000, 0x4000000, 0x6000000, 0x7000000, 0x8000000, 0x10000000, 0x20000000, 0x30000000, 0x70000000, 0x80000000):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(a, 0x1000)
    try:
        uc.mem_write(a + 0x30, b"\x01\x02\x03\x04"); print("0x%09x ok" % a)
    except Exception:
        print("0x%09x FAILED" % a)
