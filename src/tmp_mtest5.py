import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN
def t(addr, size, waddr, data, tag):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(addr, size)
    try:
        uc.mem_write(waddr, data); r = "ok"
    except Exception as e:
        r = "FAILED"
    print("%-28s map 0x%x+0x%x write@0x%x %s" % (tag, addr, size, waddr, r))
for i in range(3):
    t(0x7000000, 0x1000, 0x70000030, struct.pack("<I", 0xD65F03C0), "run%d pack" % i)
for i in range(3):
    t(0x7000000, 0x1000, 0x70000030, b"\x01\x02\x03\x04", "run%d lit" % i)
for i in range(3):
    t(0x7000000, 0x1000, 0x70000000, b"\x01\x02\x03\x04", "run%d base" % i)
print("unicorn:", __import__("unicorn").__version__)
