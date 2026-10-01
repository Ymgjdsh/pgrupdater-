from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN
def t(addr, size, waddr, n):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(addr, size)
    try:
        uc.mem_write(waddr, b"\x01"*n); print("map 0x%x+0x%x write %d bytes @0x%x ok" % (addr,size,n,waddr))
    except Exception as e:
        print("map 0x%x+0x%x write %d bytes @0x%x FAILED" % (addr,size,n,waddr))
t(0x7000000, 0x2000, 0x70001030, 4)
t(0x7000000, 0x3000, 0x70001030, 4)
t(0x7000000, 0x2000, 0x70001030, 1)
t(0x7000000, 0x2000, 0x70001800, 4)
t(0x7000000, 0x2000, 0x70001130, 4)
t(0x7000000, 0x1000, 0x70000030, 4)
