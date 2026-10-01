from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN
def t(addr, size, waddrs):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    try:
        uc.mem_map(addr, size)
    except Exception as e:
        print("map 0x%x+0x%x failed: %s" % (addr, size, e)); return
    res = []
    for w in waddrs:
        try:
            uc.mem_write(w, b"\x01"); res.append("0x%x:ok" % w)
        except Exception:
            res.append("0x%x:NO" % w)
    print("map 0x%x+0x%x -> %s" % (addr, size, " ".join(res)))
t(0x11D1000, 0x2000, [0x11D1000, 0x11D2000, 0x11D2FFF])
t(0x8000000, 0x2000, [0x8000000, 0x8001000])
t(0x7000000, 0x3000, [0x7000000, 0x7001000, 0x7002000])
t(0x7000000, 0x4000, [0x7000000, 0x7001000, 0x7002000, 0x7003000])
t(0x7000000, 0x1000, [0x7000000])
uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
uc.mem_map(0x7000000, 0x1000); uc.mem_map(0x7001000, 0x1000); uc.mem_map(0x7002000, 0x1000)
for w in (0x7000000, 0x7001000, 0x7002000):
    try:
        uc.mem_write(w, b"\x01"); print("separate maps 0x%x ok" % w)
    except Exception as e:
        print("separate maps 0x%x FAILED" % w)
