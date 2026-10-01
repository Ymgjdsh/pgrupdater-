import ctypes
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_PROT_ALL
def show(addr, size, waddr):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(addr, size)
    regs = uc.mem_regions()
    print("map 0x%x+0x%x regions=%s" % (addr, size, [(hex(a),hex(b-a+1)) for a,b,p in regs]))
    try:
        uc.mem_write(waddr, b"\x01\x02\x03\x04"); print("   write@0x%x ok" % waddr)
    except Exception as e:
        print("   write@0x%x FAILED" % waddr)
show(0x7000000, 0x1000, 0x70000030)
show(0x7000000, 0x10000, 0x70000030)
show(0x8000000, 0x1000, 0x8000000)
show(0x7000000, 0x1000, 0x70000030)
uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
buf = ctypes.create_string_buffer(0x2000)
uc.mem_map_ptr(0x7000000, 0x2000, UC_PROT_ALL, ctypes.addressof(buf))
try:
    uc.mem_write(0x70000030, b"\x01\x02\x03\x04"); print("mem_map_ptr write ok")
except Exception as e:
    print("mem_map_ptr write FAILED")
