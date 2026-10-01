import sys
sys.path.insert(0, ".")
import chained2dyld as C

VA = 0x3BFAC10

for path in ("work\\UnityFramework", "out\\UnityFramework.v13raw"):
    raw = open(path, "rb").read()
    m = C.MachO(raw)
    fo = m.foff(VA)
    with open(path, "rb") as f:
        f.seek(fo)
        b = f.read(16)
    print("%-30s VA=0x%X fo=0x%X bytes=%s" % (path, VA, fo, b.hex(" ")))
    # decode a `b` at this VA
    import struct
    w = struct.unpack_from("<I", b, 0)[0]
    if (w & 0xFC000000) == 0x14000000:
        off = w & 0x3FFFFFF
        if off & (1 << 25):
            off -= (1 << 26)
        print("    b -> 0x%X" % (VA + off * 4))
    elif w == 0xD61F0200:
        print("    br x16")
    else:
        print("    other 0x%08X" % w)
