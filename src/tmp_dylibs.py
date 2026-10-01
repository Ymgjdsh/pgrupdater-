"""tmp_dylibs.py <macho> -- print LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB / LC_RPATH names (+ LC_ID_DYLIB)."""
import struct, sys

buf = open(sys.argv[1], "rb").read()
ncmds, sizeofcmds = struct.unpack_from("<2I", buf, 16)
off = 32
for i in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<2I", buf, off)
    if cmd in (0xc, 0x80000018, 0x18, 0xd, 0x8000001c, 0x1f):
        nameoff = struct.unpack_from("<I", buf, off + 8)[0]
        end = buf.index(b"\0", off + nameoff)
        nm = buf[off + nameoff:end].decode(errors="replace")
        kind = {0xc: "LOAD", 0x80000018: "WEAK", 0x18: "REEXPORT", 0xd: "ID", 0x8000001c: "RPATH",
                0x1f: "LOAD_UPWARD"}[cmd]
        print(f"  [{i:2}] {kind:12} {nm}")
    off += cmdsize
