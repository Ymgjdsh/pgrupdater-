"""Minimal little-endian Mach-O reader shared by the recon/analysis scripts."""
import struct

def le(buf, off, fmt):
    return struct.unpack_from("<" + fmt, buf, off)

class MachO:
    def __init__(self, path):
        self.path = path
        self.buf = open(path, "rb").read()
        b = self.buf
        magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = le(b, 0, "IiiIIIII")
        assert magic == 0xFEEDFACF, hex(magic)
        self.magic, self.cputype, self.cpusub = magic, cputype, cpusub
        self.ftype, self.ncmds, self.sizeofcmds, self.flags = ftype, ncmds, sizeofcmds, flags
        self.cmds = []
        off = 32
        for i in range(ncmds):
            cmd, cmdsize = le(b, off, "II")
            self.cmds.append((cmd, cmdsize, off))
            off += cmdsize
        self.segments = []
        self.sections = []
        for cmd, cmdsize, co in self.cmds:
            if cmd == 0x19:
                segname = b[co + 8:co + 24].rstrip(b"\0").decode("utf-8", "replace")
                vmaddr, vmsize, fileoff, filesize = le(b, co + 24, "QQQQ")
                maxprot, initprot, nsects, segflags = le(b, co + 56, "iiII")
                si = len(self.segments)
                self.segments.append(dict(idx=si, name=segname, vmaddr=vmaddr, vmsize=vmsize,
                                          fileoff=fileoff, filesize=filesize, maxprot=maxprot,
                                          initprot=initprot, nsects=nsects, flags=segflags))
                so = co + 72
                for j in range(nsects):
                    sectname = b[so:so + 16].rstrip(b"\0").decode("utf-8", "replace")
                    segn2 = b[so + 16:so + 32].rstrip(b"\0").decode("utf-8", "replace")
                    addr, size = le(b, so + 32, "QQ")
                    offset, align, reloff, nreloc, sflags = le(b, so + 48, "IIIII")
                    self.sections.append(dict(seg=segn2, name=sectname, addr=addr, size=size,
                                              offset=offset, align=align, flags=sflags, segidx=si))
                    so += 80

    def lc(self, cmd):
        return [c for c in self.cmds if c[0] == cmd]

    def sect_of(self, vmaddr):
        best = None
        for s in self.sections:
            if s["addr"] <= vmaddr < s["addr"] + s["size"]:
                if best is None or s["addr"] > best["addr"]:
                    best = s
        return best
