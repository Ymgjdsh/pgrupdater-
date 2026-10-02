"""verify_ios14.py <macho...> [--main]

Re-implements the load-command validation that dyld does in
ImageLoaderMachO::sniffLoadCommands() for iOS 13/14
(dyldsrc/dyld-732.8.cpp, dyldsrc/dyld-852.2.cpp), plus the dyld3
MachOLoaded::getLinkEditLoadCommands LC_BUILD_VERSION size check and
classic arm64 pointer-fixup/segment checks from MachOAnalyzer.
Passing covers only the implemented rules, not real-device launch or signing.

Rule text mirrors the dyld source so it can be grepped against a device log.
Tier:
  [always]  enforced for every image (also in dyld-655.1.1 / iOS 12)
  [strict]  only when context.strictMachORequired (frameworks, restricted apps)
  [strict13] strict AND only present from dyld-732.8 (iOS 13) onwards
  [dyld3]   checked in dyld3's link-edit command parser
"""
import struct
import sys
import os

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_WEAK_DYLIB = 0x18 | 0x80000000
LC_REEXPORT_DYLIB = 0x1F | 0x80000000
LC_LOAD_UPWARD_DYLIB = 0x23 | 0x80000000
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO_64 = 0x2C
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x22 | 0x80000000
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_VERSION_MIN_MACOSX = 0x24
LC_VERSION_MIN_IPHONEOS = 0x25
LC_VERSION_MIN_TVOS = 0x2F
LC_VERSION_MIN_WATCHOS = 0x30
LC_BUILD_VERSION = 0x32

NAME = {
    LC_SEGMENT_64: "LC_SEGMENT_64", LC_SYMTAB: "LC_SYMTAB", LC_DYSYMTAB: "LC_DYSYMTAB",
    LC_LOAD_DYLIB: "LC_LOAD_DYLIB", LC_ID_DYLIB: "LC_ID_DYLIB",
    LC_LOAD_WEAK_DYLIB: "LC_LOAD_WEAK_DYLIB", LC_REEXPORT_DYLIB: "LC_REEXPORT_DYLIB",
    LC_LOAD_UPWARD_DYLIB: "LC_LOAD_UPWARD_DYLIB", LC_CODE_SIGNATURE: "LC_CODE_SIGNATURE",
    LC_ENCRYPTION_INFO_64: "LC_ENCRYPTION_INFO_64", LC_DYLD_INFO: "LC_DYLD_INFO",
    LC_DYLD_INFO_ONLY: "LC_DYLD_INFO_ONLY", LC_DYLD_CHAINED_FIXUPS: "LC_DYLD_CHAINED_FIXUPS",
    LC_DYLD_EXPORTS_TRIE: "LC_DYLD_EXPORTS_TRIE", LC_VERSION_MIN_IPHONEOS: "LC_VERSION_MIN_IPHONEOS",
    LC_BUILD_VERSION: "LC_BUILD_VERSION",
}

VM_PROT_READ = 1
VM_PROT_WRITE = 2
VM_PROT_EXECUTE = 4

SEG_CMD_SIZE = 72
SECT_SIZE = 80
HDR_SIZE = 32
NLIST64_SIZE = 16


def ver(v):
    return "%d.%d.%d" % ((v >> 16) & 0xFFFF, (v >> 8) & 0xFF, v & 0xFF)


class Checker:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as source:
            self.buf = source.read()
        self.fails = []
        self.notes = []

    def fail(self, tier, msg):
        self.fails.append((tier, msg))

    def note(self, msg):
        self.notes.append(msg)

    def u32(self, off):
        return struct.unpack_from("<I", self.buf, off)[0]

    def u64(self, off):
        return struct.unpack_from("<Q", self.buf, off)[0]

    def run(self):
        b = self.buf
        if len(b) < HDR_SIZE:
            self.fail("always", "file shorter than mach_header")
            return
        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, rsv = struct.unpack_from("<IiiIIIII", b, 0)
        if magic != MH_MAGIC_64:
            self.fail("always", "not a 64-bit Mach-O (magic 0x%08X)" % magic)
            return
        self.ncmds = ncmds
        self.sizeofcmds = sizeofcmds
        self.hdr = dict(cputype=cputype, filetype=filetype, flags=flags)
        if HDR_SIZE + sizeofcmds > len(b):
            self.fail("always", "sizeofcmds (%u) exceeds file size" % sizeofcmds)
            return
        if ncmds > sizeofcmds // 8:
            self.fail("always", "malformed mach-o: load commands size (%u) > %u (ncmds*8)" % (ncmds * 8, sizeofcmds))

        segs = []          # dicts
        seg_by_name = {}
        linkedit = None
        start_of_file = None
        found_lc_seg = False
        symtab = None
        dysymtab = None
        dyldinfo = None
        chained = None
        exportstrie = None
        codesig = None
        libcount = 0
        segcount = 0

        off = HDR_SIZE
        for i in range(ncmds):
            if off + 8 > HDR_SIZE + sizeofcmds:
                self.fail("always", "load command #%d runs past sizeofcmds" % i)
                break
            cmd, cmdsize = struct.unpack_from("<II", b, off)
            if cmdsize < 8:
                self.fail("always", "malformed mach-o image: load command #%d length (%u) too small" % (i, cmdsize))
                break
            if off + cmdsize > HDR_SIZE + sizeofcmds:
                self.fail("always", "malformed mach-o image: load command #%d length (%u) would exceed sizeofcmds (%u)"
                          % (i, cmdsize, sizeofcmds))
                break
            if cmdsize % 8 != 0:
                self.fail("strict", "load command #%d cmdsize %u not 8-byte aligned" % (i, cmdsize))

            if cmd == LC_SEGMENT_64:
                segname = b[off + 8:off + 24].split(b"\0")[0].decode("latin1")
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", b, off + 24)
                maxprot, initprot, nsects, sflags = struct.unpack_from("<iiII", b, off + 56)
                seg = dict(name=segname, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff, filesize=filesize,
                           maxprot=maxprot, initprot=initprot, nsects=nsects, flags=sflags, hdr_off=off)
                segs.append(seg)
                seg_by_name[segname] = seg

                if filesize > vmsize and vmsize != 0:
                    self.fail("always", "malformed mach-o image: segment load command %s filesize (0x%X) is larger than vmsize (0x%X)"
                              % (segname, filesize, vmsize))
                if cmdsize != SEG_CMD_SIZE + nsects * SECT_SIZE:
                    self.fail("always", "malformed mach-o image: LC_SEGMENT size wrong for number of sections (%s: cmdsize=%u nsects=%u)"
                              % (segname, cmdsize, nsects))
                if vmsize != 0:
                    segcount += 1
                if segname == "__LINKEDIT":
                    if fileoff == 0:
                        self.fail("always", "malformed mach-o image: __LINKEDIT has fileoff==0 which overlaps mach_header")
                    if linkedit is not None:
                        self.fail("always", "malformed mach-o image: multiple __LINKEDIT segments")
                    linkedit = seg
                else:
                    if initprot & 0xFFFFFFF8:
                        self.fail("always", "malformed mach-o image: %s segment has invalid permission bits (0x%X) in initprot" % (segname, initprot))
                    if maxprot & 0xFFFFFFF8:
                        self.fail("always", "malformed mach-o image: %s segment has invalid permission bits (0x%X) in maxprot" % (segname, maxprot))
                    if initprot != 0 and not (initprot & VM_PROT_READ):
                        self.fail("always", "malformed mach-o image: %s segment is not mapped readable" % segname)
                if fileoff == 0 and filesize != 0:
                    if not (initprot & VM_PROT_READ):
                        self.fail("always", "malformed mach-o image: %s segment maps start of file but is not readable" % segname)
                    if (initprot & VM_PROT_WRITE) == VM_PROT_WRITE:
                        self.fail("strict", "malformed mach-o image: %s segment maps start of file but is writable" % segname)
                    if filesize < HDR_SIZE + sizeofcmds:
                        self.fail("always", "malformed mach-o image: %s segment does not map all of load commands" % segname)
                    if start_of_file is not None:
                        self.fail("always", "malformed mach-o image: multiple segments map start of file: %s %s" % (start_of_file, segname))
                    start_of_file = segname

                # ---- strict geometry ----
                vm_start, vm_size = vmaddr, vmsize
                vm_end = vm_start + vm_size
                if vm_size >= 1 << 63:
                    self.fail("strict", "malformed mach-o image: segment load command %s vmsize too large in %s" % (segname, self.path))
                if vm_start > vm_end:
                    self.fail("strict", "malformed mach-o image: segment load command %s wraps around address space" % segname)
                if vm_size != filesize:
                    if initprot == 0:
                        if filesize != 0 and vm_size != 0:
                            self.fail("strict", "malformed mach-o image: unaccessable segment %s has non-zero filesize and vmsize" % segname)
                    else:
                        if vm_size < filesize:
                            self.fail("strict", "malformed mach-o image: segment %s has vmsize < filesize" % segname)
                        if initprot & VM_PROT_EXECUTE:
                            self.fail("strict", "malformed mach-o image: segment %s has vmsize != filesize and is executable" % segname)
                if fileoff < sizeofcmds and filesize != 0:
                    if fileoff != 0 or filesize < sizeofcmds + HDR_SIZE:
                        self.fail("strict", "malformed mach-o image: segment %s does not span all load commands" % segname)
                    if initprot != (VM_PROT_READ | VM_PROT_EXECUTE):
                        self.fail("strict", "malformed mach-o image: load commands found in segment %s with wrong permissions" % segname)
                    if found_lc_seg:
                        self.fail("strict", "load commands in multiple segments")
                    found_lc_seg = True
                for k in range(nsects):
                    soff = off + SEG_CMD_SIZE + k * SECT_SIZE
                    sname = b[soff:soff + 16].split(b"\0")[0].decode("latin1")
                    sseg = b[soff + 16:soff + 32].split(b"\0")[0].decode("latin1")
                    saddr, ssize, sfoff = struct.unpack_from("<QQI", b, soff + 32)
                    if sfoff != 0 and (sfoff + ssize) > (fileoff + filesize):
                        self.fail("strict", "malformed mach-o image: section %s,%s of '%s' exceeds segment %s booundary"
                                  % (sseg, sname, self.path, segname))

            elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB, LC_ID_DYLIB):
                if cmd != LC_ID_DYLIB:
                    libcount += 1
                noff = self.u32(off + 8)
                if noff > cmdsize:
                    self.fail("always", "malformed mach-o image: dylib load command #%d has offset (%u) outside its size (%u)"
                              % (i, noff, cmdsize))
                else:
                    end = b.find(b"\0", off + noff, off + cmdsize)
                    if end < 0:
                        self.fail("always", "malformed mach-o image: dylib load command #%d string extends beyond end of load command" % i)
            elif cmd == LC_CODE_SIGNATURE:
                if cmdsize != 16:
                    self.fail("always", "malformed mach-o image: LC_CODE_SIGNATURE size wrong")
                if codesig is not None:
                    self.fail("always", "malformed mach-o image: multiple LC_CODE_SIGNATURE load commands")
                codesig = (self.u32(off + 8), self.u32(off + 12))
            elif cmd == LC_ENCRYPTION_INFO_64:
                if cmdsize != 24:
                    self.fail("always", "malformed mach-o image: LC_ENCRYPTION_INFO_64 size wrong")
            elif cmd == LC_SYMTAB:
                if cmdsize != 24:
                    self.fail("always", "malformed mach-o image: LC_SYMTAB size wrong")
                symtab = dict(symoff=self.u32(off + 8), nsyms=self.u32(off + 12),
                              stroff=self.u32(off + 16), strsize=self.u32(off + 20))
            elif cmd == LC_DYSYMTAB:
                if cmdsize != 80:
                    self.fail("always", "malformed mach-o image: LC_DYSYMTAB size wrong")
                vals = struct.unpack_from("<17I", b, off + 8)
                # dysymtab_command field order: ilocalsym,nlocalsym,iextdefsym,nextdefsym,iundefsym,nundefsym,
                # tocoff,ntoc,modtaboff,nmodtab,extrefsymoff,nextrefsyms,indirectsymoff,nindirectsyms,...
                dysymtab = dict(ilocalsym=vals[0], nlocalsym=vals[1], iextdefsym=vals[2], nextdefsym=vals[3],
                                iundefsym=vals[4], nundefsym=vals[5],
                                indirectsymoff=vals[12], nindirectsyms=vals[13])
                self.note("  LC_DYSYMTAB ilocalsym=%d nlocalsym=%d iextdefsym=%d nextdefsym=%d iundefsym=%d nundefsym=%d indirectsymoff=0x%X nindirectsyms=%d"
                          % (vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[12], vals[13]))
            elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
                if cmdsize != 48:
                    self.fail("strict13", "malformed mach-o image: LC_DYLD_INFO size wrong")
                if dyldinfo is not None:
                    self.fail("strict13", "malformed mach-o image: multiple LC_DYLD_INFO")
                v = struct.unpack_from("<10I", b, off + 8)
                dyldinfo = dict(rebase_off=v[0], rebase_size=v[1], bind_off=v[2], bind_size=v[3],
                                weak_off=v[4], weak_size=v[5], lazy_off=v[6], lazy_size=v[7],
                                export_off=v[8], export_size=v[9])
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                if cmdsize != 16:
                    self.fail("strict13", "malformed mach-o image: LC_DYLD_CHAINED_FIXUPS size wrong")
                chained = (self.u32(off + 8), self.u32(off + 12))
            elif cmd == LC_DYLD_EXPORTS_TRIE:
                if cmdsize != 16:
                    self.fail("strict13", "malformed mach-o image: LC_DYLD_EXPORTS_TRIE size wrong")
                exportstrie = (self.u32(off + 8), self.u32(off + 12))
            elif cmd in (LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS, LC_VERSION_MIN_TVOS, LC_VERSION_MIN_WATCHOS):
                if cmdsize != 16:
                    self.fail("always", "malformed mach-o image: LC_VERSION_MIN size wrong")
            elif cmd == LC_BUILD_VERSION:
                # dyld3::MachOLoaded::getLinkEditLoadCommands checks this even
                # though dyld2's sniffLoadCommands does not. Apple dyld-832.7.3,
                # dyld3/MachOLoaded.cpp: LC_BUILD_VERSION case.
                if cmdsize < 24:
                    self.fail("dyld3", "LC_BUILD_VERSION load command size wrong")
                    off += cmdsize
                    continue
                plat, minos, sdk, ntools = struct.unpack_from("<IIII", b, off + 8)
                if cmdsize != 24 + ntools * 8:
                    self.fail("dyld3", "LC_BUILD_VERSION load command size wrong")
                self.note("  LC_BUILD_VERSION cmdsize=%u platform=%u minos=%s sdk=%s ntools=%u raw=%s"
                          % (cmdsize, plat, ver(minos), ver(sdk), ntools,
                             b[off:off + min(cmdsize, 40)].hex()))
            off += cmdsize

        if not found_lc_seg:
            self.fail("strict", "load commands not in a segment")
        if linkedit is None:
            self.fail("always", "malformed mach-o image: missing __LINKEDIT segment")
            return
        if start_of_file is None:
            self.fail("always", "malformed mach-o image: missing __TEXT segment that maps start of file")

        # segment overlap checks
        last_file_start = 0
        for s in segs:
            last_file_start = max(last_file_start, s["fileoff"])
        for a in range(len(segs)):
            for b2 in range(len(segs)):
                if a == b2:
                    continue
                s1, s2 = segs[a], segs[b2]
                v1s, v1e = s1["vmaddr"], s1["vmaddr"] + s1["vmsize"]
                v2s, v2e = s2["vmaddr"], s2["vmaddr"] + s2["vmsize"]
                f1s, f1e = s1["fileoff"], s1["fileoff"] + s1["filesize"]
                f2s, f2e = s2["fileoff"], s2["fileoff"] + s2["filesize"]
                if ((v2s <= v1s) and (v2e > v1s) and (v1e > v1s)) or ((v2s >= v1s) and (v2s < v1e) and (v2e > v2s)):
                    self.fail("strict", "malformed mach-o image: segment %s vm overlaps segment %s" % (s1["name"], s2["name"]))
                if ((f2s <= f1s) and (f2e > f1s) and (f1e > f1s)) or ((f2s >= f1s) and (f2s < f1e) and (f2e > f2s)):
                    self.fail("strict", "malformed mach-o image: segment %s file content overlaps segment %s" % (s1["name"], s2["name"]))
        if last_file_start != linkedit["fileoff"]:
            self.fail("strict", "malformed mach-o image: __LINKEDIT must be last segment (max fileoff 0x%X vs __LINKEDIT 0x%X)"
                      % (last_file_start, linkedit["fileoff"]))

        if dyldinfo is None and chained is None and symtab is None:
            self.fail("strict13", "malformed mach-o image: missing LC_SYMTAB, LC_DYLD_INFO, or LC_DYLD_CHAINED_FIXUPS")
        if dysymtab is None:
            self.fail("always", "malformed mach-o image: missing LC_DYSYMTAB")

        link_start = linkedit["fileoff"]
        link_end = linkedit["fileoff"] + linkedit["filesize"]

        if dyldinfo is not None:
            cur = link_start
            for label, o, s in (("rebase", dyldinfo["rebase_off"], dyldinfo["rebase_size"]),
                                ("bind", dyldinfo["bind_off"], dyldinfo["bind_size"]),
                                ("weak bind", dyldinfo["weak_off"], dyldinfo["weak_size"]),
                                ("lazy bind", dyldinfo["lazy_off"], dyldinfo["lazy_size"]),
                                ("export", dyldinfo["export_off"], dyldinfo["export_size"])):
                if s == 0:
                    continue
                if s & 0x80000000:
                    self.fail("strict", "malformed mach-o image: dyld %s info size overflow" % label)
                    continue
                if o < cur:
                    self.fail("strict", "malformed mach-o image: dyld %s info overlaps/underruns previous chunk (off 0x%X < 0x%X)" % (label, o, cur))
                cur = o + s
                if cur > link_end:
                    self.fail("strict", "malformed mach-o image: dyld %s info overruns __LINKEDIT" % label)
        if chained is not None:
            if chained[0] < link_start:
                self.fail("strict13", "malformed mach-o image: dyld chained fixups info underruns __LINKEDIT")
            if chained[0] + chained[1] > link_end:
                self.fail("strict13", "malformed mach-o image: dyld chained fixups info overruns __LINKEDIT")
        if exportstrie is not None:
            if exportstrie[0] + exportstrie[1] > link_end:
                self.fail("strict13", "malformed mach-o image: dyld export trie info overruns __LINKEDIT")

        if symtab is not None:
            if symtab["nsyms"] > 0 and symtab["symoff"] < link_start:
                self.fail("strict", "malformed mach-o image: symbol table underruns __LINKEDIT")
            if symtab["nsyms"] > 0x10000000:
                self.fail("strict", "malformed mach-o image: symbol table too large")
            symbols_size = symtab["nsyms"] * NLIST64_SIZE
            if symbols_size > linkedit["filesize"]:
                self.fail("strict", "malformed mach-o image: symbol table overruns __LINKEDIT")
            if symtab["symoff"] + symbols_size < symtab["symoff"]:
                self.fail("strict", "malformed mach-o image: symbol table size wraps")
            if symtab["symoff"] + symbols_size > symtab["stroff"]:
                self.fail("strict", "malformed mach-o image: symbol table overlaps symbol strings")
            if symtab["stroff"] + symtab["strsize"] < symtab["stroff"]:
                self.fail("strict", "malformed mach-o image: symbol string size wraps")
            if symtab["stroff"] + symtab["strsize"] > link_end:
                self.fail("strict", "malformed mach-o image: symbol strings overrun __LINKEDIT")
        if dysymtab is not None and dysymtab["nindirectsyms"] != 0:
            isz = dysymtab["nindirectsyms"] * 4
            if dysymtab["indirectsymoff"] < link_start:
                self.fail("strict", "malformed mach-o image: indirect symbol table underruns __LINKEDIT")
            if dysymtab["nindirectsyms"] > 0x10000000:
                self.fail("strict", "malformed mach-o image: indirect symbol table too large")
            if isz > linkedit["filesize"]:
                self.fail("strict", "malformed mach-o image: indirect symbol table overruns __LINKEDIT")
            if symtab is not None and dysymtab["indirectsymoff"] + isz > symtab["stroff"]:
                self.fail("strict", "malformed mach-o image: indirect symbol table overruns string pool")
        if dysymtab is not None and symtab is not None:
            for a, b2, alab, blab in (("nlocalsym", "ilocalsym", "local", "local"),
                                      ("nextdefsym", "iextdefsym", "extern", "extern"),
                                      ("nundefsym", "iundefsym", "undefined", "undefined")):
                n, ix = dysymtab[a], dysymtab[b2]
                if n > symtab["nsyms"] or ix > symtab["nsyms"]:
                    self.fail("strict", "malformed mach-o image: indirect symbol table %s symbol count exceeds total symbols" % alab)
        if segcount > 255:
            self.fail("always", "malformed mach-o image: more than 255 segments in %s" % self.path)
        if libcount > 4095:
            self.fail("always", "malformed mach-o image: more than 4095 dependent libraries in %s" % self.path)

        if dyldinfo is not None:
            from chained2dyld import MachO
            from fix_classic_segments import validate as validate_segments
            try:
                counts = validate_segments(MachO(self.buf))
                self.note("dyld3 pointer-fixup/segment checks: %s" % counts)
            except (ValueError, IndexError, KeyError, struct.error) as error:
                self.fail("dyld3", str(error))

        self.note("ncmds=%d sizeofcmds=%d segments=%d libs=%d symtab=%s dyldinfo=%s chained=%s codesig=%s"
                  % (ncmds, sizeofcmds, len(segs), libcount, symtab is not None, dyldinfo is not None,
                     chained is not None, codesig))
        for s in segs:
            self.note("  %-14s vm 0x%-9X..0x%-9X file 0x%-9X..0x%-9X prot %d/%d nsects %d"
                      % (s["name"], s["vmaddr"], s["vmaddr"] + s["vmsize"], s["fileoff"],
                         s["fileoff"] + s["filesize"], s["maxprot"], s["initprot"], s["nsects"]))


def main(argv):
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print(__doc__)
        return 2
    bad = 0
    for p in paths:
        if not os.path.exists(p):
            print("=== %s: MISSING" % p)
            bad += 1
            continue
        c = Checker(p)
        c.run()
        print("=== %s" % p)
        for n in c.notes:
            print("    " + n)
        if c.fails:
            seen = set()
            for tier, msg in c.fails:
                key = (tier, msg)
                if key in seen:
                    continue
                seen.add(key)
                print("  FAIL [%s] %s" % (tier, msg))
            bad += 1
        else:
            print("  PASS  implemented dyld2 strict and dyld3 build-version/fixup checks")
    print("\n%d/%d image(s) rejected by iOS 13/14 loader rules" % (bad, len(paths)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
