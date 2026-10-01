"""tmp_lcdump.py <macho> [--all] -- dump load commands + kernel/dyld structural rule checks."""
import struct, sys

PAGE = 0x4000
NAMES = {0x2: "LC_SYMTAB", 0xb: "LC_DYSYMTAB", 0xc: "LC_LOAD_DYLIB", 0xd: "LC_ID_DYLIB",
         0x19: "LC_SEGMENT_64", 0x1b: "LC_UUID", 0x1d: "LC_CODE_SIGNATURE", 0x25: "LC_VERSION_MIN_IPHONEOS",
         0x26: "LC_FUNCTION_STARTS", 0x29: "LC_DATA_IN_CODE", 0x2a: "LC_SOURCE_VERSION", 0x2c: "LC_ENCRYPTION_INFO_64",
         0x32: "LC_BUILD_VERSION", 0x80000018: "LC_LOAD_WEAK_DYLIB", 0x8000001c: "LC_RPATH",
         0x80000022: "LC_DYLD_INFO_ONLY", 0x80000028: "LC_MAIN", 0x80000033: "LC_DYLD_EXPORTS_TRIE",
         0x80000034: "LC_DYLD_CHAINED_FIXUPS"}


def main():
    path = sys.argv[1]
    buf = open(path, "rb").read()
    total = len(buf)
    magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from("<8I", buf, 0)
    print(f"== {path}  {total} bytes")
    print(f"   magic {magic:#x} cputype {cputype} ftype {ftype} ncmds {ncmds} sizeofcmds {sizeofcmds} flags {flags:#x}")
    print(f"   header+cmds = {32 + sizeofcmds} (must be <= first segment filesize)")
    bad = []
    off = 32
    segs = []
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<2I", buf, off)
        name = NAMES.get(cmd, hex(cmd))
        line = f"[{i:2}] {name} cmdsize {cmdsize}"
        detail = []
        if cmd == 0x19:
            (segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, sflags) = struct.unpack_from(
                "<16sQQQQIIII", buf, off + 8)
            segname = segname.rstrip(b"\0").decode()
            segs.append((segname, vmaddr, vmsize, fileoff, filesize, initprot, nsects))
            detail.append(f"seg {segname} vmaddr {vmaddr:#x} vmsize {vmsize:#x} fileoff {fileoff:#x} "
                          f"filesize {filesize:#x} initprot {initprot:#x} nsects {nsects}")
            if vmaddr % PAGE:
                bad.append(f"{segname}: vmaddr not {PAGE:#x}-aligned")
            if fileoff % PAGE:
                bad.append(f"{segname}: fileoff not {PAGE:#x}-aligned")
            if filesize > vmsize and vmsize:
                bad.append(f"{segname}: filesize > vmsize")
            if fileoff + filesize > total:
                bad.append(f"{segname}: fileoff+filesize {fileoff+filesize:#x} > file size {total:#x}")
            if initprot & 4 and filesize != vmsize:
                bad.append(f"{segname}: executable but filesize != vmsize (strictMachORequired)")
            o = off + 72
            for s in range(nsects):
                sn, sg, addr, size, soff, align, r1, r2, r3, sfl = struct.unpack_from("<16s16sQQIIIIII", buf, o)
                sn = sn.rstrip(b"\0").decode(); sg = sg.rstrip(b"\0").decode()
                if soff + size > fileoff + filesize and (sfl & 0xFF) != 1:
                    bad.append(f"section {sg},{sn}: offset+size {soff+size:#x} beyond segment file range {fileoff+filesize:#x}")
                if soff + size > total:
                    bad.append(f"section {sg},{sn}: offset+size beyond EOF")
                detail.append(f"      sect {sg},{sn} addr {addr:#x} size {size:#x} off {soff:#x} align {align} flags {sfl:#x}")
                o += 80
        elif cmd == 0x80000022:
            rb_o, rb_s, bn_o, bn_s, wk_o, wk_s, lz_o, lz_s, ex_o, ex_s = struct.unpack_from("<10I", buf, off + 8)
            detail.append(f"rebase {rb_o:#x}/{rb_s:#x} bind {bn_o:#x}/{bn_s:#x} weak {wk_o:#x}/{wk_s:#x} "
                          f"lazy {lz_o:#x}/{lz_s:#x} export {ex_o:#x}/{ex_s:#x}")
            for nm, o2, s2 in (("rebase", rb_o, rb_s), ("bind", bn_o, bn_s), ("weak", wk_o, wk_s),
                               ("lazy", lz_o, lz_s), ("export", ex_o, ex_s)):
                if s2 and o2 + s2 > total:
                    bad.append(f"LC_DYLD_INFO_ONLY {nm} stream beyond EOF")
        elif cmd in (0x1d, 0x29, 0x26, 0x80000033, 0x80000034):
            do, ds = struct.unpack_from("<2I", buf, off + 8)
            detail.append(f"dataoff {do:#x} datasize {ds:#x}")
            if do + ds > total:
                bad.append(f"{name}: dataoff+datasize {do+ds:#x} > file size {total:#x}")
        elif cmd == 0x2c:
            co, cs, cid, pad = struct.unpack_from("<4I", buf, off + 8)
            detail.append(f"cryptoff {co:#x} cryptsize {cs:#x} cryptid {cid}")
            if co + cs > total:
                bad.append(f"LC_ENCRYPTION_INFO_64: cryptoff+cryptsize beyond EOF")
        elif cmd == 0x25:
            v, sd = struct.unpack_from("<2I", buf, off + 8)
            detail.append(f"version {v>>16}.{(v>>8)&0xff}.{v&0xff} sdk {sd>>16}.{(sd>>8)&0xff}.{sd&0xff}")
        elif cmd == 0x32:
            plat, minos, sdk, ntools = struct.unpack_from("<4I", buf, off + 8)
            detail.append(f"platform {plat} minos {minos>>16}.{(minos>>8)&0xff}.{minos&0xff} ntools {ntools}")
        elif cmd == 0x80000028:
            eo, ss = struct.unpack_from("<QQ", buf, off + 8)
            detail.append(f"entryoff {eo:#x} stacksize {ss:#x}")
        elif cmd == 0x2:
            so, ns, stro, strsz = struct.unpack_from("<4I", buf, off + 8)
            detail.append(f"symoff {so:#x} nsyms {ns} stroff {stro:#x} strsize {strsz:#x}")
            if stro + strsz > total:
                bad.append("LC_SYMTAB strtab beyond EOF")
        print(line)
        for d in detail:
            print("     " + d)
        off += cmdsize
    last = segs[-1][0] if segs else None
    if last != "__LINKEDIT":
        bad.append(f"last segment is {last}, expected __LINKEDIT")
    if any(s[0] == "__LINKEDIT" for s in segs[:-1]):
        bad.append("__LINKEDIT not last / duplicated")
    if not any(s[0] == "__TEXT" and s[3] == 0 for s in segs):
        bad.append("no __TEXT at fileoff 0")
    print("== rule violations:", "NONE" if not bad else "")
    for b in bad:
        print("   ! " + b)


main()
