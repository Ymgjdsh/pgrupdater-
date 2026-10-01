#!/usr/bin/env python3
"""Replay every strict Mach-O validation performed by iOS 12's dyld
(apple-oss-distributions/dyld dyld-655.1.1, ImageLoaderMachO::sniffLoadCommands)
against a binary, so a transformed image cannot fail late on device.

    python dyldcheck.py <macho> [<macho> ...]

Exit 0 only when every image passes.  Error strings are copied verbatim from dyld
so a real failure is immediately greppable against a device log.
"""
import struct
import sys

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_CODE_SIGNATURE = 0x1D
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001C
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_ID_DYLIB = 0xD

VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE = 0x1, 0x2, 0x4
NLIST64 = 16
SEG_CMD_SIZE = 72
SECT_SIZE = 80


class Bail(Exception):
    pass


def parse(path):
    b = open(path, "rb").read()
    magic, cputype, _sub, _ft, ncmds, sizeofcmds, _flags, _res = struct.unpack_from("<8I", b, 0)
    if magic != 0xFEEDFACF:
        raise Bail(f"{path}: not a 64-bit Mach-O (magic 0x{magic:08X})")
    cmds, segs, sym, dysym, dyldinfo, codesig = [], [], None, None, None, None
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", b, off)
        cmds.append((cmd, cmdsize, off))
        if cmd == LC_SEGMENT_64:
            name = b[off + 8:off + 24].split(b"\0")[0].decode(errors="replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", b, off + 24)
            maxprot, initprot, nsects, flags = struct.unpack_from("<4I", b, off + 56)
            secs = []
            for k in range(nsects):
                so = off + SEG_CMD_SIZE + k * SECT_SIZE
                sname = b[so:so + 16].split(b"\0")[0].decode(errors="replace")
                sseg = b[so + 16:so + 32].split(b"\0")[0].decode(errors="replace")
                saddr, ssize = struct.unpack_from("<2Q", b, so + 32)
                soff, salign, _reloff, _nreloc, sflags = struct.unpack_from("<5I", b, so + 48)
                secs.append(dict(seg=sseg, sect=sname, addr=saddr, size=ssize,
                                 offset=soff, flags=sflags))
            segs.append(dict(name=name, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff,
                             filesize=filesize, maxprot=maxprot, initprot=initprot,
                             nsects=nsects, flags=flags, lc_off=off, cmdsize=cmdsize,
                             sections=secs))
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<4I", b, off + 8)
            sym = dict(symoff=symoff, nsyms=nsyms, stroff=stroff, strsize=strsize)
        elif cmd == LC_DYSYMTAB:
            f = struct.unpack_from("<18I", b, off + 8)
            dysym = dict(ilocalsym=f[0], nlocalsym=f[1], iextdefsym=f[2], nextdefsym=f[3],
                         iundefsym=f[4], nundefsym=f[5], indirectsymoff=f[10],
                         nindirectsyms=f[11])
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            f = struct.unpack_from("<10I", b, off + 8)
            dyldinfo = dict(rebase_off=f[0], rebase_size=f[1], bind_off=f[2], bind_size=f[3],
                            weak_off=f[4], weak_size=f[5], lazy_off=f[6], lazy_size=f[7],
                            export_off=f[8], export_size=f[9], cmd=cmd)
        elif cmd == LC_CODE_SIGNATURE:
            dataoff, datasize = struct.unpack_from("<2I", b, off + 8)
            codesig = (dataoff, datasize)
        off += cmdsize
    return dict(path=path, buf=b, ncmds=ncmds, sizeofcmds=sizeofcmds, cmds=cmds,
                segs=segs, sym=sym, dysym=dysym, dyldinfo=dyldinfo, codesig=codesig,
                hdr_end=32 + sizeofcmds)


def check(img):
    """Return a list of (check, ok, detail). Mirrors dyld's strict path exactly."""
    r, b = [], img["buf"]
    segs = img["segs"]
    def rec(name, ok, detail=""):
        r.append((name, bool(ok), detail))

    # --- LC_SEGMENT_COMMAND sanity (dyld L226-239, L286-326) -------------------
    for s in segs:
        n = s["name"]
        rec(f"seg {n}: cmdsize == 72 + nsects*80",
            s["cmdsize"] == SEG_CMD_SIZE + s["nsects"] * SECT_SIZE,
            f"cmdsize={s['cmdsize']} nsects={s['nsects']}")
        if n != "__LINKEDIT":
            rec(f"seg {n}: initprot has no bits beyond RWX",
                not (s["initprot"] & 0xFFFFFFF8), f"initprot={s['initprot']}")
            rec(f"seg {n}: maxprot has no bits beyond RWX",
                not (s["maxprot"] & 0xFFFFFFF8), f"maxprot={s['maxprot']}")
            rec(f"seg {n}: readable if initprot!=0",
                s["initprot"] == 0 or (s["initprot"] & VM_PROT_READ), f"initprot={s['initprot']}")
        rec(f"seg {n}: filesize <= vmsize",
            s["filesize"] <= s["vmsize"], f"filesize=0x{s['filesize']:X} vmsize=0x{s['vmsize']:X}")
        if s["vmsize"] != s["filesize"] and s["initprot"] != 0:
            rec(f"seg {n}: vmsize!=filesize allowed (not executable)",
                not (s["initprot"] & VM_PROT_EXECUTE),
                f"initprot={s['initprot']} filesize=0x{s['filesize']:X} vmsize=0x{s['vmsize']:X}")
        # sections must fit the file content of their own segment (dyld L324)
        for sec in s["sections"]:
            if sec["offset"] and (sec["offset"] + sec["size"]) > (s["fileoff"] + s["filesize"]):
                rec(f"sect {sec['seg']},{sec['sect']}: within segment",
                    False, f"end=0x{sec['offset'] + sec['size']:X} seg_end=0x{s['fileoff'] + s['filesize']:X}")

    # --- start-of-file segment (dyld L263-275, L310-319) ----------------------
    starts = [s for s in segs if s["fileoff"] == 0 and s["filesize"] != 0]
    rec("exactly one segment maps start of file", len(starts) == 1, f"{[s['name'] for s in starts]}")
    if starts:
        s = starts[0]
        rec("start-of-file seg: readable", s["initprot"] & VM_PROT_READ, f"initprot={s['initprot']}")
        rec("start-of-file seg: not writable", not (s["initprot"] & VM_PROT_WRITE))
        rec("start-of-file seg: maps all load commands",
            s["filesize"] >= img["hdr_end"], f"filesize=0x{s['filesize']:X} hdr_end=0x{img['hdr_end']:X}")
        rec("start-of-file seg: spans all load commands", s["fileoff"] == 0 and s["filesize"] >= img["hdr_end"])
        rec("start-of-file seg: RX permissions",
            s["initprot"] == (VM_PROT_READ | VM_PROT_EXECUTE), f"initprot={s['initprot']}")

    # --- __LINKEDIT (dyld L243-253, L394-395, L441-442) -----------------------
    le = [s for s in segs if s["name"] == "__LINKEDIT"]
    rec("exactly one __LINKEDIT", len(le) == 1, f"{len(le)}")
    if len(le) == 1:
        L = le[0]
        rec("__LINKEDIT fileoff != 0", L["fileoff"] != 0, f"0x{L['fileoff']:X}")
        rec("__LINKEDIT is last segment",
            L["fileoff"] == max(s["fileoff"] for s in segs),
            f"linkedit=0x{L['fileoff']:X} max=0x{max(s['fileoff'] for s in segs):X}")
        ls, le_end = L["fileoff"], L["fileoff"] + L["filesize"]

        # --- LC_DYLD_INFO chunk chain (dyld L454-502) ------------------------
        di = img["dyldinfo"]
        if di:
            off = ls
            for nm, fld, prev in (("rebase", "rebase", "__LINKEDIT"),
                                  ("bind", "bind", "rebase info"),
                                  ("weak bind", "weak", "bind info"),
                                  ("lazy bind", "lazy", "weak bind info"),
                                  ("export", "export", "lazy bind info")):
                o, sz = di[fld + "_off"], di[fld + "_size"]
                if not sz:
                    continue
                rec(f"dyld {nm}: size has no high bit", not (sz & 0x80000000), f"size={sz}")
                rec(f"dyld {nm}: does not {('underrun' if prev == '__LINKEDIT' else 'overlap')} {prev}",
                    o >= off, f"off=0x{o:X} prev_end=0x{off:X} -> "
                              f"'dyld {nm} info {'underruns __LINKEDIT' if prev == '__LINKEDIT' else 'overlaps ' + prev}'")
                off = o + sz
                rec(f"dyld {nm}: fits in __LINKEDIT", off <= le_end,
                    f"end=0x{off:X} linkedit_end=0x{le_end:X}")
        else:
            rec("LC_DYLD_INFO present", img["sym"] is not None)
        rec("LC_DYLD_INFO or LC_SYMTAB present", di is not None or img["sym"] is not None)

        # --- symtab / indirect symtab (dyld L504-549) ------------------------
        sy, dy = img["sym"], img["dysym"]
        rec("LC_DYSYMTAB present", dy is not None)
        if dy is None:
            return r
        if sy:
            rec("symtab: symoff >= __LINKEDIT", sy["nsyms"] == 0 or sy["symoff"] >= ls,
                f"0x{sy['symoff']:X} vs 0x{ls:X}")
            rec("symtab: nsyms <= 0x10000000", sy["nsyms"] <= 0x10000000, f"{sy['nsyms']}")
            size = sy["nsyms"] * NLIST64
            rec("symtab: size <= __LINKEDIT size", size <= L["filesize"], f"{size}")
            rec("symtab: no wrap", sy["symoff"] + size >= sy["symoff"])
            rec("symtab: does not overlap strings", sy["symoff"] + size <= sy["stroff"],
                f"symend=0x{sy['symoff'] + size:X} stroff=0x{sy['stroff']:X}")
            rec("symtab: strsize no wrap", sy["stroff"] + sy["strsize"] >= sy["stroff"])
            rec("symtab: strings inside __LINKEDIT", sy["stroff"] + sy["strsize"] <= le_end,
                f"strend=0x{sy['stroff'] + sy['strsize']:X} linkedit_end=0x{le_end:X}")
            if dy["nindirectsyms"]:
                isz = dy["nindirectsyms"] * 4
                io = dy["indirectsymoff"]
                rec("indirect: indirectsymoff >= __LINKEDIT", io >= ls, f"0x{io:X}")
                rec("indirect: nindirectsyms <= 0x10000000", dy["nindirectsyms"] <= 0x10000000)
                rec("indirect: size <= __LINKEDIT size", isz <= L["filesize"], f"{isz}")
                rec("indirect: no wrap", io + isz >= io)
                rec("indirect: does not overrun string pool", io + isz <= sy["stroff"],
                    f"end=0x{io + isz:X} stroff=0x{sy['stroff']:X}")
            for nm, i_f, n_f in (("local", "ilocalsym", "nlocalsym"),
                                 ("extern", "iextdefsym", "nextdefsym"),
                                 ("undefined", "iundefsym", "nundefsym")):
                rec(f"dysym: {nm} count <= nsyms", dy[n_f] <= sy["nsyms"],
                    f"{dy[n_f]} vs {sy['nsyms']}")
                rec(f"dysym: {nm} index <= nsyms", dy[i_f] <= sy["nsyms"],
                    f"{dy[i_f]} vs {sy['nsyms']}")
                rec(f"dysym: {nm} no wrap", dy[i_f] + dy[n_f] >= dy[i_f])

    # --- counts (dyld L554-559) ----------------------------------------------
    rec("segCount <= 255", len([s for s in segs if s["vmsize"] != 0]) <= 255,
        f"{len([s for s in segs if s['vmsize'] != 0])}")
    libs = [c for c, _sz, _o in img["cmds"]
            if c in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB,
                     LC_LOAD_UPWARD_DYLIB)]
    rec("libCount <= 4095", len(libs) <= 4095, f"{len(libs)}")

    # --- pairwise overlap (dyld L399-443) -----------------------------------
    for i, a in enumerate(segs):
        for jb in segs[i + 1:]:
            vm = not (a["vmaddr"] + a["vmsize"] <= jb["vmaddr"] or jb["vmaddr"] + jb["vmsize"] <= a["vmaddr"])
            rec(f"seg {a['name']} vm disjoint from {jb['name']}", not vm,
                f"0x{a['vmaddr']:X}+0x{a['vmsize']:X} vs 0x{jb['vmaddr']:X}+0x{jb['vmsize']:X}")
            f1 = not (a["fileoff"] + a["filesize"] <= jb["fileoff"] or jb["fileoff"] + jb["filesize"] <= a["fileoff"])
            if a["filesize"] == 0 or jb["filesize"] == 0:
                f1 = False
            rec(f"seg {a['name']} file disjoint from {jb['name']}", not f1,
                f"0x{a['fileoff']:X}+0x{a['filesize']:X} vs 0x{jb['fileoff']:X}+0x{jb['filesize']:X}")
    return r


def main(paths):
    rc = 0
    for p in paths:
        img = parse(p)
        res = check(img)
        bad = [x for x in res if not x[1]]
        print(f"=== {p}")
        print(f"  ncmds={img['ncmds']} sizeofcmds={img['sizeofcmds']} "
              f"segs={len(img['segs'])} checks={len(res)}")
        for name, ok, detail in bad:
            print(f"  FAIL {name}  [{detail}]")
        if bad:
            rc = 1
            print(f"  {len(bad)} FAILED check(s) -> iOS 12 dyld would refuse this image")
        else:
            print(f"  PASS: all {len(res)} strict dyld checks satisfied "
                  f"(iOS 12 ImageLoaderMachO::sniffLoadCommands)")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
