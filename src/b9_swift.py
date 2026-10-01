#!/usr/bin/env python3
# Task 4b / integrity: swift + objc runtime symbols in the two v4 binaries,
# structural checks on the app executable (LC_MAIN, segments, sections),
# and proof that the built IPA contains byte-identical copies of out/*.v4.
import struct, hashlib, zipfile, collections, sys

IPA = r"H:/file/phi/phi5/Phigros_4.0.0_iOS12_v4.ipa"
BINS = {
    "app": (r"H:/file/phi/out/Phigros.v4", "Payload/Phigros.app/Phigros"),
    "fw": (r"H:/file/phi/out/UnityFramework.v4", "Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework"),
    "app_orig": (r"H:/file/phi/work/Phigros.main", None),
    "fw_orig": (r"H:/file/phi/work/UnityFramework", None),
}
N_WEAK_REF = 0x40
N_WEAK_DEF = 0x80


def rd(b, o, f):
    return struct.unpack_from(f, b, o)


class M:
    def __init__(self, b, tag):
        self.b = b
        self.tag = tag
        m = rd(b, 0, "<I")[0]
        assert m in (0xfeedfacf, 0xfeedface), hex(m)
        self.cput, self.sub, self.ftype, self.ncmds, self.szcmds, self.flags = rd(b, 4, "<iiIIII")
        self.cmds = []
        o = 32
        for _ in range(self.ncmds):
            c, cs = rd(b, o, "<II")
            self.cmds.append((c & 0x7FFFFFFF, c, cs, o))
            o += cs
        self.segs = []
        self.sects = []
        for cm, raw, cs, o in self.cmds:
            if cm == 0x19:
                nm = b[o + 8:o + 24].split(b"\0")[0].decode()
                va, vs, fo, fs = rd(b, o + 24, "<QQQQ")
                mx, ip, _nsect, sp = rd(b, o + 56, "<iiII")
                self.segs.append(dict(name=nm, vmaddr=va, vmsize=vs, fileoff=fo, filesize=fs,
                                      initprot=ip, maxprot=mx, cmd_off=o))
                ns = rd(b, o + 64, "<I")[0]
                so = o + 72
                for _i in range(ns):
                    sn = b[so:so + 16].split(b"\0")[0].decode()
                    sa, ss = rd(b, so + 32, "<QQ")
                    soff, salign, srel, nrel, sflags = rd(b, so + 48, "<IIIII")
                    self.sects.append(dict(seg=nm, name=sn, addr=sa, size=ss, offset=soff,
                                           flags=sflags, reloff=srel, nreloc=nrel))
                    so += 80
        self.symtab = None
        self.dysym = None
        self.main = None
        self.info = None
        for cm, raw, cs, o in self.cmds:
            if cm == 0x2:
                symoff, nsyms, stroff, strsize = rd(b, o + 8, "<IIII")
                self.symtab = (symoff, nsyms, stroff, strsize)
            elif cm == 0xB:
                iloc, nloc, iext, next_, iund, nund = rd(b, o + 8, "<IIIIII")
                self.dysym = (iloc, nloc, iext, next_, iund, nund)
            elif cm == 0x80000028:
                eo, ss, stk = rd(b, o + 8, "<QQQ")
                self.main = (eo, ss, stk)
            elif cm == 0x80000022:
                self.info = rd(b, o + 8, "<12I")
            elif cm == 0x2C:
                self.enc = rd(b, o + 8, "<III")

    def symbols(self):
        symoff, nsyms, stroff, strsize = self.symtab
        und = []
        for i in range(nsyms):
            n_strx, n_type, n_sect, n_desc, n_value = rd(self.b, symoff + 16 * i, "<IBBHQ")
            if n_type & 0x0e:
                continue
            e = self.b.find(b"\0", stroff + n_strx)
            nm = self.b[stroff + n_strx:e].decode("utf-8", "replace")
            und.append((nm, n_desc, n_sect, n_value, i))
        return und


def main():
    outp = r"H:/file/phi/b9_swift.txt"
    fh = open(outp, "w", encoding="utf-8")

    def out(s):
        print(s)
        fh.write(s + "\n")

    z = zipfile.ZipFile(IPA)
    for tag, (p, member) in BINS.items():
        b = open(p, "rb").read()
        m = M(b, tag)
        out("=" * 100)
        out("## %s  %s  size=%d sha256=%s" % (tag, p, len(b), hashlib.sha256(b).hexdigest()[:16]))
        if member:
            with z.open(member) as f:
                ib = f.read()
            out("   IPA member %s size=%d sha256=%s  IDENTICAL=%s" % (
                member, len(ib), hashlib.sha256(ib).hexdigest()[:16], ib == b))
        out("   filetype=%d ncmds=%d" % (m.ftype, m.ncmds))
        out("   LC_MAIN: %s" % (m.main,))
        if m.main:
            eo = m.main[0]
            intext = None
            for s in m.segs:
                if s["name"] == "__TEXT":
                    intext = s
            sec = [x for x in m.sects if x["seg"] == "__TEXT" and x["offset"] <= eo < x["offset"] + x["size"]]
            out("   entryoff=0x%x inside __TEXT file [0x%x,0x%x) = %s ; entry section=%s" % (
                eo, intext["fileoff"], intext["fileoff"] + intext["filesize"],
                intext["fileoff"] <= eo < intext["fileoff"] + intext["filesize"],
                [(x["name"], hex(x["addr"] + (eo - x["offset"]))) for x in sec]))
            ent_vm = intext["vmaddr"] + eo
            out("   entry vmaddr = 0x%x" % ent_vm)
        for s in m.segs:
            if s["fileoff"] + s["filesize"] > len(b):
                out("   !! segment %s file extent 0x%x+0x%x = 0x%x EXCEEDS file size 0x%x" % (
                    s["name"], s["fileoff"], s["filesize"], s["fileoff"] + s["filesize"], len(b)))
        for x in m.sects:
            sg = [s for s in m.segs if s["name"] == x["seg"]][0]
            if x["offset"] + x["size"] > sg["fileoff"] + sg["filesize"] and x["size"]:
                out("   !! section %s,%s offset 0x%x size 0x%x outside segment file extent" % (
                    x["seg"], x["name"], x["offset"], x["size"]))
            if x["offset"] < sg["fileoff"] and x["size"]:
                out("   !! section %s,%s offset 0x%x before segment fileoff 0x%x" % (
                    x["seg"], x["name"], x["offset"], sg["fileoff"]))
        und = m.symbols()
        weak = [u for u in und if u[1] & N_WEAK_REF]
        strong = [u for u in und if not (u[1] & N_WEAK_REF)]
        out("   undefined symbols: %d (weak-ref %d, strong %d)" % (len(und), len(weak), len(strong)))
        pref = collections.Counter()
        for nm, d, sec, val, i in und:
            if nm.startswith("_$s") or nm.startswith("_$S"):
                pref["Swift mangled ($s/_$s)"] += 1
            elif nm.startswith("_swift_") or nm.startswith("__swift"):
                pref["swift_ runtime"] += 1
            elif nm.startswith("_swift"):
                pref["swift runtime other"] += 1
            elif nm.startswith("_objc_"):
                pref["objc runtime"] += 1
            elif nm.startswith("_os_"):
                pref["os_"] += 1
            elif nm.startswith("_dispatch_"):
                pref["dispatch"] += 1
            else:
                pref["other"] += 1
        for k, v in pref.most_common():
            out("      %-24s %5d" % (k, v))
        sw = [(nm, d, "WEAK" if d & N_WEAK_REF else "STRONG") for nm, d, sec, val, i in und
              if nm.startswith("_$s") or nm.startswith("_swift") or nm.startswith("__swift")
              or "Concurrency" in nm or "Task" in nm]
        out("   swift-related undefined symbols: %d  (STRONG=%d)" % (
            len(sw), len([x for x in sw if x[2] == "STRONG"])))
        for nm, d, w in sorted(sw)[:400]:
            out("      %-8s %s" % (w, nm))
        if len(sw) > 400:
            out("      ... (%d more)" % (len(sw) - 400))
        out("")
    z.close()
    fh.close()
    print("written", outp)


if __name__ == "__main__":
    main()
