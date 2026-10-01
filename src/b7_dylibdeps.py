#!/usr/bin/env python3
# Task 4 helper: every Mach-O in each IPA -> its dylib load commands, resolved against the bundle.
# Also: which Frameworks/ files exist, and per-binary segment/version summary.
import zipfile, struct, sys, os, collections

IPAS = {
    "4.0.0_ORIG": r"H:/file/phi/games.Pigeon.Phigros_4.0.0_und3fined.ipa",
    "3.19.0_ORIG": r"H:/file/phi/games.Pigeon.Phigros_3.19.0_und3fined.ipa",
    "BUILT_v4": r"H:/file/phi/phi5/Phigros_4.0.0_iOS12_v4.ipa",
}
MH = {0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca}
LC = {
    0xC: "LC_LOAD_DYLIB", 0x80000018: "LC_LOAD_WEAK_DYLIB", 0x1F: "LC_LOAD_UPWARD_DYLIB",
    0x8000001F: "LC_REEXPORT_DYLIB", 0x20: "LC_LAZY_LOAD_DYLIB", 0xD: "LC_ID_DYLIB",
    0x8000001C: "LC_RPATH", 0x80000023: "LC_LOAD_UPWARD_DYLIB",
}
# runtime dylibs that do NOT exist on iOS 12.5.8 (introduced iOS 13+ / not shipped in 12.x shared cache)
POST12 = {
    "libswiftDataDetection.dylib": "iOS 13.0",
    "libswiftUniformTypeIdentifiers.dylib": "iOS 14.0",
    "libswiftFileProvider.dylib": "iOS 13.0",
    "libswiftWebKit.dylib": "iOS 13.0",
    "libswiftXPC.dylib": "iOS 14.0",
    "libswiftOSLog.dylib": "iOS 14.0?",
    "libswiftos.dylib": "iOS 13.0?",
    "libswiftMetal.dylib": "iOS 13.0?",
    "libswiftCoreImage.dylib": "iOS 13.0",
    "libswiftQuartzCore.dylib": "iOS 13.0",
    "libswiftCoreFoundation.dylib": "iOS 13.0",
    "libswiftDarwin.dylib": "iOS 13.0",
    "libswiftUIKit.dylib": "iOS 13.0",
    "libswiftAVFoundation.dylib": "iOS 13.0",
    "libswiftGameplayKit.dylib": "iOS 13.0",
    "libswiftCoreAudio.dylib": "iOS 13.0",
}


def cstr(b, o, n):
    e = b.find(b"\0", o, o + n)
    return b[o:e if e >= 0 else o + n].decode("utf-8", "replace")


def scan(name, path, out):
    out("=" * 100)
    out("## IPA %s  (%s)" % (name, path))
    z = zipfile.ZipFile(path)
    names = z.namelist()
    out("entries: %d" % len(names))
    fw = sorted(n for n in names if n.startswith("Payload/Phigros.app/Frameworks/") and "/" == n[len("Payload/Phigros.app/Frameworks/"):len("Payload/Phigros.app/Frameworks/") + 1] is False)
    dirs = collections.defaultdict(list)
    for n in names:
        if n.startswith("Payload/Phigros.app/Frameworks/"):
            rest = n[len("Payload/Phigros.app/Frameworks/"):]
            dirs[rest.split("/")[0]].append(rest)
    out("Frameworks/ top-level entries:")
    for k in sorted(dirs):
        if "/" not in k:
            try:
                sz = z.getinfo("Payload/Phigros.app/Frameworks/" + k).file_size
            except KeyError:
                sz = -1
            out("    %-40s %d B" % (k, sz))
        else:
            out("    %-40s (%d files)" % (k, len(dirs[k])))
    out("Payload/Phigros.app/ non-Data top-level entries:")
    for n in sorted(names):
        pre = "Payload/Phigros.app/"
        if n.startswith(pre) and n != pre and not n.startswith(pre + "Data/") and "/" not in n[len(pre):]:
            out("    %-40s %d B" % (n[len(pre):], z.getinfo(n).file_size))
    out("")
    for n in sorted(names):
        try:
            fi = z.getinfo(n)
        except KeyError:
            continue
        if fi.file_size < 32 or n.endswith("/"):
            continue
        with z.open(n) as f:
            head = f.read(64)
        if len(head) < 32:
            continue
        magic = struct.unpack("<I", head[:4])[0]
        if magic not in MH:
            continue
        with z.open(n) as f:
            b = f.read(96 * 1024)
        cput, sub, ftype, ncmds, szcmds, flags = struct.unpack("<iiIIII", b[4:28])
        bins = b" (big-endian)" if magic in (0xcefaedfe, 0xcffaedfe, 0xbebafeca) else b""
        out("-" * 90)
        out("MACH-O %s  size=%d cputype=0x%x filetype=%d ncmds=%d flags=0x%x" % (n, fi.file_size, cput, ftype, ncmds, flags))
        o = 32 if magic in (0xfeedface, 0xfeedfacf) else 28
        minos = sdk = None
        loads = []
        rpaths = []
        dylibs_seen = []
        for i in range(ncmds):
            if o + 8 > len(b):
                out("  !! load commands truncated at %d (need %d)" % (o, o + 8))
                break
            cmd, cmdsize = struct.unpack("<II", b[o:o + 8])
            if cmdsize < 8 or o + cmdsize > len(b):
                out("  !! bad cmdsize %d at %d" % (cmdsize, o))
                break
            if cmd in LC:
                if cmd == 0x8000001C:
                    off = struct.unpack("<I", b[o + 8:o + 12])[0]
                    rpaths.append(cstr(b, o + off, cmdsize - off))
                else:
                    off = struct.unpack("<I", b[o + 8:o + 12])[0]
                    t = cstr(b, o + off, cmdsize - off)
                    loads.append((i + 1, LC[cmd], t))
                    dylibs_seen.append((LC[cmd], t))
            elif cmd == 0x32:  # LC_BUILD_VERSION
                plat, mo, sa, nt = struct.unpack("<IIII", b[o + 8:o + 24])
                minos = "%d.%d.%d" % (mo >> 16, (mo >> 8) & 0xFF, mo & 0xFF)
                sdk = "%d.%d.%d" % (sa >> 16, (sa >> 8) & 0xFF, sa & 0xFF)
                out("  LC_BUILD_VERSION platform=%d minos=%s sdk=%s ntools=%d" % (plat, minos, sdk, nt))
            elif cmd == 0x24 or cmd == 0x25:  # LC_VERSION_MIN_*
                v, s = struct.unpack("<II", b[o + 8:o + 16])
                minos = "%d.%d.%d" % (v >> 16, (v >> 8) & 0xFF, v & 0xFF)
                sdk = "%d.%d.%d" % (s >> 16, (s >> 8) & 0xFF, s & 0xFF)
                out("  LC_VERSION_MIN_%s minos=%s sdk=%s" % ("MACOSX" if cmd == 0x24 else "IPHONEOS", minos, sdk))
            o += cmdsize
        out("  rpaths: %s" % rpaths)
        out("  dylib load commands (%d):" % len(loads))
        for ordn, kind, t in loads:
            flag = ""
            base = t.rsplit("/", 1)[-1]
            if base in POST12:
                flag = "  <== POST-iOS-12 RUNTIME (%s)" % POST12[base]
            if t.startswith("@rpath/"):
                target = "Payload/Phigros.app/Frameworks/" + t[len("@rpath/"):]
                flag += "   resolves=%s" % ("PRESENT" if target in names else "*** MISSING ***")
            out("    [%2d] %-22s %s%s" % (ordn, kind, t, flag))
        out("")
    z.close()


def main():
    outp = r"H:/file/phi/b7_dylibdeps.txt"
    with open(outp, "w", encoding="utf-8") as fh:
        def out(s):
            print(s)
            fh.write(s + "\n")
        for k, v in IPAS.items():
            scan(k, v, out)
    print("written", outp)


if __name__ == "__main__":
    main()
