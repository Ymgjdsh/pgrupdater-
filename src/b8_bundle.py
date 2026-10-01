#!/usr/bin/env python3
# Task 4: scan the whole app bundle for container formats and iOS-13+ feature markers.
import zipfile, struct, collections, sys

IPAS = {
    "BUILT_v4": r"H:/file/phi/phi5/Phigros_4.0.0_iOS12_v4.ipa",
    "4.0.0_ORIG": r"H:/file/phi/games.Pigeon.Phigros_4.0.0_und3fined.ipa",
    "3.19.0_ORIG": r"H:/file/phi/games.Pigeon.Phigros_3.19.0_und3fined.ipa",
}
MAGICS = [
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit little-endian"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit little-endian"),
    (b"\xca\xfe\xba\xbe", "Mach-O FAT / universal"),
    (b"\xbe\xba\xfe\xca", "Mach-O FAT (swapped)"),
    (b"bplist00", "binary plist (bplist00)"),
    (b"BOMStore", "BOMStorage container (Assets.car)"),
    (b"UnityFS", "UnityFS asset bundle"),
    (b"UnityWeb", "UnityWeb data"),
    (b"NIBArchive", "NIBArchive nib"),
    (b"<?xml", "XML text"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"\x78\x9c", "zlib deflate"),
    (b"\x7fELF", "ELF"),
]
MARKERS = [
    b"UIApplicationSceneManifest", b"UISceneConfigurations", b"UISceneDelegate",
    b"UISceneSession", b"UISceneConnectionOptions", b"UIWindowScene", b"UISceneWillConnect",
    b"SwiftUI", b"UIKitCore", b"AppIntent", b"AppShortcut", b"NSUserActivity",
    b"INIntent", b"CPTemplateApplicationScene", b"UIStatusBarManager", b"UICollectionLayoutList",
    b"UIAction", b"UIMenu", b"UIContextMenuInteraction", b"UIListContentConfiguration",
    b"UIColor.systemBackgroundColor", b"systemBackground", b"NSDiffableDataSourceSnapshot",
]
EXTS = collections.Counter()
DIRS = collections.Counter()


def main():
    outp = r"H:/file/phi/b8_bundle.txt"
    fh = open(outp, "w", encoding="utf-8")

    def out(s):
        print(s)
        fh.write(s + "\n")

    for name, path in IPAS.items():
        out("=" * 100)
        out("## %s : %s" % (name, path))
        z = zipfile.ZipFile(path)
        names = [n for n in z.namelist() if not n.endswith("/")]
        out("file entries: %d" % len(names))
        EXTS.clear(); DIRS.clear()
        interesting = []
        archive_hits = []
        for n in names:
            base = n.rsplit("/", 1)[-1]
            ext = base.rsplit(".", 1)[-1].lower() if "." in base else "<none>"
            EXTS[ext] += 1
            parts = n.split("/")
            key = "/".join(parts[:4]) if len(parts) > 4 else n
            DIRS[key] += 1
            fi = z.getinfo(n)
            if fi.file_size < 16:
                continue
            with z.open(n) as f:
                head = f.read(24)
            kind = None
            for m, k in MAGICS:
                if head.startswith(m):
                    kind = k
                    break
            if kind is None:
                continue
            detail = ""
            if kind.startswith("bplist"):
                with z.open(n) as f:
                    blob = f.read(min(fi.file_size, 262144))
                if b"$archiver" in blob or b"$objects" in blob:
                    kind += " + NSKeyedArchiver"
                    for tok in (b"NSKeyedArchiver", b"NSKeyedUnarchiver"):
                        if tok in blob:
                            detail += " contains %s" % tok.decode()
                for tok in (b"$version", b"NSKeyedArchive"):
                    pass
            if kind.startswith("BOMStorage"):
                with z.open(n) as f:
                    blob = f.read(min(fi.file_size, 65536))
                detail += " car-keys=%s" % sorted({t.decode("latin1") for t in
                    (b"CARHEADER", b"RENDITIONS", b"FACETKEYS", b"KEYFORMAT", b"APPEARANCE",
                     b"CoreUI", b"BOMStorage", b"BOMTree", b"AppIcon", b"UIAppearanceAny")
                    if t in blob})
            interesting.append((n, fi.file_size, kind, detail))
        out("")
        out("-- container formats found (%d) --" % len(interesting))
        for n, sz, kind, detail in interesting:
            out("   %-95s %9d B  %s%s" % (n, sz, kind, detail))
        out("")
        out("-- marker scan (text-ish files) --")
        hits = 0
        for n in names:
            fi = z.getinfo(n)
            if fi.file_size < 8 or fi.file_size > 400000:
                continue
            with z.open(n) as f:
                blob = f.read()
            if b"\x00" in blob[:64] and not blob.startswith(b"bplist00") and not blob.startswith(b"BOMStore"):
                pass
            found = [m.decode() for m in MARKERS if m in blob]
            if found:
                hits += 1
                out("   %-95s %9d B  %s" % (n, fi.file_size, found))
        if not hits:
            out("   (no marker strings found in any file < 400 KB)")
        out("")
        out("-- Frameworks / PlugIns / Watch / .dylib / .appex entries --")
        for n in names:
            if "/Frameworks/" in n or "/PlugIns/" in n or n.endswith(".dylib") or ".appex" in n or "Watch" in n:
                out("   %-95s %9d B" % (n, z.getinfo(n).file_size))
        out("")
        out("-- extension census --")
        for e, c in EXTS.most_common(40):
            out("   %-20s %5d" % (e, c))
        out("")
        out("-- top-level dirs (first 4 path parts) --")
        for d, c in DIRS.most_common(60):
            out("   %-90s %5d" % (d, c))
        out("")
        z.close()
    fh.close()
    print("written", outp)


if __name__ == "__main__":
    main()
