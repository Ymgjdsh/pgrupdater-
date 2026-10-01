# -*- coding: utf-8 -*-
"""Task 1/4: resource formats in 4.0.0 vs 3.19.0 vs built v4."""
import zipfile, plistlib, hashlib, io, re, struct, collections

BASE = "H:/file/phi/"
IPAS = {
    "4.0.0": BASE + "games.Pigeon.Phigros_4.0.0_und3fined.ipa",
    "3.19.0": BASE + "games.Pigeon.Phigros_3.19.0_und3fined.ipa",
    "built_v4": BASE + "phi5/Phigros_4.0.0_iOS12_v4.ipa",
}
OUT = open(BASE + "b2_resources.txt", "w", encoding="utf-8")
def w(*a):
    s = " ".join(str(x) for x in a)
    print(s)
    OUT.write(s + "\n")

ZS = {k: zipfile.ZipFile(v) for k, v in IPAS.items()}
NAMES = {k: set(z.namelist()) for k, z in ZS.items()}

# ---------------------------------------------------------------- name diff
w("###### ENTRY NAME DIFF (non-Data) ######")
for k in IPAS:
    no = sorted(n for n in NAMES[k] if not n.startswith("Payload/Phigros.app/Data/"))
    globals()["_nd_" + k] = no
for a, b in (("4.0.0", "built_v4"), ("4.0.0", "3.19.0")):
    sa, sb = set(_nd_4_0_0) if False else set(globals()["_nd_" + a]), set(globals()["_nd_" + b])
    w("-- %s MINUS %s:" % (a, b))
    for n in sorted(sa - sb):
        w("     < %s" % n)
    w("-- %s MINUS %s:" % (b, a))
    for n in sorted(sb - sa):
        w("     > %s" % n)

# ---------------------------------------------------------------- identical-by-hash table
def h(z, n):
    return hashlib.sha256(z.read(n)).hexdigest()[:16]

interesting = []
for k, ns in NAMES.items():
    for n in ns:
        if n.startswith("Payload/Phigros.app/Data/"):
            continue
        b = n.rsplit("/", 1)[-1]
        if (b.startswith("LaunchScreen") or b in ("Assets.car", "PkgInfo", "Info.plist",
                                                  "PrivacyInfo.xcprivacy", "embedded.mobileprovision")
                or b.endswith((".nib", ".storyboardc", ".car", ".strings", ".momd", ".mom"))
                or b.endswith(".strings") or "Assets.car" in n):
            interesting.append(n)
interesting = sorted(set(interesting))
w("")
w("###### SHA256 (16 hex) of resources of interest, per IPA ######")
w("%-84s %-10s %-18s %-18s %-18s" % ("entry", "size", "4.0.0", "3.19.0", "built_v4"))
for n in interesting:
    row = []
    size = ""
    for k in ("4.0.0", "3.19.0", "built_v4"):
        if n in NAMES[k]:
            i = ZS[k].getinfo(n)
            size = i.file_size
            row.append(h(ZS[k], n))
        else:
            row.append("--absent--")
    if len(set(row)) == 1 and row[0] != "--absent--":
        row[0] = row[0] + " *ALL SAME*"
    w("%-84s %-10s %-18s %-18s %-18s" % (n, size, row[0], row[1], row[2]))

# ---------------------------------------------------------------- storyboardc / nib
def dump_bplist(z, name, label):
    raw = z.read(name)
    w("   --- %s  size=%d  magic=%r" % (name, len(raw), raw[:8]))
    if raw[:6] not in (b"bplist",):
        w("      NOT a bplist; strings found: %r" % (sorted(set(re.findall(rb"[ -~]{4,}", raw)))[:20],))
        return
    try:
        pl = plistlib.loads(raw)
    except Exception as e:
        w("      bplist parse fail: %r" % (e,))
        return
    def walk(o, path=""):
        if isinstance(o, dict):
            for kk, vv in o.items():
                if kk in ("$classname", "$classes", "NSClassName", "UID", "UIStoryboardIdentifier",
                          "$version", "$archiver", "NSDelegate", "targetRuntime", "ibtool"):
                    w("      %-60s = %r" % (path + "/" + kk, vv))
                walk(vv, path + "/" + str(kk))
        elif isinstance(o, list):
            for i2, vv in enumerate(o):
                walk(vv, path + "[%d]" % i2)
        else:
            if isinstance(o, str) and re.search(r"(ibtool|UIKit|iOS|Storyboard|Xcode|Version|Scene|SwiftUI|UIWindow|UIScene)", o):
                w("      %-60s = %r" % (path, o))
    w("      top-level keys: %s" % sorted(pl.keys()))
    if "$archiver" in pl:
        w("      $archiver = %r  $version = %r" % (pl.get("$archiver"), pl.get("$version")))
    walk(pl)
    # all unique values that look like class names
    txt = str(pl)
    w("      printable runs (>=6): %r" % sorted(set(re.findall(r"[ -~]{6,}", txt)))[:80])

for label in ("4.0.0", "3.19.0", "built_v4"):
    z = ZS[label]
    w("")
    w("###### STORYBOARD/NIB DUMP: %s ######" % label)
    ns = sorted(n for n in NAMES[label] if n.endswith((".nib",)) or ".storyboardc/" in n)
    for n in ns:
        dump_bplist(z, n, label)

# ---------------------------------------------------------------- Assets.car
w("")
w("###### Assets.car ######")
for label in ("4.0.0", "3.19.0", "built_v4"):
    z = ZS[label]
    for n in sorted(n for n in NAMES[label] if n.endswith("Assets.car")):
        raw = z.read(n)
        w("-- %s :: %s  size=%d sha=%s" % (label, n, len(raw), hashlib.sha256(raw).hexdigest()[:16]))
        w("   first64 : %s" % " ".join("%02x" % c for c in raw[:64]))
        w("   ascii   : %r" % raw[:64])
        try:
            magic, ver, l2, ver2 = struct.unpack_from("<16sIIB", raw, 0)
            w("   BOMStorage magic=%r version=%d ?=%d ver2=%d" % (magic.rstrip(b"\0"), ver, l2, ver2))
        except Exception as e:
            w("   bom parse fail %r" % (e,))
        # look for the CAR/BOM header of the actual CAR file inside
        for pat in (b"BOMStorage", b"CARHEADER", b"CAR ", b"REND", b"CORE", b"appearances",
                    b"UIAppearance", b"kCRThemeAppearanceName", b"AssetType", b"NSAppearance",
                    b"META", b"style", b"Icon Image", b"AppIcon"):
            idx = []
            i = raw.find(pat)
            while i != -1 and len(idx) < 4:
                idx.append(i)
                i = raw.find(pat, i + 1)
            if idx:
                w("   pat %-24r at %s" % (pat, [hex(x) for x in idx]))
        # version-ish strings
        for m in sorted(set(re.findall(rb"(?:car|CAR|CoreUI|BOM|REND)[ -~]{0,24}", raw)))[:40]:
            w("   str %r" % m)
        w("   REND appearance/scale records (first 6):")
        cnt = 0
        i = raw.find(b"REND")
        while i != -1 and cnt < 6:
            w("      @0x%X %s" % (i, raw[i:i+40].hex()))
            cnt += 1
            i = raw.find(b"REND", i + 1)
        # asset names: keys are strings ending with \0 near the 'keyfmt' area; dump printable utf8-ish runs
        runs = re.findall(rb"[A-Za-z0-9_.@/ -]{4,}", raw)
        c = collections.Counter(runs)
        w("   most common printable runs: %r" % c.most_common(25))

OUT.close()
print("\nwritten b2_resources.txt")
