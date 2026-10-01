#!/usr/bin/env python3
"""b16: what do the libswift*.dylib files shipped inside the working 3.19.0 IPA provide?
 - install name, minos/sdk, exported symbol set (export trie + symtab)
 - how many of the 403 strong->weak flipped symbols they cover
"""
import struct, zipfile

IPA319 = r"H:/file/phi/games.Pigeon.Phigros_3.19.0_und3fined.ipa"


def rd(b, o, f):
    return struct.unpack_from(f, b, o)


def uleb(b, p):
    r = s = 0
    while True:
        x = b[p]; p += 1
        r |= (x & 0x7F) << s
        if not (x & 0x80):
            return r, p
        s += 7


def exports(b):
    ncmds, = rd(b, 16, "<I")
    o = 32
    exps = set()
    symoff = nsyms = stroff = 0
    minos = sdk = None
    inst = None
    for _ in range(ncmds):
        c, cs = rd(b, o, "<II")
        mc = c & 0x7FFFFFFF
        if mc == 0x22:  # LC_DYLD_INFO_ONLY
            f = rd(b, o + 8, "<10I")
            exp_off, exp_sz = f[8], f[9]
            if exp_sz:
                exps |= trie(b, exp_off, exp_sz)
        elif c == 0x80000033:  # LC_DYLD_EXPORTS_TRIE
            eo, es = rd(b, o + 8, "<II")
            exps |= trie(b, eo, es)
        elif c == 0x2:
            symoff, nsyms, stroff, strsize = rd(b, o + 8, "<IIII")
        elif c == 0xD:
            no, = rd(b, o + 8, "<I")
            inst = b[o + 24:o + 24 + no].split(b"\0")[0].decode()
        elif c == 0x32:
            plat, minv, sdkv, nt = rd(b, o + 8, "<IIII")
            minos, sdk = "%d/%d.%d.%d" % (plat, minv >> 16, (minv >> 8) & 0xFF, minv & 0xFF), "%d.%d.%d" % (sdkv >> 16, (sdkv >> 8) & 0xFF, sdkv & 0xFF)
        elif c == 0x25:
            v, s = rd(b, o + 8, "<II")
            minos, sdk = "iphoneos/%d.%d.%d" % (v >> 16, (v >> 8) & 0xFF, v & 0xFF), "%d.%d.%d" % (s >> 16, (s >> 8) & 0xFF, s & 0xFF)
        o += cs
    if nsyms:
        for i in range(nsyms):
            nt, ns, nd, nv = rd(b, symoff + 16 * i, "<BBHI")
            if nt & 0x0E and not (nt & 0x02):  # defined, not undefined
                e = b.find(b"\0", stroff + ns)
                nm = b[stroff + ns:e].decode("utf-8", "replace")
                if nm:
                    exps.add(nm)
    return exps, minos, sdk, inst


def trie(b, off, size):
    out = set()

    def walk(p, acc):
        ts, p2 = uleb(b, p)
        cnt, p2 = uleb(b, p2)
        for _ in range(cnt):
            e = b.find(b"\0", p2)
            edge = b[p2:e].decode("utf-8", "replace")
            p2 = e + 1
            child, p2 = uleb(b, p2)
            walk(off + child, acc + edge)
        if ts:
            out.add(acc)
    try:
        walk(off, "")
    except Exception as ex:
        print("   trie error:", ex)
    return out


flips = {l.split("\t")[0] for l in open("b15_non_swift_flips.txt").read().splitlines() if l}
flips |= {l for l in open("b15_swift_flips.txt").read().splitlines() if l}
print("flipped names loaded: %d" % len(flips))

z = zipfile.ZipFile(IPA319)
names = [n for n in z.namelist() if "/Frameworks/libswift" in n and n.endswith(".dylib")]
print("3.19.0 bundles %d libswift dylibs:" % len(names))
union = set()
for n in sorted(names):
    b = z.read(n)
    ex, minos, sdk, inst = exports(b)
    union |= ex
    print("   %-60s %9d B  exports %6d  minos=%s sdk=%s install=%s"
          % (n.split("/")[-1], len(b), len(ex), minos, sdk, inst))

# framework's own load commands for swift
fw = z.read("Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework")
ncmds, = rd(fw, 16, "<I")
o = 32
print()
print("3.19.0 UnityFramework libswift load commands:")
for _ in range(ncmds):
    c, cs = rd(fw, o, "<II")
    if c in (0xC, 0x80000018, 0x8000001F, 0x8000001C):
        no, = rd(fw, o + 8, "<I")
        nm = fw[o + 24:o + 24 + no].split(b"\0")[0].decode()
        if "swift" in nm or c == 0x8000001C:
            print("   %-22s %s" % ({0xC: "LC_LOAD_DYLIB", 0x80000018: "LC_LOAD_WEAK_DYLIB",
                                     0x8000001F: "LC_REEXPORT", 0x8000001C: "LC_RPATH"}[c], nm))
    o += cs

cov = flips & union
print()
print("flipped names covered by 3.19.0's bundled libswift union: %d / %d" % (len(cov), len(flips)))
miss = sorted(flips - union)
print("NOT covered (%d), first 40:" % len(miss))
for m in miss[:40]:
    print("   %s" % m)
open("b16_missing_flips.txt", "w").write("\n".join(miss))
