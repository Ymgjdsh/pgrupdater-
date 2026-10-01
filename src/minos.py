import struct, sys, glob, os, plistlib

LC_BUILD_VERSION = 0x32
LC_VERSION_MIN_IPHONEOS = 0x25

CPU = {0x0100000C: "arm64", 12: "armv7", 0x01000007: "x86_64"}

def minos_of(path):
    with open(path, "rb") as f:
        buf = f.read(0x4000 + 0x1000)
    magic = struct.unpack_from("<I", buf, 0)[0]
    if magic != 0xFEEDFACF:
        return ("not-macho(0x%08X)" % magic, None, None, None)
    cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from("<IIIIIII", buf, 4)
    off = 32
    mins = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmd == LC_BUILD_VERSION:
            plat, minos, sdk, ntools = struct.unpack_from("<IIII", buf, off + 8)
            mins.append(("LC_BUILD_VERSION", plat, minos, sdk))
        elif cmd == LC_VERSION_MIN_IPHONEOS:
            vm, sdk = struct.unpack_from("<II", buf, off + 8)
            mins.append(("LC_VERSION_MIN_IPHONEOS", None, vm, sdk))
        off += cmdsize
    return (None, CPU.get(cputype, hex(cputype)), mins, ftype)

def ver(v):
    return "%d.%d.%d" % (v >> 16, (v >> 8) & 0xFF, v & 0xFF)

print("=== Mach-O minos ===")
files = sorted(glob.glob("out\\UnityFramework.v*"))
files += sorted(glob.glob("out\\Phigros.v*"))
files += ["work\\UnityFramework"]
for p in files:
    err, cpu, mins, ftype = minos_of(p)
    if err:
        print("%-34s %s" % (p, err)); continue
    s = ", ".join("%s platform=%s minos=%s sdk=%s" % (m[0], m[1], ver(m[2]), ver(m[3])) for m in mins)
    print("%-34s %-6s ftype=%d  %s" % (p, cpu, ftype, s))

print()
print("=== Info.plist MinimumOSVersion ===")
for p in ["out\\Info.plist", "out\\FW-Info.plist", "out\\Info-bid12.plist", "out\\chk_app.plist"]:
    if not os.path.exists(p):
        continue
    with open(p, "rb") as f:
        d = plistlib.load(f)
    print("%-24s MinimumOSVersion=%s CFBundleIdentifier=%s CFBundleShortVersionString=%s" % (
        p, d.get("MinimumOSVersion"), d.get("CFBundleIdentifier"), d.get("CFBundleShortVersionString")))
