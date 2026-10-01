import zipfile, hashlib, plistlib, sys, io, struct, os

ipa = sys.argv[1]
z = zipfile.ZipFile(ipa)
names = z.namelist()
print("entries:", len(names))
bad = [n for n in names if "_CodeSignature" in n or "SC_Info" in n]
print("leftover signature entries:", bad)
for n in ("Payload/Phigros.app/Phigros",
          "Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework",
          "Payload/Phigros.app/Info.plist"):
    i = z.getinfo(n)
    data = z.read(n)
    print(f"  {n}\n     usize={i.file_size} csize={i.compress_size} crc=0x{i.CRC:08X} "
          f"sha256={hashlib.sha256(data).hexdigest()[:24]}")
    if os.path.exists(n.split("/")[-1]):
        pass
d = plistlib.loads(z.read("Payload/Phigros.app/Info.plist"))
print("  MinimumOSVersion =", d["MinimumOSVersion"], "| CFBundleShortVersionString =",
      d["CFBundleShortVersionString"], "| CFBundleVersion =", d["CFBundleVersion"])

# parse the mach-o load commands straight out of the archive
b = z.read("Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework")
ncmds, sizeofcmds = struct.unpack_from("<II", b, 16)
print(f"  UnityFramework in-ipa: ncmds={ncmds} sizeofcmds={sizeofcmds} size={len(b)}")
found = {}
off = 32
for _ in range(ncmds):
    cmd, cs = struct.unpack_from("<II", b, off)
    found[cmd] = found.get(cmd, 0) + 1
    off += cs
print("  cmd census:", {hex(k): v for k, v in sorted(found.items())})
for k, lbl in ((0x80000034, "LC_DYLD_CHAINED_FIXUPS"), (0x80000033, "LC_DYLD_EXPORTS_TRIE"),
               (0x80000022, "LC_DYLD_INFO_ONLY"), (0x80000028, "LC_MAIN")):
    print(f"  {lbl}: {found.get(k, 0)}")
b2 = z.read("Payload/Phigros.app/Phigros")
print("  main exe size", len(b2), "first cmd bytes", b2[32:40].hex())
print("  testzip ->", "all CRCs OK" if z.testzip() is None else "CORRUPT")
