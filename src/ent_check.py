#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Print the XML entitlements embedded in a Mach-O's signature and the profile's values."""
import plistlib
import struct
import sys
import zipfile

macho, ipa = sys.argv[1], sys.argv[2]
buf = open(macho, "rb").read()
magic, _ct, _cs, _ft, ncmds, _sc, _fl, _r = struct.unpack_from("<8I", buf, 0)
off = 32
dataoff = datasize = 0
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", buf, off)
    if cmd == 0x1D:
        dataoff, datasize = struct.unpack_from("<II", buf, off + 8)
    off += cmdsize
b = buf[dataoff:dataoff + datasize]
blen, count = struct.unpack_from(">II", b, 4)
print("== embedded entitlements (%s)" % macho)
for i in range(count):
    t, o = struct.unpack_from(">II", b, 12 + i * 8)
    if t == 5:
        slen = struct.unpack_from(">I", b, o + 4)[0]
        print(b[o + 8:o + slen].decode(errors="replace"))
print("== profile entitlements / identifiers (%s)" % ipa)
z = zipfile.ZipFile(ipa)
raw = z.read("Payload/Phigros.app/embedded.mobileprovision")
start = raw.find(b"<?xml")
end = raw.find(b"</plist>") + len(b"</plist>")
pl = plistlib.loads(raw[start:end])
ent = pl.get("Entitlements", {})
for k in ("application-identifier", "com.apple.developer.team-identifier", "get-task-allow",
          "keychain-access-groups", "beta-reports-active"):
    print("   %-42s %s" % (k, ent.get(k)))
print("   %-42s %s" % ("ProvisionedDevices", pl.get("ProvisionedDevices")))
print("   %-42s %s" % ("ExpirationDate", pl.get("ExpirationDate")))
print("   %-42s %s" % ("Name", pl.get("Name")))
