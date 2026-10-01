#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inspect the signing certificate of a signed IPA against its embedded profile.

Usage: python certprobe.py <signed.ipa>

Writes out/prof_cert_*.der and out/sig_cert_*.der and prints a comparison.
AMFI kills a process at exec (instant bounce, NO crash report) when the CMS
signer is not one of the profile's DeveloperCertificates / not Apple-trusted.
"""
import hashlib
import os
import plistlib
import struct
import sys
import zipfile

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")


def cms_certs(blob):
    """Find DER certificates inside a PKCS#7 blob (SEQUENCE{cert...})."""
    certs = []
    i = 0
    n = len(blob)
    while i < n - 8:
        if blob[i] == 0x30 and blob[i + 1] == 0x82:
            ln = struct.unpack(">H", blob[i + 2:i + 4])[0]
            if 4 + ln <= n and blob[i + 4] == 0x30 and blob[i + 5] == 0x82:
                tln = struct.unpack(">H", blob[i + 6:i + 8])[0]
                if 8 + tln <= n and 800 < ln < 4000 and tln < ln:
                    cand = blob[i:i + 4 + ln]
                    if cand not in certs:
                        certs.append(cand)
                    i += 4 + ln
                    continue
        i += 1
    return certs


def superblob(buf):
    magic, length, count = struct.unpack_from(">3I", buf, 0)
    assert magic == 0xFADE0CC0, "not a SuperBlob: 0x%x" % magic
    idx = []
    for k in range(count):
        t, off = struct.unpack_from(">2I", buf, 12 + 8 * k)
        idx.append((t, off))
    return idx


def main(ipa):
    os.makedirs(OUT, exist_ok=True)
    z = zipfile.ZipFile(ipa)
    names = z.namelist()
    app = [n for n in names if n.startswith("Payload/") and n.count("/") == 2 and n.endswith(".app/")] or \
          [n for n in names if n.startswith("Payload/")][:1]
    base = app[0].rstrip("/") if app[0].endswith(".app/") else app[0]
    prof_name = base + "/embedded.mobileprovision"
    exe_name = None
    if base.endswith(".app"):
        # read Info.plist for CFBundleExecutable
        try:
            pl = plistlib.loads(z.read(base + "/Info.plist"))
            exe_name = base + "/" + pl["CFBundleExecutable"]
        except Exception as e:
            print("could not read app Info.plist: %s" % e)
    print("app dir          : %s" % base)
    print("executable       : %s" % exe_name)

    prof = z.read(prof_name)
    print("\n=== embedded.mobileprovision (%d bytes) ===" % len(prof))
    certs_in_profile = []
    try:
        start = prof.index(b"<?xml")
        end = prof.index(b"</plist>") + len(b"</plist>")
        pl = plistlib.loads(prof[start:end])
        for k in ("Name", "TeamIdentifier", "ApplicationIdentifierPrefix", "UUID", "CreationDate",
                  "ExpirationDate", "TimeToLive", "Platform", "ProvisionedDevices"):
            if k in pl:
                v = pl[k]
                if isinstance(v, list) and len(v) > 6:
                    v = "%d item(s): %s ..." % (len(v), v[:3])
                print("   %-28s %s" % (k, v))
        ent = pl.get("Entitlements", {})
        for k in sorted(ent):
            print("   ent %-24s %s" % (k, ent[k]))
        for k in ("DeveloperCertificates", "LocalProvision"):
            if k in pl:
                for j, c in enumerate(pl[k] if isinstance(pl[k], list) else [pl[k]]):
                    if isinstance(c, bytes):
                        p = os.path.join(OUT, "prof_cert_%d.der" % j)
                        open(p, "wb").write(c)
                        h = hashlib.sha1(c).hexdigest()
                        certs_in_profile.append(h)
                        print("   DeveloperCertificates[%d] %d bytes sha1=%s -> %s" % (j, len(c), h, p))
    except Exception as e:
        print("   profile plist parse failed: %s" % e)

    if exe_name:
        buf = z.read(exe_name)
        ncmds = struct.unpack_from("<I", buf, 16)[0]
        off = 32
        cs = None
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", buf, off)
            if cmd == 0x1D:
                cs = struct.unpack_from("<2I", buf, off + 8)
            off += cmdsize
        print("\n=== %s (%d bytes) LC_CODE_SIGNATURE=%s ===" % (exe_name, len(buf), cs))
        if cs:
            blob = buf[cs[0]:cs[0] + cs[1]]
            idx = superblob(blob)
            print("   SuperBlob entries: %s" % [(hex(t), hex(o)) for t, o in idx])
            for t, o in idx:
                if t == 65536:
                    cms = blob[o:]
                    print("   CMS blob: %d bytes" % len(cms))
                    certs = cms_certs(cms)
                    print("   embedded certificates found: %d" % len(certs))
                    for j, c in enumerate(certs):
                        p = os.path.join(OUT, "sig_cert_%d.der" % j)
                        open(p, "wb").write(c)
                        h = hashlib.sha1(c).hexdigest()
                        print("      sig_cert_%d %d bytes sha1=%s -> %s   %s" %
                              (j, len(c), h, p, "IN PROFILE" if h in certs_in_profile else "NOT IN PROFILE <<<"))
    z.close()


if __name__ == "__main__":
    main(sys.argv[1])
