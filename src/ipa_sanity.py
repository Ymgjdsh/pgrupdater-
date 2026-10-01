"""ipa_sanity.py - structural sanity checks a re-signing tool (/Sideloadly/ldid) would care about.

Checks:
  * exactly one Payload/<something>.app bundle, and it has Info.plist + its CFBundleExecutable
  * entry names: no backslashes, no absolute paths, no '..', no empty names
  * symlink entries (unix mode 0xA000) and their targets
  * executable-bit audit for every Mach-O-looking member (magic feedface/feedfacf/cffaedfe)
  * stray signature material (CodeResources, _CodeSignature, SC_Info, embedded.mobileprovision)
  * mode / create_system of every member of the .app that is a Mach-O binary

usage: python ipa_sanity.py <file.ipa> [...]
"""
import stat
import struct
import sys
import zipfile

MACHO_MAGICS = {0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE}


def unix_mode(i):
    m = (i.external_attr >> 16) & 0xFFFF
    return m


def main(argv):
    for path in argv[1:]:
        print("=" * 100)
        print(f"FILE {path}")
        z = zipfile.ZipFile(path)
        infos = z.infolist()
        names = [i.filename for i in infos]

        apps = sorted({n.split("/")[1] for n in names
                       if n.startswith("Payload/") and n.count("/") >= 2 and n.split("/")[1].endswith(".app")})
        print(f"  entries={len(infos)}  .app bundles under Payload/: {apps}")
        for app in apps:
            exe = None
            plist = f"Payload/{app}/Info.plist"
            if plist in names:
                data = z.read(plist)
                if data[:6] == b"bplist":
                    import plistlib
                    exe = plistlib.loads(data).get("CFBundleExecutable")
                else:
                    import re
                    m = re.search(rb"<key>CFBundleExecutable</key>\s*<string>([^<]+)</string>", data)
                    exe = m.group(1).decode() if m else None
            exe_path = f"Payload/{app}/{exe}" if exe else None
            print(f"    {app}: CFBundleExecutable={exe} present={exe_path in names if exe_path else None}")

        bad = [n for n in names if "\\" in n or n.startswith("/") or ".." in n.split("/") or n == ""]
        print(f"  suspicious names: {len(bad)}" + (f" e.g. {bad[:5]}" if bad else ""))

        links = [(i.filename, z.read(i)[:120].decode("utf-8", "replace"))
                 for i in infos if stat.S_ISLNK(unix_mode(i))]
        print(f"  symlink entries: {len(links)}")
        for nm, tgt in links[:20]:
            print(f"    {nm} -> {tgt}")

        sig = [n for n in names if "_CodeSignature" in n or n.endswith("CodeResources")
               or n.startswith("Payload/SC_Info") or n.endswith("embedded.mobileprovision")
               or "SC_Info" in n.split("/")]
        print(f"  signature material: {len(sig)}" + (f" {sig[:6]}" if sig else ""))

        # ---- mode census over the .app (central directory only, no decompression) ----
        for app in apps:
            prefix = f"Payload/{app}/"
            buckets = {}
            for i in infos:
                if not i.filename.startswith(prefix) or i.is_dir():
                    continue
                buckets.setdefault((i.create_system, i.create_version, i.extract_version,
                                    unix_mode(i)), []).append(i.filename)
            print(f"  mode census for {app} (create_system, vmade, vneed, unix_mode -> count):")
            for k, v in sorted(buckets.items(), key=lambda kv: -len(kv[1]))[:24]:
                print(f"    {k} -> {len(v)}   e.g. {v[0]}")

        # ---- Mach-O audit, restricted to plausible executable members ----
        cand = [i for i in infos if not i.is_dir() and (
            i.filename.endswith(".dylib") or i.filename.count("/") == 2
            or "/Frameworks/" in i.filename or i.filename.endswith(".appex"))]
        macho = []
        for i in cand:
            head = z.read(i)[:4]
            if len(head) == 4 and struct.unpack("<I", head)[0] in MACHO_MAGICS:
                macho.append(i)
        print(f"  Mach-O members (of {len(cand)} candidates): {len(macho)}")
        for i in macho:
            mode = unix_mode(i)
            ok = "EXEC" if mode & 0o111 else "**NOT-EXECUTABLE**"
            print(f"    {i.filename}  mode={mode:o} create_system={i.create_system} vmade={i.create_version} "
                  f"vneed={i.extract_version} method={i.compress_type} {ok}")
        z.close()


if __name__ == "__main__":
    main(sys.argv)
