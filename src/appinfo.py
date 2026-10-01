"""appinfo.py <ipa> [entry]

Print CFBundleIdentifier / versions / MinimumOSVersion and TapTap-ish Info.plist
keys (URL schemes, LSApplicationQueriesSchemes) from an IPA's app Info.plist.
Read-only.
"""
import plistlib
import sys
import zipfile

KEYS = [
    "CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion",
    "MinimumOSVersion", "CFBundleURLTypes", "LSApplicationQueriesSchemes",
    "TapClientId", "TapClientID", "TapAppId", "TapAppID",
]


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    ipa = argv[1]
    entry = argv[2] if len(argv) > 2 else "Payload/Phigros.app/Info.plist"
    with zipfile.ZipFile(ipa) as z:
        data = z.read(entry)
    pl = plistlib.loads(data)
    print(f"{ipa} :: {entry}")
    for k in KEYS:
        if k in pl:
            print(f"  {k} = {pl[k]!r}")
    extra = [k for k in pl if "tap" in k.lower() or "Pigeon" in k]
    for k in sorted(extra):
        if k not in KEYS:
            print(f"  {k} = {pl[k]!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
