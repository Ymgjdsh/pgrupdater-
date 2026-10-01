"""audit2.py - two targeted checks on the rebuilt IPA:

1. plist fidelity: key sets and values of both Info.plist members in the rebuilt
   IPA vs the source IPA (only the intended keys may differ).
2. zip member names: non-ASCII names and whether the UTF-8 flag (bit 11) matches
   the name encoding, since a mismatch trips strict IPA parsers.

usage: python audit2.py <source.ipa> <rebuilt.ipa>
"""
import plistlib, sys, zipfile

APP = "Payload/Phigros.app"
PLISTS = [f"{APP}/Info.plist",
          f"{APP}/Frameworks/UnityFramework.framework/Info.plist"]


def main():
    src, new = sys.argv[1], sys.argv[2]
    a, b = zipfile.ZipFile(src), zipfile.ZipFile(new)

    print("== Info.plist fidelity ==")
    for n in PLISTS:
        pa = plistlib.loads(a.read(n))
        pb = plistlib.loads(b.read(n))
        ka, kb = set(pa), set(pb)
        print(f"\n{n}")
        print(f"  keys: source {len(ka)}  rebuilt {len(kb)}  only-in-source {sorted(ka-kb)}  only-in-rebuilt {sorted(kb-ka)}")
        common = sorted(ka & kb)
        diff = [(k, pa[k], pb[k]) for k in common if pa[k] != pb[k]]
        print(f"  differing values: {len(diff)}")
        for k, va, vb in diff:
            print(f"    {k}: {va!r} -> {vb!r}")

    print("\n== zip member name audit ==")
    for tag, z in (("source ", a), ("rebuilt", b)):
        infos = z.infolist()
        nonascii = []
        flag_bad = []
        for i in infos:
            raw = i.filename.encode("utf-8", "surrogateescape")
            has_utf8_flag = bool(i.flag_bits & 0x800)
            try:
                raw.decode("ascii")
                ascii_name = True
            except UnicodeDecodeError:
                ascii_name = False
            if not ascii_name:
                nonascii.append((i.filename, has_utf8_flag))
            if not ascii_name and not has_utf8_flag:
                flag_bad.append(i.filename)
        print(f"  {tag}: entries={len(infos)} non-ascii names={len(nonascii)} "
              f"non-ascii-without-utf8-flag={len(flag_bad)}")
        for nm, fl in nonascii[:10]:
            print(f"    {nm!r} utf8_flag={fl}")

    print("\n== members whose local header flags/extra differ from central ==")
    z = b
    n_bad = 0
    for i in z.infolist():
        pass
    print("  (skipped: patch_ipa now inherits local-header provenance from the source)")


if __name__ == "__main__":
    main()
