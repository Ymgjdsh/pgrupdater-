"""Compare an IPA's members against the binaries a build spec says to inject.

usage: python cmp_ver.py <version> <ipa> [<ipa> ...]
       (reads ipaspec_<version>.json; prints MATCH/DIFF per member, then
        sha256/size of every artifact, the ipa specs and the IPAs)
"""
import hashlib
import json
import os
import sys
import zipfile


def h(b):
    return hashlib.sha256(b).hexdigest()


def main(ver, ipas):
    spec = json.load(open(f"ipaspec_{ver}.json"))
    want = spec["replace"]
    ok = True
    for ipa in ipas:
        with zipfile.ZipFile(ipa) as z:
            for member, path in want.items():
                inh = h(z.read(member))
                ref = h(open(path, "rb").read())
                same = inh == ref
                ok = ok and same
                print(("MATCH" if same else "DIFF "), os.path.basename(ipa),
                      member.split("/")[-1], inh[:16], ref[:16])
    for p in want.values():
        print(f"artifact {p}: {os.path.getsize(p)} B  {h(open(p, 'rb').read())}")
    for ipa in ipas:
        print(f"ipa {ipa}: {os.path.getsize(ipa)} B  {h(open(ipa, 'rb').read())}")
    print("ALL MATCH" if ok else "MISMATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2:]))
