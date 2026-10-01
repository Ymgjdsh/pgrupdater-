import hashlib
import sys
import zipfile


def h(b):
    return hashlib.sha256(b).hexdigest()


want = {
    "Payload/Phigros.app/Phigros": r"out\Phigros.v6",
    "Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework":
        r"out\UnityFramework.v8",
}
for ipa in sys.argv[1:]:
    z = zipfile.ZipFile(ipa)
    for member, path in want.items():
        inh = h(z.read(member))
        ref = h(open(path, "rb").read())
        print(("MATCH" if inh == ref else "DIFF "), ipa, member.split("/")[-1],
              inh[:16], ref[:16])
for p in (r"out\UnityFramework.v8", r"out\UnityFramework.v7", r"out\Phigros.v6"):
    print(f"{p}: {h(open(p, 'rb').read())}")
