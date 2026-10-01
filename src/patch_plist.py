import plistlib, sys, os

src, dst = sys.argv[1], sys.argv[2]
raw = open(src, "rb").read()
binary = raw[:8] == b"bplist00"
d = plistlib.loads(raw)
print("format:", "binary" if binary else "xml")
for k in sorted(d):
    v = d[k]
    s = repr(v)
    print(f"  {k} = {s[:110]}")

changes = {"MinimumOSVersion": "12.0"}
# the SDK/build metadata is informational, but keep it self-consistent for installers
if "DTPlatformVersion" in d:
    changes["DTPlatformVersion"] = "12.4"
if "DTSDKName" in d:
    changes["DTSDKName"] = "iphoneos12.4"
if "DTSDKBuild" in d:
    changes["DTSDKBuild"] = "16G77"

for k, v in changes.items():
    old = d.get(k, "<absent>")
    d[k] = v
    print(f"CHANGED {k}: {old!r} -> {v!r}")

out = plistlib.dumps(d, fmt=plistlib.FMT_BINARY if binary else plistlib.FMT_XML,
                     sort_keys=False)
open(dst, "wb").write(out)
print("wrote", dst, len(out), "bytes (src", len(raw), ")")
chk = plistlib.loads(open(dst, "rb").read())
print("re-read MinimumOSVersion =", chk["MinimumOSVersion"], "| key count", len(chk))
