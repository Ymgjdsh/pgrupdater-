import sys, struct, re

def find(needle, path):
    b = open(path, "rb").read()
    out = []
    i = b.find(needle)
    while i != -1:
        out.append(i)
        i = b.find(needle, i + 1)
    return b, out

print("=== Info.plist (patched, what the device runs) ===")
p = open("out\\Info.plist", "rb").read()
txt = p.decode("utf-8", "replace")
for m in re.finditer(r"<key>([^<]*[Ss]cene[^<]*)</key>", txt):
    print("  key:", m.group(1))
print("  UIApplicationSceneManifest present:", "UIApplicationSceneManifest" in txt)

print()
print("=== pristine 4.0.0 Info.plist ===")
p2 = open("work\\Info.plist", "rb").read().decode("utf-8", "replace")
print("  UIApplicationSceneManifest present:", "UIApplicationSceneManifest" in p2)

print()
print("=== strings in UnityFramework (pristine) ===")
b, offs = find(b"UIApplicationSceneManifest", "work\\UnityFramework")
print("  UIApplicationSceneManifest hits:", offs)
for n in (b"UISceneDelegate", b"UISceneSession", b"UnitySceneDelegate", b"sceneManifest", b"UISceneConfiguration"):
    _, o = find(n, "work\\UnityFramework")
    print("  %-24s %s" % (n.decode(), o[:8]))

print()
print("=== context around the scene-manifest strings ===")
for o in offs:
    s = b[o-40:o+80].split(b"\x00")
    print("  @0x%X:" % o, [x.decode('latin1') for x in s if x])
