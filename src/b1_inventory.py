# -*- coding: utf-8 -*-
"""Task 1a: inventory the non-Data part of each app bundle + parse Info.plist."""
import zipfile, plistlib, collections

BASE = "H:/file/phi/"
IPAS = {
    "4.0.0": BASE + "games.Pigeon.Phigros_4.0.0_und3fined.ipa",
    "3.19.0": BASE + "games.Pigeon.Phigros_3.19.0_und3fined.ipa",
    "built_v4": BASE + "phi5/Phigros_4.0.0_iOS12_v4.ipa",
}
OUT = open(BASE + "b1_inventory.txt", "w", encoding="utf-8")
def w(*a):
    s = " ".join(str(x) for x in a)
    print(s)
    OUT.write(s + "\n")

for label, path in IPAS.items():
    z = zipfile.ZipFile(path)
    names = z.namelist()
    w("=" * 78)
    w("IPA %s  %s  total entries=%d" % (label, path, len(names)))
    w("=" * 78)
    objs = z.infolist()
    inter = [i for i in objs if not i.filename.startswith("Payload/Phigros.app/Data/")]
    w("-- %d entries outside Payload/Phigros.app/Data/" % len(inter))
    for i in sorted(inter, key=lambda x: x.filename):
        w("   %12d  %s" % (i.file_size, i.filename))
    d1 = collections.Counter()
    datan = 0
    for i in objs:
        f = i.filename
        if f.startswith("Payload/Phigros.app/Data/"):
            datan += 1
            rest = f[len("Payload/Phigros.app/Data/"):]
            d1[rest.split("/")[0] if "/" in rest else rest] += 1
            if rest.count("/") == 0:
                w("   DATA-TOP %12d %s" % (i.file_size, f))
    w("-- Data/ subtrees (%d entries): %s" % (datan, dict(d1)))
    for cand in ("Payload/Phigros.app/Info.plist",
                 "Payload/Phigros.app/Frameworks/UnityFramework.framework/Info.plist"):
        if cand in names:
            raw = z.read(cand)
            w("-- %s  (%d bytes) first8=%s" % (cand, len(raw), raw[:8].hex()))
            try:
                pl = plistlib.loads(raw)
            except Exception as e:
                w("   PLIST PARSE FAIL: %r" % (e,))
                continue
            keys = ["MinimumOSVersion", "DTPlatformVersion", "DTSDKName", "DTSDKBuild",
                    "DTXcode", "DTXcodeBuild", "DTCompiler", "BuildMachineOSBuild",
                    "UIRequiredDeviceCapabilities", "UILaunchStoryboardName",
                    "UILaunchStoryboardDefinitions", "UILaunchImages",
                    "UIApplicationSceneManifest", "UISceneConfigurations",
                    "CFBundleIconName", "CFBundleIcons", "CFBundleIcons~ipad",
                    "NSUserActivityTypes", "UIViewControllerBasedStatusBarAppearance",
                    "LSMinimumSystemVersion", "UIStatusBarStyle", "UIStatusBarHidden",
                    "CFBundleExecutable", "CFBundleIdentifier", "CFBundleSupportedPlatforms",
                    "CFBundleDevelopmentRegion", "CFBundleInfoDictionaryVersion",
                    "UIRequiresFullScreen", "UISupportedInterfaceOrientations",
                    "UISupportedInterfaceOrientations~ipad",
                    "DTPlatformName", "DTPlatformBuild", "UIUserInterfaceStyle",
                    "CFBundleVersion", "CFBundleShortVersionString", "UIMainStoryboardFile",
                    "NSExtension", "LSApplicationCategoryType",
                    "UIApplicationSupportsIndirectInputEvents"]
            w("   --- keys of interest:")
            for k in keys:
                if k in pl:
                    sv = repr(pl[k])
                    if len(sv) > 600:
                        sv = sv[:600] + " ...TRUNC(%d)" % len(sv)
                    w("      %-38s = %s" % (k, sv))
            w("   --- ALL keys sorted: %s" % sorted(pl.keys()))
        else:
            w("-- %s MISSING" % cand)
    for cand in ("Payload/Phigros.app/PkgInfo",
                 "Payload/Phigros.app/embedded.mobileprovision",
                 "Payload/Phigros.app/CodeResources",
                 "Payload/Phigros.app/SC_Info/Phigros.sinf",
                 "Payload/Phigros.app/SC_Info/Phigros.supp"):
        state = "PRESENT" if cand in names else "ABSENT"
        w("-- %s : %s" % (cand, state))
        if cand in names:
            w("      head: %r" % (z.read(cand)[:96],))
    z.close()

OUT.close()
print("\nwritten b1_inventory.txt")
