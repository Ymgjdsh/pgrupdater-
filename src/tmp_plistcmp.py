"""compare the scene/lifecycle keys of the three IPAs' Info.plist files"""
import sys, zipfile, plistlib

KEYS = ("CFBundleIdentifier", "CFBundleExecutable", "CFBundleShortVersionString",
        "CFBundleVersion", "MinimumOSVersion", "UIApplicationSceneManifest",
        "UIApplicationSupportsIndirectInputEvents", "UILaunchStoryboardName",
        "UIMainStoryboardFile", "LSRequiresIPhoneOS", "UIRequiredDeviceCapabilities",
        "UISupportedInterfaceOrientations", "UIStatusBarHidden",
        "UIViewControllerBasedStatusBarAppearance", "UIFileSharingEnabled",
        "LSSupportsOpeningDocumentsInPlace", "UIApplicationExitsOnSuspend",
        "UIBackgroundModes", "CFBundleURLTypes", "LSApplicationQueriesSchemes")

for path in sys.argv[1:]:
    print("=" * 72)
    print(path)
    try:
        z = zipfile.ZipFile(path)
    except Exception as e:
        print("  open failed:", e)
        continue
    names = [n for n in z.namelist() if n.endswith("Info.plist")
             and ("Phigros.app/Info.plist" in n or "UnityFramework.framework/Info.plist" in n)]
    for n in names:
        try:
            d = plistlib.loads(z.read(n))
        except Exception as e:
            print(" ", n, "ERR", e)
            continue
        print("-", n)
        for k in KEYS:
            if k in d:
                print(f"    {k} = {d[k]!r}")
        for k in sorted(d):
            if ("Scene" in k or "scene" in k) and k not in KEYS:
                print(f"    [other] {k} = {d[k]!r}")
