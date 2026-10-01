#!/usr/bin/env python3
"""b14: final launch-relevant checks.
 - LC_MAIN / entry point presence in pristine + patched binaries (masked cmd compare)
 - LC_ENCRYPTION_INFO_64 cryptid
 - built-IPA Info.plist special keys (app + framework)
 - iOS-13+ ObjC class / selector references inside the patched Mach-Os
"""
import struct, zipfile, plistlib, re, io

BINS = [
    ("ORIG app ", r"H:/file/phi/work/Phigros.main"),
    ("ORIG fw  ", r"H:/file/phi/work/UnityFramework"),
    ("PATCH app", r"H:/file/phi/out/Phigros.v4"),
    ("PATCH fw ", r"H:/file/phi/out/UnityFramework.v4"),
    ("3.19 fw  ", r"H:/file/phi/work319/...Frameworks__UnityFramework.framework__UnityFramework"),
]
IPA = r"H:/file/phi/phi5/Phigros_4.0.0_iOS12_v4.ipa"


def rd(b, o, f):
    return struct.unpack_from(f, b, o)


def cmds_of(b):
    ncmds, = rd(b, 16, "<I")
    o = 32
    out = []
    for _ in range(ncmds):
        c, cs = rd(b, o, "<II")
        out.append((c, cs, o))
        o += cs
    return out


print("== LC_MAIN / entry point and encryption ==")
for label, p in BINS:
    try:
        b = open(p, "rb").read()
    except OSError as e:
        print("  %s : cannot open (%s)" % (label, e))
        continue
    main = unix = enc = None
    for c, cs, o in cmds_of(b):
        mc = c & 0x7FFFFFFF
        if mc == 0x28 and cs >= 24:
            main = rd(b, o + 8, "<QQ")
        elif c == 0x5:
            unix = True
        elif mc == 0x2C and cs >= 24:
            enc = rd(b, o + 8, "<III")
        elif mc == 0x22 and cs >= 20 and c & 0x80000000 == 0:
            enc = rd(b, o + 8, "<II") + (0,)
    print("  %s  LC_MAIN=%s  LC_UNIXTHREAD=%s  encryption(cryptoff,cryptsize,cryptid)=%s"
          % (label, ("entryoff=0x%x stacksize=0x%x" % main) if main else None, unix, enc))

print()
print("== built IPA Info.plist special keys ==")
KEYS = ["MinimumOSVersion", "DTPlatformVersion", "DTSDKName", "DTSDKBuild", "DTXcode", "DTXcodeBuild",
        "DTCompiler", "BuildMachineOSBuild", "UIRequiredDeviceCapabilities", "UILaunchStoryboardName",
        "UILaunchStoryboardDefinitions", "UILaunchImages", "UIApplicationSceneManifest", "UISceneConfigurations",
        "CFBundleIconName", "NSUserActivityTypes", "UIViewControllerBasedStatusBarAppearance",
        "LSMinimumSystemVersion", "UIStatusBarStyle", "CFBundleSupportedPlatforms", "UISupportedInterfaceOrientations",
        "CFBundleExecutable", "CFBundleIdentifier", "CFBundleIconFiles", "UIRequiresFullScreen", "CFBundlePackageType",
        "UIStatusBarHidden", "UIApplicationSupportsIndirectInputEvents", "UIFileSharingEnabled", "CFBundleIcons",
        "CFBundleIcons~ipad", "CFBundleShortVersionString", "CFBundleVersion", "CFBundleDevelopmentRegion"]
z = zipfile.ZipFile(IPA)
for member, what in [("Payload/Phigros.app/Info.plist", "app"),
                     ("Payload/Phigros.app/Frameworks/UnityFramework.framework/Info.plist", "framework")]:
    try:
        pl = plistlib.loads(z.read(member))
    except KeyError:
        print("  %s : MISSING" % member)
        continue
    print(" -- %s : %s" % (what, member))
    for k in KEYS:
        if k in pl:
            v = pl[k]
            if isinstance(v, (bytes, bytearray)):
                v = "<%d bytes>" % len(v)
            print("      %-38s = %r" % (k, v))
    extra = [k for k in pl if k not in KEYS]
    print("      other keys (%d): %s" % (len(extra), extra[:12]))

print()
print("== iOS-13+ / post-iOS-12 API references inside patched Mach-Os ==")
PROBE = [b"UIApplicationSceneManifest", b"UISceneConfiguration", b"UISceneSession", b"UIWindowScene",
         b"UISceneDelegate", b"UISceneActivationState", b"UIStatusBarManager", b"UICollectionLayoutListConfiguration",
         b"UIListContentConfiguration", b"UIContextMenuInteraction", b"UIAction", b"UIMenu", b"UIMenuElement",
         b"systemBackgroundColor", b"NSDiffableDataSourceSnapshot", b"SwiftUI", b"AppIntent", b"AppShortcut",
         b"NSUserActivity", b"INIntent", b"CPTemplateApplicationScene", b"UISceneWillConnectNotification",
         b"UIMainStoryboardFile", b"UIApplicationSupportsMultipleScenes", b"UISceneConnectionOptions",
         b"UIWindowSceneGeometryPreferences", b"NSPrivacyCollectedDataTypes", b"UIFontTextStyleExtraLargeTitle"]
for label, p in BINS[:4]:
    b = open(p, "rb").read()
    hits = [(t.decode(), len(re.findall(re.escape(t), b))) for t in PROBE if t in b]
    print("  %s : %d/%d probe strings present" % (label, len(hits), len(PROBE)))
    if hits:
        print("     %s" % ", ".join("%s x%d" % h for h in hits))
    # objective-C class-name section listing
    objs = [x.decode("utf-8", "replace") for x in re.findall(rb"UI[A-Za-z]{3,40}", b[:0])]
    print("     superclass/class-name table probe: %s" %
          (", ".join(sorted({x.decode() for x in re.findall(rb"UI[A-Z][A-Za-z]+", b) if b"Scene" in x or b"Action" in x or b"Menu" in x or b"Content" in x}))[:600] or "none"))
