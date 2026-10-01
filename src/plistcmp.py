#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compare launch-relevant Info.plist keys between several IPAs."""
import plistlib
import sys
import zipfile

KEYS = ["CFBundleIdentifier", "CFBundleExecutable", "CFBundleShortVersionString", "CFBundleVersion",
        "MinimumOSVersion", "DTPlatformVersion", "DTSDKName", "DTSDKBuild", "DTXcode", "DTXcodeBuild",
        "DTCompiler", "BuildMachineOSBuild", "UIRequiredDeviceCapabilities", "UILaunchStoryboardName",
        "UILaunchStoryboardDefinitions", "UILaunchImages", "UIApplicationSceneManifest",
        "UISceneConfigurations", "CFBundleIconName", "CFBundleIcons", "CFBundleIcons~ipad",
        "NSUserActivityTypes", "LSMinimumSystemVersion", "LSRequiresIPhoneOS", "UIStatusBarStyle",
        "UIViewControllerBasedStatusBarAppearance", "UIRequiredDeviceCapabilities", "UIUserInterfaceStyle",
        "UIApplicationSupportsIndirectInputEvents", "CFBundleSupportedPlatforms", "UIRequiresFullScreen",
        "CADisableMinimumFrameDurationOnPhone", "UISupportedInterfaceOrientations~ipad", "CFBundlePackageType"]


def dump(path, label):
    z = zipfile.ZipFile(path)
    pl = None
    fw = None
    for n in z.namelist():
        if n.endswith(".app/Info.plist"):
            pl = plistlib.loads(z.read(n))
        if n.endswith("UnityFramework.framework/Info.plist"):
            fw = plistlib.loads(z.read(n))
    print("=" * 100)
    print("%s  (%s)" % (label, path))
    print("=" * 100)
    for k in KEYS:
        if pl is not None and k in pl:
            print("  app  %-46s %r" % (k, pl[k]))
    for k in KEYS:
        if fw is not None and k in fw:
            print("  fw   %-46s %r" % (k, fw[k]))
    if pl is not None:
        extra = [k for k in pl if k.startswith(("UI", "CFBundleIcon", "LS", "NS")) and k not in KEYS]
        print("  app other UI/CF/LS/NS keys: %s" % sorted(extra))


for a in sys.argv[1:]:
    dump(a, "IPA")
