#!/usr/bin/env python3
"""port_to_ios12.py - one-command port of a modern (Unity 2022.3) Phigros IPA to iOS 12.

Steps, all in a scratch dir:
  1. pull the 4 payload files we need out of the source IPA
  2. convert both Mach-O files: LC_DYLD_CHAINED_FIXUPS -> classic LC_DYLD_INFO_ONLY,
     fix minos/sdk, optionally RET-patch UnityEngine.Application.Quit, then apply
     the existing v11-v14 runtime patches to the framework in their original order
     Segment commands/indices are normalized by the converter: LINKEDIT last.
  3. apply the iOS 13/14 loader fixes: remove the duplicate legacy version command
     and relocate both images' classic link-edit streams ahead of the
     signature slot; reserve signer space in both images
  4. rewrite MinimumOSVersion / DTSDK* in the app and framework Info.plist
  5. rebuild the IPA byte-for-byte except those entries, dropping stale signatures

usage:
  python port_to_ios12.py <in.ipa> [out.ipa] [--workdir DIR] [--weak-file weak.txt]
                          [--no-quit-patch]
"""
import argparse, json, os, shutil, subprocess, sys, zipfile, plistlib, tempfile
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable or "python"

APP = "Payload/Phigros.app"
MAIN = f"{APP}/Phigros"
FRAME = f"{APP}/Frameworks/UnityFramework.framework/UnityFramework"
PLIST = f"{APP}/Info.plist"
FWPLIST = f"{APP}/Frameworks/UnityFramework.framework/Info.plist"

# (member in the IPA, filename in the scratch dir) - the two Info.plist files must
# NOT collide, so they get distinct local names.
PAYLOAD = [(MAIN, "Phigros"), (FRAME, "UnityFramework"),
           (PLIST, "app-Info.plist"), (FWPLIST, "framework-Info.plist")]

DROPS = [f"{APP}/_CodeSignature/", f"{APP}/SC_Info/",
         f"{APP}/Frameworks/UnityFramework.framework/_CodeSignature/",
         f"{APP}/Frameworks/UnityFramework.framework/SC_Info/"]

PLIST_CHANGES = {"MinimumOSVersion": "12.0", "DTPlatformVersion": "12.4",
                 "DTSDKName": "iphoneos12.4", "DTSDKBuild": "16G77"}

# These were previously applied only in incremental/manual builds. Keep their
# order: later patches depend on code caves and metadata created by earlier ones.
FRAMEWORK_PATCHES = ("rebind_avfaudio.py", "patch_crashret.py",
                     "patch_v12.py", "patch_v13.py", "patch_v14.py")
MAIN_CONVERSION_FLAGS = ["--no-avail-dispatch", "--no-avail-stubs",
                         "--no-window-shim"]
DEFAULT_WEAK_FILE = os.path.join(HERE, "report", "weak.txt")


def check_unencrypted_header(header, member):
    if len(header) < 32 or header[:4] != b"\xcf\xfa\xed\xfe":
        raise ValueError("unsupported input: expected thin arm64 Mach-O in " + member)
    if struct.unpack_from("<I", header, 4)[0] != 0x100000C:
        raise ValueError("unsupported CPU: expected arm64 in " + member)
    count, command_bytes = struct.unpack_from("<II", header, 16)
    end = 32 + command_bytes
    if end > len(header):
        raise ValueError("truncated Mach-O load commands in " + member)
    offset = 32
    for _ in range(count):
        if offset + 8 > end:
            raise ValueError("truncated load command in " + member)
        command, size = struct.unpack_from("<II", header, offset)
        if size < 8 or offset + size > end:
            raise ValueError("invalid load command size in " + member)
        if command in (0x21, 0x2C):
            if size < 20:
                raise ValueError("truncated encryption command in " + member)
            if struct.unpack_from("<I", header, offset + 16)[0]:
                raise ValueError("输入 IPA 仍有 App Store 加密（cryptid=1），当前工具只能转换已解密的 Phigros 4.0.0 IPA：" + member)
        offset += size


def sh(args, expected=None):
    print("+", " ".join(str(a) for a in args), flush=True)
    if expected and os.path.exists(expected):
        sys.exit(f"refusing stale stage output: {expected}")
    # The portable GUI relaunches this same executable as a worker, so it can
    # carry the conversion scripts without requiring a separate Python install.
    if os.environ.get("PHI_PORTABLE_WORKER") == "1":
        args = [PY, "--worker"] + args[1:]
    r = subprocess.run(args, cwd=HERE)
    if r.returncode != 0:
        sys.exit(f"FAILED: {args[0]} (exit {r.returncode})")
    if expected and (not os.path.isfile(expected) or os.path.getsize(expected) == 0):
        sys.exit(f"stage succeeded without producing a non-empty output: {expected}")


def convert_image(src, dst, framework, weak_file, no_quit_patch=False):
    def run(script, source, output, extra=()):
        sh([PY, os.path.join(HERE, script), source, output] + list(extra), expected=output)

    flags = (["--weak-file", weak_file] + ([] if no_quit_patch else ["--patch-quit"])) \
        if framework else MAIN_CONVERSION_FLAGS
    raw = dst + ".converted"
    run("chained2dyld.py", src, raw, flags)
    if framework:
        for i, script in enumerate(FRAMEWORK_PATCHES):
            patched = dst + ".runtime-%d" % i
            run(script, raw, patched)
            raw = patched
    reserved = dst + ".reserved"
    versioned = dst + ".versioned"
    run("add_sig_reserve.py", raw, reserved, ["0xC0000" if framework else "0x10000"])
    run("strip_legacy_version.py", reserved, versioned)
    if framework:
        # Canonical packing already places ALL live link-edit payloads. Avoid
        # first running the older, partial stream relocation on the framework.
        run("canonicalize_linkedit.py", versioned, dst)
    else:
        relocated = dst + ".relocated"
        run("relocate_streams.py", versioned, relocated)
        run("clear_codesig.py", relocated, dst)


def patch_plist(src, dst):
    with open(src, "rb") as source:
        raw = source.read()
    d = plistlib.loads(raw)
    for k, v in PLIST_CHANGES.items():
        if k in d:
            print(f"   {os.path.basename(src)}: {k} {d[k]!r} -> {v!r}")
            d[k] = v
    if "MinimumOSVersion" not in d:
        d["MinimumOSVersion"] = "12.0"
    with open(dst, "wb") as output:
        output.write(plistlib.dumps(
            d, fmt=plistlib.FMT_BINARY if raw[:8] == b"bplist00" else plistlib.FMT_XML,
            sort_keys=False))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ipa")
    ap.add_argument("out", nargs="?")
    ap.add_argument("--workdir", default=os.path.join(HERE, "portwork"))
    ap.add_argument("--weak-file", default=DEFAULT_WEAK_FILE)
    ap.add_argument("--no-quit-patch", action="store_true")
    a = ap.parse_args()

    # Child scripts run under src/. Resolve user paths in the invoking cwd
    # BEFORE changing cwd, otherwise root-relative IPA paths point elsewhere.
    a.ipa = os.path.abspath(a.ipa)
    a.weak_file = os.path.abspath(a.weak_file)
    out_ipa = os.path.abspath(a.out or os.path.splitext(a.ipa)[0] + "_iOS12.ipa")
    if os.path.normcase(out_ipa) == os.path.normcase(a.ipa):
        sys.exit("refusing to overwrite the source IPA")
    if os.path.exists(out_ipa):
        sys.exit(f"output already exists; choose a new output path: {out_ipa}")
    if not os.path.isfile(a.weak_file) or os.path.getsize(a.weak_file) == 0:
        sys.exit(f"required weak-import list missing or empty: {a.weak_file}")
    work_root = os.path.abspath(a.workdir)
    os.makedirs(work_root, exist_ok=True)
    wd = tempfile.mkdtemp(prefix="build-", dir=work_root)
    print("build directory:", wd, flush=True)

    print("[1/5] extracting payload from", a.ipa)
    with zipfile.ZipFile(a.ipa) as z:
        names = set(z.namelist())
        for n, _local in PAYLOAD:
            if n not in names:
                sys.exit(f"not a Phigros IPA: missing {n}")
        for n in (MAIN, FRAME):
            with z.open(n) as source:
                header = source.read(32)
                if len(header) == 32 and header[:4] == b"\xcf\xfa\xed\xfe":
                    size = struct.unpack_from("<I", header, 20)[0]
                    if size > 1 << 20:
                        sys.exit("unsupported Mach-O load-command size")
                    header += source.read(size)
            try:
                check_unencrypted_header(header, n)
            except ValueError as error:
                sys.exit(str(error))
        for n, local in PAYLOAD:
            dst = os.path.join(wd, local)
            with z.open(n) as f, open(dst, "wb") as o:
                shutil.copyfileobj(f, o, 1 << 20)
            print(f"   {n} -> {dst} ({os.path.getsize(dst)} B)")

    main_b = os.path.join(wd, "Phigros")
    frame_b = os.path.join(wd, "UnityFramework")
    info_p = os.path.join(wd, "app-Info.plist")
    fwinfo_p = os.path.join(wd, "framework-Info.plist")

    print("[2/5] converting Mach-O -> classic dyld info, minos 12.0")
    outputs = []
    for src, dst, framework in ((frame_b, frame_b + ".patched", True),
                                 (main_b, main_b + ".patched", False)):
        convert_image(src, dst, framework, a.weak_file, a.no_quit_patch)
        outputs.append(dst)

    print("[3/5] checking iOS 13/14 load-command compatibility")
    sh([PY, os.path.join(HERE, "verify_ios14.py")] + outputs)

    print("[4/5] patching Info.plist files")
    patch_plist(info_p, info_p + ".patched")
    patch_plist(fwinfo_p, fwinfo_p + ".patched")

    print("[5/5] rebuilding IPA (byte-copy of every other entry)")
    spec = {"replace": {FRAME: frame_b + ".patched",
                        MAIN: main_b + ".patched",
                        PLIST: info_p + ".patched",
                        FWPLIST: fwinfo_p + ".patched"},
            "drop_prefix": DROPS}
    spec_p = os.path.join(wd, "ipaspec.json")
    with open(spec_p, "w", encoding="utf-8") as spec_file:
        json.dump(spec, spec_file, indent=2, ensure_ascii=False)
    sh([PY, os.path.join(HERE, "patch_ipa.py"), a.ipa, out_ipa, spec_p], expected=out_ipa)

    print("\ndone ->", out_ipa, f"({os.path.getsize(out_ipa)} bytes)")
    print("install it with a re-signing tool (Sideloadly / AltStore), or on a jailbroken")
    print("device with AppSync Unified.  Requires iOS 12.2 or newer (Swift runtime).")
    print("Candidate only: passing offline checks does not establish device compatibility.")


if __name__ == "__main__":
    main()
