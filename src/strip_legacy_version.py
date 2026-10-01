"""strip_legacy_version.py <in> <out> [--dry-run] [--allow-no-build]

Remove legacy LC_VERSION_MIN_* load commands (0x24 MACOSX, 0x25 IPHONEOS,
0x2F TVOS, 0x30 WATCHOS) from a 64-bit Mach-O that ALSO carries
LC_BUILD_VERSION (0x32).

Why: until iOS 12 the kernel (xnu-4903.221.2) has **no** LC_BUILD_VERSION case
in parse_machfile and ignores that command (its `default:` arm), reading the
platform/min-OS only from LC_VERSION_MIN_IPHONEOS.  From iOS 13 on
(xnu-7195.81.3) the kernel handles LC_BUILD_VERSION *and* LC_VERSION_MIN_* with a
single shared flag: a second version command of either kind makes
`load_version()` / the LC_BUILD_VERSION case return LOAD_BADMACHO
(mach_loader.c:2509-2511 and :1387-1390).  A main executable carrying both
commands therefore still spawns on iOS 12 but fails on iOS 13/14 with
EBADMACHO (POSIX 88, "Malformed Mach-o file") from launchd/posix_spawn --
before a single instruction of the image runs.

The edit touches only the load-command region [32, 32+sizeofcmds): the fields
ncmds/sizeofcmds are rewritten and the commands after each removed one are
shifted 16 bytes left, the freed tail inside the old command region is zeroed.
No segment, section, symbol or __LINKEDIT offset moves, so a classic
LC_DYLD_INFO_ONLY stream stays valid; only the code signature must be redone by
the signer.

usage:
  python strip_legacy_version.py out\\Phigros.v6 out\\Phigros.v7
  python strip_legacy_version.py out\\UnityFramework.v14raw out\\UnityFramework.v15raw
"""
import struct
import sys

LEGACY = {0x24: "LC_VERSION_MIN_MACOSX",
          0x25: "LC_VERSION_MIN_IPHONEOS",
          0x2F: "LC_VERSION_MIN_TVOS",
          0x30: "LC_VERSION_MIN_WATCHOS"}
LC_BUILD_VERSION = 0x32


def parse(buf):
    magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from("<IiiIIIII", buf, 0)
    assert magic == 0xFEEDFACF, hex(magic)
    cmds = []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        cmds.append((cmd, cmdsize, off))
        off += cmdsize
    assert off == 32 + sizeofcmds, "command walk %d != sizeofcmds end %d" % (off, 32 + sizeofcmds)
    return ftype, ncmds, sizeofcmds, cmds


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = set(a for a in sys.argv[1:] if a.startswith("--"))
    src, dst = args[0], args[1]
    dry = "--dry-run" in flags

    buf = bytearray(open(src, "rb").read())
    ftype, ncmds, sizeofcmds, cmds = parse(buf)
    print("%s: size %d ftype %d ncmds %d sizeofcmds %d" % (src, len(buf), ftype, ncmds, sizeofcmds))

    has_build = any(c[0] == LC_BUILD_VERSION for c in cmds)
    legacy = [(c, s, o) for (c, s, o) in cmds if c in LEGACY]
    for c, s, o in cmds:
        if c == LC_BUILD_VERSION:
            plat, minos, sdk = struct.unpack_from("<III", buf, o + 8)
            print("  [%3d] LC_BUILD_VERSION cmdsize %d platform %d minos %d.%d.%d sdk %d.%d.%d"
                  % (cmds.index((c, s, o)), s, plat, minos >> 16, (minos >> 8) & 0xFF, minos & 0xFF,
                     sdk >> 16, (sdk >> 8) & 0xFF, sdk & 0xFF))
    for c, s, o in legacy:
        ver, sdk = struct.unpack_from("<II", buf, o + 8)
        print("  [%3d] %-26s cmdsize %d version %d.%d.%d sdk %d.%d.%d"
              % (cmds.index((c, s, o)), LEGACY[c], s, ver >> 16, (ver >> 8) & 0xFF, ver & 0xFF,
                 sdk >> 16, (sdk >> 8) & 0xFF, sdk & 0xFF))

    if not legacy:
        print("no legacy LC_VERSION_MIN_* command -- nothing to do")
        if not dry:
            # Keep the post-processing pipeline idempotent when a future
            # converter stops emitting the duplicate command itself.
            open(dst, "wb").write(buf)
            print("copied %s (%d bytes)" % (dst, len(buf)))
        return
    if not has_build:
        print("WARNING: no LC_BUILD_VERSION -- removing the legacy command would leave the image "
              "without any version command; refusing (use --allow-no-build to override)")
        if "--allow-no-build" not in flags:
            return

    # rebuild the command region without the legacy commands
    out = bytearray()
    removed_bytes = 0
    for c, s, o in cmds:
        if c in LEGACY:
            removed_bytes += s
            continue
        out += buf[o:o + s]
    new_sizeofcmds = sizeofcmds - removed_bytes
    assert len(out) == new_sizeofcmds, (len(out), new_sizeofcmds)
    new_ncmds = ncmds - len(legacy)

    struct.pack_into("<II", buf, 16, new_ncmds, new_sizeofcmds)
    region = bytes(out) + b"\0" * (sizeofcmds - len(out))
    buf[32:32 + sizeofcmds] = region
    assert len(buf) == len(open(src, "rb").read())

    # diff report
    orig = open(src, "rb").read()
    diff = [i for i in range(min(len(orig), len(buf))) if orig[i] != buf[i]]
    ranges = []
    for i in diff:
        if ranges and i == ranges[-1][1] + 1:
            ranges[-1][1] = i
        else:
            ranges.append([i, i])
    print("removed %d command(s), %d bytes; ncmds %d -> %d, sizeofcmds %d -> %d"
          % (len(legacy), removed_bytes, ncmds, new_ncmds, sizeofcmds, new_sizeofcmds))
    print("changed %d byte(s) in %d range(s): %s"
          % (len(diff), len(ranges), ", ".join("0x%x-0x%x" % (a, b) for a, b in ranges[:12])))

    if dry:
        print("dry run, not written")
        return
    open(dst, "wb").write(buf)
    print("wrote %s (%d bytes)" % (dst, len(buf)))

    # verification pass
    buf2 = bytearray(open(dst, "rb").read())
    ftype2, n2, s2, cmds2 = parse(buf2)
    left = [(c, o) for (c, s, o) in cmds2 if c in LEGACY]
    builds = [(c, s, o) for (c, s, o) in cmds2 if c == LC_BUILD_VERSION]
    print("verify: ftype %d ncmds %d sizeofcmds %d; LC_BUILD_VERSION x%d; legacy LC_VERSION_MIN_* x%d %s"
          % (ftype2, n2, s2, len(builds), len(left), [LEGACY[c] for c, o in left]))
    assert len(left) == 0 and len(builds) == 1


main()
