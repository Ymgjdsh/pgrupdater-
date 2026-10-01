#!/usr/bin/env python3
"""Dump LC_DYLD_INFO(_ONLY) + the other __LINKEDIT commands and replay iOS 12 dyld's
monotonic link-edit validation (ImageLoaderMachO.cpp, dyld-635.2/655.1.1 lines 445-502).

    python dyldinfo.py <macho> [<macho> ...]
"""
import struct
import sys

LC_REQ_DYLD = 0x80000000
NAMES = {
    0x1: "LC_SEGMENT", 0x19: "LC_SEGMENT_64", 0x2: "LC_SYMTAB", 0xb: "LC_DYSYMTAB", 0xc: "LC_LOAD_DYLIB",
    0xd: "LC_ID_DYLIB", 0xe: "LC_LOAD_DYLINKER", 0x1b: "LC_UUID", 0x1d: "LC_CODE_SIGNATURE",
    0x1e: "LC_SEGMENT_SPLIT_INFO", 0x26: "LC_FUNCTION_STARTS", 0x29: "LC_DATA_IN_CODE",
    0x2b: "LC_SOURCE_VERSION", 0x2c: "LC_ENCRYPTION_INFO_64", 0x32: "LC_BUILD_VERSION",
    0x25: "LC_VERSION_MIN_IPHONEOS", 0x22: "LC_DYLD_INFO", 0x24: "LC_VERSION_MIN_MACOSX",
    LC_REQ_DYLD | 0x22: "LC_DYLD_INFO_ONLY",
}
FIELD = {"LC_CODE_SIGNATURE": ("dataoff", "datasize"),
         "LC_FUNCTION_STARTS": ("dataoff", "datasize"),
         "LC_DATA_IN_CODE": ("dataoff", "datasize")}


def load(p):
    with open(p, "rb") as fh:
        return bytearray(fh.read())


def cmds(b):
    ncmds, = struct.unpack_from("<I", b, 16)
    off = 32
    out = []
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", b, off)
        out.append((i, cmd, cmdsize, off))
        off += cmdsize
    return out


def main(paths):
    for p in paths:
        b = load(p)
        print("=" * 100)
        print(f"{p}  ({len(b)} bytes)")
        info = None
        le = None
        for i, cmd, cmdsize, off in cmds(b):
            name = NAMES.get(cmd, f"0x{cmd:x}")
            if cmd in (0x22, LC_REQ_DYLD | 0x22):
                f = struct.unpack_from("<10I", b, off + 8)
                info = dict(zip(("rebase_off", "rebase_size", "bind_off", "bind_size",
                                 "weak_bind_off", "weak_bind_size", "lazy_bind_off",
                                 "lazy_bind_size", "export_off", "export_size"), f))
                print(f"  [{i:2d}] {name}")
                for k, v in info.items():
                    print(f"        {k:15s} 0x{v:x} ({v})")
            elif cmd == 0x2:  # LC_SYMTAB
                symoff, nsyms, stroff, strsize = struct.unpack_from("<4I", b, off + 8)
                print(f"  [{i:2d}] {name}: symoff=0x{symoff:x} nsyms={nsyms} stroff=0x{stroff:x} strsize={strsize}")
            elif cmd == 0x1d and le is None:
                dataoff, datasize = struct.unpack_from("<II", b, off + 8)
                print(f"  [{i:2d}] {name}: dataoff=0x{dataoff:x} datasize=0x{datasize:x} ({datasize})")
            elif cmd == 0x19 and le is None:
                segname = b[off + 8:off + 24].rstrip(b"\0").decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", b, off + 24)
                if segname == "__LINKEDIT":
                    le = (vmaddr, vmsize, fileoff, filesize)
                    print(f"  [{i:2d}] __LINKEDIT: vmaddr=0x{vmaddr:x} vmsize=0x{vmsize:x} "
                          f"fileoff=0x{fileoff:x} filesize=0x{filesize:x}")
        if info is None or le is None:
            print("  (no LC_DYLD_INFO / __LINKEDIT)")
            continue

        # --- replay dyld's checks (dyld-655.1.1 ImageLoaderMachO.cpp:454-502) ---
        start = le[2]
        end = le[2] + le[3]
        offset = start
        verdict = "PASS: iOS 12 dyld accepts the link-edit layout"
        prev = "__LINKEDIT.fileoff"
        for key, sz_key, msg in (("rebase", "rebase_size", "dyld rebase info"),
                                 ("bind", "bind_size", "dyld bind info"),
                                 ("weak_bind", "weak_bind_size", "dyld weak bind info"),
                                 ("lazy_bind", "lazy_bind_size", "dyld lazy bind info"),
                                 ("export", "export_size", "dyld export info")):
            so, ss = info[key + "_off"], info[sz_key]
            if ss == 0:
                continue
            if so < offset:
                verdict = (f"FAIL: malformed mach-o image: {msg} overlaps {prev}\n"
                           f"      {key}_off=0x{so:x} < 0x{offset:x} (end of {prev})")
                break
            offset = so + ss
            if offset > end:
                verdict = f"FAIL: malformed mach-o image: {msg} overruns __LINKEDIT"
                break
            prev = msg
        print(f"  {verdict}")


if __name__ == "__main__":
    main(sys.argv[1:])
