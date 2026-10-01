#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify the v4 (LC_CODE_SIGNATURE tail-reserve) packages against v3b.

usage: python verify_v4.py <v3b.ipa> <v4.ipa>

Checks, per Mach-O member:
  * starts with MH_MAGIC_64 and parses to the same ncmds/sizeofcmds
  * LC_CODE_SIGNATURE points at a page-aligned tail region, size == reserve
  * the reserve is entirely zero
  * __LINKEDIT filesize/vmsize cover the new EOF and stay page-aligned
  * every byte before the reserve is identical to v3b except the two command
    field groups (LC_CODE_SIGNATURE.dataoff/datasize, __LINKEDIT filesize/vmsize)
"""
import struct
import sys
import zipfile

MEMBERS = [
    "Payload/Phigros.app/Phigros",
    "Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework",
]
LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT_64 = 0x19


def align_up(v, a):
    return (v + a - 1) & ~(a - 1)


def load(path, member):
    return zipfile.ZipFile(path).read(member)


def parse(buf):
    magic, _ct, _cs, _ft, ncmds, sizeofcmds, _fl, _r = struct.unpack_from("<8I", buf, 0)
    assert magic == 0xFEEDFACF, "bad magic %s" % hex(magic)
    cs = le = None
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmd == LC_CODE_SIGNATURE:
            cs = off
        elif cmd == LC_SEGMENT_64 and bytes(buf[off + 8:off + 24]).rstrip(b"\0") == b"__LINKEDIT":
            le = off
        off += cmdsize
    return ncmds, sizeofcmds, cs, le


def main():
    v3b, v4 = sys.argv[1], sys.argv[2]
    fails = 0
    for member in MEMBERS:
        a = load(v3b, member)
        b = load(v4, member)
        name = member.rsplit("/", 1)[-1]
        n_a, s_a, cs_a, le_a = parse(a)
        n_b, s_b, cs_b, le_b = parse(b)
        print("== %s  v3b %d bytes -> v4 %d bytes" % (name, len(a), len(b)))
        checks = []
        checks.append(("ncmds/sizeofcmds unchanged", (n_a, s_a) == (n_b, s_b)))
        dataoff, datasize = struct.unpack_from("<II", b, cs_b + 8)
        vmaddr_l, vmsize_l, fileoff_l, filesize_l = struct.unpack_from("<4Q", b, le_b + 24)
        r_dataoff, r_datasize = struct.unpack_from("<II", a, cs_a + 8)
        checks.append(("v3b cs was zeroed", (r_dataoff, r_datasize) == (0, 0)))
        checks.append(("dataoff page aligned", dataoff % 0x1000 == 0))
        checks.append(("dataoff == align_up(old EOF)", dataoff == align_up(len(a), 0x1000)))
        checks.append(("reserve reaches new EOF", dataoff + datasize == len(b)))
        checks.append(("reserve all zero", b[dataoff:] == b"\0" * (len(b) - dataoff)))
        checks.append(("vmsize page aligned >= filesize",
                       vmsize_l % 0x1000 == 0 and vmsize_l >= filesize_l))
        checks.append(("__LINKEDIT ends at EOF", fileoff_l + filesize_l == len(b)))
        checks.append(("tail padding+reserve all zero", b[len(a):] == b"\0" * (len(b) - len(a))))
        # allow exactly the command-field diffs
        allowed = set()
        for i in range(8):
            allowed.add(cs_b + 8 + i)
        for i in range(32):
            allowed.add(le_b + 24 + i)
        diffs = [i for i in range(min(dataoff, len(a))) if a[i] != b[i]]
        checks.append(("only command fields differ (%d diff bytes)" % len(diffs),
                       set(diffs) <= allowed))
        # everything before the reserve is the v3b payload, ignoring the fields we rewrote
        same = all(a[i] == b[i] for i in range(len(a)) if i not in allowed)
        checks.append(("all other payload bytes identical to v3b", same))
        for label, ok in checks:
            print("   %s  %s" % ("PASS" if ok else "FAIL", label))
            if not ok:
                fails += 1
        print("   CS=(%s,%s)  __LINKEDIT vmaddr=%s vmsize=%s fileoff=%s filesize=%s"
              % (hex(dataoff), hex(datasize), hex(vmaddr_l), hex(vmsize_l),
                 hex(fileoff_l), hex(filesize_l)))
    print("\n%s" % ("ALL V4 CHECKS PASSED" if fails == 0 else "%d CHECK(S) FAILED" % fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
