#!/usr/bin/env python3
"""Compare live link-edit payloads before/after canonical packing."""
import struct
import sys

from chained2dyld import MachO, verify_classic


def read(path):
    b = open(path, "rb").read()
    n = struct.unpack_from("<I", b, 16)[0]
    out = {"buf": b, "streams": {}, "aux": {}, "sym": None,
           "indirect": None, "str": None, "link": None, "sig": None}
    off = 32
    for _ in range(n):
        cmd, size = struct.unpack_from("<II", b, off)
        if cmd == 0x19 and b[off + 8:off + 24].rstrip(b"\0") == b"__LINKEDIT":
            out["link"] = struct.unpack_from("<QQQQ", b, off + 24)
        elif cmd in (0x22, 0x80000022):
            vals = struct.unpack_from("<10I", b, off + 8)
            for name, o, s in zip(("rebase", "bind", "weak", "lazy", "export"), vals[::2], vals[1::2]):
                if s:
                    out["streams"][name] = (o, s, b[o:o + s])
        elif cmd == 0x26:
            o, s = struct.unpack_from("<II", b, off + 8)
            out["aux"]["function_starts"] = (o, s, b[o:o + s]) if s else None
        elif cmd == 0x29:
            o, s = struct.unpack_from("<II", b, off + 8)
            out["aux"]["data_in_code"] = (o, s, b[o:o + s]) if s else None
        elif cmd == 0x2:
            o, count, so, ss = struct.unpack_from("<4I", b, off + 8)
            out["sym"] = (o, count * 16, b[o:o + count * 16])
            out["str"] = (so, ss, b[so:so + ss])
        elif cmd == 0xB:
            io, count = struct.unpack_from("<2I", b, off + 56)
            out["indirect"] = (io, count * 4, b[io:io + count * 4]) if count else None
        elif cmd == 0x1D:
            out["sig"] = struct.unpack_from("<2I", b, off + 8)
        off += size
    return out


def main(before, after):
    a, z = read(before), read(after)
    assert len(a["buf"]) == len(z["buf"])
    assert a["link"] == z["link"]
    assert a["streams"].keys() == z["streams"].keys()
    for name in a["streams"]:
        assert a["streams"][name][2] == z["streams"][name][2], name
    for key in ("function_starts", "data_in_code"):
        av, zv = a["aux"].get(key), z["aux"].get(key)
        assert (av is None) == (zv is None), key
        if av is not None:
            assert av[1:] == zv[1:], key
    for key in ("sym", "indirect", "str"):
        assert a[key][2] == z[key][2], key
    ra, rz = verify_classic(before, verbose=False), verify_classic(after, verbose=False)
    assert ra["rebase"] == rz["rebase"]
    assert ra["bind"] == rz["bind"]
    assert a["buf"][ra["export_off"]:ra["export_off"] + ra["export_size"]] == \
           z["buf"][rz["export_off"]:rz["export_off"] + rz["export_size"]]
    assert z["sig"][0] == z["str"][0] + z["str"][1]
    print("PASS: segments, dyld fixups, auxiliary tables, symbols, strings and export trie preserved")
    print("      old signature boundary %#x -> new %#x" %
          (a["str"][0] + a["str"][1], z["sig"][0]))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify_canonical_linkedit.py <before> <after>")
    main(sys.argv[1], sys.argv[2])
