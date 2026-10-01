"""Verify relocation preserves live data and tolerates a rebuilt signature tail.

Usage: verify_relocation.py <before> <after>
The signature-tail scenario is a model, not a reproduction of a device signer.
"""
import struct
import sys

from chained2dyld import MachO, verify_classic
from verify_ios14 import Checker


def main(before, after):
    old = MachO(open(before, "rb").read())
    new = MachO(open(after, "rb").read())
    assert len(old.buf) == len(new.buf)
    assert old.segments == new.segments
    assert old.sections == new.sections
    linkstart = old.seg_by_name["__LINKEDIT"]["fileoff"]
    old_prefix = bytearray(old.buf[:linkstart])
    new_prefix = bytearray(new.buf[:linkstart])
    for a, b in zip(old.cmds, new.cmds):
        assert (a["cmd"], a["size"], a["off"]) == (b["cmd"], b["size"], b["off"])
        if a["cmd"] in (0x1D, 0x22, 0x80000022):
            start, end = a["off"] + 8, a["off"] + a["size"]
            old_prefix[start:end] = new_prefix[start:end]
    assert old_prefix == new_prefix, "code/data changed outside relocation fields"

    sym = old.lc(0x2)[0]["off"]
    sy, ns, st, ss = struct.unpack_from("<4I", old.buf, sym + 8)
    dysym = old.lc(0xB)[0]["off"]
    ind, count = struct.unpack_from("<2I", old.buf, dysym + 56)
    starts = old.lc(0x26)[0]["off"]
    fs, size = struct.unpack_from("<2I", old.buf, starts + 8)
    for off, length in ((sy, ns * 16), (st, ss), (ind, count * 4), (fs, size)):
        assert old.buf[off:off + length] == new.buf[off:off + length]

    a = verify_classic(before)
    b = verify_classic(after)
    assert a["rebase"] == b["rebase"]
    assert a["bind"] == b["bind"]
    assert a["export_size"] == b["export_size"]
    size = a["export_size"]
    assert old.buf[a["export_off"]:a["export_off"] + size] == new.buf[b["export_off"]:b["export_off"] + size]
    print("PASS: code/data, symbol tables, function starts, fixups and export trie preserved")

    # Model rebuilding the signature at the legacy SuperBlob location with a
    # 768 KB slot. This tests the exact boundary failure seen in the syslog.
    legacy_slot = st + ss
    assert old.buf[legacy_slot:legacy_slot + 4] == bytes.fromhex("fade0cc0")
    for path, m, slot in ((before, old, legacy_slot),
                          (after, new, struct.unpack_from("<I", new.buf, new.lc(0x1D)[0]["off"] + 8)[0])):
        end = slot + 0xC0000
        checker = Checker(path)
        data = bytearray(m.buf[:end])
        le = m.seg_by_name["__LINKEDIT"]
        struct.pack_into("<Q", data, le["lc_off"] + 48, end - linkstart)
        struct.pack_into("<II", data, m.lc(0x1D)[0]["off"] + 8, slot, 0xC0000)
        checker.buf = bytes(data)
        checker.run()
        if path == before:
            assert any("dyld rebase info overruns __LINKEDIT" in msg for _, msg in checker.fails)
            print("PASS: legacy signature-tail model reproduces the logged rebase overrun")
        else:
            assert not checker.fails, checker.fails
            print("PASS: relocated image passes iOS 14 checks with the rebuilt signature tail")


if __name__ == "__main__":
    main(*sys.argv[1:])
