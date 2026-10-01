"""Regression coverage for the v20 iOS14 framework load failure."""
import struct
import unittest
from chained2dyld import MachO
from fix_classic_segments import repair, streams, validate, walk_stream


def sample():
    commands = []
    for name, vm, fileoff, prot, section in (
            ("__TEXT", 0, 0, 5, "__text"),
            ("__DATA", 0x1000, 0x1000, 3, "__data"),
            ("__LINKEDIT", 0x2000, 0x3000, 1, None),
            ("__DATA_METHLIST", 0x4000, 0x2000, 3, "__objc_methlist")):
        raw = bytearray(struct.pack("<II16sQQQQiiII", 0x19, 152 if section else 72,
                                   name.encode(), vm, 0x1000, fileoff, 0x1000, prot, prot, bool(section), 0))
        if section:
            raw += struct.pack("<16s16sQQIIIIIIII", section.encode(), name.encode(),
                               vm + 0x800, 0x100, fileoff + 0x800, 3, 0, 0, 0, 0, 0, 0)
        commands.append(bytes(raw))
    rebase = b"\x11\x23\x24\x51\0"
    bind = b"\x10\x40_t$\0\x51\x73\x74\x90\0"
    weak = b"\x40_weak\0\x73\x40\x90\0"
    lazy = b"\x10\x40_lazy\0\x73\x50\x90\0\x73\x60\x90\0"
    payloads = [rebase, bind, weak, lazy]
    offsets = []
    cursor = 0x3000
    for stream in payloads:
        offsets += [cursor, len(stream)]
        cursor += len(stream)
    commands.append(struct.pack("<12I", 0x80000022, 48, *offsets, 0, 0))
    header = struct.pack("<8I", 0xFEEDFACF, 0x100000C, 0, 6, len(commands),
                         sum(map(len, commands)), 0, 0)
    out = bytearray(0x4000)
    out[:len(header)] = header
    out[32:32 + sum(map(len, commands))] = b"".join(commands)
    out[0x3000:cursor] = b"".join(payloads)
    struct.pack_into("<Q", out, 0x2024, 0x888)
    return out


def semantics(data):
    m = MachO(data)
    return [(kind, m.segments[row[0]]["name"], m.segments[row[0]]["vmaddr"] + row[1], *row[2:])
            for kind, _, stream in streams(m) for row in walk_stream(stream, kind)]


class SegmentTests(unittest.TestCase):
    def test_old_failure_and_new_layout_semantics(self):
        before = sample()
        with self.assertRaisesRegex(ValueError, "rebase segment index 3 too large"):
            validate(MachO(before))
        after, report = repair(before)
        self.assertEqual(validate(MachO(after)), {"rebase": 1, "bind": 1, "weak_bind": 1, "lazy_bind": 2})
        self.assertEqual(semantics(before), semantics(after))
        self.assertEqual(len(before), len(after))
        self.assertEqual(before[0x1000:0x3000], after[0x1000:0x3000])
        self.assertEqual(report["segment_map"], {0: 0, 1: 1, 3: 2, 2: 3})
        self.assertEqual(report["new_linkedit_vm"], 0x8000)
        self.assertEqual(len(report["remapped_opcodes"]), 5)
        self.assertEqual(repair(after)[0], after)
        self.assertEqual(repair(after)[1]["remapped_opcodes"], [])

    def test_operands_and_symbols_are_not_mistaken_for_opcodes(self):
        before = sample()
        after, report = repair(before)
        changed = [i for i in range(0x3000, 0x4000) if before[i] != after[i]]
        self.assertEqual(changed, [c["file_offset"] for c in report["remapped_opcodes"]])
        self.assertIn(b"_t$\0", after)
        self.assertIn(b"\x72\x74\x90", after)
        self.assertIn(b"\x22\x24\x51", after)

    def test_rebase_pointer_into_linkedit_rejected(self):
        before = sample()
        struct.pack_into("<Q", before, 0x2024, 0x2200)
        with self.assertRaisesRegex(ValueError, "pointer targets it"):
            repair(before)

    def test_linkedit_fixup_rejected_instead_of_remapped(self):
        before = sample()
        before[0x3001] = 0x22
        with self.assertRaisesRegex(ValueError, "invalid fixup segment 2"):
            repair(before)

    def test_all_rebase_repeat_and_add_opcodes(self):
        stream = bytes.fromhex("11 21 00 51 30 08 41 60 02 70 08 80 02 08 00")
        self.assertEqual([x[1] for x in walk_stream(stream, "rebase")], [0, 24, 32, 40, 56, 72])

    def test_bind_repeats_addend_and_special_ordinal(self):
        stream = bytes.fromhex("3e 40 5f 66 00 51 60 7f 71 00 90 a0 08 b1 c0 02 08 00")
        rows = list(walk_stream(stream, "bind"))
        self.assertEqual([x[1] for x in rows], [0, 8, 24, 40, 56])
        self.assertTrue(all(row[3:6] == (-2, b"_f", -1) for row in rows))

    def test_truncated_unknown_and_threaded_streams_fail_closed(self):
        for kind, stream in (("rebase", b"\x21\x80"), ("bind", b"\x40abc"),
                             ("bind", b"\xd0"), ("rebase", b"\xf0"),
                             ("lazy_bind", b"\x51"), ("bind", b"\0\x74")):
            with self.subTest(kind=kind, stream=stream), self.assertRaises(ValueError):
                list(walk_stream(stream, kind))

    def test_invalid_fixup_bounds_and_permissions(self):
        valid, _ = repair(sample())
        m = MachO(valid)
        meta = m.seg_by_name["__DATA_METHLIST"]
        for field, value, message in ((32, 0x20, "beyond segment size"),
                                       (60, 1, "requires writable")):
            broken = bytearray(valid)
            struct.pack_into("<Q" if field == 32 else "<I", broken, meta["lc_off"] + field, value)
            with self.assertRaisesRegex(ValueError, message):
                validate(MachO(broken))


if __name__ == "__main__":
    unittest.main()
