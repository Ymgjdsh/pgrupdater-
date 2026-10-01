"""Regression tests for the iOS 14 launch failure reported on 2026-10-01."""
import struct
import tempfile
import unittest
from pathlib import Path

from fix_build_version import repair
from verify_ios14 import Checker
from ips import parse_any


def sample(ntools=0, records=1, tool=3):
    size = 24 + 8 * records
    header = struct.pack("<8I", 0xFEEDFACF, 0x100000C, 0, 2, 1, size, 0, 0)
    cmd = struct.pack("<6I", 0x32, size, 2, 0xC0000, 0xC0400, ntools)
    return header + cmd + struct.pack("<2I", tool, 0x4CE0100) * records


class BuildVersionTests(unittest.TestCase):
    def test_repairs_only_count_and_is_idempotent(self):
        original = sample()
        result, changes = repair(original)
        self.assertEqual([i for i,(a,b) in enumerate(zip(original,result)) if a != b], [52])
        self.assertEqual(changes[0]["new_ntools"], 1)
        self.assertEqual(repair(result), (result, []))

    def test_preserves_valid_zero_one_and_two_records(self):
        for count in (0, 1, 2):
            with self.subTest(count=count):
                original = sample(ntools=count, records=count)
                self.assertEqual(repair(original), (original, []))

    def test_refuses_unrecognized_malformed_commands(self):
        for original in (sample(ntools=2), sample(tool=99), sample()[:-1], b"PK"):
            with self.subTest(original=original):
                with self.assertRaises(ValueError):
                    repair(original)

    def test_checker_reports_device_message_and_handles_short_command(self):
        fixed, _ = repair(sample())
        short = bytearray(sample())
        struct.pack_into("<I", short, 36, 16)
        for data, rejects in ((sample(), True), (fixed, False), (bytes(short), True)):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory)/"macho"
                path.write_bytes(data)
                checker = Checker(str(path)); checker.run()
                # This minimal fixture has no segments; isolate the version rule.
                self.assertEqual(any(msg == "LC_BUILD_VERSION load command size wrong"
                                     for _, msg in checker.fails), rejects)

    def test_recognizes_ios14_legacy_ips_body(self):
        report = ('{"app_name":"Phigros"}\nIncident Identifier: test\n'
                  'Exception Type: EXC_CRASH (SIGABRT)\n'
                  'Termination Description: DYLD, LC_BUILD_VERSION load command size wrong\n')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"report.ips"
            path.write_text(report, encoding="utf-8")
            header, data = parse_any(path)
            self.assertEqual(header["app_name"], "Phigros")
            self.assertIn("LC_BUILD_VERSION load command size wrong", data["_legacy_text"])


if __name__ == "__main__":
    unittest.main()
