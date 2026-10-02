"""ZIP signatures in opaque game data must not be mistaken for records."""
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import patch_ipa as pack


class ArchiveTests(unittest.TestCase):
    def archive(self, comment=b""):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            z.writestr("game.data", b"prefixPK\x06\x07suffix")
            z.writestr("replace.me", b"old")
            z.comment = comment
        return out.getvalue()

    def test_signature_in_payload_and_comment_is_not_zip64(self):
        entries, *_ = pack.parse_central(self.archive(b"PK\x06\x07"))
        self.assertEqual([e["name"] for e in entries], ["game.data", "replace.me"])

    def test_fake_eocd_inside_comment_is_ignored(self):
        entries, *_ = pack.parse_central(self.archive(b"PK\x05\x06" + bytes(24)))
        self.assertEqual(len(entries), 2)

    def test_actual_zip64_locator_is_rejected(self):
        raw = self.archive()
        locator = struct.pack("<IIQI", 0x07064B50, 0, 0, 1)
        with self.assertRaisesRegex(SystemExit, "ZIP64 locator"):
            pack.parse_central(raw[:-22] + locator + raw[-22:])

    def test_repack_preserves_payload_containing_signature(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            source, output = folder / "in.ipa", folder / "out.ipa"
            source.write_bytes(self.archive())
            replacement = folder / "new.bin"
            replacement.write_bytes(b"replacement")
            spec = folder / "spec.json"
            spec.write_text(json.dumps({"replace": {"replace.me": str(replacement)}}))
            result = subprocess.run([sys.executable, pack.__file__, str(source), str(output), str(spec)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            with zipfile.ZipFile(output) as z:
                self.assertIsNone(z.testzip())
                self.assertEqual(z.read("game.data"), b"prefixPK\x06\x07suffix")
                self.assertEqual(z.read("replace.me"), b"replacement")


if __name__ == "__main__":
    unittest.main()
