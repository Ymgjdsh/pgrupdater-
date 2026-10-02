"""Reject unknown layouts and mismatched patch sites before writing bytes."""
from types import SimpleNamespace
from uuid import UUID
import unittest
from runtime_profiles import PROFILES, profile_for, require_bytes


class ProfileTests(unittest.TestCase):
    def image(self, identity):
        return SimpleNamespace(lc=lambda _: [{"raw": bytes(8) + UUID(identity).bytes}])

    def test_known_builds_select_distinct_runtime_sites(self):
        old, new = [profile_for(self.image(key)) for key in PROFILES]
        self.assertEqual((old.version, new.version), ("4.0.0", "4.0.1"))
        self.assertNotEqual(old.quit_sites, new.quit_sites)
        self.assertNotEqual(old.availability_entry, new.availability_entry)

    def test_unknown_build_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "Unsupported UnityFramework"):
            profile_for(self.image("00000000-0000-0000-0000-000000000000"))

    def test_missing_uuid_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "LC_UUID"):
            profile_for(SimpleNamespace(lc=lambda _: []))

    def test_bytes_guard_rejects_corruption_or_unmapped_site(self):
        image = SimpleNamespace(buf=bytearray(b"abcd"), foff=lambda va: 0 if va == 16 else None)
        self.assertEqual(require_bytes(image, 16, b"abcd", "test"), 0)
        with self.assertRaises(SystemExit):
            require_bytes(image, 16, b"abce", "test")
        with self.assertRaises(SystemExit):
            require_bytes(image, 32, b"abcd", "test")
        self.assertEqual(image.buf, b"abcd")


if __name__ == "__main__":
    unittest.main()
