"""Reject unknown layouts and mismatched patch sites before writing bytes."""
from types import SimpleNamespace
from uuid import UUID
import unittest
from runtime_profiles import PROFILES, profile_for, require_bytes
from port_to_ios12 import check_framework_profile


class ProfileTests(unittest.TestCase):
    def image(self, identity):
        return SimpleNamespace(lc=lambda _: [{"raw": bytes(8) + UUID(identity).bytes}])

    def test_known_builds_select_distinct_runtime_sites(self):
        profiles = [profile_for(self.image(key)) for key in PROFILES]
        self.assertEqual(tuple(p.version for p in profiles), ("4.0.0", "4.0.1", "4.0.3"))
        self.assertEqual(len({p.quit_sites for p in profiles}), len(profiles))
        self.assertEqual(len({p.availability_entry for p in profiles}), len(profiles))

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

    def test_ipa_version_must_match_framework_profile(self):
        import struct
        from uuid import UUID
        identity = UUID("70f666eb-6f4e-325e-9e8a-75b568085f26")
        header = struct.pack("<8I", 0xFEEDFACF, 0x100000C, 0, 6, 1, 24, 0, 0)
        header += struct.pack("<II", 0x1B, 24) + identity.bytes
        self.assertEqual(check_framework_profile(header, "4.0.3").version, "4.0.3")
        with self.assertRaisesRegex(ValueError, "拒绝混用补丁"):
            check_framework_profile(header, "4.0.1")


if __name__ == "__main__":
    unittest.main()
