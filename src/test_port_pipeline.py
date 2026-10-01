"""Pipeline plumbing tests; these do not simulate a full Unity launch."""
import os
import plistlib
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import port_to_ios12 as port

ROOT = Path(__file__).resolve().parent.parent


class PipelineTests(unittest.TestCase):
    def test_required_weak_list_is_shipped(self):
        weak = Path(port.DEFAULT_WEAK_FILE)
        self.assertTrue(weak.is_file())
        self.assertTrue(weak.read_text(encoding="utf-8").strip())

    def test_missing_weak_list_fails_before_opening_ipa(self):
        with tempfile.TemporaryDirectory() as folder:
            args = ["port_to_ios12.py", str(Path(folder)/"source.ipa"),
                    "--weak-file", str(Path(folder)/"missing.txt")]
            with patch.object(sys, "argv", args):
                with self.assertRaisesRegex(SystemExit, "weak-import list missing"):
                    port.main()

    def test_success_without_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(SystemExit, "without producing"):
                port.sh([sys.executable, "-c", "pass"], str(Path(folder)/"missing"))

    def test_stale_output_is_rejected_without_overwriting(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/"old-output"
            target.write_bytes(b"preserve")
            with self.assertRaisesRegex(SystemExit, "stale stage output"):
                port.sh([sys.executable, "-c", "pass"], str(target))
            self.assertEqual(target.read_bytes(), b"preserve")

    def test_relative_paths_survive_child_working_directory(self):
        pristine = ROOT/"reference/binaries/Phigros-4.0.0-pristine"
        known = ROOT/"src/analysis_v20/Phigros"
        if not pristine.exists() or not known.exists():
            self.skipTest("requires original and checked v20 main executable fixtures")
        original_convert = port.convert_image

        def convert_for_path_test(src, dst, framework, weak_file, no_quit_patch=False):
            if framework:
                # Small valid Mach-O fixture stands in for the framework here.
                # This test covers orchestration/packaging, not framework patches.
                shutil.copyfile(known, dst)
            else:
                original_convert(src, dst, framework, weak_file, no_quit_patch)

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root/"input.ipa"
            info = plistlib.dumps({"CFBundleExecutable": "Phigros",
                                  "CFBundleIdentifier": "games.Pigeon.Phigros",
                                  "MinimumOSVersion": "15.0"})
            with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(port.MAIN, pristine.read_bytes())
                archive.writestr(port.FRAME, pristine.read_bytes())
                archive.writestr(port.PLIST, info)
                archive.writestr(port.FWPLIST, info)
                archive.writestr(port.APP + "/fixture.txt", b"keep me")
            previous_cwd = os.getcwd()
            try:
                os.chdir(root)
                args = ["port_to_ios12.py", "input.ipa", "output.ipa", "--workdir", "work"]
                with patch.object(sys, "argv", args), patch.object(port, "convert_image", convert_for_path_test):
                    port.main()
            finally:
                os.chdir(previous_cwd)
            with zipfile.ZipFile(root/"output.ipa") as archive:
                self.assertIsNone(archive.testzip())
                self.assertEqual(archive.read(port.MAIN), known.read_bytes())
                self.assertEqual(archive.read(port.APP + "/fixture.txt"), b"keep me")
                self.assertEqual(plistlib.loads(archive.read(port.PLIST))["MinimumOSVersion"], "12.0")


if __name__ == "__main__":
    unittest.main()
