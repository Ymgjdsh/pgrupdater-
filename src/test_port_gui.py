"""Regression coverage for the GUI accidentally spawning another GUI."""
import queue
import plistlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import port_gui as gui


class GuiTests(unittest.TestCase):
    def test_input_version_and_output_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "phigros.ipa"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("Payload/Phigros.app/Info.plist",
                                 plistlib.dumps({"CFBundleShortVersionString": "4.0.3", "MinimumOSVersion": "12.0"}))
                archive.writestr("Payload/Phigros.app/Phigros", b"main")
                archive.writestr("Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework", b"framework")
            self.assertEqual(gui.input_version(source), "4.0.3")
            gui.validate_output(source)

    def test_selecting_another_input_refreshes_only_automatic_output(self):
        class Var:
            def __init__(self, value=""):
                self.value = value

            def get(self):
                return self.value

            def set(self, value):
                self.value = value

        with tempfile.TemporaryDirectory() as folder:
            sources = []
            for version in ("4.0.1", "4.0.3"):
                source = Path(folder) / (version + ".ipa")
                with zipfile.ZipFile(source, "w") as archive:
                    archive.writestr("Payload/Phigros.app/Info.plist",
                                     plistlib.dumps({"CFBundleShortVersionString": version}))
                sources.append(source)
            app = object.__new__(gui.ConverterApp)
            app.input_var, app.output_var = Var(str(sources[0])), Var()
            app.input_info_var, app.status_var = Var(), Var()
            app.auto_output = None
            app.refresh_input()
            first = app.output_var.get()
            app.input_var.set(str(sources[1]))
            app.refresh_input()
            self.assertNotEqual(first, app.output_var.get())
            self.assertIn("4.0.3", app.input_info_var.get())
            app.output_var.set(str(Path(folder) / "custom.ipa"))
            app.input_var.set(str(sources[0]))
            app.refresh_input()
            self.assertTrue(app.output_var.get().endswith("custom.ipa"))

    def test_generic_input_name_includes_ipa_version(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "phigros.ipa"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("Payload/Phigros.app/Info.plist",
                                 plistlib.dumps({"CFBundleShortVersionString": "4.0.3"}))
            name = gui.ConverterApp.default_output(source).name
            self.assertTrue(name.startswith("phigros_4.0.3_iOS12_ported_"), name)

    def test_worker_preserves_exit_codes_and_prints_text_errors(self):
        with patch.object(gui.os, "chdir"), patch.object(sys, "argv"), \
             patch.object(sys, "path", list(sys.path)), patch.object(gui.runpy, "run_path") as run:
            for code in (None, 0, 2, "input rejected"):
                run.side_effect = SystemExit(code)
                with patch("builtins.print") as output:
                    self.assertEqual(gui.worker_main([__file__]), code if isinstance(code, int) else (0 if code is None else 1))
                    if isinstance(code, str):
                        output.assert_called_once_with(code, file=sys.stderr)

    def test_source_command_uses_python_and_frozen_command_uses_hidden_worker(self):
        args = tuple(Path(name) for name in ("script.py", "in.ipa", "out.ipa", "work"))
        with patch.object(sys, "frozen", False, create=True):
            self.assertEqual(gui.conversion_command(*args)[:3], [sys.executable, "-u", "script.py"])
        with tempfile.TemporaryDirectory() as folder:
            worker = Path(folder) / "PhigrosPortWorker.exe"
            worker.touch()
            with patch.object(sys, "executable", str(Path(folder) / "GUI.exe")), patch.object(sys, "frozen", True, create=True):
                self.assertEqual(gui.conversion_command(*args)[:3], [str(worker), "--worker", "script.py"])

    def test_missing_worker_produces_an_error_instead_of_a_gui(self):
        with patch.object(sys, "frozen", True, create=True), patch.object(gui.Path, "is_file", return_value=False):
            with self.assertRaises(FileNotFoundError):
                gui.conversion_command(*(Path(n) for n in ("script", "in", "out", "work")))

    def test_exit_zero_without_output_is_never_success(self):
        with tempfile.TemporaryDirectory() as folder:
            app = object.__new__(gui.ConverterApp)
            app.events = queue.Queue()
            with patch.object(gui, "conversion_command", return_value=[sys.executable, "-c", "print('worker started')"]):
                app.convert(Path(folder) / "in.ipa", Path(folder) / "out.ipa")
            events = list(app.events.queue)
            self.assertIn(("log", "worker started\n"), events)
            self.assertTrue(any(kind == "error" for kind, _ in events))
            self.assertFalse(any(kind == "done" and value == "0" for kind, value in events))

    def test_existing_but_invalid_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "out.ipa"
            with zipfile.ZipFile(output, "w") as archive:
                archive.writestr("placeholder", "x")
            with self.assertRaises(ValueError):
                gui.validate_output(output)


if __name__ == "__main__":
    unittest.main()
