"""Regression coverage for the GUI accidentally spawning another GUI."""
import queue
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import port_gui as gui


class GuiTests(unittest.TestCase):
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
