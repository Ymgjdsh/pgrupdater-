"""Build both portable executables with identical shared runtime dependencies."""
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ("port_gui.py", "port_worker.py", "runtime_profiles.py", "port_to_ios12.py", "chained2dyld.py",
           "fix_classic_segments.py", "verify_ios14.py", "add_sig_reserve.py",
           "strip_legacy_version.py", "canonicalize_linkedit.py", "relocate_streams.py",
           "clear_codesig.py", "patch_crashret.py", "patch_v12.py", "patch_v13.py",
           "patch_v14.py", "rebind_avfaudio.py", "patch_ipa.py")


def main():
    staging = ROOT / "portable_build/src"
    staging.mkdir(parents=True, exist_ok=True)
    for name in SCRIPTS:
        shutil.copyfile(ROOT / "src" / name, staging / name)
    (staging / "report").mkdir(exist_ok=True)
    shutil.copyfile(ROOT / "src/report/weak.txt", staging / "report/weak.txt")
    options = ["--noconfirm", "--clean", "--onedir", "--hidden-import", "plistlib",
               "--hidden-import", "dataclasses", "--hidden-import", "uuid",
               "--hidden-import", "mmap", "--add-data", str(staging) + ";src"]
    for name, entry, mode in (("PhigrosPortGUI", "port_gui.py", "--windowed"),
                              ("PhigrosPortWorker", "port_worker.py", "--console")):
        subprocess.run([sys.executable, "-m", "PyInstaller", *options, mode, "--name", name,
                        str(staging / entry)], cwd=ROOT, check=True)
    destination = ROOT / "portable/PhigrosPortGUI"
    # Never leave a stale worker or script in a newly distributed folder.
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(ROOT / "dist/PhigrosPortGUI", destination)
    shutil.copytree(ROOT / "dist/PhigrosPortWorker/_internal", destination / "_internal", dirs_exist_ok=True)
    shutil.copyfile(ROOT / "dist/PhigrosPortWorker/PhigrosPortWorker.exe",
                    destination / "PhigrosPortWorker.exe")
    shutil.copyfile(ROOT / "docs/GUI使用说明.txt", destination / "使用说明.txt")
    package = ROOT / "portable/PhigrosPortGUI.zip"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(destination.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(destination.parent))
    print("Built:", destination)
    print("Packaged:", package)


if __name__ == "__main__":
    main()
