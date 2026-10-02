#!/usr/bin/env python3
"""Small Windows GUI for the bundled Phigros iOS compatibility converter."""
from __future__ import annotations

import os
import queue
import runpy
import shutil
import subprocess
import sys
import tempfile
import threading
import zipfile
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


def bundle_root() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))


def worker_main(argv: list[str]) -> int:
    """Run one bundled source script inside the current PyInstaller executable."""
    if not argv:
        print("worker: missing script", file=sys.stderr)
        return 2
    script = Path(argv[0])
    if not script.is_absolute() or not script.exists():
        script = bundle_root() / script
    script = script.resolve()
    source_root = script.parent
    sys.path.insert(0, str(source_root))
    os.chdir(source_root)
    sys.argv = [str(script)] + argv[1:]
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as error:
        if error.code is None:
            return 0
        if isinstance(error.code, int):
            return error.code
        print(error.code, file=sys.stderr)
        return 1
    return 0


def conversion_command(script: Path, source: Path, output: Path, workdir: Path) -> list[str]:
    if getattr(sys, "frozen", False):
        worker = Path(sys.executable).with_name("PhigrosPortWorker.exe")
        if not worker.is_file():
            raise FileNotFoundError("便携版缺少 PhigrosPortWorker.exe，请解压完整文件夹后重试。")
        return [str(worker), "--worker", str(script), str(source), str(output), "--workdir", str(workdir)]
    return [sys.executable, "-u", str(script), str(source), str(output), "--workdir", str(workdir)]


def validate_output(output: Path):
    if not output.is_file() or not output.stat().st_size:
        raise ValueError("转换进程退出了，但没有生成 IPA。")
    with zipfile.ZipFile(output) as archive:
        members = set(archive.namelist())
        for member in ("Payload/Phigros.app/Phigros", "Payload/Phigros.app/Info.plist",
                       "Payload/Phigros.app/Frameworks/UnityFramework.framework/UnityFramework"):
            if member not in members or not archive.getinfo(member).file_size:
                raise ValueError("输出 IPA 不完整：" + member)


class ConverterApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Phigros iOS 12+ 转换器")
        self.root.geometry("900x620")
        self.root.minsize(760, 520)
        self.root.configure(bg="#0f141b")
        self.events: queue.Queue[tuple[str, str]] = queue.Queue()
        self.running = False

        self.colors = {
            "bg": "#0f141b", "panel": "#171e27", "panel2": "#1c2530",
            "text": "#edf4f7", "muted": "#8b9aa4", "accent": "#6de7c5",
            "accent_active": "#8af0d3", "blue": "#8bd5ff", "line": "#2c3945",
        }
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("Dark.Horizontal.TProgressbar", troughcolor=self.colors["panel2"],
                        background=self.colors["accent"], bordercolor=self.colors["panel2"],
                        lightcolor=self.colors["accent"], darkcolor=self.colors["accent"])

        frame = tk.Frame(root, bg=self.colors["bg"], padx=28, pady=24)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(3, weight=1)

        header = tk.Frame(frame, bg=self.colors["bg"])
        header.grid(row=0, column=0, sticky="ew", pady=(0, 22))
        header.columnconfigure(0, weight=1)
        tk.Label(header, text="PHIGROS PORT", bg=self.colors["bg"], fg=self.colors["accent"],
                 font=("Segoe UI", 10, "bold"), anchor="w").grid(row=0, column=0, sticky="w")
        tk.Label(header, text="iOS 12+ compatibility converter", bg=self.colors["bg"], fg=self.colors["text"],
                 font=("Segoe UI", 21, "bold"), anchor="w").grid(row=1, column=0, sticky="w", pady=(4, 0))
        tk.Label(header, text="支持 Phigros 4.0.0 / 4.0.1 破壳 IPA · 4.0.1 待真机验证", bg=self.colors["bg"],
                 fg=self.colors["muted"], font=("Segoe UI", 10), anchor="w").grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.status_var = tk.StringVar(value="等待选择 IPA")
        tk.Label(header, textvariable=self.status_var, bg=self.colors["bg"], fg=self.colors["blue"],
                 font=("Segoe UI", 9), anchor="e").grid(row=1, column=1, rowspan=2, sticky="e")

        panel = tk.Frame(frame, bg=self.colors["panel"], padx=18, pady=15,
                         highlightthickness=1, highlightbackground=self.colors["line"])
        panel.grid(row=1, column=0, sticky="ew")
        panel.columnconfigure(1, weight=1)
        tk.Label(panel, text="INPUT", bg=self.colors["panel"], fg=self.colors["accent"],
                 font=("Segoe UI", 8, "bold")).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
        tk.Label(panel, text="破壳 IPA", bg=self.colors["panel"], fg=self.colors["text"],
                 font=("Segoe UI", 10)).grid(row=1, column=0, sticky="w", pady=6)
        self.input_var = tk.StringVar()
        self.input_entry = tk.Entry(panel, textvariable=self.input_var, bg=self.colors["panel2"], fg=self.colors["text"],
                                    insertbackground=self.colors["accent"], relief="flat", font=("Segoe UI", 10))
        self.input_entry.grid(row=1, column=1, sticky="ew", padx=12, ipady=7)
        self.make_button(panel, "浏览", self.choose_input).grid(row=1, column=2, padx=(4, 0))

        tk.Label(panel, text="输出 IPA", bg=self.colors["panel"], fg=self.colors["text"],
                 font=("Segoe UI", 10)).grid(row=2, column=0, sticky="w", pady=6)
        self.output_var = tk.StringVar()
        self.output_entry = tk.Entry(panel, textvariable=self.output_var, bg=self.colors["panel2"], fg=self.colors["text"],
                                     insertbackground=self.colors["accent"], relief="flat", font=("Segoe UI", 10))
        self.output_entry.grid(row=2, column=1, sticky="ew", padx=12, ipady=7)
        self.make_button(panel, "浏览", self.choose_output).grid(row=2, column=2, padx=(4, 0))

        log_header = tk.Frame(frame, bg=self.colors["bg"])
        log_header.grid(row=2, column=0, sticky="ew", pady=(20, 8))
        tk.Label(log_header, text="转换日志", bg=self.colors["bg"], fg=self.colors["text"],
                 font=("Segoe UI", 11, "bold")).pack(side="left")
        tk.Label(log_header, text="实时输出", bg=self.colors["bg"], fg=self.colors["muted"],
                 font=("Segoe UI", 9)).pack(side="right")

        log_frame = tk.Frame(frame, bg=self.colors["panel"], highlightthickness=1,
                             highlightbackground=self.colors["line"])
        log_frame.grid(row=3, column=0, sticky="nsew")
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        self.log = tk.Text(log_frame, height=16, state="disabled", wrap="none", bg="#11171e",
                           fg="#c7d5da", insertbackground=self.colors["accent"], relief="flat",
                           padx=14, pady=12, font=("Consolas", 9))
        self.log.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scroll.set)

        action = tk.Frame(frame, bg=self.colors["bg"])
        action.grid(row=4, column=0, sticky="ew", pady=(14, 0))
        self.progress = ttk.Progressbar(action, mode="indeterminate", style="Dark.Horizontal.TProgressbar")
        self.progress.pack(side="left", fill="x", expand=True, padx=(0, 18))
        self.make_button(action, "打开输出文件夹", self.open_output_folder).pack(side="right", padx=(0, 8))
        self.start_button = self.make_button(action, "开始转换", self.start, accent=True)
        self.start_button.pack(side="right")

        tk.Label(frame, text="Backward, go backward, turn back to the antemundane realm, go back to the",
                 bg=self.colors["bg"], fg="#60717a", font=("Segoe UI", 8)).grid(row=5, column=0, pady=(18, 0))
        self.root.after(100, self.poll_events)

    def make_button(self, parent, text, command, accent=False):
        return tk.Button(parent, text=text, command=command, relief="flat", bd=0, cursor="hand2",
                         padx=16, pady=7, font=("Segoe UI", 9, "bold" if accent else "normal"),
                         bg=self.colors["accent"] if accent else self.colors["panel2"],
                         fg="#102019" if accent else self.colors["text"],
                         activebackground=self.colors["accent_active"] if accent else self.colors["line"],
                         activeforeground="#102019" if accent else self.colors["text"])

    def append(self, text: str):
        self.log.configure(state="normal")
        self.log.insert("end", text.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def choose_input(self):
        path = filedialog.askopenfilename(title="选择 Phigros 破壳 IPA", filetypes=[("IPA 文件", "*.ipa"), ("所有文件", "*.*")])
        if path:
            self.input_var.set(path)
            self.status_var.set("已选择输入文件")
            if not self.output_var.get():
                self.output_var.set(str(self.default_output(Path(path))))

    def choose_output(self):
        path = filedialog.asksaveasfilename(title="选择输出 IPA", defaultextension=".ipa", filetypes=[("IPA 文件", "*.ipa")])
        if path:
            self.output_var.set(path)

    def open_output_folder(self):
        target = Path(self.output_var.get()).expanduser()
        folder = target.parent if target.parent.exists() else Path.cwd()
        os.startfile(str(folder))

    @staticmethod
    def default_output(source: Path) -> Path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return source.with_name(source.stem + "_iOS12_ported_" + stamp + ".ipa")

    def start(self):
        if self.running:
            return
        source = Path(self.input_var.get()).expanduser()
        output = Path(self.output_var.get()).expanduser() if self.output_var.get().strip() else self.default_output(source)
        self.output_var.set(str(output))
        if not source.is_file() or source.suffix.lower() != ".ipa":
            messagebox.showerror("输入错误", "请选择一个存在的 IPA 文件。")
            return
        if source.resolve() == output.resolve():
            messagebox.showerror("输出错误", "输出文件不能覆盖输入 IPA。")
            return
        if output.exists():
            messagebox.showerror("输出已存在", "请选择一个尚不存在的输出文件名。")
            return
        output.parent.mkdir(parents=True, exist_ok=True)
        self.running = True
        self.start_button.configure(state="disabled")
        self.progress.start(12)
        self.status_var.set("正在转换…")
        self.append("开始转换：" + str(source))
        threading.Thread(target=self.convert, args=(source, output), daemon=True).start()

    def convert(self, source: Path, output: Path):
        # Keep the scratch files beside the destination. The framework is large,
        # and using the system temp drive can add a costly cross-volume copy.
        workdir = None
        try:
            local_temp = output.parent / ".phigros-port-work"
            try:
                local_temp.mkdir(parents=True, exist_ok=True)
                workdir = Path(tempfile.mkdtemp(prefix="build-", dir=local_temp))
            except OSError:
                workdir = Path(tempfile.mkdtemp(prefix="PhigrosPortGUI-"))
            script = bundle_root() / "src" / "port_to_ios12.py"
            env = os.environ.copy()
            env["PYTHONUTF8"] = "1"
            env["PYTHONUNBUFFERED"] = "1"
            if getattr(sys, "frozen", False):
                env["PHI_PORTABLE_WORKER"] = "1"
            else:
                env.pop("PHI_PORTABLE_WORKER", None)
            command = conversion_command(script, source, output, workdir)
            process = subprocess.Popen(command, cwd=str(script.parent), env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                                       bufsize=1, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            assert process.stdout is not None
            with process.stdout:
                for line in process.stdout:
                    self.events.put(("log", line))
            code = process.wait()
            if code == 0:
                validate_output(output)
            self.events.put(("done", str(code)))
        except Exception as error:
            self.events.put(("error", repr(error)))
        finally:
            if workdir is not None:
                shutil.rmtree(workdir, ignore_errors=True)

    def poll_events(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "log":
                    self.append(value)
                elif kind == "done":
                    self.running = False
                    self.progress.stop()
                    self.start_button.configure(state="normal")
                    if value == "0":
                        self.status_var.set("转换完成")
                        self.append("转换完成。请使用签名工具重新签名后安装。")
                        try:
                            self.reveal_output()
                        except OSError as error:
                            self.append("IPA 已生成，打开资源管理器失败：" + str(error))
                        messagebox.showinfo("转换完成", "IPA 已生成，请重新签名后安装。")
                    else:
                        self.status_var.set("转换失败")
                        self.append("转换失败，退出码：" + value)
                        messagebox.showerror("转换失败", "转换程序退出码：" + value + "。请查看日志。")
                elif kind == "error":
                    self.running = False
                    self.progress.stop()
                    self.start_button.configure(state="normal")
                    self.status_var.set("程序错误")
                    self.append("程序错误：" + value)
                    messagebox.showerror("程序错误", value)
        except queue.Empty:
            pass
        self.root.after(100, self.poll_events)

    def reveal_output(self):
        output = Path(self.output_var.get()).expanduser()
        if output.is_file():
            subprocess.Popen(["explorer.exe", "/select,", str(output)])


def main():
    if "--worker" in sys.argv:
        raise SystemExit(worker_main(sys.argv[sys.argv.index("--worker") + 1:]))
    root = tk.Tk()
    ttk.Style().theme_use("vista") if "vista" in ttk.Style().theme_names() else None
    ConverterApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
