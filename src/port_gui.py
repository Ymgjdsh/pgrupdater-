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
        return int(error.code or 0)
    return 0


class ConverterApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Phigros iOS 12+ 转换器")
        self.root.geometry("760x520")
        self.root.minsize(680, 440)
        self.events: queue.Queue[tuple[str, str]] = queue.Queue()
        self.running = False

        frame = ttk.Frame(root, padding=16)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(3, weight=1)

        ttk.Label(frame, text="正版 IPA：").grid(row=0, column=0, sticky="w", pady=6)
        self.input_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.input_var).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(frame, text="选择…", command=self.choose_input).grid(row=0, column=2)

        ttk.Label(frame, text="输出 IPA：").grid(row=1, column=0, sticky="w", pady=6)
        self.output_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.output_var).grid(row=1, column=1, sticky="ew", padx=8)
        ttk.Button(frame, text="选择…", command=self.choose_output).grid(row=1, column=2)

        self.progress = ttk.Progressbar(frame, mode="indeterminate")
        self.progress.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(10, 12))
        self.log = tk.Text(frame, height=16, state="disabled", wrap="none")
        self.log.grid(row=3, column=0, columnspan=3, sticky="nsew")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.log.yview)
        scroll.grid(row=3, column=3, sticky="ns")
        self.log.configure(yscrollcommand=scroll.set)

        buttons = ttk.Frame(frame)
        buttons.grid(row=4, column=0, columnspan=3, sticky="e", pady=(12, 0))
        self.start_button = ttk.Button(buttons, text="开始转换", command=self.start)
        self.start_button.pack(side="right")
        ttk.Button(buttons, text="打开输出文件夹", command=self.open_output_folder).pack(side="right", padx=8)
        self.root.after(100, self.poll_events)

    def append(self, text: str):
        self.log.configure(state="normal")
        self.log.insert("end", text.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def choose_input(self):
        path = filedialog.askopenfilename(title="选择正版 Phigros IPA", filetypes=[("IPA 文件", "*.ipa"), ("所有文件", "*.*")])
        if path:
            self.input_var.set(path)
            if not self.output_var.get():
                source = Path(path)
                self.output_var.set(str(source.with_name(source.stem + "_iOS12.ipa")))

    def choose_output(self):
        path = filedialog.asksaveasfilename(title="选择输出 IPA", defaultextension=".ipa", filetypes=[("IPA 文件", "*.ipa")])
        if path:
            self.output_var.set(path)

    def open_output_folder(self):
        target = Path(self.output_var.get()).expanduser()
        folder = target.parent if target.parent.exists() else Path.cwd()
        os.startfile(str(folder))

    def start(self):
        if self.running:
            return
        source = Path(self.input_var.get()).expanduser()
        output = Path(self.output_var.get()).expanduser()
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
        self.append("开始转换：" + str(source))
        threading.Thread(target=self.convert, args=(source, output), daemon=True).start()

    def convert(self, source: Path, output: Path):
        temp_root = Path(tempfile.gettempdir()) / "PhigrosPortGUI"
        temp_root.mkdir(parents=True, exist_ok=True)
        workdir = Path(tempfile.mkdtemp(prefix="build-", dir=temp_root))
        script = bundle_root() / "src" / "port_to_ios12.py"
        env = os.environ.copy()
        env["PHI_PORTABLE_WORKER"] = "1"
        env["PYTHONUTF8"] = "1"
        command = [sys.executable, str(script), str(source), str(output), "--workdir", str(workdir)]
        try:
            process = subprocess.Popen(command, cwd=str(script.parent), env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                                       bufsize=1)
            assert process.stdout is not None
            for line in process.stdout:
                self.events.put(("log", line))
            code = process.wait()
            self.events.put(("done", str(code)))
        except Exception as error:
            self.events.put(("error", repr(error)))

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
                        self.append("转换完成。请使用签名工具重新签名后安装。")
                        messagebox.showinfo("转换完成", "IPA 已生成，请重新签名后安装。")
                    else:
                        self.append("转换失败，退出码：" + value)
                        messagebox.showerror("转换失败", "转换程序退出码：" + value + "。请查看日志。")
                elif kind == "error":
                    self.running = False
                    self.progress.stop()
                    self.start_button.configure(state="normal")
                    self.append("程序错误：" + value)
                    messagebox.showerror("程序错误", value)
        except queue.Empty:
            pass
        self.root.after(100, self.poll_events)


def main():
    if "--worker" in sys.argv:
        raise SystemExit(worker_main(sys.argv[sys.argv.index("--worker") + 1:]))
    root = tk.Tk()
    ttk.Style().theme_use("vista") if "vista" in ttk.Style().theme_names() else None
    ConverterApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
