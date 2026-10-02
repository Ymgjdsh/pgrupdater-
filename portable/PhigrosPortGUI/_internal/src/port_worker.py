"""Console worker, started without a visible window by the portable GUI."""
import sys
from port_gui import worker_main


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if stream is not None:
            stream.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    if len(sys.argv) < 3 or sys.argv[1] != "--worker":
        raise SystemExit("This executable is launched by PhigrosPortGUI.exe.")
    raise SystemExit(worker_main(sys.argv[2:]))
