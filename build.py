"""Build a single-file program for the current OS.

    pip install pyinstaller
    python build.py

Output: dist/Sentinel.exe on Windows, dist/Sentinel on macOS / Linux.
Build on each OS you want to support (GitHub Actions does this automatically, see
.github/workflows/build.yml).
"""
import os
import sys

import PyInstaller.__main__

sep = os.pathsep  # ';' on Windows, ':' elsewhere
args = [
    "run_sentinel.py",
    "--name", "Sentinel",
    "--onefile",
    "--console",          # it's a text menu, so it needs a console window
    "--clean",
    "--noconfirm",
    "--add-data", f"sentinel/data{sep}sentinel/data",
]
if os.path.exists("icon.ico") and sys.platform == "win32":
    args += ["--icon", "icon.ico"]

PyInstaller.__main__.run(args)
