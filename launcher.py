#!/usr/bin/env python3
"""secret-scout launcher: sets up a private venv, installs deps, opens the UI."""
from __future__ import annotations

import os
import subprocess
import sys
import time
import venv
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
PORT = 5000
URL = f"http://127.0.0.1:{PORT}"


def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def ensure_env() -> Path:
    py = venv_python()
    if not py.exists():
        print("[secret-scout] first run: creating virtual environment...")
        venv.create(VENV, with_pip=True)
    print("[secret-scout] installing/updating dependencies...")
    subprocess.run([str(py), "-m", "pip", "install", "-q", "--upgrade", "pip"],
                   cwd=ROOT)
    subprocess.run([str(py), "-m", "pip", "install", "-q", "-r",
                    str(ROOT / "requirements.txt")], cwd=ROOT, check=True)
    return py


def main():
    # Optional: pass an API token as the first argument to protect /api/*
    api_token = sys.argv[1] if len(sys.argv) > 1 else None
    py = ensure_env()
    cmd = [str(py), "-m", "secretscout.cli", "ui", "--port", str(PORT)]
    if api_token:
        cmd += ["--api-token", api_token]
    print(f"[secret-scout] starting dashboard at {URL}")
    proc = subprocess.Popen(cmd, cwd=ROOT)
    time.sleep(3)
    try:
        webbrowser.open(URL)
    except Exception:
        pass
    print("[secret-scout] running. Close this window to stop.")
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()


if __name__ == "__main__":
    main()
