#!/usr/bin/env python3
"""
Valkyrie unified entry point.

  No args          → start API server + open pywebview window (normal user launch)
  --engine <args>  → run valkyrie engine subprocess (called internally by valkyrie_api)
"""
import os
import sys
import threading
import time


def _setup_paths():
    """Fix import paths and working directory when running from PyInstaller bundle."""
    if hasattr(sys, '_MEIPASS'):
        if sys._MEIPASS not in sys.path:
            sys.path.insert(0, sys._MEIPASS)
        # CWD → folder next to the .exe so db/logs/blocklists land there
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        os.chdir(exe_dir)


def run_engine():
    """Run valkyrie.py engine with the args that follow --engine."""
    sys.argv = [sys.argv[0]] + sys.argv[2:]
    from valkyrie import main as _main
    _main()


def _wait_for_server(port: int = 8000, timeout: float = 20.0) -> bool:
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=1)
            return True
        except Exception:
            time.sleep(0.25)
    return False


def run_ui():
    """Start uvicorn in a daemon thread, then open a pywebview window."""
    import uvicorn

    def _server():
        uvicorn.run("valkyrie_api:app", host="127.0.0.1", port=8000, log_level="warning")

    threading.Thread(target=_server, daemon=True).start()
    _wait_for_server()

    try:
        import webview
        webview.create_window(
            "Valkyrie — Privacy Engine",
            "http://127.0.0.1:8000",
            width=1440,
            height=900,
            min_size=(900, 600),
        )
        webview.start()
    except Exception:
        # Fallback: open default browser and keep process alive
        import webbrowser
        webbrowser.open("http://127.0.0.1:8000")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    _setup_paths()
    if len(sys.argv) > 1 and sys.argv[1] == "--engine":
        run_engine()
    else:
        run_ui()
