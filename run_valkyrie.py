"""Frozen-build entry point for PyInstaller (produces valkyrie.exe).

`valkyrie/__main__.py` uses package-relative imports, so PyInstaller cannot use
it directly as a script - it must import the package. This thin wrapper does
exactly that. For normal use, keep running `python -m valkyrie`; this file only
exists so the whole app (EDR layer included) can be packaged into a single
executable via valkyrie.spec.

The frozen exe is built as a GUI-subsystem app (console=False) so it never
allocates a console window - it is a background daemon. A GUI-subsystem process
launched without a console has sys.stdout/sys.stderr == None, which would make
any stray print()/Rich write raise. `_ensure_std_streams()` installs safe
sinks so the daemon runs identically whether or not a console/pipe is attached.
"""

from __future__ import annotations

import multiprocessing
import os
import sys


def _ensure_std_streams() -> None:
    """Guarantee sys.stdout/sys.stderr are writable, even windowed with no
    console. NSSM attaches real pipes (captured to the service logs); a direct
    or portable launch has none, so fall back to os.devnull."""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None:
            try:
                setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))
            except OSError:
                pass


def _run() -> None:
    from valkyrie.__main__ import main
    main()


if __name__ == "__main__":
    _ensure_std_streams()
    # Required for PyInstaller one-file builds on Windows: without it a frozen
    # process that ever spawns a child would re-run the whole program.
    multiprocessing.freeze_support()
    _run()
