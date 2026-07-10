"""Frozen-build entry point for PyInstaller (produces valkyrie.exe).

`valkyrie/__main__.py` uses package-relative imports, so PyInstaller cannot use
it directly as a script — it must import the package. This thin wrapper does
exactly that. For normal use, keep running `python -m valkyrie`; this file only
exists so the whole app (EDR layer included) can be packaged into a single
executable via valkyrie.spec.
"""

from __future__ import annotations

import multiprocessing


def _run() -> None:
    from valkyrie.__main__ import main
    main()


if __name__ == "__main__":
    # Required for PyInstaller one-file builds on Windows: without it a frozen
    # process that ever spawns a child would re-run the whole program.
    multiprocessing.freeze_support()
    _run()
