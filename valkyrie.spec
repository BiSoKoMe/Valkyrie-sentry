# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build spec for Valkyrie → a single valkyrie.exe.

Bundles the whole application, including the new EDR / security-operations
layer, the web dashboard, and the EDR console. Build it on Windows with:

    build_exe.bat            (or: pyinstaller --clean --noconfirm valkyrie.spec)

The result is dist/valkyrie.exe — a self-contained executable that needs no
Python install on the target machine. Its writable state (data/, rules, logs)
is created next to the .exe on first run (see valkyrie/config.py frozen paths).

NOTE: PyInstaller does not cross-compile. Run this ON WINDOWS to get a Windows
.exe; running it on Linux/macOS produces a native binary for that OS instead.
"""

import os
from PyInstaller.utils.hooks import collect_submodules, collect_all

# Output name is overridable so the same recipe can build valkyrie.exe or, e.g.,
# valkyrie_test.exe:  set VALKYRIE_EXE_NAME before running PyInstaller.
APP_NAME = os.environ.get("VALKYRIE_EXE_NAME", "valkyrie")

# ---------------------------------------------------------------------------
# Read-only assets the running app loads by path (web templates are served via
# FileResponse; config paths for these resolve into the bundle at runtime).
# ---------------------------------------------------------------------------
#
# IMPORTANT (release hygiene): only read-only, ship-safe assets go here. NEVER
# add data/, logs, *.db, *.log, *.env, *.pem/*.key, control tokens, or the
# repo-root working valkyrie_rules.yaml — the installer must contain ZERO user
# or developer state. The factory-default rule set (rules.default.yaml) is
# bundled read-only and copied to %ProgramData%\Valkyrie on first launch.
datas = [
    ("valkyrie/web/dashboard.html", "valkyrie/web"),
    ("valkyrie/web/edr.html",       "valkyrie/web"),
    ("valkyrie/web/launcher.html",  "valkyrie/web"),
    ("valkyrie/fleet/dashboard.html", "valkyrie/fleet"),
    ("valkyrie/defaults/rules.default.yaml", "valkyrie/defaults"),   # factory default
]

binaries = []

# ---------------------------------------------------------------------------
# Hidden imports. uvicorn/fastapi/anyio/dnspython load large parts of
# themselves dynamically, so PyInstaller's static analysis misses them — the
# #1 cause of a "works from source, crashes as .exe" build. Collect them
# explicitly, plus the whole valkyrie package (so every EDR submodule and any
# discovered-plugin dependency is present).
# ---------------------------------------------------------------------------
hiddenimports = []
hiddenimports += collect_submodules("valkyrie")
hiddenimports += collect_submodules("fastapi")
hiddenimports += collect_submodules("starlette")
hiddenimports += collect_submodules("anyio")
hiddenimports += collect_submodules("dns")
hiddenimports += ["rich", "yaml", "psutil"]

# uvicorn ships its own data + many dynamically-imported protocol/loop modules.
_uv_datas, _uv_binaries, _uv_hidden = collect_all("uvicorn")
datas += _uv_datas
binaries += _uv_binaries
hiddenimports += _uv_hidden

# Optional runtime extras — bundle them only if they're installed in the build
# environment, so the offline paths still work when they're absent.
# httpx backs the vendor-neutral AI investigation providers (ai_provider.py) and
# the fleet control-plane client; bundled when present so those paths work in the
# frozen build. No AI-vendor SDK is bundled — providers speak plain HTTP.
for _opt in ("httpx", "cryptography", "h11", "httptools", "websockets", "click"):
    try:
        _d, _b, _h = collect_all(_opt)
        datas += _d
        binaries += _b
        hiddenimports += _h
    except Exception:
        pass


a = Analysis(
    ["run_valkyrie.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "PyQt5", "PySide2", "numpy", "pandas"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    # console=False → GUI subsystem: the engine is a background daemon and must
    # NEVER allocate a console window, no matter how it is launched (service,
    # portable child, or fallback). It runs with --no-ui and logs to a file;
    # run_valkyrie.py guards sys.stdout/stderr so windowed mode can't crash on
    # a stray print. See docs/adr/0001-windowless-engine.md.
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
