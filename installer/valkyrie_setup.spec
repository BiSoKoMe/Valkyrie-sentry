# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: freeze installer.py -> ValkyrieSetup.exe.

Embeds the already-built engine (dist/valkyrie.exe) plus the runtime scripts as
data, so the single ValkyrieSetup.exe carries the entire app. Build via
build_setup.ps1 (which builds the engine first), or directly:

    python -m PyInstaller --clean --noconfirm installer/valkyrie_setup.spec

Result: dist/ValkyrieSetup.exe.  requestedExecutionLevel is left as-is; the stub
self-elevates at runtime via ShellExecute 'runas' so a normal double-click works.
"""

import os

# SPECPATH is injected by PyInstaller and points at this file's directory.
HERE = os.path.abspath(SPECPATH)              # ...\installer
ROOT = os.path.dirname(HERE)                  # repo root

ENGINE = os.path.join(ROOT, "dist", "valkyrie.exe")
if not os.path.exists(ENGINE):
    raise SystemExit(
        "dist/valkyrie.exe not found — build the engine first "
        "(build_exe.ps1 or build_setup.ps1)."
    )

# (source_path, dest_dir_inside_bundle). '.' puts the file at the payload root,
# which is exactly where installer.py's payload_source() looks (sys._MEIPASS).
datas = [
    (ENGINE, "."),
    # The FACTORY DEFAULT, never the repo-root working valkyrie_rules.yaml.
    # That file is the developer's own actively-edited rules (it has
    # referenced personal ISP/DoH and editor-telemetry entries at various
    # points) and was being bundled into every installer verbatim -- the
    # exact thing valkyrie.spec's own datas comment says must never happen.
    # It turned out to be harmless functionally (the engine's RULES_PATH is
    # DATA_DIR-based, per config.py, and never reads this install-directory
    # copy) but it shipped a leak of the developer's personal config into
    # every user's Program Files for no purpose at all. Found while building
    # a fresh installer for VM/red-team testing (2026-07-30).
    (os.path.join(ROOT, "valkyrie", "defaults", "rules.default.yaml"),
     "."),
    (os.path.join(ROOT, "start_all.ps1"), "."),
    (os.path.join(ROOT, "stop_all.ps1"), "."),
    (os.path.join(HERE, "payload", "register-tasks.ps1"), "."),
    (os.path.join(HERE, "payload", "unregister-tasks.ps1"), "."),
    (os.path.join(HERE, "payload", "uninstall.ps1"), "."),
]

a = Analysis(
    [os.path.join(HERE, "installer.py")],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Keep the stub tiny — it only needs the stdlib.
    excludes=["tkinter", "matplotlib", "numpy", "pandas", "PyQt5", "PySide2"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ValkyrieSetup",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,          # show install progress
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
