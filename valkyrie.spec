# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all, collect_submodules

# Collect pywebview and all its platform backends
webview_datas, webview_binaries, webview_hidden = collect_all('webview')

datas = [
    ('ui/dist', 'ui/dist'),        # Pre-built React app
    ('blocklists', 'blocklists'),  # Curated tracker blocklists
    ('valkyrie.py', '.'),          # Engine script (imported by launcher --engine)
    ('valkyrie_api.py', '.'),      # API module (imported by uvicorn)
] + webview_datas

binaries = [] + webview_binaries

hiddenimports = [
    # uvicorn internals (not auto-detected by PyInstaller)
    'uvicorn.logging',
    'uvicorn.loops',
    'uvicorn.loops.auto',
    'uvicorn.loops.asyncio',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.http.h11_impl',
    'uvicorn.protocols.websockets',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.protocols.websockets.websockets_impl',
    'uvicorn.lifespan',
    'uvicorn.lifespan.on',
    'uvicorn.lifespan.off',
    # FastAPI / Starlette
    'fastapi',
    'fastapi.staticfiles',
    'starlette.staticfiles',
    'starlette.responses',
    'starlette.routing',
    'starlette.middleware.cors',
    # HTTP / async
    'h11',
    'anyio',
    'anyio._backends._asyncio',
    'sniffio',
    # Valkyrie deps
    'dnslib',
    'psutil',
    'psutil._pswindows',
    'sqlite3',
    # pywebview
    *webview_hidden,
] + collect_submodules('uvicorn')

a = Analysis(
    ['launcher.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy', 'PIL', 'PyQt5', 'PyQt6', 'wx'],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Valkyrie',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,       # No black console window on launch
    disable_windowed_traceback=False,
    uac_admin=True,      # Auto-request UAC elevation (needed for DNS port 53)
    icon=None,
)
