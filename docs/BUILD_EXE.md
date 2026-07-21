# Building `valkyrie.exe`

This packages the **entire** application — DNS protection, firewall, behavioural
+ intelligence engines, the web dashboard, **and the full EDR /
security-operations layer** (incidents, threat hunting, response, plugins,
signed remote response) — into a single self-contained `valkyrie.exe` that runs
on a Windows machine with **no Python install required**.

---

## One important honesty note

**PyInstaller does not cross-compile.** A Windows `.exe` must be built *on
Windows*. You cannot produce a Windows executable from Linux or macOS — running
the build there yields a native binary for *that* OS instead. So the repo ships
the **build tooling** (a validated PyInstaller spec + build scripts); you run it
once on a Windows box to get the actual `valkyrie.exe`.

The spec has been build-validated end-to-end (the frozen app boots, serves the
dashboard and the `/edr` console, and loads all 11 EDR plugins) — so the Windows
build is a turn-key `pyinstaller valkyrie.spec`, not a debugging project.

---

## Build it (on Windows)

1. Install **Python 3.10+** from python.org (tick *Add Python to PATH*).
2. Open a terminal in the Valkyrie folder.
3. Run **one** of:

   ```bat
   build_exe.bat
   ```
   ```powershell
   .\build_exe.ps1              # AI investigation is bundled by default (httpx; no vendor SDK)
   ```

   Or directly:
   ```bat
   pip install -r requirements_modular.txt pyinstaller cryptography
   pyinstaller --clean --noconfirm valkyrie.spec
   ```

The result is **`dist\valkyrie.exe`**.

---

## Run it

```bat
dist\valkyrie.exe --web            REM full shield + dashboard + /edr console
dist\valkyrie.exe --hunt list      REM list saved threat hunts
dist\valkyrie.exe --incidents      REM print current incidents
dist\valkyrie.exe --help           REM every flag
```

The exe keeps its **writable state next to itself** — `data\` (database,
learned intelligence, EDR incidents), `valkyrie_rules.yaml`, and logs are
created in the same folder as `valkyrie.exe` on first run. To deploy, copy the
whole `dist\` folder. (This is handled by the frozen-path logic in
`valkyrie/config.py`; nothing changes for the `python -m valkyrie` flow.)

---

## What's bundled vs optional

| Included by default | Notes |
|---|---|
| DNS sinkhole, firewall, behavioural + intelligence engines | core |
| Web dashboard + **EDR console** (`/edr`) | HTML assets bundled |
| EDR layer: detections, incidents, hunting, local response, plugins | all offline |
| Offline AI-assisted investigation analyst | fully local, no key |
| `cryptography` (signed policy + **signed remote response**) | installed by the build scripts |

| Optional | How |
|---|---|
| **LLM-assisted** investigation narrative (vendor-neutral) | Bundled by default via `httpx` — no vendor SDK. Off by default at runtime; configure a provider with `VALKYRIE_AI_PROVIDER` / `VALKYRIE_AI_KEY` (or use `local` for on-box) |
| TLS inspection (`--tls`) | `pip install mitmproxy` before building |

Third-party EDR plugins are **not** frozen into the exe — drop them into a
`plugins\` folder next to `valkyrie.exe` and point at it with
`--edr-plugin-dir plugins`, so you can extend detections/responders without
rebuilding.

---

## How the packaging works (for maintainers)

- `run_valkyrie.py` — thin entry point (`valkyrie/__main__` uses package-relative
  imports and can't be a PyInstaller script directly).
- `valkyrie.spec` — the build recipe. It force-collects the parts PyInstaller's
  static analysis misses: `uvicorn` (dynamic protocol/loop modules), `fastapi`,
  `starlette`, `anyio`, `dnspython`, and every `valkyrie.*` submodule. Web HTML
  is added as data at `valkyrie/web` and `valkyrie/fleet` so `FileResponse`
  finds it inside the bundle. Optional extras (`httpx`, `cryptography`, …)
  are collected only if present in the build environment.
- `valkyrie/config.py` — when `sys.frozen` is set, writable paths resolve next
  to the executable and read-only assets to `sys._MEIPASS`.

`dist/` and `build/` are git-ignored; the built binary is never committed.
