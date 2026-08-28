# Valkyrie - How to Run (complete guide)

The product is the **Valkyrie desktop app**. Everything below happens on your
own machine in your own PowerShell window. There are three ways to run,
from "real product" to "developer poking at code":

| Way | What you get | Admin? | Command |
|---|---|---|---|
| **A. Installed app** (the product) | App + background service, survives reboots, real DNS protection | UAC once at install | `.\build_app.ps1` -> run `ValkyrieSetup.exe` |
| **B. Portable app** | Same app, single exe, no install/no service, state beside the exe | No | `.\build_app.ps1 -Portable` -> run `ValkyriePortable.exe` |
| **C. Dev mode** | App window running against the repo source (for development) | No (protection features limited) | `cd electron; npm run dev` |

Golden rule: **the exes are snapshots.** After any code change, rebuild
(way A/B) or you are running the old engine.

---

## A. The installed app (recommended)

### 1. Build the installer

Open PowerShell (a normal window - the build itself needs no admin):

```powershell
cd "C:\Users\badam\OneDrive\Desktop\Valkyrie"
.\build_app.ps1
```

If Windows says *"running scripts is disabled on this system"*:

```powershell
powershell -ExecutionPolicy Bypass -File .\build_app.ps1
```

What it does (visible as [1/4]...[4/4]):
1. **Engine** - PyInstaller freezes the whole Python engine (DNS sinkhole,
   firewall, EDR, threat intel, ransomware shield, sensors) into
   `dist\valkyrie.exe`.
2. **Stage** - copies engine + service scripts into `electron\engine_payload\`.
3. **Audits (release-blocking)** - checks the payload contains zero
   developer/user data and that the engine is windowless (never flashes a
   console). The build *aborts* if either fails.
4. **App** - electron-builder + NSIS produce **`ValkyrieSetup.exe`** in the
   repo root.

First build takes several minutes (npm downloads its toolchain once);
later builds are much faster.

Flags:
- `-SkipEngine` - reuse the last `dist\valkyrie.exe`; only rebuilds the app
  shell. **Never use it after engine (Python) changes.**
- `-Portable` - build `ValkyriePortable.exe` instead (see B).
- `-NoVCRedist` - skip the optional VC++ runtime download.

### 2. Install

Double-click **`ValkyrieSetup.exe`** -> accept the UAC prompt -> installer
finishes and launches the app. You get Desktop + Start-Menu shortcuts named
**Valkyrie**. Upgrading = build a new Setup and run it again; your data and
settings are kept.

### 3. Use the app

- **START** - arms protection: the ValkyrieShield service runs the engine and
  your system DNS is pointed at it. Browse normally; blocks/incidents appear
  in the app's DATA view.
- **STOP** - disarms: system DNS is restored, internet works exactly as
  before Valkyrie.
- The service keeps protection alive across reboots; the app window is just
  the control surface - closing it does not stop protection.

### 4. Uninstall

Windows Settings -> Apps -> **Valkyrie** -> Uninstall (restores DNS and removes
the service; your ProgramData stays unless you delete it).

---

## B. The portable app

```powershell
.\build_app.ps1 -Portable
# or, right after a full build (engine already fresh):
.\build_app.ps1 -Portable -SkipEngine
```

Produces **`ValkyriePortable.exe`** in the repo root. Run it from anywhere
(USB stick included): no install, no admin, no service. All state lives in a
folder beside the exe.

**Honest limitation:** without admin/service it cannot take over system DNS -
so it runs the engine + app + monitoring, but system-wide DNS protection
requires the installed version (way A).

---

## C. Dev mode (working on the code)

```powershell
cd "C:\Users\badam\OneDrive\Desktop\Valkyrie\electron"
npm install        # first time only
npm run dev
```

Opens the real app window wired to the **repo source** - every engine change
is live without rebuilding. START in dev mode drives the repo's
`start_all.ps1` (it will self-elevate when arming DNS).

Engine-only, no app window (fastest loop while hacking on Python):

```powershell
python -m valkyrie --web        # DNS on 127.0.0.1:5300, does NOT touch system DNS
python tests\test_dns.py doubleclick.net    # probe it → should print BLOCKED
```

---

## Updating blocklists & threat-intel feeds

Downloads are opt-in. To refresh everything (tracker lists + abuse.ch IOC
feeds) and exit:

```powershell
python -m valkyrie --update
```

Prints `Update complete. N domains, N IOCs.` Cached feeds then load offline
on every start; the running engine also self-refreshes feeds every 6 h when
downloads are enabled.

---

## Verify / troubleshoot

- **Run the test suite** (36 tests, all offline):
  ```powershell
  $env:PYTHONUTF8=1; python tests\run_tests.py
  ```
- **Is the engine alive?** The app's DATA view populates; or
  `http://127.0.0.1:8090/api/health` returns OK (this port is the app's
  internal backend - not a separate product).
- **"scripts is disabled"** -> use the `-ExecutionPolicy Bypass` form above.
- **No internet after a crash while armed** -> run `.\stop_all.ps1` (restores
  system DNS and the native Unbound service). This is the panic button.
- **Installed app behaves like the old version** -> you forgot to rebuild:
  `.\build_app.ps1` then run the new `ValkyrieSetup.exe`.
- **Build fails** -> the failing stage prints why; the audits failing means
  the build *correctly* refused to ship (fix the reported violation, don't
  bypass).

## Where things live

| Thing | Location |
|---|---|
| Installed engine + app | `Program Files` (installer choice) |
| Installed mutable state (DB, lists, intel cache, logs) | `C:\ProgramData\Valkyrie` |
| Portable state | folder beside `ValkyriePortable.exe` |
| Dev/source state | repo `data\` |
| Threat-intel cache | `<state>\threat_intel\` |
