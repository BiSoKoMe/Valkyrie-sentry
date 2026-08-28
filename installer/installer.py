r"""Valkyrie installer stub -> frozen into ValkyrieSetup.exe.

Running ValkyrieSetup.exe performs a Steam-like local install with NO GitHub
round-trip:

    * self-elevates (single UAC prompt),
    * copies the bundled engine (valkyrie.exe) + scripts into
      %ProgramFiles%\Valkyrie, preserving any existing data\ folder,
    * registers the no-prompt ValkyrieStart / ValkyrieStop scheduled tasks,
    * drops Start-Menu + Desktop shortcuts and an Add/Remove Programs entry.

The whole payload is embedded inside this exe (see valkyrie_setup.spec), so the
single file is the update: rebuild it locally with build_setup.ps1 and hand it
to any machine. Re-running it over an existing install is a safe in-place
update - the engine is stopped first, files are refreshed, user data is kept.

Only the Python standard library is used, so it freezes to a tiny stub.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time
import winreg
from pathlib import Path

APP_NAME = "Valkyrie"
VERSION = "0.2.0"
PUBLISHER = "Valkyrie"
WEB_PORT = 8090

# Files that must be present in the payload and land in the install directory.
PAYLOAD = [
    "valkyrie.exe",
    "valkyrie_rules.yaml",
    "start_all.ps1",
    "stop_all.ps1",
    "register-tasks.ps1",
    "unregister-tasks.ps1",
    "uninstall.ps1",
]

SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
SCHTASKS = str(SYSTEM32 / "schtasks.exe")
POWERSHELL = str(SYSTEM32 / "WindowsPowerShell" / "v1.0" / "powershell.exe")

_errors = 0


def log(msg: str) -> None:
    print(msg, flush=True)


def warn(msg: str) -> None:
    global _errors
    _errors += 1
    print(f"[WARN] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Elevation
# ---------------------------------------------------------------------------
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate_and_exit() -> None:
    """Re-launch this exe elevated, wait for it, then mirror its exit code."""
    log("[*] Requesting Administrator privileges...")
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    # SEE_MASK_NOCLOSEPROCESS so we can wait on the elevated child and surface
    # its result instead of returning immediately.
    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    SEE_MASK_NOASYNC = 0x00000100

    class SHELLEXECUTEINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_ulong),
            ("fMask", ctypes.c_ulong),
            ("hwnd", ctypes.c_void_p),
            ("lpVerb", ctypes.c_wchar_p),
            ("lpFile", ctypes.c_wchar_p),
            ("lpParameters", ctypes.c_wchar_p),
            ("lpDirectory", ctypes.c_wchar_p),
            ("nShow", ctypes.c_int),
            ("hInstApp", ctypes.c_void_p),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", ctypes.c_wchar_p),
            ("hkeyClass", ctypes.c_void_p),
            ("dwHotKey", ctypes.c_ulong),
            ("hIcon", ctypes.c_void_p),
            ("hProcess", ctypes.c_void_p),
        ]

    sei = SHELLEXECUTEINFO()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
    sei.lpVerb = "runas"
    sei.lpFile = sys.executable
    sei.lpParameters = params
    sei.nShow = 1
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        log("[ERROR] Elevation was declined. Installation cancelled.")
        sys.exit(1)
    if sei.hProcess:
        ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, 0xFFFFFFFF)
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(sei.hProcess)
        sys.exit(code.value)
    sys.exit(0)


# ---------------------------------------------------------------------------
# Payload resolution (frozen: sys._MEIPASS; dev: repo layout)
# ---------------------------------------------------------------------------
def payload_source(name: str) -> Path:
    if getattr(sys, "frozen", False):
        # "valkyrie_rules.yaml" is special: the bundled datas entry is the
        # factory default (valkyrie/defaults/rules.default.yaml), NOT a file
        # literally named valkyrie_rules.yaml -- PyInstaller's `datas` keeps
        # the source basename, so it lands in _MEIPASS as rules.default.yaml.
        # Read from there; still WRITTEN to the target as valkyrie_rules.yaml
        # (copy_payload controls the destination name, unchanged).
        if name == "valkyrie_rules.yaml":
            return Path(getattr(sys, "_MEIPASS")) / "rules.default.yaml"
        return Path(getattr(sys, "_MEIPASS")) / name
    # Running installer.py directly from a source checkout, for testing.
    repo = Path(__file__).resolve().parent.parent
    dev_map = {
        "valkyrie.exe": repo / "dist" / "valkyrie.exe",
        # Factory default, never the repo-root working file -- see the datas
        # comment in installer/valkyrie_setup.spec for why.
        "valkyrie_rules.yaml": repo / "valkyrie" / "defaults" / "rules.default.yaml",
        "start_all.ps1": repo / "start_all.ps1",
        "stop_all.ps1": repo / "stop_all.ps1",
        "register-tasks.ps1": repo / "installer" / "payload" / "register-tasks.ps1",
        "unregister-tasks.ps1": repo / "installer" / "payload" / "unregister-tasks.ps1",
        "uninstall.ps1": repo / "installer" / "payload" / "uninstall.ps1",
    }
    return dev_map[name]


def run_ps(script: Path, args: list[str] | None = None) -> int:
    cmd = [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)]
    if args:
        cmd += args
    return subprocess.run(cmd).returncode


# ---------------------------------------------------------------------------
# Install steps
# ---------------------------------------------------------------------------
def stop_running_instance() -> None:
    """Free valkyrie.exe so it can be overwritten during an update."""
    subprocess.run([SCHTASKS, "/run", "/tn", "ValkyrieStop"],
                   capture_output=True)
    time.sleep(1)
    subprocess.run(["taskkill", "/f", "/im", "valkyrie.exe"],
                   capture_output=True)
    time.sleep(1)


def copy_payload(install_dir: Path) -> None:
    install_dir.mkdir(parents=True, exist_ok=True)
    for name in PAYLOAD:
        src = payload_source(name)
        if not src.exists():
            log(f"[ERROR] Missing payload file: {name}")
            sys.exit(2)
        dst = install_dir / name
        # Retry the engine copy a few times in case the old process is still
        # releasing the file handle after being stopped.
        for attempt in range(5):
            try:
                dst.write_bytes(src.read_bytes())
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(1)
        log(f"[OK] Installed {name}")


def create_shortcuts(install_dir: Path) -> None:
    engine = install_dir / "valkyrie.exe"
    uninstall = install_dir / "uninstall.ps1"
    start_menu = Path(os.environ["ProgramData"]) / \
        "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Valkyrie"
    public_desktop = Path(os.environ["PUBLIC"]) / "Desktop"

    # Build every shortcut in one WScript.Shell PowerShell pass.
    ps = f"""
$W = New-Object -ComObject WScript.Shell
$menu = '{start_menu}'
New-Item -ItemType Directory -Path $menu -Force | Out-Null

function New-Lnk($path, $target, $arguments, $icon) {{
    $s = $W.CreateShortcut($path)
    $s.TargetPath = $target
    $s.Arguments = $arguments
    if ($icon) {{ $s.IconLocation = $icon }}
    $s.WorkingDirectory = '{install_dir}'
    $s.Save()
}}

New-Lnk (Join-Path $menu 'Start Valkyrie Protection.lnk') '{SCHTASKS}' '/run /tn ValkyrieStart' '{engine}'
New-Lnk (Join-Path $menu 'Stop Valkyrie Protection.lnk')  '{SCHTASKS}' '/run /tn ValkyrieStop'  '{engine}'
New-Lnk (Join-Path $menu 'Uninstall Valkyrie.lnk') '{POWERSHELL}' '-NoProfile -ExecutionPolicy Bypass -File "{uninstall}"' '{engine}'
New-Lnk (Join-Path '{public_desktop}' 'Valkyrie.lnk') '{SCHTASKS}' '/run /tn ValkyrieStart' '{engine}'

# Dashboard: an internet shortcut is the reliable way to open a URL.
$url = Join-Path $menu 'Valkyrie Dashboard.url'
Set-Content -Path $url -Encoding ASCII -Value @('[InternetShortcut]', 'URL=http://localhost:{WEB_PORT}')
"""
    rc = subprocess.run(
        [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps]
    ).returncode
    if rc == 0:
        log("[OK] Created Start Menu + Desktop shortcuts")
    else:
        warn("Some shortcuts could not be created")


def register_arp(install_dir: Path) -> None:
    """Add the Add/Remove Programs (Apps & Features) entry."""
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Valkyrie"
    uninstall = install_dir / "uninstall.ps1"
    engine = install_dir / "valkyrie.exe"
    uninstall_cmd = (
        f'"{POWERSHELL}" -NoProfile -ExecutionPolicy Bypass -File "{uninstall}"'
    )
    try:
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
            def s(name, value):
                winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)

            def d(name, value):
                winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, value)

            s("DisplayName", APP_NAME)
            s("DisplayVersion", VERSION)
            s("Publisher", PUBLISHER)
            s("InstallLocation", str(install_dir))
            s("DisplayIcon", str(engine))
            s("UninstallString", uninstall_cmd)
            d("NoModify", 1)
            d("NoRepair", 1)
            # Rough size in KB so Apps & Features shows something sensible.
            try:
                kb = sum(f.stat().st_size for f in install_dir.glob("*")) // 1024
                d("EstimatedSize", int(kb))
            except Exception:
                pass
        log("[OK] Registered in Add/Remove Programs")
    except Exception as e:
        warn(f"Could not register uninstaller: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def check_payload() -> int:
    """--check: verify every payload file is embedded, without installing.

    A safe self-test for the frozen ValkyrieSetup.exe - no elevation, no writes,
    no UAC prompt. Exit 0 if the bundle is complete, non-zero otherwise.
    """
    print(f"[*] {APP_NAME}Setup self-check (v{VERSION})")
    print(f"[*] Frozen: {getattr(sys, 'frozen', False)}")
    missing = 0
    for name in PAYLOAD:
        src = payload_source(name)
        if src.exists():
            size = src.stat().st_size
            print(f"  [OK]  {name:<22} {size:>12,} bytes")
        else:
            missing += 1
            print(f"  [MISSING] {name}  (expected at {src})")
    if missing:
        print(f"[FAIL] {missing} payload file(s) missing.")
        return 1
    print("[PASS] Payload is complete - ValkyrieSetup.exe is ready to install.")
    return 0


def main() -> None:
    if "--check" in sys.argv[1:]:
        sys.exit(check_payload())

    print()
    print("=" * 60)
    print(f"  {APP_NAME} Setup  (v{VERSION})")
    print("=" * 60)

    if not is_admin():
        elevate_and_exit()  # never returns

    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    install_dir = Path(program_files) / APP_NAME
    existing = install_dir.exists()
    log(f"[*] Install location : {install_dir}")
    log(f"[*] Mode             : {'update (in place)' if existing else 'fresh install'}")

    if existing:
        log("[*] Stopping any running Valkyrie instance...")
        stop_running_instance()

    log("[*] Copying files...")
    copy_payload(install_dir)

    log("[*] Registering protection tasks...")
    rc = run_ps(install_dir / "register-tasks.ps1", ["-Root", str(install_dir)])
    if rc != 0:
        log("[ERROR] Failed to register scheduled tasks.")
        sys.exit(3)

    log("[*] Creating shortcuts...")
    create_shortcuts(install_dir)

    log("[*] Registering uninstaller...")
    register_arp(install_dir)

    print()
    print("=" * 60)
    if _errors == 0:
        print(f"  {APP_NAME} installed successfully.")
    else:
        print(f"  {APP_NAME} installed with {_errors} warning(s) (see above).")
    print("=" * 60)
    print()
    print("  Start protection : Start Menu -> Valkyrie -> Start Valkyrie Protection")
    print("                     (or the Valkyrie icon on the Desktop)")
    print(f"  Dashboard        : http://localhost:{WEB_PORT}")
    print("  Stop protection  : Start Menu -> Valkyrie -> Stop Valkyrie Protection")
    print()

    # Pause so a double-clicked installer's window doesn't vanish instantly.
    if sys.stdout.isatty():
        try:
            input("Press Enter to close...")
        except EOFError:
            pass


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        print(f"\n[FATAL] Installation failed: {e}", flush=True)
        if sys.stdout.isatty():
            try:
                input("Press Enter to close...")
            except EOFError:
                pass
        sys.exit(1)
