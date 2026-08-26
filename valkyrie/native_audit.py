r"""Turn on Windows' native process-creation auditing (Security 4688 + cmdline).

This is what makes `etw/native_process.py` work, and it is the piece that lets
Valkyrie give command-line detection with **nothing to download** - because
everything here is a built-in Windows configuration change, not an install:

  1. `auditpol /set /subcategory:{GUID} /success:enable`
     - makes Windows write Security event 4688 on every process start.
  2. a registry policy value:
     `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`
     `ProcessCreationIncludeCmdLine_Enabled = 1 (DWORD)`
     - makes 4688 include the full command line, which is the whole point.

Both require administrator/SYSTEM. Valkyrie runs as the ValkyrieShield service
(SYSTEM), so the engine can enable this itself at startup; the functions here
are also exposed via `--enable-native-audit` for a manual run.

Design choices that matter:
  * The subcategory is selected by its stable GUID, not the localised display
    name "Process Creation" - auditpol matches the name by locale, so a
    name-based call fails on a non-English Windows exactly like a name-based
    ACL does. Same bug class fixed in secure_file.py.
  * Enabling is IDEMPOTENT and reports whether it actually changed anything, so
    calling it every startup is safe and quiet.
  * Command construction is pure and unit-testable; execution is guarded so a
    locked-down or non-Windows host degrades to "could not enable" rather than
    raising.
"""

from __future__ import annotations

import platform
import subprocess

_IS_WINDOWS = platform.system() == "Windows"

_AUDIT_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
_CMDLINE_VALUE = "ProcessCreationIncludeCmdLine_Enabled"

# The Process Creation subcategory's stable GUID - locale-independent, unlike
# the display name "Process Creation" that auditpol otherwise matches by locale.
_PROC_CREATION_GUID = "{0CCE922B-69AE-11D9-BED3-505054503030}"

_SYS32_AUDITPOL = r"C:\Windows\System32\auditpol.exe"
_TIMEOUT = 20


# --- Pure command construction (unit-tested; no execution) ---

def _enable_audit_cmd() -> list[str]:
    return [_SYS32_AUDITPOL, "/set", "/subcategory:" + _PROC_CREATION_GUID,
            "/success:enable"]


def _query_audit_cmd() -> list[str]:
    return [_SYS32_AUDITPOL, "/get", "/subcategory:" + _PROC_CREATION_GUID]


# --- Execution (guarded; never raises) ---

def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=_TIMEOUT, encoding="utf-8", errors="replace")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as exc:                      # noqa: BLE001
        return 1, f"{type(exc).__name__}: {exc}"


def _cmdline_reg_enabled() -> bool:
    if not _IS_WINDOWS:
        return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _AUDIT_KEY) as k:
            val, _ = winreg.QueryValueEx(k, _CMDLINE_VALUE)
            return int(val) == 1
    except FileNotFoundError:
        return False
    except OSError:
        return False


def _set_cmdline_reg() -> bool:
    if not _IS_WINDOWS:
        return False
    try:
        import winreg
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, _AUDIT_KEY) as k:
            winreg.SetValueEx(k, _CMDLINE_VALUE, 0, winreg.REG_DWORD, 1)
        return True
    except OSError:
        return False


def is_process_auditing_enabled() -> bool:
    """True when 4688 fires AND carries the command line - both must hold.

    Either half alone is useless: auditing without the cmdline policy gives
    image+parent but no command line (so encoded-PowerShell etc. slip through),
    and the reg value without auditing gives no events at all.
    """
    if not _IS_WINDOWS:
        return False
    if not _cmdline_reg_enabled():
        return False
    code, out = _run(_query_audit_cmd())
    # auditpol prints the subcategory row with "Success" (or a localized column)
    # when success auditing is on. Match loosely on the ASCII token.
    return code == 0 and "Success" in out


def enable_process_auditing() -> tuple[bool, str]:
    """Enable 4688 + command-line auditing. Idempotent. Needs admin/SYSTEM.

    Returns ``(enabled_now, detail)``. ``enabled_now`` reflects the state AFTER
    the call (verified by re-reading), not merely that the commands returned 0 -
    the same verify-don't-assume discipline used for the file-permission fixes.
    """
    if not _IS_WINDOWS:
        return False, "not Windows"
    if is_process_auditing_enabled():
        return True, "already enabled"

    reg_ok = _set_cmdline_reg()
    code, out = _run(_enable_audit_cmd())
    if is_process_auditing_enabled():
        return True, "enabled (4688 + command line)"
    detail = "could not enable"
    if not reg_ok:
        detail += "; cmdline registry write failed (need admin?)"
    if code != 0:
        detail += f"; auditpol failed: {out.strip()[:160]}"
    elif "Access" in out or "denied" in out.lower():
        detail += "; auditpol reported access denied (need admin?)"
    return False, detail
