r"""Restrict a secret file so only privileged principals can read it.

WHY THIS EXISTS
---------------
Valkyrie's TLS inspection needs a certificate authority, and it stores that
CA's **private key** on disk (`valkyrie-ca.key`, plus mitmproxy's own
`mitmproxy-ca.pem` in its config dir). Those files live under the engine's
data directory, which on Windows is `%ProgramData%\Valkyrie` — and
`%ProgramData%` subdirectories inherit a default ACL that grants
`BUILTIN\\Users` read access.

That is not a small permissions nit. Whoever holds that private key can mint
a valid-looking certificate for *any* domain and impersonate it to this
machine — bank, email, anything — and the browser shows a normal padlock,
because the machine has been told to trust that CA. So a world-readable CA
key turns "any local account, or any process running as one" into "total
TLS interception of this machine". It converts the security product into the
attack.

WHAT "PROPERLY" MEANS HERE
--------------------------
* **Set by SID, not by name.** `BUILTIN\\Administrators` is localised —
  `Administradores`, `Administrateurs`, … — so a name-based ACL silently
  fails to apply on a non-English Windows and leaves the key exposed while
  appearing to succeed. Well-known SIDs are identical on every install.
* **Break inheritance.** The dangerous grant is *inherited* from
  `%ProgramData%`, so granting the right principals is not enough; the
  inherited ACEs have to be removed (`/inheritance:r`).
* **Harden the directory BEFORE the key is generated.** mitmproxy creates
  its CA inside its config dir at startup. Hardening only afterwards leaves
  a real window where the key exists world-readable on disk.
* **Verify, never assume.** `icacls` can report success while leaving an ACE
  in place. `verify()` re-reads the ACL and enumerates the SIDs that
  actually have access, so the result is measured rather than hoped for.
* **Fail loud.** A caller that cannot harden a secret should refuse to
  proceed, not continue quietly — the whole failure mode this module exists
  to prevent is a secret being exposed while everything looks fine.
"""

from __future__ import annotations

import os
import platform
import stat
import subprocess
from pathlib import Path

_IS_WINDOWS = platform.system() == "Windows"

# Well-known SIDs. Locale-independent, identical on every Windows install.
SID_ADMINISTRATORS = "S-1-5-32-544"
SID_SYSTEM = "S-1-5-18"
SID_CREATOR_OWNER = "S-1-3-0"

# Principals allowed to retain access to a secret. CREATOR OWNER is accepted
# because it only ever resolves to whoever created the file, which for engine
# state is the (already privileged) engine itself.
#
# The account the ENGINE RUNS AS is added dynamically by _allowed_sids(): as a
# Windows service it is SYSTEM, but in a dev or portable run it is an ordinary
# user account, and stripping that account's access would lock the engine out
# of its own key. The threat being closed is *other* local accounts reading the
# key — principally the inherited `BUILTIN\Users` grant on %ProgramData% — not
# the engine's own identity.
_BASE_ALLOWED_SIDS = frozenset({SID_ADMINISTRATORS, SID_SYSTEM, SID_CREATOR_OWNER})

# Never acceptable on a secret, whatever else is present.
SID_EVERYONE = "S-1-1-0"
SID_USERS = "S-1-5-32-545"
SID_AUTHENTICATED_USERS = "S-1-5-11"
SID_GUESTS = "S-1-5-32-546"
SID_ANONYMOUS = "S-1-5-7"
_FORBIDDEN_SIDS = frozenset({SID_EVERYONE, SID_USERS, SID_AUTHENTICATED_USERS,
                             SID_GUESTS, SID_ANONYMOUS})

_current_user_sid_cache: list = []


def current_user_sid() -> str:
    """SID of the account this process is running as ('' off Windows)."""
    if not _IS_WINDOWS:
        return ""
    if _current_user_sid_cache:
        return _current_user_sid_cache[0]
    code, out = _run([
        _POWERSHELL, "-NoProfile", "-NonInteractive", "-Command",
        "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    ])
    sid = out.strip().splitlines()[0].strip() if code == 0 and out.strip() else ""
    _current_user_sid_cache.append(sid)
    return sid


def _allowed_sids() -> set[str]:
    allowed = set(_BASE_ALLOWED_SIDS)
    me = current_user_sid()
    if me:
        allowed.add(me)
    return allowed

_SYS32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
_ICACLS = str(_SYS32 / "icacls.exe")
_POWERSHELL = str(_SYS32 / "WindowsPowerShell" / "v1.0" / "powershell.exe")

_TIMEOUT = 20


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=_TIMEOUT, encoding="utf-8", errors="replace")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as exc:                      # noqa: BLE001
        return 1, f"{type(exc).__name__}: {exc}"


def harden(path: Path, *, is_dir: bool = False) -> tuple[bool, str]:
    """Restrict *path* to Administrators + SYSTEM (Windows) or 0600 (POSIX).

    Returns ``(ok, detail)``. ``ok`` is the result of an independent
    verification pass, not merely of the command's exit code.
    """
    p = Path(path)
    if not p.exists():
        return False, f"does not exist: {p}"

    if not _IS_WINDOWS:
        try:
            os.chmod(p, 0o700 if p.is_dir() else 0o600)
        except OSError as exc:
            return False, f"chmod failed: {exc}"
        return verify(p)

    # (OI)(CI) so newly created children inherit the restriction — this is what
    # protects a key that mitmproxy has not written yet.
    inherit = "(OI)(CI)" if (is_dir or p.is_dir()) else ""
    grants = [
        "/grant:r", f"*{SID_ADMINISTRATORS}:{inherit}(F)",
        "/grant:r", f"*{SID_SYSTEM}:{inherit}(F)",
    ]
    me = current_user_sid()
    if me and me not in (SID_ADMINISTRATORS, SID_SYSTEM):
        # The engine must keep access to its own key when not running as SYSTEM.
        grants += ["/grant:r", f"*{me}:{inherit}(F)"]

    code, out = _run([_ICACLS, str(p), "/inheritance:r"] + grants)
    if code != 0:
        return False, f"icacls failed ({code}): {out.strip()[:300]}"

    # `/inheritance:r` drops INHERITED aces and `/grant:r` replaces the grants
    # for the SIDs named above — but any OTHER *explicit* ACE survives both.
    # That is not hypothetical: the first test of this module found exactly such
    # a surviving explicit ACE, and the initial implementation reported success
    # while the file was still exposed. So enumerate what actually remains and
    # remove anything that is not allowed.
    allowed = _allowed_sids()
    sids, err = access_sids(p)
    if err:
        return False, err
    for sid in sorted(sids - allowed):
        _run([_ICACLS, str(p), "/remove:g", f"*{sid}", "/remove:d", f"*{sid}"])

    return verify(p)


def access_sids(path: Path) -> tuple[set[str], str]:
    """SIDs that currently hold any access to *path* (Windows only).

    Read back through PowerShell and translated to raw SIDs, because
    `icacls` prints localised display names that cannot be compared reliably
    across locales.
    """
    if not _IS_WINDOWS:
        return set(), "not windows"
    script = (
        "$ErrorActionPreference='Stop';"
        f"$a=(Get-Acl -LiteralPath '{path}').Access;"
        "$a | ForEach-Object { try {"
        "$_.IdentityReference.Translate("
        "[System.Security.Principal.SecurityIdentifier]).Value"
        "} catch { $_.IdentityReference.Value } }"
    )
    code, out = _run([_POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script])
    if code != 0:
        return set(), f"Get-Acl failed: {out.strip()[:200]}"
    return {ln.strip() for ln in out.splitlines() if ln.strip()}, ""


def verify(path: Path) -> tuple[bool, str]:
    """True when only privileged principals can reach *path*."""
    p = Path(path)
    if not p.exists():
        return False, f"does not exist: {p}"

    if not _IS_WINDOWS:
        mode = stat.S_IMODE(p.stat().st_mode)
        if mode & 0o077:
            return False, f"group/other bits set: {oct(mode)}"
        return True, f"mode {oct(mode)}"

    sids, err = access_sids(p)
    if err:
        return False, err
    if not sids:
        return False, "could not read ACL"
    # A forbidden principal is fatal regardless of anything else — these are the
    # ones that make a secret readable by every account on the machine.
    forbidden = sids & _FORBIDDEN_SIDS
    if forbidden:
        return False, f"world/group-readable via {sorted(forbidden)}"
    extra = sids - _allowed_sids()
    if extra:
        return False, f"readable by non-privileged principal(s): {sorted(extra)}"
    return True, f"restricted to {sorted(sids)}"


def describe(path: Path) -> str:
    """One-line human summary, for logs and the refuse-to-start message."""
    ok, detail = verify(path)
    return f"{'OK' if ok else 'EXPOSED'}: {path} — {detail}"


# ---------------------------------------------------------------------------
# The secret registry.
#
# Four separate secrets were found unprotected on Windows in a single audit —
# the TLS CA private key, the MAC install key, the API control token, and the
# fleet enrolment token — each for the same reason: DATA_DIR inherits a
# BUILTIN\Users:read ACE from %ProgramData%, so anything written there is
# world-readable unless something actively prevents it. Two of them even
# carried code that protected them on POSIX and explicitly skipped Windows.
#
# Fixing each write site is necessary but not sufficient: the next secret
# added will have the same default. This registry plus harden_known_secrets()
# is the systemic backstop — every launch re-asserts the invariant, so a
# missed write site is corrected rather than shipped.
# ---------------------------------------------------------------------------

def known_secrets() -> list[tuple[str, Path]]:
    """(label, path) for every file Valkyrie writes that must stay private.

    Imported lazily so this module stays usable without pulling in config.
    """
    from . import config as C
    return [
        ("TLS CA private key", C.TLS_CA_KEY_PATH),
        ("mitmproxy CA directory", C.TLS_MITMPROXY_CONF_DIR),
        ("MAC install key", C.MAC_KEY_PATH),
        ("API control token", C.DATA_DIR / "control_token.txt"),
        ("fleet enrolment token", C.FLEET_AGENT_IDENTITY_PATH),
        ("WireGuard server config", C.WIREGUARD_CONF_PATH),
        ("WireGuard client config", C.WIREGUARD_CLIENT_PATH),
        ("WireGuard hop-1 config", C.WIREGUARD_HOP1_CONF),
        ("WireGuard hop-2 config", C.WIREGUARD_HOP2_CONF),
    ]


def audit_secrets() -> list[tuple[str, Path, bool, str]]:
    """Report protection state for every known secret that exists on disk."""
    out = []
    for label, path in known_secrets():
        try:
            if not Path(path).exists():
                continue
            ok, detail = verify(path)
        except Exception as exc:                  # noqa: BLE001
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        out.append((label, Path(path), ok, detail))
    return out


def harden_known_secrets() -> list[tuple[str, Path, bool, str]]:
    """Re-assert the invariant on every known secret. Returns what was fixed.

    Safe to call on every launch: hardening is idempotent, and a secret that
    is already restricted is left untouched.
    """
    fixed = []
    for label, path in known_secrets():
        p = Path(path)
        try:
            if not p.exists():
                continue
            ok, _ = verify(p)
            if ok:
                continue
            ok2, detail2 = harden(p, is_dir=p.is_dir())
            fixed.append((label, p, ok2, detail2))
        except Exception as exc:                  # noqa: BLE001
            fixed.append((label, p, False, f"{type(exc).__name__}: {exc}"))
    return fixed
