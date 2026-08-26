r"""Restrict a secret file so only privileged principals can read it.

WHY THIS EXISTS
---------------
Valkyrie's TLS inspection needs a certificate authority, and it stores that
CA's **private key** on disk (`valkyrie-ca.key`, plus mitmproxy's own
`mitmproxy-ca.pem` in its config dir). Those files live under the engine's
data directory, which on Windows is `%ProgramData%\Valkyrie` - and
`%ProgramData%` subdirectories inherit a default ACL that grants
`BUILTIN\\Users` read access.

That is not a small permissions nit. Whoever holds that private key can mint
a valid-looking certificate for *any* domain and impersonate it to this
machine - bank, email, anything - and the browser shows a normal padlock,
because the machine has been told to trust that CA. So a world-readable CA
key turns "any local account, or any process running as one" into "total
TLS interception of this machine". It converts the security product into the
attack.

WHAT "PROPERLY" MEANS HERE
--------------------------
* **Set by SID, not by name.** `BUILTIN\\Administrators` is localised -
  `Administradores`, `Administrateurs`, ... - so a name-based ACL silently
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
  proceed, not continue quietly - the whole failure mode this module exists
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
# key - principally the inherited `BUILTIN\Users` grant on %ProgramData% - not
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

    # (OI)(CI) so newly created children inherit the restriction - this is what
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
    # for the SIDs named above - but any OTHER *explicit* ACE survives both.
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


def _verdict_from_sids(sids: set[str], err: str) -> tuple[bool, str]:
    """The ACL verdict for a Windows secret, given the SIDs that hold access.

    Single source of truth so the per-file ``verify()`` and the batched
    ``audit_secrets()`` cannot drift apart. A read error or an empty ACL is
    treated as NOT protected - the conservative direction for a secret we
    cannot confirm is locked down.
    """
    if err:
        return False, err
    if not sids:
        return False, "could not read ACL"
    # A forbidden principal is fatal regardless of anything else - these are the
    # ones that make a secret readable by every account on the machine.
    forbidden = sids & _FORBIDDEN_SIDS
    if forbidden:
        return False, f"world/group-readable via {sorted(forbidden)}"
    extra = sids - _allowed_sids()
    if extra:
        return False, f"readable by non-privileged principal(s): {sorted(extra)}"
    return True, f"restricted to {sorted(sids)}"


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
    return _verdict_from_sids(sids, err)


def describe(path: Path) -> str:
    """One-line human summary, for logs and the refuse-to-start message."""
    ok, detail = verify(path)
    return f"{'OK' if ok else 'EXPOSED'}: {path} — {detail}"


# ---------------------------------------------------------------------------
# The secret registry.
#
# Four separate secrets were found unprotected on Windows in a single audit -
# the TLS CA private key, the MAC install key, the API control token, and the
# fleet enrolment token - each for the same reason: DATA_DIR inherits a
# BUILTIN\Users:read ACE from %ProgramData%, so anything written there is
# world-readable unless something actively prevents it. Two of them even
# carried code that protected them on POSIX and explicitly skipped Windows.
#
# Fixing each write site is necessary but not sufficient: the next secret
# added will have the same default. This registry plus harden_known_secrets()
# is the systemic backstop - every launch re-asserts the invariant, so a
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
        # KEPT DELIBERATELY after the ADR 0044 freeze, even though core no
        # longer creates these. An upgrader who ran an older build still has a
        # real fleet_agent.json (device token) and wg0.conf (WireGuard
        # PrivateKey) sitting in DATA_DIR. Dropping them from the sweep would
        # stop protecting secrets that already exist on disk - a genuine
        # exposure - whereas hardening a path that is absent is a harmless
        # no-op (audit_secrets tolerates missing files by design, pinned by
        # test_secret_hygiene). Removing these was tried and correctly
        # rejected by that test.
        ("fleet enrolment token", C.FLEET_AGENT_IDENTITY_PATH),
        ("WireGuard server config", C.WIREGUARD_CONF_PATH),
        ("WireGuard client config", C.WIREGUARD_CLIENT_PATH),
        ("WireGuard hop-1 config", C.WIREGUARD_HOP1_CONF),
        ("WireGuard hop-2 config", C.WIREGUARD_HOP2_CONF),
    ]


def _access_sids_batch(paths: list[Path]) -> dict[str, tuple[set[str], str]]:
    """Read the access SIDs for MANY paths in a SINGLE PowerShell invocation.

    The per-file `access_sids()` spawns one PowerShell process each; auditing
    ~10 secrets that way cost ~6s (measured) and dominated the coverage
    refresh. One batched Get-Acl pass is the same read, ~10x fewer subprocess
    launches. Returns {str(path): (sids, err)}; any path the batch could not
    read back is marked unread so its verdict stays conservative (not
    protected), exactly as a single-file read error would.
    """
    result: dict[str, tuple[set[str], str]] = {}
    if not _IS_WINDOWS or not paths:
        return {str(p): (set(), "") for p in paths}

    def _q(s: object) -> str:                      # PowerShell single-quote escaping
        return "'" + str(s).replace("'", "''") + "'"

    arr = ",".join(_q(p) for p in paths)
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$ps=@({arr});"
        "foreach($p in $ps){'###P###'+$p;"
        "try{(Get-Acl -LiteralPath $p).Access|ForEach-Object{"
        "try{$_.IdentityReference.Translate("
        "[System.Security.Principal.SecurityIdentifier]).Value}"
        "catch{$_.IdentityReference.Value}}}"
        "catch{'###E###'+$_.Exception.Message}}"
    )
    code, out = _run([_POWERSHELL, "-NoProfile", "-NonInteractive",
                      "-Command", script])
    cur = None
    for raw in out.splitlines():
        ln = raw.strip()
        if not ln:
            continue
        if ln.startswith("###P###"):
            cur = ln[len("###P###"):]
            result.setdefault(cur, (set(), ""))
            continue
        if cur is None:
            continue
        if ln.startswith("###E###"):
            result[cur] = (set(), ln[len("###E###"):] or "Get-Acl failed")
            continue
        sids, err = result[cur]
        if err:
            continue
        result[cur] = (sids | {ln}, "")
    # A path the batch never echoed back (truncated/failed output) must not read
    # as protected - keep the conservative "unread" verdict for it.
    for p in paths:
        result.setdefault(str(p), (set(), "ACL not returned by batch read"))
    return result


def audit_secrets() -> list[tuple[str, Path, bool, str]]:
    """Report protection state for every known secret that exists on disk.

    On Windows the ACL reads are batched into a single PowerShell call (see
    `_access_sids_batch`) so the whole audit is one subprocess rather than one
    per file - the coverage layer runs this off the hot path, but it should not
    cost seconds. The verdict per file is identical to `verify()`.
    """
    existing: list[tuple[str, Path]] = []
    for label, path in known_secrets():
        try:
            p = Path(path)
            if p.exists():
                existing.append((label, p))
        except Exception:                          # noqa: BLE001
            # A path that cannot even be stat'd is not an exposed secret.
            continue

    if not _IS_WINDOWS:
        out = []
        for label, p in existing:
            try:
                ok, detail = verify(p)
            except Exception as exc:               # noqa: BLE001
                ok, detail = False, f"{type(exc).__name__}: {exc}"
            out.append((label, p, ok, detail))
        return out

    sids_by_path = _access_sids_batch([p for _, p in existing])
    out = []
    for label, p in existing:
        sids, err = sids_by_path.get(str(p), (set(), "ACL not read"))
        ok, detail = _verdict_from_sids(sids, err)
        out.append((label, p, ok, detail))
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
