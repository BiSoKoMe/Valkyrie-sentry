"""Is a file the operating system itself, or something dropped onto the box?

This is the single judgment behind a whole class of false positives found on
real hardware: Valkyrie flagged Windows Update (TrustedInstaller), Windows
Defender (MpDefenderCoreService, WdAiNisDrv.sys), Edge's updater, SmartScreen
(CHXSmartScreen.exe), and even its own installer as suspicious — because the
*shape* of what they do (create an autostart entry, carry a machine-looking
name) matches what malware does. What separates them is provenance: they are
signed OS components living in OS-owned locations, doing OS maintenance.

The rigorous signal is Authenticode code-signing, but verifying a signature
per event is a subprocess and far too expensive for the hot path. The standard
EDR proxy — used here — is the **trusted path**: a binary under a Windows-owned
root that a non-administrator cannot write to. An attacker who can already
write to ``C:\\Windows\\System32`` holds SYSTEM, at which point an autostart
entry is the least of the endpoint's problems and other signals will have
fired. So trusted-path is a sound noise-reduction proxy, not a security
boundary — and it is applied ONLY to downgrade noise, never to suppress a
signal that stands on its own.

Deliberately EXCLUDED from trust even though they sit inside trusted roots:
the world-writable scratch dirs (``\\Temp``, ``\\Tasks``), because malware
drops there too and the OS location must not launder it.
"""

from __future__ import annotations

import os

_SYS = os.environ.get("SystemRoot", r"C:\Windows")
_PF = os.environ.get("ProgramFiles", r"C:\Program Files")
_PF86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
_PD = os.environ.get("ProgramData", r"C:\ProgramData")


def _norm(p: str) -> str:
    return (p or "").strip().strip('"').lower().replace("\\", "/").rstrip("/")


def _pref(*parts: str) -> str:
    return _norm(os.path.join(*parts)) + "/"


# Roots owned by the OS / Microsoft signed code. Trailing slash so a prefix
# match is boundary-safe (``/windowsapps`` never matches ``/windowsappsevil``).
_TRUSTED_PREFIXES = tuple(sorted({
    _norm(_SYS) + "/",                                   # all of C:\Windows\...
    _pref(_PF, "Windows Defender"),
    _pref(_PF86, "Windows Defender"),
    _pref(_PD, "Microsoft", "Windows Defender"),
    _pref(_PF, "WindowsApps"),
    _pref(_PF86, "Microsoft", "Edge"),
    _pref(_PF86, "Microsoft", "EdgeWebView"),
    _pref(_PF86, "Microsoft", "EdgeCore"),
    _pref(_PF, "Microsoft", "Edge"),
    _pref(_PF, "Microsoft", "EdgeWebView"),
    _pref(_PF, "Common Files", "Microsoft Shared"),
}, key=len, reverse=True))

# World-writable scratch inside otherwise-trusted roots — never trusted.
_UNTRUSTED_WITHIN = ("/temp/", "/tmp/", "/tasks/",
                     "/downloaded program files/", "/appdata/local/temp/")


def is_trusted_os_path(path: str) -> bool:
    """True if *path* is a binary under a Windows/Microsoft-owned root that a
    normal user cannot write to (so OS self-maintenance is not a threat)."""
    p = _norm(path)
    if not p:
        return False
    # World-writable scratch inside a trusted root launders nothing.
    if any(bad in ("/" + p + "/") for bad in _UNTRUSTED_WITHIN):
        return False
    # Relative image forms from service ImagePath / driver registration:
    #   \SystemRoot\System32\...   system32\drivers\x.sys   syswow64\...
    if p.startswith(("/systemroot/", "systemroot/", "system32/", "syswow64/")):
        return True
    # Absolute Windows / Microsoft-signed roots.
    return p.startswith(_TRUSTED_PREFIXES)


def image_from_command(command: str) -> str:
    """Extract the leading executable path from a command line.

    Handles a quoted first token (``"C:\\...\\setup.exe" --flag``) and an
    unquoted one (``C:\\Windows\\System32\\reg.exe add ...``)."""
    c = (command or "").strip()
    if not c:
        return ""
    if c[0] in ('"', "'"):
        end = c.find(c[0], 1)
        return c[1:end] if end != -1 else c[1:]
    return c.split()[0] if c.split() else ""


def is_trusted_os_command(command: str) -> bool:
    """As is_trusted_os_path, but for a full command line (checks its image)."""
    return is_trusted_os_path(image_from_command(command))


# ---------------------------------------------------------------------------
# Valkyrie's own components — the security tool must never report ITSELF as the
# threat. Its resolver forwards to upstream DNS (so it "connects to 8.8.8.8"),
# its service writes an autostart entry, and its frozen engine is a native,
# LOLBin-shaped exe. All legitimate; flagging any of it is a pure false positive
# that also looks terrible to anyone evaluating the product.
# ---------------------------------------------------------------------------

_SELF_NAMES = frozenset({"valkyrie.exe", "valkyrie", "nssm.exe"})
_SELF_PATH_MARKERS = (
    "/program files/valkyrie/", "/program files (x86)/valkyrie/",
    "/programdata/valkyrie/", "/valkyrie/resources/engine/",
    "/appdata/local/programs/valkyrie/",
)


def is_self(name: str = "", path: str = "") -> bool:
    """True for Valkyrie's own processes / binaries / data directories."""
    if (name or "").strip().lower() in _SELF_NAMES:
        return True
    p = _norm(path)
    if not p:
        return False
    hay = "/" + p + "/"
    return any(m in hay for m in _SELF_PATH_MARKERS)


# Well-known public DNS resolvers / anycast infra. A connection to one of these
# — Valkyrie's own upstream forwarders, or any app's DNS/DoH — is not C2, so a
# stale learned-threat or an over-broad range can never paint Google/Cloudflare/
# Quad9 DNS as malicious.
_PUBLIC_RESOLVER_IPS = frozenset({
    "8.8.8.8", "8.8.4.4",                          # Google
    "1.1.1.1", "1.0.0.1",                          # Cloudflare
    "9.9.9.9", "149.112.112.112",                  # Quad9
    "208.67.222.222", "208.67.220.220",            # OpenDNS
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2620:fe::fe", "2620:fe::9",
})


def is_public_resolver_ip(ip: str) -> bool:
    """True for well-known public DNS resolver IPs (never treat as threat C2)."""
    return (ip or "").strip().lower() in _PUBLIC_RESOLVER_IPS


def is_benign_os_autorun(writer: str, target: str = "") -> bool:
    """An autostart write is benign OS churn when a trusted OS binary makes it
    AND what it points at is not in a world-writable scratch dir.

    This silences the constant legitimate autorun writes (services.exe,
    sihost.exe, TrustedInstaller, dismhost, WMIADAP) that otherwise flood as
    "autorun registry modification" false positives — while KEEPING the real
    abuse case, a trusted process dropping an autorun into %TEMP%, alerting.
    (The persistence collector remains the authoritative persistence detector
    and still raises a removable incident for genuine new autostart entries.)
    """
    if not is_trusted_os_path(writer):
        return False
    tgt = _norm(image_from_command(target)) if target else ""
    if tgt and any(bad in ("/" + tgt + "/") for bad in _UNTRUSTED_WITHIN):
        return False
    return True
