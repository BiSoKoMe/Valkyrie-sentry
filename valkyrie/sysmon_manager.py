"""Sysmon - a first-class Valkyrie dependency, not a bundled binary.

WHY SYSMON IS A DEPENDENCY, NOT AN OPTIONAL EXTRA
--------------------------------------------------
Three techniques Valkyrie claims to detect - T1055 (process injection) and
both T1003.001 paths (LSASS credential dumping) - are ONLY observable
through Sysmon's EID 8 (CreateRemoteThread) and EID 10 (ProcessAccess to
lsass.exe); nothing else in this product's sensor stack sees them. And
without Sysmon EID 1, command-line-shaped detection (the 40-rule IOA engine,
cmdline_normalize, the reconnaissance-burst sequence) falls back to a 2-second
psutil poll that most native Windows tools - which exit in well under a
second - simply outrun. A shipped client silently running that degraded path
is not an edge case worth a TODO; it is the difference between the product's
advertised detection rate and its real one. Hence: Sysmon is treated here as
a real dependency, the way a database or a TLS library would be, not as a
bundled convenience.

LICENSING
---------
The Sysinternals EULA does not permit redistribution. Valkyrie NEVER ships
Sysmon64.exe in the installer or the repo, and never commits it to source
control. Instead: download the official signed build from Microsoft's own
Sysinternals live endpoint at install/first-run time (`config.SYSMON_
DOWNLOAD_URL`), verify its Authenticode signature names Microsoft BEFORE
executing anything extracted from the archive, then install it with
Valkyrie's own minimal event config (`VALKYRIE_SYSMON_CONFIG` below) -
narrowly scoped to exactly the event types Valkyrie's detectors read
(1/3/6/7/8/10/11/13/25), not the much larger SwiftOnSecurity community config
used only by the dev/red-team provisioning script (redteam/provision.ps1),
which is appropriate for a researcher's box, not for a shipped agent's
telemetry footprint.

DEGRADED MODE IS A MAIN PATH, NOT AN EDGE CASE
------------------------------------------------
Found live on 2026-08-04, on the machine this code was written on: a
mainstream consumer AV (Avast) silently removed SysmonDrv.sys from disk with
no clean-uninstall trail (no SCM removal event, no uninstall command in any
shell history) sometime after a successful install, and Sysmon64 crashed 25
seconds after the next boot trying to reach its now-missing driver. Worse:
even an elevated Administrator token could not delete the resulting broken
service registration - `DeleteService` returned Access Denied despite a
service DACL that explicitly grants Administrators the delete right. That
combination (readable and queryable, but not modifiable, by an admin, against
a driver-backed service, despite a DACL that says it should work) is the
signature of a security product's self-defense driver intercepting the SCM
call, not a permissions bug on this host.

This is not a one-off. A very common class of consumer AV treats any new
kernel-driver-backed monitoring tool as suspicious by construction - that is
what Sysmon looks like to a behavioral AV engine, and it is exactly the kind
of interference a real fleet of client machines will hit. So this module
treats "Sysmon install was blocked by other security software" as a expected,
first-class OUTCOME with its own reported reason - not a caught exception on
the way to a generic error - and Valkyrie must come up and clearly report
which detection mode it is running in regardless of which branch fires.
Never fail closed: a missing or blocked Sysmon must degrade coverage, never
prevent the agent from starting.

SENSOR TAMPER DETECTION
------------------------
Nothing previously noticed when Valkyrie's OWN sensors disappeared - which is
exactly what happened live, with zero audit trail, on this development
machine while this ADR was being written. A detection sensor vanishing is
itself an attack technique (T1562.001 - Impair Defenses: Disable or Modify
Tools), and a security product that cannot notice its own blinding is not
defensible. See `sensor_tamper.py` for the periodic health check that turns
"a sensor silently died" into a CRITICAL incident instead of silence.

THE LONG-TERM ANSWER
---------------------
The kernel driver (`driver/valkyrie_km`, ADR 0026/0031/0043) removes this
dependency entirely once it ships: it needs no third-party AV's cooperation
to see process/thread/image-load events, because it IS a kernel component
with its own callback registrations, not a second driver an AV's behavioral
engine has to be talked into tolerating. Until it is signed and loadable in
production (it is currently unsigned and MUST NOT be loaded - see
driver/BRINGUP.md), Sysmon is the best available substitute for that
visibility and is treated with the seriousness of a real dependency, not a
nice-to-have.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import time
import zipfile
from dataclasses import asdict, dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Optional

from .config import DATA_DIR, SYSMON_DOWNLOAD_URL

# ---------------------------------------------------------------------------
# Environment probe (moved from redteam/evaluation/environment.py - this is
# now product code the running agent depends on, not just evaluation
# tooling. redteam/evaluation/environment.py re-exports from here so the
# red-team evaluation scores against the SAME probe the product uses,
# instead of a second implementation that could silently drift from it.)
# ---------------------------------------------------------------------------

# An event newer than this proves the pipeline is delivering right now. Ten
# minutes is loose enough to survive an idle desktop (Sysmon EID 3/7 traffic
# never really stops) and tight enough that a service stopped an hour ago fails.
FRESHNESS_SECONDS = 600

# Sysmon rule-config section names, keyed by the EID this project consumes.
_EID_RULE_SECTION = {
    1:  "ProcessCreate",
    3:  "NetworkConnect",
    6:  "DriverLoad",
    7:  "ImageLoad",
    8:  "CreateRemoteThread",
    10: "ProcessAccess",
    11: "FileCreate",
    13: "RegistryEvent",
}

_LOG_NAME = "Microsoft-Windows-Sysmon/Operational"


@dataclass
class SysmonEnvironment:
    """What is actually true about Sysmon on this host, with the evidence."""
    present: bool = False
    service_state: str = "not-found"
    log_enabled: bool = False
    log_record_count: int = 0
    newest_event_age_seconds: Optional[float] = None
    collection_live: bool = False
    configured_eids: tuple = ()
    config_hash: str = ""
    detail: str = ""
    errors: tuple = field(default_factory=tuple)
    # True when a probe step could not run because this process lacks the
    # privilege to look -- NOT because the thing being probed was absent.
    #
    # This distinction is load-bearing and its absence caused two false
    # diagnoses on 2026-08-23. The Sysmon operational log is
    # Administrators-only, and every read below uses -ErrorAction
    # SilentlyContinue, so an unprivileged probe produced log_enabled=False,
    # record_count=0, newest_event=None, collection_live=False -- byte-identical
    # to a genuinely dead sensor. The product then told a human it was blind
    # while it was in fact collecting 49,000 events. "I am not allowed to look"
    # and "there is nothing there" are different facts and must not render the
    # same.
    access_denied: bool = False

    @property
    def determinable(self) -> bool:
        """False when this probe could not establish the truth either way."""
        return not self.access_denied

    def provides(self, eid: int) -> bool:
        """True only if this host will actually deliver `eid` to a classifier.

        Stays False when undeterminable: authority must never be granted on an
        unverified sensor. Callers that need to explain themselves to a human
        must consult `determinable`/`why_not` rather than reading this as
        evidence of absence.
        """
        return (self.present and self.collection_live
                and eid in self.configured_eids)

    def why_not(self, eid: int) -> str:
        if self.access_denied:
            return ("cannot determine -- the Sysmon operational log is "
                    "readable only by Administrators and this probe ran "
                    "unprivileged. This is NOT evidence that Sysmon is dark; "
                    "re-run elevated to establish the truth")
        if not self.present:
            return f"Sysmon not installed/running on this host ({self.service_state})"
        if not self.collection_live:
            age = self.newest_event_age_seconds
            age_s = "no events at all" if age is None else f"newest event {age:.0f}s old"
            return (f"Sysmon present but collection is not live "
                    f"({age_s}, threshold {FRESHNESS_SECONDS}s)")
        if eid not in self.configured_eids:
            section = _EID_RULE_SECTION.get(eid, f"EID {eid}")
            return (f"Sysmon running, but '{section}' is absent from the active "
                    f"rule configuration -- EID {eid} is never emitted")
        return ""

    def as_dict(self) -> dict:
        return asdict(self)


def _powershell(script: str, timeout: int = 30) -> tuple:
    try:
        p = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return p.returncode == 0, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


# Substrings Windows/PowerShell emit when a read failed for PRIVILEGE reasons
# rather than because the target was missing. Matched case-insensitively.
_ACCESS_DENIED_MARKERS = (
    "unauthorizedaccessexception",
    "access is denied",
    "attempted to perform an unauthorized operation",
    "requested registry access is not allowed",
)


def _is_access_denied(text: str) -> bool:
    """True when this output is a permission failure, not a negative finding.

    Deliberately a text match: `Get-WinEvent -ErrorAction SilentlyContinue`
    gives us no structured error, so the only evidence available is what it
    printed. A false positive here costs a "cannot determine" instead of a
    definite answer, which is the safe direction to be wrong in.
    """
    low = (text or "").lower()
    return any(m in low for m in _ACCESS_DENIED_MARKERS)


def _decode_sysmon_config(raw: str) -> str:
    """`Sysmon64.exe -c` writes UTF-16 that arrives as text with NUL-ish gaps.

    Captured through a pipe it commonly lands as 'P r o c e s s A c c e s s'.
    Collapsing single-space-separated single characters recovers it. Cheap and
    tolerant: if the output was already sane this is close to a no-op.
    """
    if "\x00" in raw:
        raw = raw.replace("\x00", "")
    return re.sub(r"(?<=\b\w) (?=\w\b)", "", raw)


def probe_sysmon() -> SysmonEnvironment:
    """Read-only. Never installs, never changes anything, never raises."""
    env = SysmonEnvironment()
    if platform.system() != "Windows":
        env.service_state = "n/a-not-windows"
        env.detail = "Sysmon is Windows-only; this host is " + platform.system()
        return env

    errors: list = []

    ok, out = _powershell(
        "$s = Get-Service -Name Sysmon64,Sysmon -ErrorAction SilentlyContinue | "
        "Select-Object -First 1; if ($s) { $s.Status.ToString() } else { 'not-found' }"
    )
    env.service_state = out.strip().splitlines()[-1].strip() if ok and out.strip() else "not-found"
    if env.service_state != "Running":
        env.detail = f"Sysmon service state is '{env.service_state}'"
        env.errors = tuple(errors)
        return env
    env.present = True

    denied = False

    ok, out = _powershell(
        "(Get-WinEvent -ListLog '" + _LOG_NAME + "' -ErrorAction SilentlyContinue).IsEnabled"
    )
    denied = denied or _is_access_denied(out)
    env.log_enabled = ok and out.strip().lower().endswith("true")

    ok, out = _powershell(
        "(Get-WinEvent -ListLog '" + _LOG_NAME + "' -ErrorAction SilentlyContinue).RecordCount"
    )
    denied = denied or _is_access_denied(out)
    tail = out.strip().splitlines()[-1].strip() if out.strip() else ""
    try:
        env.log_record_count = int(float(tail))
    except ValueError:
        if env.log_enabled:
            errors.append(f"unparsable RecordCount {tail!r}")

    ok, out = _powershell(
        "$e = Get-WinEvent -LogName '" + _LOG_NAME + "' -MaxEvents 1 "
        "-ErrorAction SilentlyContinue; "
        "if ($e) { ((Get-Date) - $e.TimeCreated).TotalSeconds } else { -1 }"
    )
    denied = denied or _is_access_denied(out)
    tail = out.strip().splitlines()[-1].strip() if out.strip() else ""
    try:
        a = float(tail)
        env.newest_event_age_seconds = None if a < 0 else a
    except ValueError:
        # An access-denied here is a PRIVILEGE fact, not a malformed number.
        # Recording it as "unparsable" (the old behaviour) buried the one piece
        # of evidence that distinguished "cannot look" from "nothing there".
        if not _is_access_denied(out):
            errors.append(f"unparsable newest-event age {tail!r}")

    env.access_denied = denied

    env.collection_live = bool(
        env.log_enabled
        and env.newest_event_age_seconds is not None
        and env.newest_event_age_seconds <= FRESHNESS_SECONDS
    )

    if denied:
        # Do not let three swallowed permission errors masquerade as three
        # negative observations. collection_live stays False (authority is
        # never granted on an unverified sensor) but the DETAIL now says which
        # of the two worlds we are in.
        errors.append("Sysmon log reads were denied (probe is not elevated); "
                      "log_enabled/record_count/event-age above are NOT "
                      "observations")
        env.detail = ("cannot determine Sysmon collection state: the "
                      "operational log requires Administrator and this probe "
                      "ran unprivileged")

    ok, out = _powershell(
        "$p = (Get-CimInstance Win32_Service -Filter \"Name='Sysmon64' or Name='Sysmon'\" "
        "| Select-Object -First 1).PathName; "
        "if ($p) { $exe = ($p -replace '\"','').Trim(); & $exe -c }",
        timeout=60,
    )
    cfg = _decode_sysmon_config(out)
    if ok or "Rule configuration" in cfg or "Ruleconfiguration" in cfg:
        found = []
        for eid, section in _EID_RULE_SECTION.items():
            if re.search(rf"\b{section}\b", cfg):
                found.append(eid)
        env.configured_eids = tuple(sorted(found))
        m = re.search(r"Confighash:\s*(\S+)", cfg) or re.search(r"Config hash:\s*(\S+)", cfg)
        if m:
            env.config_hash = m.group(1)
    else:
        errors.append("could not read active Sysmon rule configuration")

    env.errors = tuple(errors)
    if env.access_denied:
        # The raw field dump below is actively misleading when the reads were
        # refused: "log_enabled=False records=0 newest_event_age=None" states
        # three negatives that were never observed. Lead with the truth and
        # keep the raw values behind an explicit label.
        env.detail = (
            "CANNOT DETERMINE Sysmon collection state -- the operational log "
            "requires Administrator and this probe ran unprivileged. The "
            "following are NOT observations: "
            f"log_enabled={env.log_enabled} records={env.log_record_count} "
            f"newest_event_age={env.newest_event_age_seconds}s. "
            f"Established: service={env.service_state} "
            f"configured_eids={list(env.configured_eids)}"
        )
    else:
        env.detail = (
            f"service={env.service_state} log_enabled={env.log_enabled} "
            f"records={env.log_record_count} "
            f"newest_event_age={env.newest_event_age_seconds}s "
            f"configured_eids={list(env.configured_eids)}"
        )
    return env


def check_requirements(requires: tuple, sysmon: SysmonEnvironment) -> tuple:
    """Return (all_met, reason_if_not). Unknown tokens fail CLOSED."""
    for token in requires:
        m = re.fullmatch(r"sysmon_eid(\d+)", token)
        if m:
            eid = int(m.group(1))
            if not sysmon.provides(eid):
                return False, sysmon.why_not(eid)
            continue
        return False, f"unknown precondition token {token!r} (failing closed)"
    return True, ""


# ---------------------------------------------------------------------------
# Install-time dependency management (new).
# ---------------------------------------------------------------------------

# Narrowly scoped to exactly what Valkyrie's own detectors read:
#   1  ProcessCreate      - command-line detection (IOA rules, cmdline_normalize,
#                           reconnaissance-burst)
#   3  NetworkConnect     - corroborates network_score.py's list-free signals
#   6  DriverLoad         - unsigned or user-directory driver load (BYOVD)
#   7  ImageLoad          - unsigned user-mode modules
#   8  CreateRemoteThread - T1055 process injection (etw/sysmon.py EID 8)
#   10 ProcessAccess      - T1003.001 LSASS credential dumping (EID 10),
#                           scoped to lsass.exe only - this is not a general
#                           process-access monitor
#   11 FileCreate         - startup-folder and browser-extension integrity
#   13 RegistryEvent      - Run-key and extension-policy integrity
#   25 ProcessTampering   - process hollowing
# Deliberately NOT the SwiftOnSecurity community config used by
# redteam/provision.ps1 for red-team research - that config is appropriate
# for a researcher's box, not for a shipped agent's telemetry footprint.
VALKYRIE_SYSMON_CONFIG = """<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- 1: process create (carries the COMMAND LINE - the key gap) -->
    <RuleGroup groupRelation="or"><ProcessCreate onmatch="exclude" /></RuleGroup>
    <!-- 3: network connect -->
    <RuleGroup groupRelation="or"><NetworkConnect onmatch="exclude" /></RuleGroup>
    <!-- 6: driver load - rare, high-value BYOVD evidence -->
    <RuleGroup groupRelation="or"><DriverLoad onmatch="exclude" /></RuleGroup>
    <!-- 7: image load - unsigned user-mode modules -->
    <RuleGroup groupRelation="or">
      <ImageLoad onmatch="include"><Signed condition="is">false</Signed></ImageLoad>
    </RuleGroup>
    <!-- 8: CreateRemoteThread -> T1055 process injection -->
    <RuleGroup groupRelation="or"><CreateRemoteThread onmatch="exclude" /></RuleGroup>
    <!-- 10: ProcessAccess to lsass -> T1003.001 credential dumping -->
    <RuleGroup groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="image">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
    <!-- 11: startup and browser-extension integrity. Nested AND rules keep
         browser cache/history writes out of the event log. -->
    <RuleGroup groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\\Start Menu\\Programs\\Startup</TargetFilename>
        <Rule groupRelation="and">
          <TargetFilename condition="contains">\\Google\\Chrome\\User Data\\</TargetFilename>
          <TargetFilename condition="contains">\\Extensions\\</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <TargetFilename condition="contains">\\Microsoft\\Edge\\User Data\\</TargetFilename>
          <TargetFilename condition="contains">\\Extensions\\</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <TargetFilename condition="contains">\\BraveSoftware\\Brave-Browser\\User Data\\</TargetFilename>
          <TargetFilename condition="contains">\\Extensions\\</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <TargetFilename condition="contains">\\Vivaldi\\User Data\\</TargetFilename>
          <TargetFilename condition="contains">\\Extensions\\</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <TargetFilename condition="contains">\\Mozilla\\Firefox\\Profiles\\</TargetFilename>
          <TargetFilename condition="contains">\\extensions\\</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <TargetFilename condition="contains">\\Mozilla\\Firefox\\Profiles\\</TargetFilename>
          <TargetFilename condition="end with">\\extensions.json</TargetFilename>
        </Rule>
        <!-- Preference writes matter only when a non-browser actor makes them.
             Browser self-writes are intentionally filtered at source. -->
        <Rule groupRelation="and">
          <TargetFilename condition="contains any">\\Google\\Chrome\\User Data\\;\\Microsoft\\Edge\\User Data\\;\\BraveSoftware\\Brave-Browser\\User Data\\;\\Vivaldi\\User Data\\</TargetFilename>
          <TargetFilename condition="contains any">\\Preferences;\\Secure Preferences</TargetFilename>
          <Image condition="excludes any">\\chrome.exe;\\msedge.exe;\\brave.exe;\\vivaldi.exe;\\opera.exe</Image>
        </Rule>
      </FileCreate>
    </RuleGroup>
    <!-- 12/13: registry autostart and extension force-install policy -->
    <RuleGroup groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">\\CurrentVersion\\Run</TargetObject>
        <TargetObject condition="contains any">\\ExtensionInstallForcelist;\\ExtensionSettings</TargetObject>
      </RegistryEvent>
    </RuleGroup>
    <!-- 25: process tampering (hollowing) -->
    <RuleGroup groupRelation="or"><ProcessTampering onmatch="exclude" /></RuleGroup>
  </EventFiltering>
</Sysmon>
"""

# A validly-signed-by-someone-else binary must NOT pass. Matched against the
# certificate subject string, the same shape Windows itself reports.
_MICROSOFT_SIGNER_MARKER = "O=Microsoft Corporation"

_MANAGED_MARKER_PATH = DATA_DIR / "sysmon_managed_by_valkyrie.json"

# Outcomes of install_or_verify(). Every branch is a real, expected shape -
# not a caught exception dressed up as a string.
MODE_ALREADY_OURS       = "already_ours"            # our config, healthy
MODE_INSTALLED          = "installed"               # fresh install succeeded
MODE_FOREIGN_CONFIG     = "foreign_config_left_alone"  # someone else's Sysmon; not touched
MODE_BLOCKED            = "blocked_by_security_software"  # the finding this ADR documents
MODE_BROKEN_NEEDS_REPAIR = "broken_needs_manual_repair"   # present, unhealthy, not ours to force-fix
MODE_DOWNLOAD_FAILED    = "download_failed"
MODE_SIGNATURE_REJECTED = "signature_rejected"
MODE_NOT_WINDOWS        = "not_windows"
MODE_UNKNOWN_ERROR      = "unknown_error"

# Modes in which Sysmon-dependent detection cannot be relied on. Never used to
# decide whether Valkyrie starts - only to decide what the status/ADR-mandated
# warning says.
DEGRADED_MODES = frozenset({
    MODE_FOREIGN_CONFIG, MODE_BLOCKED, MODE_BROKEN_NEEDS_REPAIR,
    MODE_DOWNLOAD_FAILED, MODE_SIGNATURE_REJECTED, MODE_NOT_WINDOWS,
    MODE_UNKNOWN_ERROR,
})


@dataclass
class SysmonInstallResult:
    mode: str
    degraded: bool
    reason: str
    env: SysmonEnvironment


def verify_microsoft_signed(path: Path) -> bool:
    """True only if *path* has a Valid Authenticode signature naming Microsoft
    as the signer. Best-effort, never raises, fails CLOSED on any error -
    an unverifiable binary must never be treated as trusted."""
    try:
        if not path.is_file():
            return False
        esc = str(path).replace("'", "''")
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             f"$s = Get-AuthenticodeSignature -LiteralPath '{esc}'; "
             f"if ($s.Status -eq 'Valid') {{ $s.SignerCertificate.Subject }}"],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return r.returncode == 0 and _MICROSOFT_SIGNER_MARKER in (r.stdout or "")
    except Exception:      # noqa: BLE001 - signature check must never raise
        return False


def download_sysmon(dest_dir: Path) -> Optional[Path]:
    """Download the official Sysmon archive and extract Sysmon64.exe.

    Returns the path to a verified-Microsoft-signed Sysmon64.exe, or None on
    any failure (network error, corrupt archive, missing entry, unsigned or
    non-Microsoft-signed binary). Never raises: a failed download degrades
    detection, it must never crash startup.
    """
    import urllib.request
    try:
        req = urllib.request.Request(
            SYSMON_DOWNLOAD_URL, headers={"User-Agent": "Valkyrie-SysmonSetup/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            blob = resp.read()
    except Exception:      # noqa: BLE001 - offline/blocked network is expected
        return None

    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(BytesIO(blob)) as zf:
            names = [n for n in zf.namelist() if n.lower().endswith("sysmon64.exe")]
            if not names:
                return None
            data = zf.read(names[0])
        exe_path = dest_dir / "Sysmon64.exe"
        exe_path.write_bytes(data)
    except Exception:      # noqa: BLE001 - corrupt/unexpected archive shape
        return None

    if not verify_microsoft_signed(exe_path):
        try:
            exe_path.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    return exe_path


def _run_sysmon(exe: Path, args: list, timeout: int = 60) -> tuple:
    try:
        r = subprocess.run(
            [str(exe), "-accepteula", *args],
            capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as exc:      # noqa: BLE001
        return -1, f"{type(exc).__name__}: {exc}"


def _write_config_file(workdir: Path) -> Path:
    cfg_path = workdir / "valkyrie_sysmon.xml"
    cfg_path.write_text(VALKYRIE_SYSMON_CONFIG, encoding="utf-8")
    return cfg_path


def _mark_managed(config_text: str) -> None:
    try:
        _MANAGED_MARKER_PATH.write_text(json.dumps({
            "installed_by": "valkyrie",
            "installed_at": time.time(),
            "config_sha256": hashlib.sha256(config_text.encode("utf-8")).hexdigest(),
        }), encoding="utf-8")
    except OSError:
        pass   # best-effort; worst case a later uninstall treats it as foreign


def _we_installed_it() -> bool:
    return _MANAGED_MARKER_PATH.exists()


def install_or_verify(workdir: Optional[Path] = None) -> SysmonInstallResult:
    """Ensure Sysmon is present and usable, or report clearly why it is not.

    NEVER raises, and never blocks startup: this only ever informs the
    caller what detection mode is available. Every branch below is a real,
    expected outcome - see the module docstring for why "blocked by another
    security product" specifically gets its own reported mode instead of
    reading as a generic failure.
    """
    if platform.system() != "Windows":
        return SysmonInstallResult(
            MODE_NOT_WINDOWS, True, "Sysmon is Windows-only", SysmonEnvironment())

    env = probe_sysmon()

    if env.present and env.collection_live:
        if _we_installed_it():
            return SysmonInstallResult(MODE_ALREADY_OURS, False,
                                       "Sysmon already installed and healthy "
                                       "(installed by Valkyrie)", env)
        # Someone else's Sysmon. Do NOT clobber it - their config may be
        # load-bearing for their own tooling. Report whether it happens to
        # cover what Valkyrie needs; degraded is judged on EID coverage, not
        # on authorship.
        needed = set(_EID_RULE_SECTION)
        have = set(env.configured_eids)
        missing = needed - have
        if not missing:
            return SysmonInstallResult(
                MODE_FOREIGN_CONFIG, False,
                "A pre-existing Sysmon installation (not Valkyrie's) already "
                "covers every event type Valkyrie needs; left untouched.", env)
        return SysmonInstallResult(
            MODE_FOREIGN_CONFIG, True,
            "A pre-existing Sysmon installation (not Valkyrie's) is running "
            f"but its active config does not include: "
            f"{sorted(_EID_RULE_SECTION[e] for e in missing)}. Left untouched "
            "rather than overwritten — detection depending on those event "
            "types is degraded.", env)

    if env.present and not env.collection_live:
        # Registered and "Running" per SCM, but not actually delivering
        # events - the exact broken shape found live on 2026-08-04 (driver
        # gone, service crash-looping). This is NOT ours to force-fix: an
        # automated uninstall/reinstall cycle risks repeating the same
        # self-defense collision that made THIS exact state undeletable even
        # from an elevated admin token. Report it; do not touch it.
        return SysmonInstallResult(
            MODE_BROKEN_NEEDS_REPAIR, True,
            "Sysmon service is registered but not delivering events "
            f"({env.detail}). This machine likely has the same failure mode "
            "documented in ADR 0048: a security product removed the kernel "
            "driver after install with no clean-uninstall trail. Automated "
            "repair is not attempted — it risks the same self-defense "
            "collision. Manual remediation (or a security-software "
            "exclusion for Sysmon) is required.", env)

    # Not present at all: attempt a fresh install.
    wd = Path(workdir) if workdir is not None else DATA_DIR / "sysmon_setup"
    exe = download_sysmon(wd)
    if exe is None:
        return SysmonInstallResult(
            MODE_DOWNLOAD_FAILED, True,
            f"Could not download/verify Sysmon from {SYSMON_DOWNLOAD_URL} "
            "(offline, blocked, or the binary was not validly signed by "
            "Microsoft). Command-line and injection/credential-dump "
            "detection will run in degraded mode.", env)

    cfg_path = _write_config_file(wd)
    rc, out = _run_sysmon(exe, ["-i", str(cfg_path)])

    post = probe_sysmon()
    if rc == 0 and post.present:
        _mark_managed(VALKYRIE_SYSMON_CONFIG)
        # A driver that gets removed by another security product minutes
        # after a "successful" install is exactly what this ADR documents -
        # a clean rc==0 here is necessary but not sufficient. The caller
        # (sensor_tamper.py) is what catches a LATER disappearance; this
        # function reports what it can observe right now.
        return SysmonInstallResult(MODE_INSTALLED, False,
                                   "Sysmon installed successfully.", post)

    # Install reported success but the driver isn't actually live, OR the
    # install call itself failed. Either way, this is the "blocked by
    # another security product" shape this ADR exists to name explicitly -
    # never surfaced as a bare/generic error.
    return SysmonInstallResult(
        MODE_BLOCKED, True,
        "Sysmon install did not result in a running, event-delivering "
        f"service (exit {rc}: {out.strip()[:400]!r}). The most common cause "
        "is another security product's self-defense/behavior-shield "
        "blocking a new kernel-driver-backed monitoring tool — treat this "
        "as expected on a meaningful fraction of client machines, not as an "
        "installer bug. Command-line and injection/credential-dump "
        "detection will run in degraded mode.", post)


def uninstall_valkyrie_sysmon() -> tuple:
    """Remove Sysmon ONLY if Valkyrie was the one that installed it.

    Returns (removed: bool, reason: str). A pre-existing, foreign Sysmon
    installation is never touched - Valkyrie has no way to know it is safe
    to remove someone else's monitoring setup, and assuming so is exactly
    the kind of "clobber the existing config" behavior Part 1c rules out.
    """
    if not _we_installed_it():
        return False, ("Sysmon was not installed by Valkyrie (no managed-by "
                       "marker found); leaving it in place.")
    env = probe_sysmon()
    if not env.present:
        try:
            _MANAGED_MARKER_PATH.unlink(missing_ok=True)
        except OSError:
            pass
        return True, "Sysmon was already absent; cleared the managed-by marker."

    exe = Path(r"C:\WINDOWS\Sysmon64.exe")
    if not exe.exists():
        return False, "Managed-by marker present but Sysmon64.exe is gone; " \
                      "cannot run an uninstall. Manual cleanup required."
    rc, out = _run_sysmon(exe, ["-u", "force"])
    if rc == 0:
        try:
            _MANAGED_MARKER_PATH.unlink(missing_ok=True)
        except OSError:
            pass
        return True, "Sysmon (installed by Valkyrie) uninstalled."
    return False, f"Uninstall failed (exit {rc}): {out.strip()[:400]!r}"
