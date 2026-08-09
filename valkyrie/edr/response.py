"""Response actions — the "R" in EDR.

Every action is:
  * dry-run by default — you see exactly what *would* happen first;
  * audited — a ResponseAction row is written whether it ran, was simulated,
    or failed;
  * honest about privileges — an action that needs admin/root and doesn't have
    it reports ``skipped`` with the reason, it does not silently no-op.

Built-in responders:
  block_domain     — add a domain to the user block rules (enforced by DNS).
  unblock_domain   — remove it again.
  kill_process     — terminate a PID (never a system/critical PID).
  isolate_host     — network-contain the endpoint (block all egress except the
                     local resolver + loopback). Generates the exact commands;
                     applies them only with privileges + an explicit non-dry-run.
  release_isolation— lift containment.

Responders are ordinary ResponderPlugins, so a third-party plugin can add new
actions (quarantine file, disable NIC, notify SIEM, …) via the same registry.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import platform
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

from ..config import ISOLATION_BACKUP_DIR, PERSISTENCE_BACKUP_DIR
from . import cascade, invariants, leases, reversibility
from .plugins import PluginContext, ResponderPlugin
from .schema import ResponseAction, severity_rank

log = logging.getLogger("valkyrie.response")

_SYSTEM = platform.system()

# Cap what a startup-file rollback snapshot will hold inline as base64 in the
# backup JSON — a dropped ransomware payload can be hundreds of MB; there is
# no reason a rollback snapshot for an autostart entry needs to hold that
# much, and an unbounded read would make remove_persistence's latency depend
# on attacker-controlled file size.
_MAX_SNAPSHOT_FILE_BYTES = 5 * 1024 * 1024


# ---------------------------------------------------------------------------
# Persistence-removal rollback snapshots (valkyrie/edr/reversibility.py)
#
# remove_persistence used to be delete-only: once an autostart entry was gone,
# a false-positive removal (legitimate software misclassified) had no way
# back. Every ASEP type except service_install now gets a pre-delete snapshot
# here, undoable via the restore_persistence responder. service_install is
# the one exception -- see RemovePersistenceResponder._remove_service for why
# it stays a forensic-only snapshot rather than an automated restore.
# ---------------------------------------------------------------------------

def _pb_path() -> Path:
    PERSISTENCE_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    return PERSISTENCE_BACKUP_DIR / "removed.json"


def _pb_load() -> dict:
    p = _pb_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _pb_save(store: dict) -> None:
    try:
        _pb_path().write_text(json.dumps(store, indent=2), encoding="utf-8")
    except OSError:
        pass


def _pb_record(asep_type: str, identity: str, restorable: bool, data: dict) -> str:
    """Persist a pre-delete snapshot; returns the backup id, or "" on failure.

    Never raises -- a snapshot that can't be written must not block the
    removal itself (a stuck ASEP is a worse outcome than an un-rollback-able
    one), but the caller uses the empty-string return to say so honestly in
    its result message instead of implying a rollback exists that doesn't.
    """
    try:
        store = _pb_load()
        bid = uuid.uuid4().hex[:16]
        store[bid] = {
            "asep_type": asep_type, "identity": identity,
            "restorable": bool(restorable), "restored": False,
            "removed_at": time.time(), "data": data,
        }
        _pb_save(store)
        return bid
    except Exception:
        return ""

# PIDs / process names that must never be killed by an automated response.
_PROTECTED_PIDS = {0, 4}
_PROTECTED_NAMES = {
    "system", "systemd", "init", "svchost.exe", "services.exe", "lsass.exe",
    "csrss.exe", "wininit.exe", "smss.exe", "registry", "winlogon.exe",
    "kernel_task", "launchd",
}


def _is_admin() -> bool:
    """Best-effort privilege check across platforms."""
    try:
        if _SYSTEM == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# block_domain / unblock_domain
# ---------------------------------------------------------------------------

class BlockDomainResponder(ResponderPlugin):
    name = "responder.block_domain"
    description = "Block or unblock a domain via the analysis memory (no manual list)"

    def actions(self) -> list[str]:
        return ["block_domain", "unblock_domain"]

    def execute(self, action, target, *, dry_run, ctx):
        # Valkyrie keeps NO human-authored block/allow list. A block from the EDR
        # (a confirmed-C2 playbook, or a manual "block this") is recorded in the
        # ANALYSIS memory — the same learned-intelligence store the DNS engine
        # consults — so it is enforced on the next lookup without any rules file.
        domain = (target or "").strip().lower()
        if not domain or not all(c.isalnum() or c in ".-_*" for c in domain):
            return ("failed", f"invalid domain: {target!r}")
        intel = ctx.intelligence
        if intel is None:
            return ("skipped", "analysis (intelligence) layer not available")
        if action == "block_domain":
            if dry_run:
                return ("dry_run", f"would block '{domain}' via analysis memory")
            try:
                intel.remember_block(domain, "edr:auto_block")
            except Exception as exc:      # noqa: BLE001
                return ("failed", f"could not block '{domain}': {exc}")
            return ("succeeded",
                    f"'{domain}' blocked via analysis (effective next lookup)")
        # unblock_domain
        if dry_run:
            return ("dry_run", f"would mark '{domain}' known-good")
        try:
            intel.remember_good(domain, "")
        except Exception as exc:          # noqa: BLE001
            return ("failed", f"could not unblock '{domain}': {exc}")
        return ("succeeded", f"'{domain}' marked known-good (unblocked)")


# ---------------------------------------------------------------------------
# kill_process
# ---------------------------------------------------------------------------

class KillProcessResponder(ResponderPlugin):
    name = "responder.kill_process"
    description = "Terminate a process by PID (refuses system/critical PIDs)"

    def actions(self) -> list[str]:
        return ["kill_process"]

    def execute(self, action, target, *, dry_run, ctx):
        try:
            pid = int(str(target).strip())
        except (TypeError, ValueError):
            return ("failed", f"invalid pid: {target!r}")
        if pid in _PROTECTED_PIDS or pid <= 0:
            return ("skipped", f"refusing to kill protected pid {pid}")
        try:
            import psutil
        except ImportError:
            return ("skipped", "psutil not available — cannot kill by pid")
        try:
            proc = psutil.Process(pid)
            pname = (proc.name() or "").lower()
        except psutil.NoSuchProcess:
            return ("failed", f"no such process (pid {pid})")
        except psutil.AccessDenied:
            return ("skipped", f"access denied to pid {pid} (needs admin/root)")
        if pname in _PROTECTED_NAMES:
            return ("skipped", f"refusing to kill critical system process '{pname}'")
        if dry_run:
            return ("dry_run", f"would terminate '{pname}' (pid {pid})")
        try:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
            return ("succeeded", f"terminated '{pname}' (pid {pid})")
        except psutil.AccessDenied:
            return ("skipped", f"access denied terminating pid {pid} (needs admin/root)")
        except Exception as exc:
            return ("failed", f"kill failed: {exc}")


# ---------------------------------------------------------------------------
# isolate_host / release_isolation  (network containment)
# ---------------------------------------------------------------------------

class IsolateHostResponder(ResponderPlugin):
    """Network-contain the endpoint, with a rollback path that actually holds.

    A prior version of ``release_isolation`` reset the firewall to a
    HARDCODED policy (``blockinbound,allowoutbound``) instead of whatever
    policy existed before isolation — on this project's own machine, a live
    isolate/release cycle left the host's WiFi cut, because "restore" and
    "reset to a guessed default" are not the same operation. ``isolate_host``
    now snapshots the FULL pre-isolation firewall state first (``netsh
    advfirewall export`` / ``iptables-save``) and ``release_isolation``
    restores that exact snapshot (``netsh advfirewall import`` /
    ``iptables-restore``), falling back to the old fixed commands only when
    no snapshot exists (e.g. isolation applied by an older Valkyrie build).
    If the snapshot can't be captured, ``isolate_host`` now REFUSES to
    isolate rather than cut the network with no verified way back.
    """

    name = "responder.isolate_host"
    description = "Network-contain the endpoint (block egress except resolver + loopback)"

    def actions(self) -> list[str]:
        return ["isolate_host", "release_isolation"]

    def _snapshot_path(self) -> Path:
        ISOLATION_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        name = "firewall_state.wfw" if _SYSTEM == "Windows" else "iptables_state.rules"
        return ISOLATION_BACKUP_DIR / name

    def _commands(self, action: str) -> list[str]:
        """Return the exact platform commands this action would run.

        For release_isolation these are the FALLBACK ONLY, used when no
        pre-isolation snapshot exists — see execute(). They no longer are the
        primary rollback mechanism.
        """
        if _SYSTEM == "Windows":
            if action == "isolate_host":
                return [
                    'netsh advfirewall set allprofiles firewallpolicy '
                    'blockinbound,blockoutbound',
                    'netsh advfirewall firewall add rule name="Valkyrie-Isolate-Loopback" '
                    'dir=out action=allow remoteip=127.0.0.1',
                ]
            return ['netsh advfirewall set allprofiles firewallpolicy '
                    'blockinbound,allowoutbound',
                    'netsh advfirewall firewall delete rule name="Valkyrie-Isolate-Loopback"']
        else:  # Linux / macOS (iptables)
            if action == "isolate_host":
                return [
                    "iptables -I OUTPUT 1 -o lo -j ACCEPT",
                    "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT",
                    "iptables -A OUTPUT -j DROP",
                ]
            return ["iptables -D OUTPUT -j DROP",
                    "iptables -D OUTPUT -p udp --dport 53 -j ACCEPT",
                    "iptables -D OUTPUT -o lo -j ACCEPT"]

    def _backup_state(self) -> tuple[bool, str]:
        """Snapshot the FULL current firewall state before isolating.

        Returns (ok, detail) — detail is the snapshot path on success, or a
        diagnostic on failure. Never raises.
        """
        import subprocess
        path = self._snapshot_path()
        try:
            if _SYSTEM == "Windows":
                r = subprocess.run(
                    ["netsh", "advfirewall", "export", str(path)],
                    capture_output=True, text=True, timeout=20)
                if r.returncode != 0 or not path.exists():
                    return (False, (r.stderr or r.stdout or
                                    "netsh advfirewall export failed").strip())
                return (True, str(path))
            r = subprocess.run(["iptables-save"], capture_output=True,
                               text=True, timeout=20)
            if r.returncode != 0:
                return (False, (r.stderr or "iptables-save failed").strip())
            path.write_text(r.stdout, encoding="utf-8")
            return (True, str(path))
        except Exception as exc:                          # noqa: BLE001
            return (False, f"{type(exc).__name__}: {exc}")

    def _restore_state(self) -> tuple[bool, str]:
        """Restore the pre-isolation snapshot, if one exists. Never raises."""
        import subprocess
        path = self._snapshot_path()
        if not path.exists():
            return (False, "no pre-isolation snapshot found")
        try:
            if _SYSTEM == "Windows":
                r = subprocess.run(
                    ["netsh", "advfirewall", "import", str(path)],
                    capture_output=True, text=True, timeout=20)
                ok, detail = r.returncode == 0, (r.stderr or r.stdout or "").strip()
            else:
                with open(path, "r", encoding="utf-8") as f:
                    r = subprocess.run(["iptables-restore"], stdin=f,
                                       capture_output=True, text=True, timeout=20)
                ok, detail = r.returncode == 0, (r.stderr or "").strip()
            if ok:
                try:
                    # Consumed: a stale snapshot must never be silently
                    # reapplied by a LATER, unrelated release_isolation call.
                    path.unlink()
                except OSError:
                    pass
            return (ok, detail or str(path))
        except Exception as exc:                          # noqa: BLE001
            return (False, f"{type(exc).__name__}: {exc}")

    def execute(self, action, target, *, dry_run, ctx):
        cmds = self._commands(action)
        verb = "isolate endpoint" if action == "isolate_host" else "release isolation"
        if dry_run:
            note = (" A full firewall-state snapshot is captured first so "
                    "release_isolation can restore exactly what existed, not "
                    "a hardcoded default policy."
                    if action == "isolate_host" else
                    " Prefers restoring the pre-isolation snapshot captured "
                    "at isolate time; falls back to these fixed commands "
                    "only if no snapshot exists.")
            return ("dry_run", f"would {verb} via:\n  " + "\n  ".join(cmds) + "\n" + note)
        if not _is_admin():
            return ("skipped",
                    f"cannot {verb}: needs admin/root. Commands:\n  " + "\n  ".join(cmds))

        if action == "isolate_host":
            backed_up, detail = self._backup_state()
            if not backed_up:
                # This IS the fix for the real incident: isolating with no
                # verified way back is exactly what cut this host's WiFi.
                return ("skipped",
                        f"refusing to isolate: could not capture a "
                        f"pre-isolation firewall snapshot first ({detail}) "
                        f"— isolating without a verified rollback path "
                        f"violates this action's reversibility floor")

        import subprocess
        errors = []
        for c in cmds:
            try:
                # Shell use is safe here by construction: every string comes
                # from _commands() above, which returns fixed literals chosen by
                # an internal `action` enum. No caller input, incident field, or
                # hostname is ever interpolated, so there is no injection
                # surface. Kept as-is rather than refactored to argv because
                # this path installs live firewall rules and cannot be exercised
                # safely outside a VM, so changing it blind is the greater risk.
                # Revisit during VM validation (docs/TEST_PLAN.md tier 4).
                subprocess.run(c, shell=True, check=True,  # nosec B602
                               capture_output=True)
            except subprocess.CalledProcessError as exc:
                errors.append(f"{c!r}: {exc.stderr.decode(errors='replace').strip()}")
        if errors:
            return ("failed", f"{verb} partially failed: " + "; ".join(errors))

        if action == "release_isolation":
            restored, detail = self._restore_state()
            if restored:
                return ("succeeded",
                        f"{verb} applied; full pre-isolation firewall state "
                        f"restored from snapshot ({detail})")
            return ("succeeded",
                    f"{verb} applied via explicit rule removal only — "
                    f"{detail}; if the pre-isolation policy differed from "
                    f"Valkyrie's default, it was NOT restored")
        return ("succeeded",
                f"{verb} applied; pre-isolation firewall state snapshotted "
                f"for rollback via release_isolation")


# ---------------------------------------------------------------------------
# remove_persistence  (rip out an attacker-created autostart entry)
# ---------------------------------------------------------------------------

class RemovePersistenceResponder(ResponderPlugin):
    """Remove a single attacker-created Auto-Start Extension Point (ASEP).

    The target is a structured descriptor ``"<type>::<identity>"`` that the
    persistence detection places on its incident entity, so a playbook needs
    only ``target_from: entity`` to hand us exactly what to remove:

        scheduled_task::<task path>        → schtasks /delete /tn <path> /f
        service_install::<service name>    → sc stop + sc delete <name>
        registry_run_key::<loc>::<value>   → winreg DeleteValue
        startup_folder::<full file path>   → delete the dropped file

    Safety model (removing persistence is far less destructive than killing a
    process, but still guarded):
      * A denylist of critical Windows service names is never deleted.
      * System scheduled-task trees (``Microsoft\\Windows\\``) are never deleted.
      * Startup-folder deletes are confined to recognised Startup directories.
      * Registry deletes are confined to the known autorun keys.
      * Missing privilege reports ``skipped`` with the reason — never a silent
        no-op — exactly like the other responders.

    Reversibility (IIBA §4.2.5 — this used to be delete-only, no way back):
    ``scheduled_task``, ``registry_run_key`` and ``startup_folder`` now
    snapshot the exact prior state BEFORE deleting (task XML export /
    registry value+type / file bytes) into ``PERSISTENCE_BACKUP_DIR``, so a
    false-positive removal can be undone via
    ``RestorePersistenceResponder`` (action ``restore_persistence``, target =
    the backup id returned in the result message).

    ``service_install`` is the deliberate exception: reconstructing a Windows
    service from ``sc qc`` output well enough to auto-recreate it correctly
    is not reliable (failure actions, SIDs, and descriptions live outside
    ``sc qc``'s output), and a subtly-wrong auto-recreated service is a worse
    outcome than an honestly-irreversible deletion. It still captures a
    forensic ``sc qc`` snapshot for a human to recreate the service by hand,
    but is marked ``restorable: False`` and ``restore_persistence`` refuses
    it rather than attempt a reconstruction it cannot guarantee.
    """

    name = "responder.remove_persistence"
    description = "Remove an attacker-created autostart entry (task/service/run-key/startup file)"

    _PROTECTED_SERVICES = {
        "windefend", "wdnissvc", "wscsvc", "securityhealthservice", "sense",
        "wuauserv", "bits", "eventlog", "dnscache", "rpcss", "dcomlaunch",
        "lsm", "samss", "schedule", "termservice", "winmgmt", "trustedinstaller",
        "mpssvc", "sysmon", "sysmon64", "lanmanserver", "lanmanworkstation",
        "netlogon", "profsvc", "gpsvc", "valkyrie", "nssm",
    }

    def actions(self) -> list[str]:
        return ["remove_persistence"]

    def execute(self, action, target, *, dry_run, ctx):
        asep_type, sep, identity = (target or "").partition("::")
        asep_type = asep_type.strip().lower()
        identity = identity.strip()
        if not sep or not identity:
            return ("failed",
                    f"target must be '<type>::<identity>', got {target!r}")
        handler = {
            "scheduled_task":    self._remove_task,
            "service_install":   self._remove_service,
            "registry_run_key":  self._remove_run_key,
            "startup_folder":    self._remove_startup_file,
        }.get(asep_type)
        if handler is None:
            return ("failed", f"unknown persistence type {asep_type!r}")
        try:
            return handler(identity, dry_run)
        except Exception as exc:                       # noqa: BLE001
            return ("failed", f"remove_persistence error: {type(exc).__name__}: {exc}")

    # -- scheduled task -----------------------------------------------------
    def _remove_task(self, identity: str, dry_run: bool) -> tuple[str, str]:
        name = identity.replace("/", "\\").lstrip("\\")
        if name.lower().startswith("microsoft\\windows\\"):
            return ("skipped", f"refusing to delete system scheduled task '{name}'")
        tn = "\\" + name
        if dry_run:
            return ("dry_run", f"would delete scheduled task '{tn}' "
                               f"(schtasks /delete /tn {tn} /f) — a rollback "
                               f"snapshot (task XML export) is captured first")
        import subprocess
        backup_id = ""
        try:
            xr = subprocess.run(["schtasks", "/query", "/tn", tn, "/xml", "ONE"],
                                capture_output=True, text=True, timeout=20)
            if xr.returncode == 0 and xr.stdout.strip():
                backup_id = _pb_record("scheduled_task", identity, True,
                                       {"tn": tn, "xml": xr.stdout})
        except Exception:                                # noqa: BLE001
            pass   # best-effort snapshot; must never block the removal itself
        r = subprocess.run(["schtasks", "/delete", "/tn", tn, "/f"],
                           capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            suffix = (f" (rollback: restore_persistence '{backup_id}')" if backup_id
                     else " (no rollback snapshot captured — restore is manual)")
            return ("succeeded", f"deleted scheduled task '{tn}'{suffix}")
        err = (r.stderr or r.stdout or "").strip()
        if "access is denied" in err.lower():
            return ("skipped", f"access denied deleting task '{tn}' (needs admin)")
        return ("failed", f"schtasks delete '{tn}' failed: {err}")

    # -- service ------------------------------------------------------------
    def _remove_service(self, identity: str, dry_run: bool) -> tuple[str, str]:
        svc = identity.strip().strip('"')
        if svc.lower() in self._PROTECTED_SERVICES:
            return ("skipped", f"refusing to delete protected service '{svc}'")
        if dry_run:
            return ("dry_run", f"would stop and delete service '{svc}' "
                               f"(sc.exe delete {svc}) — NOTE: service deletion "
                               f"cannot be auto-restored, only a forensic config "
                               f"snapshot (sc qc) is captured for manual recreation")
        import subprocess
        forensic_id = ""
        try:
            qc = subprocess.run(["sc.exe", "qc", svc],
                                capture_output=True, text=True, timeout=20)
            forensic_id = _pb_record("service_install", identity, False,
                                     {"sc_qc": qc.stdout})
        except Exception:                                # noqa: BLE001
            pass   # best-effort forensic capture only; must not block the delete
        subprocess.run(["sc.exe", "stop", svc],
                       capture_output=True, text=True, timeout=20)
        r = subprocess.run(["sc.exe", "delete", svc],
                           capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            suffix = (f" (forensic snapshot '{forensic_id}' saved for MANUAL "
                      f"recreation — service deletion is not auto-restorable)"
                     if forensic_id else " (no forensic snapshot captured)")
            return ("succeeded", f"deleted service '{svc}'{suffix}")
        err = (r.stderr or r.stdout or "").strip()
        if "access is denied" in err.lower():
            return ("skipped", f"access denied deleting service '{svc}' (needs admin)")
        return ("failed", f"sc delete '{svc}' failed: {err}")

    # -- registry run key ---------------------------------------------------
    def _remove_run_key(self, identity: str, dry_run: bool) -> tuple[str, str]:
        # identity is "<display loc>::<value name>"; the display loc maps back to
        # a real (hive, subkey) via the persistence collector's own spec table,
        # so we never guess a registry path.
        loc, sep, value = identity.rpartition("::")
        if not sep:
            return ("failed", f"malformed run-key identity {identity!r}")
        try:
            import winreg
            from ..persistence_telemetry import _run_key_specs
        except Exception as exc:                       # noqa: BLE001
            return ("failed", f"registry access unavailable: {exc}")
        loc2hive = {display: (hive, subkey)
                    for hive, subkey, display in _run_key_specs()}
        coords = loc2hive.get(loc.strip())
        if coords is None:
            return ("skipped", f"unrecognised run-key location '{loc}'")
        hive, subkey = coords
        if dry_run:
            return ("dry_run", f"would delete run-key value '{value}' under {loc} "
                               f"— a rollback snapshot is captured first")
        backup_id = ""
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as k:
                existing, reg_type = winreg.QueryValueEx(k, value)
            backup_id = _pb_record("registry_run_key", identity, True,
                                   {"loc": loc.strip(), "value": value,
                                    "existing": existing, "reg_type": reg_type})
        except FileNotFoundError:
            pass   # nothing to back up -- the value is already gone
        except OSError:
            pass   # best-effort snapshot; a read failure must not block removal
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, value)
        except FileNotFoundError:
            return ("succeeded", f"run-key value '{value}' already gone")
        except PermissionError:
            return ("skipped", f"access denied removing run-key '{value}' (needs admin)")
        suffix = (f" (rollback: restore_persistence '{backup_id}')" if backup_id
                 else " (no rollback snapshot captured — restore is manual)")
        return ("succeeded", f"removed run-key value '{value}' under {loc}{suffix}")

    # -- startup folder file ------------------------------------------------
    def _remove_startup_file(self, identity: str, dry_run: bool) -> tuple[str, str]:
        try:
            from ..persistence_telemetry import _startup_dirs
        except Exception as exc:                       # noqa: BLE001
            return ("failed", f"startup path lookup unavailable: {exc}")
        path = os.path.normpath(identity)
        allowed = [os.path.normpath(d).lower() for d in _startup_dirs()]
        if not any(path.lower().startswith(d) for d in allowed):
            return ("skipped",
                    f"refusing to delete '{path}' — outside recognised Startup folders")
        if dry_run:
            return ("dry_run", f"would delete startup file '{path}' — a rollback "
                               f"snapshot of its bytes is captured first")
        backup_id = ""
        try:
            size = os.path.getsize(path)
            if size <= _MAX_SNAPSHOT_FILE_BYTES:
                content_b64 = base64.b64encode(Path(path).read_bytes()).decode("ascii")
                backup_id = _pb_record("startup_folder", identity, True,
                                       {"path": path, "content_b64": content_b64})
        except FileNotFoundError:
            pass   # nothing to back up -- the file is already gone
        except OSError:
            pass   # best-effort snapshot; a read failure must not block removal
        try:
            os.remove(path)
        except FileNotFoundError:
            return ("succeeded", f"startup file '{path}' already gone")
        except PermissionError:
            return ("skipped", f"access denied deleting '{path}' (needs admin)")
        suffix = (f" (rollback: restore_persistence '{backup_id}')" if backup_id
                 else " (no rollback snapshot captured — file was too large or "
                      "unreadable; restore is manual)")
        return ("succeeded", f"deleted startup file '{path}'{suffix}")


# ---------------------------------------------------------------------------
# restore_persistence  (undo a remove_persistence action from its snapshot)
# ---------------------------------------------------------------------------

class RestorePersistenceResponder(ResponderPlugin):
    """Reverse a ``remove_persistence`` action from the snapshot it captured.

    Target is the backup id returned in a ``remove_persistence`` result
    message (e.g. ``"remove_persistence"`` said ``"...(rollback:
    restore_persistence 'a1b2c3d4e5f6a7b8')"`` — the target here is that id).
    Explicit and operator-invoked only, never automatic: whether a removal
    was a false positive is a judgement call restore_persistence does not
    make for you (unlike the removal itself, which correlation/detection
    already decided).
    """

    name = "responder.restore_persistence"
    description = "Undo a remove_persistence action from its pre-delete snapshot"

    def actions(self) -> list[str]:
        return ["restore_persistence"]

    def execute(self, action, target, *, dry_run, ctx):
        bid = (target or "").strip()
        if not bid:
            return ("failed", "target must be a backup id")
        store = _pb_load()
        entry = store.get(bid)
        if entry is None:
            return ("failed", f"no rollback snapshot found for id '{bid}'")
        if entry.get("restored"):
            return ("skipped", f"snapshot '{bid}' was already restored")
        if not entry.get("restorable", False):
            return ("skipped",
                    f"'{entry.get('asep_type')}' removal of "
                    f"'{entry.get('identity')}' has no automated rollback — "
                    f"see the forensic snapshot data for manual recreation")
        handler = {
            "registry_run_key": self._restore_run_key,
            "startup_folder":   self._restore_startup_file,
            "scheduled_task":   self._restore_scheduled_task,
        }.get(entry.get("asep_type"))
        if handler is None:
            return ("failed", f"no restore handler for '{entry.get('asep_type')}'")
        if dry_run:
            return ("dry_run", f"would restore {entry['asep_type']} "
                               f"'{entry['identity']}' from snapshot '{bid}'")
        try:
            status, msg = handler(entry["data"])
        except Exception as exc:                          # noqa: BLE001
            return ("failed", f"restore error: {type(exc).__name__}: {exc}")
        if status == "succeeded":
            try:
                store = _pb_load()
                if bid in store:
                    store[bid]["restored"] = True
                    _pb_save(store)
            except Exception:                             # noqa: BLE001
                pass   # the restore itself already succeeded; bookkeeping is best-effort
        return (status, msg)

    def _restore_run_key(self, data: dict) -> tuple[str, str]:
        try:
            import winreg
            from ..persistence_telemetry import _run_key_specs
        except Exception as exc:                          # noqa: BLE001
            return ("failed", f"registry access unavailable: {exc}")
        loc2hive = {display: (hive, subkey)
                    for hive, subkey, display in _run_key_specs()}
        coords = loc2hive.get(data["loc"])
        if coords is None:
            return ("failed",
                    f"unrecognised run-key location '{data['loc']}' "
                    f"(persistence spec table changed since removal?)")
        hive, subkey = coords
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, data["value"], 0, data["reg_type"], data["existing"])
        except PermissionError:
            return ("skipped",
                    f"access denied restoring run-key '{data['value']}' (needs admin)")
        return ("succeeded",
                f"restored run-key value '{data['value']}' under {data['loc']}")

    def _restore_startup_file(self, data: dict) -> tuple[str, str]:
        try:
            content = base64.b64decode(data["content_b64"])
            Path(data["path"]).write_bytes(content)
        except PermissionError:
            return ("skipped", f"access denied restoring '{data['path']}' (needs admin)")
        except OSError as exc:
            return ("failed", f"restore write failed: {exc}")
        return ("succeeded", f"restored startup file '{data['path']}'")

    def _restore_scheduled_task(self, data: dict) -> tuple[str, str]:
        import subprocess
        import tempfile
        tn = data["tn"]
        try:
            fd, xml_path = tempfile.mkstemp(suffix=".xml")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data["xml"])
        except OSError as exc:
            return ("failed", f"could not write task XML for restore: {exc}")
        try:
            r = subprocess.run(["schtasks", "/create", "/tn", tn, "/xml", xml_path, "/f"],
                               capture_output=True, text=True, timeout=20)
        finally:
            try:
                os.remove(xml_path)
            except OSError:
                pass
        if r.returncode == 0:
            return ("succeeded", f"restored scheduled task '{tn}'")
        err = (r.stderr or r.stdout or "").strip()
        return ("failed", f"schtasks create '{tn}' failed: {err}")


# ---------------------------------------------------------------------------
# ResponseManager — the front door the web API / CLI / fleet call
# ---------------------------------------------------------------------------

BUILTIN_RESPONDERS = [
    BlockDomainResponder,
    KillProcessResponder,
    IsolateHostResponder,
    RemovePersistenceResponder,
    RestorePersistenceResponder,
]


def register_responders(registry) -> None:
    for cls in BUILTIN_RESPONDERS:
        registry.register(cls())


class ResponseManager:
    """Dispatches response actions to responders and audits every attempt."""

    def __init__(self, registry, ctx: PluginContext, edr_store=None) -> None:
        self._registry = registry
        self._ctx = ctx
        self._store = edr_store

    def available_actions(self) -> list[str]:
        return self._registry.available_actions()

    def _reversibility_floor_block(self, action: str, incident_id: str,
                                    severity: str) -> Optional[tuple[str, str]]:
        """Enforce IIBA §4.2.5's "require a higher confidence floor" rule for
        actions with no rollback path. Returns a (status, result) tuple to
        use INSTEAD of running the responder, or None to proceed.

        Only IRREVERSIBLE actions are hard-gated here — a reversible action
        (block/isolate/remove-with-snapshot) can be undone if a human judges
        it wrong, so a manual operator call with no incident context is a
        legitimate, low-risk use that must keep working. An irreversible
        action (kill_process) gets exactly one chance to be right, so it must
        prove the incident actually clears the floor before it is allowed to
        run for real — "severity unknown" does not clear it.
        """
        rev = reversibility.get(action)
        if rev is None or rev.reversible:
            return None
        sev = severity
        if not sev and incident_id and self._store is not None:
            try:
                inc = self._store.get_incident(incident_id)
                if inc is not None:
                    sev = inc.severity
            except Exception:                             # noqa: BLE001
                sev = ""
        if not sev or severity_rank(sev) < severity_rank(rev.min_severity):
            return ("skipped",
                    f"refusing '{action}': irreversible action requires "
                    f"incident severity >= '{rev.min_severity}' "
                    f"(got: {sev or 'unknown — no incident_id/severity given'}) "
                    f"— confidence floor for actions with no rollback path")
        return None

    def _after_enforced(self, action: str, target: str,
                        lease_ttl_s: Optional[float]) -> None:
        """Book-keeping after an enforcement action really ran.

        Two things, both best-effort: neither may take down the response path,
        because a bookkeeping failure must not turn a successful enforcement
        into a reported failure.

        The lease is granted AFTER the action succeeds, never before. A lease
        recorded for enforcement that then failed to apply would schedule a
        reverse action against a host state that was never changed.
        """
        try:
            cascade.budget().record(action, target)
        except Exception:                                  # noqa: BLE001
            log.exception("cascade budget record failed for %s on %s", action, target)
        rev = reversibility.get(action)
        if rev is not None and rev.leasable:
            try:
                leases.registry().grant(
                    action, target,
                    ttl_s=lease_ttl_s or leases.DEFAULT_TTL_S,
                    reason=f"auto-granted on {action}")
            except Exception:                              # noqa: BLE001
                log.exception("lease grant failed for %s on %s", action, target)

    def _invariant_block(self, action: str, target: str) -> Optional[tuple[str, str]]:
        """Categorical veto. Checked BEFORE the severity floor, because a floor
        is a threshold and this is not -- there is no severity at which
        disabling the user's network adapter or terminating lsass.exe becomes
        the right call. See valkyrie/edr/invariants.py.
        """
        inv = invariants.check(action, target)
        if inv is None:
            return None
        return ("skipped",
                f"refusing '{action}' on '{target}': invariant "
                f"{inv.invariant_id!r} — {inv.reason}")

    def sweep_expired_leases(self, *, dry_run: bool = False,
                             now: Optional[float] = None) -> list[ResponseAction]:
        """Revert every enforcement whose lease has run out.

        This is the half of the lease design that makes it real: without a
        sweeper, a lease is a note nobody reads and a time-boxed block is just
        a permanent one. Reverse actions are RESTORATIVE (unblock_domain,
        release_isolation) -- a sweep can only ever remove enforcement, never
        add it, so a bug here fails toward the host being less constrained.

        Leases whose deadline passed while the process was down are included,
        which is why they are persisted (see leases.py).
        """
        out: list[ResponseAction] = []
        reg = leases.registry()
        for lease in reg.due(now=now):
            act = self.respond(lease.reverse_action, lease.target,
                               dry_run=dry_run, operator="lease-sweeper",
                               severity="critical")
            out.append(act)
            # Release only on a real, successful revert. If the reverse action
            # failed, the lease stays due and the next sweep retries it --
            # dropping it here would strand the very enforcement this exists
            # to lift.
            if not dry_run and act.status in ("ok", "success", "completed"):
                reg.release(lease.lease_id)
        return out

    def respond(self, action: str, target: str = "", *, dry_run: bool = True,
                operator: str = "local", incident_id: str = "",
                severity: str = "", lease_ttl_s: Optional[float] = None) -> ResponseAction:
        """Run (or simulate) a response action and return the audited record.

        ``severity`` lets a caller that already knows the triggering
        incident's severity pass it directly; otherwise it is looked up via
        ``incident_id``. Only consulted for actions the reversibility
        registry marks irreversible (see ``_reversibility_floor_block``).
        """
        act = ResponseAction(action=action, target=target, dry_run=dry_run,
                             operator=operator, incident_id=incident_id)
        responder = self._registry.responder_for(action)
        if responder is None:
            act.status = "failed"
            act.result = f"no responder handles action '{action}'"
        else:
            # Invariants first: categorical, and cheap to check. A severity
            # floor is a threshold that a confident-enough incident clears;
            # this is not one, so it must not sit behind it.
            block = (self._invariant_block(action, target)
                     if not dry_run else None)
            if block is None and not dry_run:
                block = self._reversibility_floor_block(action, incident_id, severity)
            if block is not None:
                act.status, act.result = block
            else:
                try:
                    status, result = responder.execute(
                        action, target, dry_run=dry_run, ctx=self._ctx)
                    act.status, act.result = status, result
                except Exception as exc:          # noqa: BLE001
                    act.status = "failed"
                    act.result = f"responder error: {type(exc).__name__}: {exc}"
                else:
                    if not dry_run and status in ("ok", "success", "completed"):
                        self._after_enforced(action, target, lease_ttl_s)
        if self._store is not None:
            try:
                self._store.record_response(act)
            except Exception:
                # An audit-trail write failing must never crash the response
                # path, but it must not vanish either — a response that
                # "succeeded" yet was never recorded is exactly the kind of
                # gap an EDR cannot afford to have silently.
                log.exception("failed to record response audit row for action %s (incident %s)",
                             act.action, act.incident_id)
        return act


# ---------------------------------------------------------------------------
# Reversibility registry entries — one per action, checked by
# tests/test_responder_reversibility.py against every registered responder
# action so a new one can't ship undocumented. See valkyrie/edr/reversibility.py.
# ---------------------------------------------------------------------------

reversibility.register(reversibility.Reversibility(
    action="block_domain", reversible=True,
    rollback="unblock_domain (intel.remember_good) reverses it on the next DNS lookup",
    residual_on_crash="none — a single synchronous intel.remember_block() call; "
                      "if the process dies before it returns, the block was never "
                      "recorded, so there is nothing left behind",
    false_positive_impact="a benign domain stops resolving until unblock_domain "
                          "runs; no data loss, no persistent host-state change "
                          "beyond the analysis-memory entry itself",
    min_severity="low",
    reverse_action="unblock_domain",
))
reversibility.register(reversibility.Reversibility(
    action="unblock_domain", reversible=True,
    rollback="block_domain re-applies the block",
    residual_on_crash="none — a single synchronous intel.remember_good() call, "
                      "same shape as block_domain's write",
    false_positive_impact="a domain that should stay blocked resolves again "
                          "until it is re-blocked",
    min_severity="low",
))
reversibility.register(reversibility.Reversibility(
    action="kill_process", reversible=False,
    rollback="none — process termination cannot be undone",
    residual_on_crash="if Valkyrie itself dies after proc.terminate()/kill() "
                      "but before the ResponseAction is recorded, the audit "
                      "trail loses the record but the target process is gone "
                      "either way; no NEW artifact is left by Valkyrie's own "
                      "crash, only by the kill itself",
    false_positive_impact="a legitimate process is killed; in-flight unsaved "
                          "work and open file handles are lost, and any file "
                          "the process was mid-write to may be left truncated "
                          "or corrupt. Recovery is manual (restart the "
                          "process/application) — there is no undo",
    min_severity="critical",
))
reversibility.register(reversibility.Reversibility(
    action="isolate_host", reversible=True,
    rollback="release_isolation restores the exact pre-isolation firewall "
            "state from the snapshot netsh advfirewall export / iptables-save "
            "captured at isolate time (falls back to explicit rule-removal "
            "commands only if no snapshot exists — see IsolateHostResponder)",
    residual_on_crash="if the process dies after the snapshot is captured but "
                      "before the block commands finish, the host is left with "
                      "BOTH the pre-isolation snapshot AND whatever partial "
                      "block rules landed — release_isolation still fully "
                      "recovers by running the same command+restore sequence "
                      "again; isolate_host now REFUSES to isolate at all if "
                      "the snapshot capture itself fails, so a snapshot always "
                      "exists once isolation is actually applied",
    false_positive_impact="the host loses ALL non-resolver network "
                          "connectivity (including this session's own remote "
                          "access) until release_isolation runs — this is the "
                          "exact real incident that motivated this audit "
                          "(docs/FIREWALL_AUDIT_REPORT.md)",
    min_severity="critical",
    reverse_action="release_isolation",
))
reversibility.register(reversibility.Reversibility(
    action="release_isolation", reversible=True,
    rollback="isolate_host re-applies containment",
    residual_on_crash="none beyond isolate_host's own residual state",
    false_positive_impact="containment is lifted while a real threat may "
                          "still be on the host — this is the SAFE direction "
                          "of failure (connectivity restored, not cut)",
    min_severity="low",
))
reversibility.register(reversibility.Reversibility(
    action="remove_persistence", reversible=True,
    rollback="restore_persistence(backup_id) undoes registry_run_key / "
            "startup_folder / scheduled_task removals from the snapshot "
            "captured before deletion. service_install is the ONE exception: "
            "no automated restore exists (see RemovePersistenceResponder "
            "docstring) — only a forensic sc-qc snapshot for manual recreation",
    residual_on_crash="if the process dies after the snapshot write but "
                      "before the delete, the snapshot is orphaned but "
                      "harmless (an unused backup entry); if it dies after "
                      "the delete but before the result is recorded, the "
                      "removal already happened and the snapshot/backup id "
                      "still exists on disk for later lookup by an operator "
                      "who checks PERSISTENCE_BACKUP_DIR by hand",
    false_positive_impact="legitimate software's autostart entry is deleted; "
                          "restorable via restore_persistence for 3 of 4 ASEP "
                          "types (not service_install)",
    min_severity="medium",
))
reversibility.register(reversibility.Reversibility(
    action="restore_persistence", reversible=True,
    rollback="calling remove_persistence again re-removes it",
    residual_on_crash="none — restore is a single write/subprocess call per type",
    false_positive_impact="an attacker-created ASEP that was correctly "
                          "removed gets reinstated by mistake — this action "
                          "is explicit and operator-invoked only, never "
                          "fired automatically by any playbook",
    min_severity="low",
))
# mac_randomize / mac_restore are not EDR responders (not wired through
# ResponseManager/playbooks — MacRandomizer is a standing privacy feature,
# not an incident response), but they are exactly the "MAC change" /
# "registry write" enforcement actions item 1 requires auditing, so they are
# documented in the same registry for completeness. min_severity is
# informational only here — nothing enforces it, since these never flow
# through ResponseManager.respond().
reversibility.register(reversibility.Reversibility(
    action="mac_randomize", reversible=True,
    rollback="mac_randomizer.restore(iface) — also exposed as POST /api/mac/restore",
    residual_on_crash="prior to this audit, a netsh enable failure (non-timeout) "
                      "left the adapter DISABLED with no automatic recovery "
                      "attempt — CLOSED in this pass: _apply_windows now makes "
                      "a best-effort retry-enable on explicit enable failure, "
                      "matching the pre-existing timeout-branch behaviour (see "
                      "tests/test_mac.py section 7b/7b2). If the process dies "
                      "before even that retry runs, the adapter can still be "
                      "left disabled; the operator's fallback is `netsh "
                      "interface set interface name=<iface> admin=enabled` by "
                      "hand, or toggling the adapter from Windows Settings",
    false_positive_impact="not applicable in the traditional sense — MAC "
                          "randomisation is a standing privacy feature, not a "
                          "threat response. The risk is availability, not "
                          "false-positive containment: a broken cycle drops "
                          "connectivity until the interface recovers",
    min_severity="low",
))
reversibility.register(reversibility.Reversibility(
    action="mac_restore", reversible=True,
    rollback="mac_randomizer.randomize(iface) re-applies a fresh address",
    residual_on_crash="none beyond mac_randomize's own residual state",
    false_positive_impact="the device reverts to its real hardware MAC "
                          "earlier than intended, briefly reducing "
                          "unlinkability — not a security-relevant impact "
                          "compared to a broken cycle",
    min_severity="low",
))
