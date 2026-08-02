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

import logging
import os
import platform
import threading
from typing import Optional

from ..config import RULES_PATH
from .plugins import PluginContext, ResponderPlugin
from .schema import ResponseAction

log = logging.getLogger("valkyrie.response")

_SYSTEM = platform.system()

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
    name = "responder.isolate_host"
    description = "Network-contain the endpoint (block egress except resolver + loopback)"

    def actions(self) -> list[str]:
        return ["isolate_host", "release_isolation"]

    def _commands(self, action: str) -> list[str]:
        """Return the exact platform commands this action would run."""
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
            return ["iptables -D OUTPUT -j DROP"]

    def execute(self, action, target, *, dry_run, ctx):
        cmds = self._commands(action)
        verb = "isolate endpoint" if action == "isolate_host" else "release isolation"
        if dry_run:
            return ("dry_run", f"would {verb} via:\n  " + "\n  ".join(cmds))
        if not _is_admin():
            return ("skipped",
                    f"cannot {verb}: needs admin/root. Commands:\n  " + "\n  ".join(cmds))
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
        return ("succeeded", f"{verb} applied")


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

    Safety model (removing persistence is *reversible-ish* and far less
    destructive than killing a process, but still guarded):
      * A denylist of critical Windows service names is never deleted.
      * System scheduled-task trees (``Microsoft\\Windows\\``) are never deleted.
      * Startup-folder deletes are confined to recognised Startup directories.
      * Registry deletes are confined to the known autorun keys.
      * Missing privilege reports ``skipped`` with the reason — never a silent
        no-op — exactly like the other responders.
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
                               f"(schtasks /delete /tn {tn} /f)")
        import subprocess
        r = subprocess.run(["schtasks", "/delete", "/tn", tn, "/f"],
                           capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            return ("succeeded", f"deleted scheduled task '{tn}'")
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
                               f"(sc.exe delete {svc})")
        import subprocess
        subprocess.run(["sc.exe", "stop", svc],
                       capture_output=True, text=True, timeout=20)
        r = subprocess.run(["sc.exe", "delete", svc],
                           capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            return ("succeeded", f"deleted service '{svc}'")
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
            return ("dry_run", f"would delete run-key value '{value}' under {loc}")
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, value)
        except FileNotFoundError:
            return ("succeeded", f"run-key value '{value}' already gone")
        except PermissionError:
            return ("skipped", f"access denied removing run-key '{value}' (needs admin)")
        return ("succeeded", f"removed run-key value '{value}' under {loc}")

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
            return ("dry_run", f"would delete startup file '{path}'")
        try:
            os.remove(path)
        except FileNotFoundError:
            return ("succeeded", f"startup file '{path}' already gone")
        except PermissionError:
            return ("skipped", f"access denied deleting '{path}' (needs admin)")
        return ("succeeded", f"deleted startup file '{path}'")


# ---------------------------------------------------------------------------
# ResponseManager — the front door the web API / CLI / fleet call
# ---------------------------------------------------------------------------

BUILTIN_RESPONDERS = [
    BlockDomainResponder,
    KillProcessResponder,
    IsolateHostResponder,
    RemovePersistenceResponder,
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

    def respond(self, action: str, target: str = "", *, dry_run: bool = True,
                operator: str = "local", incident_id: str = "") -> ResponseAction:
        """Run (or simulate) a response action and return the audited record."""
        act = ResponseAction(action=action, target=target, dry_run=dry_run,
                             operator=operator, incident_id=incident_id)
        responder = self._registry.responder_for(action)
        if responder is None:
            act.status = "failed"
            act.result = f"no responder handles action '{action}'"
        else:
            try:
                status, result = responder.execute(
                    action, target, dry_run=dry_run, ctx=self._ctx)
                act.status, act.result = status, result
            except Exception as exc:          # noqa: BLE001
                act.status = "failed"
                act.result = f"responder error: {type(exc).__name__}: {exc}"
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
