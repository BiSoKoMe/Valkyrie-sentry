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

import os
import platform
import threading
from typing import Optional

from ..config import RULES_PATH
from .plugins import PluginContext, ResponderPlugin
from .schema import ResponseAction

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
    description = "Add or remove a domain in the user block rules"

    _lock = threading.Lock()

    def actions(self) -> list[str]:
        return ["block_domain", "unblock_domain"]

    def execute(self, action, target, *, dry_run, ctx):
        domain = (target or "").strip().lower()
        if not domain or not all(c.isalnum() or c in ".-_*" for c in domain):
            return ("failed", f"invalid domain: {target!r}")
        if action == "block_domain":
            if dry_run:
                return ("dry_run", f"would add always_block rule for '{domain}' "
                                   f"in {RULES_PATH.name}")
            ok, msg = self._mutate(domain, add=True)
            if ok and ctx.intelligence is not None:
                try:
                    ctx.intelligence.remember_block(domain, "edr:manual_block")
                except Exception:
                    pass
            return ("succeeded" if ok else "failed", msg)
        else:  # unblock_domain
            if dry_run:
                return ("dry_run", f"would remove always_block rule for '{domain}'")
            ok, msg = self._mutate(domain, add=False)
            return ("succeeded" if ok else "failed", msg)

    def _mutate(self, domain: str, *, add: bool) -> tuple[bool, str]:
        try:
            import yaml
        except ImportError:
            return (False, "pyyaml not available")
        with self._lock:
            try:
                text = RULES_PATH.read_text(encoding="utf-8") if RULES_PATH.exists() else ""
                data = yaml.safe_load(text) or {}
            except Exception as exc:
                return (False, f"could not read rules: {exc}")
            block = data.get("always_block") or []
            existing = {str(r.get("domain", "")).lower() for r in block if isinstance(r, dict)}
            if add:
                if domain in existing:
                    return (True, f"'{domain}' already blocked")
                block.append({"domain": domain})
            else:
                if domain not in existing:
                    return (True, f"'{domain}' was not in block rules")
                block = [r for r in block
                         if str(r.get("domain", "")).lower() != domain]
            data["always_block"] = block
            try:
                RULES_PATH.write_text(yaml.safe_dump(data, sort_keys=False),
                                      encoding="utf-8")
            except Exception as exc:
                return (False, f"could not write rules: {exc}")
        verb = "blocked" if add else "unblocked"
        return (True, f"'{domain}' {verb} (takes effect within ~5s via rules reload)")


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
                subprocess.run(c, shell=True, check=True, capture_output=True)
            except subprocess.CalledProcessError as exc:
                errors.append(f"{c!r}: {exc.stderr.decode(errors='replace').strip()}")
        if errors:
            return ("failed", f"{verb} partially failed: " + "; ".join(errors))
        return ("succeeded", f"{verb} applied")


# ---------------------------------------------------------------------------
# ResponseManager — the front door the web API / CLI / fleet call
# ---------------------------------------------------------------------------

BUILTIN_RESPONDERS = [
    BlockDomainResponder,
    KillProcessResponder,
    IsolateHostResponder,
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
                pass
        return act
