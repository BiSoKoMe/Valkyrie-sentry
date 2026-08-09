"""Coverage — what fraction of Valkyrie's intended defenses are actually live.

Generalizes ``sensor_tamper.py``'s Sysmon-only health check into a coverage
report over EVERY control in ``valkyrie/control_taxonomy.py``. IIBA's
*Cybersecurity Analysis* handbook (§4.8.3) and Clinton's *Cybersecurity for
Business* (ch. 9) both make the same point Valkyrie's own incident record
already proves: coverage is not a yes/no fact. Sysmon can be *installed* and
still deliver nothing — a state that is not "protected" no matter what an
installer's exit code says.

**Three states, not two:**

    EFFECTIVE  implemented, actively verified, working right now
    DEGRADED   implemented but only partially effective, OR present with no
               independent way to verify it's actually running (this
               module refuses to call something EFFECTIVE it cannot prove)
    ABSENT     missing outright, OR present-but-stopped (Sysmon installed
               but not delivering events lands here, NOT in effective —
               this is the exact case that motivated this module)

**How a verdict is reached, per control:**

  * A handful of controls have a REAL, standalone liveness probe reusing
    code that already exists for another purpose (Sysmon via
    ``sysmon_manager.probe_sysmon()`` — the same probe ``sensor_tamper.py``
    already calls; decoys via ``decoys._ACTIVE``; secrets via
    ``secure_file.audit_secrets()``; rules/playbook policy via a real
    parse). These get an honest EFFECTIVE/DEGRADED/ABSENT verdict.
  * Passing a :class:`CoverageContext` with live singletons (the firewall
    manager, the sensor-tamper monitor, the EDR engine) upgrades several
    more controls from the generic fallback to a real verdict — this is how
    a running Valkyrie process gets a materially more accurate report than
    a cold, standalone one.
  * Everything else falls back categorically, honestly:
      - DIRECTIVE controls (pure policy/config code, no independent runtime
        state to probe beyond "does it load") are EFFECTIVE if importable.
      - Every other category defaults to DEGRADED — "implemented... but
        only somewhat effective / unverified" is IIBA §4.8.3's own
        definition, and a bare successful import is exactly that: it
        proves the code exists, not that it is running. This module does
        not invent a verified-working claim it cannot back up.
  * A control whose module cannot even be imported is ABSENT.

This is a classification of the same 56 entries in ``control_taxonomy.py``
by a different axis (is it LIVE, vs. what KIND of control it is) — the two
modules are deliberately separate so a taxonomy edit and a liveness-probe
edit are independent changes.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Optional

from .control_taxonomy import CONTROLS, DIRECTIVE, Control

EFFECTIVE = "effective"
DEGRADED  = "degraded"
ABSENT    = "absent"

STATES = (EFFECTIVE, DEGRADED, ABSENT)


@dataclass(frozen=True)
class CoverageResult:
    name: str
    category: str
    state: str
    detail: str


@dataclass
class CoverageContext:
    """Live singletons a running Valkyrie process can supply for a more
    accurate report than the standalone fallbacks give. Every field is
    optional; missing ones just mean those specific controls fall back to
    the generic (honest, conservative) verdict."""
    firewall: Optional[object] = None                 # valkyrie.firewall.FirewallManager
    sensor_tamper: Optional[object] = None             # valkyrie.sensor_tamper.SensorTamperMonitor
    decoy_manager: Optional[object] = None             # valkyrie.decoys.DecoyManager (defaults to the process-global _ACTIVE)
    playbook_engine: Optional[object] = None           # valkyrie.edr.playbooks.PlaybookEngine
    sensor_manager: Optional[object] = None            # valkyrie.etw.framework.SensorManager
    component_registry: Optional[object] = None        # valkyrie.components.ComponentRegistry
    responder_registry: Optional[object] = None        # valkyrie.edr.plugins.PluginRegistry


def _module_importable(module_path: str) -> tuple[bool, str]:
    """Resolve a Control.module path: the longest importable prefix, then
    getattr() for any trailing .ClassName/.method segments. A prefix that
    imports but leaves unresolved trailing segments is NOT success — e.g.
    'valkyrie.nonexistent_xyz' must not report OK just because the parent
    package 'valkyrie' imports fine."""
    parts = module_path.split(".")
    last_err = "empty module path"
    for split in range(len(parts), 0, -1):
        mod_path = ".".join(parts[:split])
        try:
            obj = importlib.import_module(mod_path)
        except ImportError as exc:
            last_err = str(exc)
            continue
        for attr in parts[split:]:
            try:
                obj = getattr(obj, attr)
            except AttributeError as exc:
                return False, str(exc)
        return True, ""
    return False, last_err


# ---------------------------------------------------------------------------
# Specific, real liveness probes -- reuse existing code, never re-derive it.
# ---------------------------------------------------------------------------

def _check_sysmon() -> CoverageResult:
    from .sysmon_manager import _EID_RULE_SECTION, probe_sysmon
    env = probe_sysmon()
    if not env.present:
        return CoverageResult("etw_sysmon", "detective", ABSENT,
                              env.detail or "Sysmon not installed/running")
    if not env.collection_live:
        # Installed but not delivering events: the exact "present-but-
        # stopped lands in effective by mistake" bug this module exists to
        # prevent. It is not effective, and it is not merely "degraded" --
        # it is providing ZERO of the events Valkyrie's detectors read.
        return CoverageResult("etw_sysmon", "detective", ABSENT,
                              f"installed but not collecting: {env.detail}")
    missing = set(_EID_RULE_SECTION) - set(env.configured_eids)
    if missing:
        names = sorted(_EID_RULE_SECTION[e] for e in missing)
        return CoverageResult("etw_sysmon", "detective", DEGRADED,
                              f"collecting, but not configured for {names}")
    return CoverageResult("etw_sysmon", "detective", EFFECTIVE,
                          env.detail or "collecting all required event types")


def _check_decoys(ctx: CoverageContext) -> CoverageResult:
    from . import decoys as _dm
    mgr = ctx.decoy_manager if ctx.decoy_manager is not None else _dm._ACTIVE
    if mgr is None:
        return CoverageResult("decoys", "deterrent", ABSENT,
                              "no DecoyManager active -- decoys not deployed")
    n = len(mgr.tokens())
    if n == 0:
        return CoverageResult("decoys", "deterrent", DEGRADED,
                              "DecoyManager active but zero tokens planted")
    return CoverageResult("decoys", "deterrent", EFFECTIVE,
                          f"{n} decoy token(s) live")


def _check_secure_file() -> CoverageResult:
    from . import secure_file
    audits = secure_file.audit_secrets()
    if not audits:
        return CoverageResult("secure_file", "preventive", EFFECTIVE,
                              "no secret files on disk yet -- nothing exposed")
    bad = [label for label, _path, ok, _detail in audits if not ok]
    if bad:
        return CoverageResult("secure_file", "preventive", DEGRADED,
                              f"{len(bad)}/{len(audits)} secret file(s) not "
                              f"hardened: {', '.join(bad)}")
    return CoverageResult("secure_file", "preventive", EFFECTIVE,
                          f"all {len(audits)} known secret file(s) hardened")


def _check_user_rules() -> CoverageResult:
    from . import config
    path = config.RULES_PATH
    if not path.exists():
        return CoverageResult("user_rules", "directive", EFFECTIVE,
                              "no rules file yet -- default (empty) policy is valid")
    try:
        import yaml
        yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:                              # noqa: BLE001
        return CoverageResult("user_rules", "directive", DEGRADED,
                              f"rules file present but does not parse: {exc}")
    return CoverageResult("user_rules", "directive", EFFECTIVE,
                          "rules file present and parses")


def _check_playbook_policy(ctx: CoverageContext) -> CoverageResult:
    if ctx.playbook_engine is not None:
        st = ctx.playbook_engine.status()
        if st.get("load_errors"):
            return CoverageResult("playbook_policy", "directive", DEGRADED,
                                  f"{len(st['load_errors'])} playbook load error(s)")
        n = len(st.get("playbooks") or [])
        if n == 0:
            return CoverageResult("playbook_policy", "directive", ABSENT,
                                  "playbook engine active but zero playbooks loaded")
        return CoverageResult("playbook_policy", "directive", EFFECTIVE,
                              f"{n} playbook(s) loaded, engine active")
    from . import config
    path = config.PLAYBOOKS_PATH if config.PLAYBOOKS_PATH.exists() else config.DEFAULT_PLAYBOOKS_PATH
    if not path.exists():
        return CoverageResult("playbook_policy", "directive", ABSENT,
                              "no playbooks file found (shipped default missing?)")
    try:
        import yaml
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:                              # noqa: BLE001
        return CoverageResult("playbook_policy", "directive", DEGRADED,
                              f"playbooks file present but does not parse: {exc}")
    n = len(raw.get("playbooks") or [])
    if n == 0:
        return CoverageResult("playbook_policy", "directive", DEGRADED,
                              "playbooks file parses but defines zero playbooks")
    return CoverageResult("playbook_policy", "directive", DEGRADED,
                          f"{n} playbook(s) defined in the file, but no live "
                          f"engine reference was given -- cannot confirm one "
                          f"is actually loaded and running")


def _check_firewall(ctx: CoverageContext) -> Optional[CoverageResult]:
    if ctx.firewall is None:
        return None   # no live reference -- fall back to the generic rule
    fw = ctx.firewall
    active = getattr(fw, "_active", None)
    count = fw.count() if hasattr(fw, "count") else 0
    if not active:
        return CoverageResult("firewall", "preventive", ABSENT,
                              "FirewallManager present but not started")
    if count == 0:
        return CoverageResult("firewall", "preventive", DEGRADED,
                              "FirewallManager active but zero ranges enforced")
    return CoverageResult("firewall", "preventive", EFFECTIVE,
                          f"active, enforcing {count:,} range(s)")


def _check_etw_sensor(control_name: str, sensor_name: str,
                      ctx: CoverageContext) -> Optional[CoverageResult]:
    """Look up one named Sensor's health() from a live SensorManager.stats().
    Returns None (generic fallback) when no manager was supplied, or when
    that sensor isn't registered on this host at all (e.g. non-Windows)."""
    if ctx.sensor_manager is None:
        return None
    sensors = {s["name"]: s for s in ctx.sensor_manager.stats().get("sensors", [])}
    h = sensors.get(sensor_name)
    if h is None:
        return None
    if not h.get("running"):
        return CoverageResult(control_name, "detective", ABSENT,
                              f"sensor '{sensor_name}' registered but not running"
                              + (f" (last error: {h['last_error']})"
                                 if h.get("last_error") else ""))
    if h.get("errors"):
        return CoverageResult(control_name, "detective", DEGRADED,
                              f"running, {h['errors']} error(s) so far"
                              + (f" (last: {h['last_error']})"
                                 if h.get("last_error") else ""))
    return CoverageResult(control_name, "detective", EFFECTIVE,
                          f"running, {h.get('emitted', 0)} event(s) emitted")


# ---------------------------------------------------------------------------
# Registry-backed probes.
#
# Before these, 50 of the 57 controls reported the same sentence: "module
# present and importable, but no independent liveness probe is wired". That is
# not a measurement of the defense -- it is a measurement of how many probes
# someone has written. The coverage number was therefore reporting the state of
# coverage.py, not the state of the host, while being consumed as if it meant
# the latter (including, in authority.py, as a gate on autonomous action).
#
# Two live health surfaces already existed in a running engine and were simply
# not consulted here:
#
#   * ComponentRegistry -- 19 subsystems, each already exposing real health()
#     (up / degraded / down / disabled / error).
#   * the responder PluginRegistry -- which response actions are actually
#     registered and dispatchable right now.
#
# These probes can and DO return ABSENT. That is the point: converting an
# "unknown" into a truthful "absent" LOWERS the effective fraction, and that is
# a better number than the one before it. A probe that can only confirm good
# news is not a probe.
# ---------------------------------------------------------------------------

# Control name -> the ComponentRegistry name that IS that control. Only
# genuine 1:1 relationships belong here. ransomware_canaries is deliberately
# absent: it would have to be inferred from ransomware_shield, and a proxy
# reported as a direct measurement is exactly the dishonesty being removed.
_COMPONENT_BACKED = {
    "blocklist":             "blocklist",
    "threat_intel":          "threat_intel",
    "process_telemetry":     "process_collector",
    "network_telemetry":     "network_collector",
    "persistence_telemetry": "persistence_collector",
    "browser_cred_watch":    "cred_watch",
    "amsi_scan":             "amsi",
    "ransomware_response":   "ransomware_shield",
    "playbook_automation":   "playbooks",
    "mac_randomizer":        "mac_randomizer",
    "content_watch":         "content_watch",
    "process_watcher":       "process_watcher",
}

# Component health state -> coverage state. "disabled" maps to ABSENT, not to
# some fourth thing: a control that does not apply on this host is not
# protecting this host, whatever the reason.
_COMPONENT_STATE_MAP = {
    "up":       EFFECTIVE,
    "degraded": DEGRADED,
    "error":    DEGRADED,     # the probe itself failed -- genuinely unknown
    "down":     ABSENT,
    "disabled": ABSENT,
}

# Control name -> the response action that must be dispatchable for it to be
# real. A responder whose module imports but which no registry will dispatch
# is not a control, it is dead code.
_RESPONDER_BACKED = {
    "block_domain":        "block_domain",
    "kill_process":        "kill_process",
    "isolate_host":        "isolate_host",
    "remove_persistence":  "remove_persistence",
    "release_isolation":   "release_isolation",
    "restore_persistence": "restore_persistence",
    "mac_restore":         "mac_restore",
}


def _check_component(ctl: Control, ctx: CoverageContext) -> Optional[CoverageResult]:
    """Resolve a control from the live ComponentRegistry's own health."""
    reg = ctx.component_registry
    comp_name = _COMPONENT_BACKED.get(ctl.name)
    if reg is None or comp_name is None:
        return None
    try:
        health = reg.health()
    except Exception as exc:                              # noqa: BLE001
        return CoverageResult(ctl.name, ctl.category, DEGRADED,
                              f"component registry health() raised: {exc}")
    h = health.get(comp_name)
    if h is None:
        # Registered nowhere. Not "unknown" -- the engine booted and did not
        # wire this up, which is a real, reportable absence.
        return CoverageResult(ctl.name, ctl.category, ABSENT,
                              f"no component '{comp_name}' registered in this "
                              f"engine -- not wired at startup")
    state = _COMPONENT_STATE_MAP.get(h.get("state", ""), DEGRADED)
    detail = h.get("detail") or ""
    return CoverageResult(
        ctl.name, ctl.category, state,
        f"component '{comp_name}' reports {h.get('state')}"
        + (f": {detail}" if detail else ""))


def _check_responder(ctl: Control, ctx: CoverageContext) -> Optional[CoverageResult]:
    """A response control is real only if its action is dispatchable now."""
    reg = ctx.responder_registry
    action = _RESPONDER_BACKED.get(ctl.name)
    if reg is None or action is None:
        return None
    try:
        available = set(reg.available_actions())
    except Exception as exc:                              # noqa: BLE001
        return CoverageResult(ctl.name, ctl.category, DEGRADED,
                              f"responder registry raised: {exc}")
    if action not in available:
        return CoverageResult(ctl.name, ctl.category, ABSENT,
                              f"no enabled responder handles '{action}' -- "
                              f"the module exists but nothing will dispatch it")
    return CoverageResult(ctl.name, ctl.category, EFFECTIVE,
                          f"'{action}' is registered and dispatchable")


def _check_sensor_tamper(ctx: CoverageContext) -> Optional[CoverageResult]:
    if ctx.sensor_tamper is None:
        return None
    st = ctx.sensor_tamper
    running = st.is_running() if hasattr(st, "is_running") else False
    if not running:
        return CoverageResult("sensor_tamper", "detective", ABSENT,
                              "SensorTamperMonitor not running")
    return CoverageResult("sensor_tamper", "detective", EFFECTIVE,
                          "monitoring sensor health")


# Name -> a zero-arg or ctx-arg check function. Kept separate from CONTROLS
# itself (control_taxonomy.py) so a taxonomy edit and a liveness-probe edit
# stay independent.
_STANDALONE_CHECKS = {
    "etw_sysmon": lambda ctx: _check_sysmon(),
    "decoys": _check_decoys,
    "secure_file": lambda ctx: _check_secure_file(),
    "user_rules": lambda ctx: _check_user_rules(),
    "playbook_policy": _check_playbook_policy,
}
_CTX_ONLY_CHECKS = {
    "firewall": _check_firewall,
    "sensor_tamper": _check_sensor_tamper,
    "etw_powershell": lambda ctx: _check_etw_sensor("etw_powershell", "powershell", ctx),
    "etw_wmi": lambda ctx: _check_etw_sensor("etw_wmi", "wmi", ctx),
    "native_process": lambda ctx: _check_etw_sensor("native_process", "native_process", ctx),
}


def _generic_verdict(ctl: Control) -> CoverageResult:
    ok, err = _module_importable(ctl.module)
    if not ok:
        return CoverageResult(ctl.name, ctl.category, ABSENT,
                              f"module does not import: {err}")
    if ctl.category == DIRECTIVE:
        # Pure policy/config code: there is no independent runtime state
        # beyond "does the code exist and load" -- that IS the complete
        # liveness proof for this class of control.
        return CoverageResult(ctl.name, ctl.category, EFFECTIVE,
                              "policy/config module present and importable")
    return CoverageResult(ctl.name, ctl.category, DEGRADED,
                          "module present and importable, but no independent "
                          "liveness probe is wired -- cannot confirm it is "
                          "actually running (see coverage.py to add one)")


def check_all(ctx: Optional[CoverageContext] = None) -> list[CoverageResult]:
    """One CoverageResult per Control in control_taxonomy.CONTROLS."""
    ctx = ctx or CoverageContext()
    out: list[CoverageResult] = []
    for ctl in CONTROLS:
        try:
            if ctl.name in _CTX_ONLY_CHECKS:
                r = _CTX_ONLY_CHECKS[ctl.name](ctx)
                out.append(r if r is not None else _generic_verdict(ctl))
                continue
            if ctl.name in _STANDALONE_CHECKS:
                out.append(_STANDALONE_CHECKS[ctl.name](ctx))
                continue
            # Registry-backed probes come after the hand-written specific
            # checks (which are more precise) and before the generic verdict
            # (which measures nothing but importability). Each returns None
            # when the relevant registry was not supplied, so a standalone
            # invocation degrades to the old behaviour instead of inventing a
            # verdict from a registry it does not have.
            r = _check_component(ctl, ctx)
            if r is None:
                r = _check_responder(ctl, ctx)
            out.append(r if r is not None else _generic_verdict(ctl))
        except Exception as exc:                          # noqa: BLE001
            # A broken probe must be visible, not silently absent from the
            # report -- and it must not crash the whole coverage pass.
            out.append(CoverageResult(ctl.name, ctl.category, DEGRADED,
                                      f"coverage probe raised: "
                                      f"{type(exc).__name__}: {exc}"))
    return out


@dataclass
class CoverageSummary:
    fraction_effective: float
    counts: dict
    gaps: list                      # CoverageResult entries that are not EFFECTIVE
    total: int


def summarize(results: list[CoverageResult]) -> CoverageSummary:
    counts = {s: 0 for s in STATES}
    for r in results:
        counts[r.state] += 1
    total = len(results)
    frac = (counts[EFFECTIVE] / total) if total else 0.0
    gaps = [r for r in results if r.state != EFFECTIVE]
    return CoverageSummary(fraction_effective=frac, counts=counts,
                           gaps=gaps, total=total)
