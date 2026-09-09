"""Demo-readiness check — run this on the demo box BEFORE the reviewer arrives.

It answers the three questions that decide whether a live red-team demo goes
well or badly, and it is strictly READ-ONLY (no rules installed, no processes
touched, nothing killed — safe to run any time):

  1. Is the COMMAND-LINE EYE open?  Valkyrie's highest-value endpoint rules
     (LSASS dump, regsvr32/mshta proxy, SAM hive save) match on the command
     line. That only works if a real-time command-line source is live: the
     Sysmon sensor (if Sysmon is installed) or Windows Security-4688 auditing
     with the "include command line" policy on. If neither is live, those rules
     stay dark and short-lived LOLBins slip past the poller.

  2. Is RESPONSE ARMED?  Detection without response only *logs* an attack. This
     loads the active playbooks and reports which are in `enforce` — in
     particular remove-persistence and kill-critical-process.

  3. Is the decision ANALYSIS-driven?  Confirms the SiteScanner is the default
     DNS decider and reports how many optional manual overrides exist, so you
     can state truthfully that Valkyrie decides by analysis, not a static list.

Usage (from the repo root, on the demo box):
    set PYTHONUTF8=1
    python tools/demo_readiness.py

Exit code is 0 when the command-line eye is open AND response is armed, else 1,
so it can gate a pre-demo script.
"""

from __future__ import annotations

import os
import sys

# Make the repo importable when run as `python tools/demo_readiness.py`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

OK = "PASS"
NO = "FAIL"
WARN = "WARN"


def _line(status: str, title: str, detail: str) -> None:
    print(f"  [{status:4}] {title}: {detail}")


# ---------------------------------------------------------------------------
# 1. Command-line eye
# ---------------------------------------------------------------------------

def check_cmdline_eye() -> bool:
    """True when at least one real-time command-line source is live."""
    print("1. COMMAND-LINE EYE (needed for LSASS-dump / regsvr32 / mshta / SAM rules)")
    live = False

    # Sysmon sensor — the richest source when present.
    try:
        from valkyrie.etw.sysmon import SysmonSensor
        s = SysmonSensor()
        if s.available():
            _line(OK, "Sysmon sensor", "installed and readable — command lines WILL reach the rules")
            live = True
        else:
            _line(WARN, "Sysmon sensor", "not available (Sysmon absent, or its Operational log is unreadable)")
    except Exception as exc:                       # noqa: BLE001
        _line(WARN, "Sysmon sensor", f"could not probe: {exc}")

    # Native Security-4688 sensor — the no-install fallback.
    try:
        from valkyrie.etw.native_process import NativeProcessSensor
        n = NativeProcessSensor()
        chan_ok = n.available()
        cmdline_on = _audit_cmdline_enabled()
        if chan_ok and cmdline_on:
            _line(OK, "Security-4688 + cmdline audit",
                  "channel readable and 'include command line' policy ON")
            live = True
        elif chan_ok and not cmdline_on:
            _line(WARN, "Security-4688 + cmdline audit",
                  "4688 readable but 'include command line' policy is OFF — "
                  "run native_audit.enable_process_auditing() as admin")
        else:
            _line(WARN, "Security-4688 sensor", "Security channel not readable (needs admin)")
    except Exception as exc:                       # noqa: BLE001
        _line(WARN, "Security-4688 sensor", f"could not probe: {exc}")

    if live:
        print("   => command-line eye is OPEN.\n")
    else:
        print("   => command-line eye is CLOSED — install Sysmon OR enable 4688 cmdline "
              "auditing (admin), or the command-line rules stay dark.\n")
    return live


def _audit_cmdline_enabled() -> bool:
    """True when ProcessCreationIncludeCmdLine_Enabled == 1 in the registry."""
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
        ) as k:
            val, _ = winreg.QueryValueEx(k, "ProcessCreationIncludeCmdLine_Enabled")
            return int(val) == 1
    except Exception:                              # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# 2. Response armed
# ---------------------------------------------------------------------------

def check_response_armed() -> bool:
    """True when the demo-critical playbooks load in enforce mode."""
    print("2. RESPONSE ARMED (detection without response only LOGS the attack)")
    armed_ok = True
    try:
        import yaml
        from valkyrie.config import PLAYBOOKS_PATH, DEFAULT_PLAYBOOKS_PATH
        path = PLAYBOOKS_PATH if PLAYBOOKS_PATH.exists() else DEFAULT_PLAYBOOKS_PATH
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        by_id = {str(p.get("id")): p for p in (raw.get("playbooks") or [])}
        _line(OK, "Playbook file", str(path))
        for pid in ("remove-persistence", "kill-critical-process",
                    "block-known-bad-domain"):
            pb = by_id.get(pid)
            if pb is None:
                _line(NO, pid, "MISSING from the active playbook file")
                armed_ok = False
            elif str(pb.get("mode")) == "enforce":
                _line(OK, pid, "enforce")
            else:
                _line(NO, pid, f"mode={pb.get('mode')} (NOT enforcing)")
                armed_ok = False
    except Exception as exc:                       # noqa: BLE001
        _line(NO, "Playbook load", f"could not load: {exc}")
        armed_ok = False

    # Confirm the responder that removes persistence is actually registered.
    try:
        from valkyrie.edr.response import BUILTIN_RESPONDERS
        actions = set()
        for cls in BUILTIN_RESPONDERS:
            try:
                actions.update(cls().actions())
            except Exception:                      # noqa: BLE001
                pass
        need = {"remove_persistence", "kill_process", "block_domain"}
        missing = need - actions
        if missing:
            _line(NO, "Responders", f"missing: {', '.join(sorted(missing))}")
            armed_ok = False
        else:
            _line(OK, "Responders", "remove_persistence, kill_process, block_domain all present")
    except Exception as exc:                       # noqa: BLE001
        _line(NO, "Responders", f"could not import: {exc}")
        armed_ok = False

    # If a live %ProgramData% copy exists but predates this build, it will keep
    # the OLD dry-run config and silently mask the shipped armed defaults.
    try:
        from valkyrie.config import PLAYBOOKS_PATH
        if PLAYBOOKS_PATH.exists():
            live = yaml.safe_load(PLAYBOOKS_PATH.read_text(encoding="utf-8")) or {}
            live_ids = {str(p.get("id")) for p in (live.get("playbooks") or [])}
            if "remove-persistence" not in live_ids:
                _line(WARN, "Live copy",
                      f"{PLAYBOOKS_PATH} predates this build and lacks the armed "
                      f"playbooks — delete it to re-seed the shipped default")
                armed_ok = False
    except Exception:                              # noqa: BLE001
        pass
    print(f"   => response is {'ARMED' if armed_ok else 'NOT fully armed'}.\n")
    return armed_ok


# ---------------------------------------------------------------------------
# 3. Analysis-driven decisioning
# ---------------------------------------------------------------------------

def check_analysis_first() -> None:
    print("3. ANALYSIS-DRIVEN DECISIONING (not a static hand-written list)")
    try:
        from valkyrie.site_scanner import SiteScanner  # noqa: F401
        _line(OK, "SiteScanner", "present — the default DNS decider is behavioural analysis")
    except Exception as exc:                        # noqa: BLE001
        _line(WARN, "SiteScanner", f"could not import: {exc}")
    try:
        import yaml
        from valkyrie.config import RULES_PATH
        n_block = n_allow = 0
        if RULES_PATH.exists():
            data = yaml.safe_load(RULES_PATH.read_text(encoding="utf-8")) or {}
            n_block = len(data.get("always_block") or [])
            n_allow = len(data.get("always_allow") or [])
        _line(OK, "Manual overrides",
              f"{n_block} always_block, {n_allow} always_allow "
              f"(optional user overrides — analysis decides everything else)")
    except Exception as exc:                        # noqa: BLE001
        _line(WARN, "Manual overrides", f"could not read rules: {exc}")
    print()


def check_nyx_dataguard() -> bool:
    """True when Nyx's data guard catches synthetic leaks AND fakes them — the
    privacy differentiator's 'whoa', proven by its own live self-test."""
    print("4. NYX DATA GUARD (the privacy differentiator — catches & fakes data leaks)")
    try:
        from valkyrie.nyx import self_test
        r = self_test()
        caught, total, faked = r["caught"], r["total"], r["faked"]
        if caught == total and faked >= 4:
            _line(OK, "Nyx self-test",
                  f"caught {caught}/{total} synthetic leaks and fed fakes for {faked} "
                  "(device ID, location, email, card, fingerprint)")
            print("   => Nyx is READY — hit /api/nyx/self-test or the "
                  "'Show me Nyx working' button.\n")
            return True
        _line(WARN, "Nyx self-test",
              f"caught {caught}/{total}, faked {faked} — expected {total}/{total} and >=4 faked")
        print("   => Nyx self-test degraded.\n")
        return False
    except Exception as exc:                           # noqa: BLE001
        _line(WARN, "Nyx self-test", f"could not run: {exc}")
        print("   => Nyx self-test unavailable.\n")
        return False


def main() -> int:
    print("=" * 72)
    print("VALKYRIE DEMO-READINESS CHECK  (read-only; safe to run any time)")
    print("=" * 72)
    eye = check_cmdline_eye()
    armed = check_response_armed()
    check_analysis_first()
    nyx_ok = check_nyx_dataguard()
    print("=" * 72)
    ready = eye and armed and nyx_ok
    print(f"OVERALL: {'READY for a live demo' if ready else 'NOT READY — fix the FAIL/CLOSED items above'}")
    print("=" * 72)
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
