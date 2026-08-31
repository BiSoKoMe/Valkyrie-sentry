#!/usr/bin/env python3
"""Process telemetry collector - heuristics + diff/emit behavior (ADR-0012)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    from valkyrie.process_telemetry import (
        classify_process, diff_snapshots, ProcInfo, ProcessCollector)
    from valkyrie import telemetry as T

    print("\n=== process telemetry heuristics ===\n")

    print("[1] classify_process")
    sev, labels, _ = classify_process("chrome.exe", "C:/Program Files/chrome.exe")
    _check("benign proc -> info, no labels", sev == T.SEV_INFO and labels == [])

    sev, labels, reason = classify_process("powershell.exe", "C:/Windows/System32/ps.exe")
    _check("lolbin -> medium", sev == T.SEV_MEDIUM)
    _check("lolbin labelled", "lolbin" in labels)

    sev, labels, reason = classify_process("cmd.exe", "C:/x/cmd.exe", parent_name="winword.exe")
    _check("office->shell -> high", sev == T.SEV_HIGH)
    _check("office->shell labelled", "office_child_shell" in labels)

    sev, labels, _ = classify_process("thing.exe", "C:/Users/me/AppData/Local/Temp/thing.exe")
    _check("temp-dir exec -> at least low", T.severity_rank(sev) >= T.severity_rank(T.SEV_LOW))
    _check("temp-dir labelled", "suspicious_path" in labels)

    sev, labels, _ = classify_process("powershell.exe", "/tmp/p.exe")
    _check("lolbin + temp -> >= medium", T.severity_rank(sev) >= T.severity_rank(T.SEV_MEDIUM))
    _check("both labels present", "lolbin" in labels and "suspicious_path" in labels)

    print("\n[1c] classify_discovery — weak, INFO-only Discovery-tactic labeling")
    from valkyrie.process_telemetry import classify_discovery
    sev, dlabels, _, tech = classify_discovery("systeminfo.exe", "systeminfo")
    _check("systeminfo -> discovery_command / T1082",
           sev == T.SEV_INFO and "discovery_command" in dlabels and "T1082" in tech)
    _, dlabels, _, tech = classify_discovery("tasklist.exe", "tasklist")
    _check("tasklist -> T1057", "T1057" in tech)
    _, dlabels, _, tech = classify_discovery("whoami.exe", "whoami")
    _check("bare whoami -> T1033", "T1033" in tech)
    _, dlabels, _, tech = classify_discovery("net.exe", "net view")
    _check("net view -> T1018", "T1018" in tech)
    _, dlabels, _, tech = classify_discovery("net.exe", "net user")
    _check("bare net user (list) -> T1087.001", "T1087.001" in tech)
    # UPDATED CONTRACT (Detection Coverage milestone, 2026-08-26): this used
    # to assert T1087.001, which was itself the live-fire gap - the real
    # Atomic Red Team T1069.001 test runs exactly this command, but the old
    # code mislabeled it as T1087.001 (Account Discovery), so a live scorer
    # that never credits a technique under the wrong label never credited
    # it. 'net localgroup' is MITRE's own canonical example for T1069.001
    # (Permission Groups Discovery: Local Groups), distinct from 'net user'
    # (T1087.001, still asserted above and unchanged).
    _, dlabels, _, tech = classify_discovery("net.exe", "net localgroup administrators")
    _check("net localgroup administrators (list) -> T1069.001, not T1087.001",
           "T1069.001" in tech and "T1087.001" not in tech)
    _, dlabels, _, tech = classify_discovery("net.exe", "net localgroup")
    _check("bare net localgroup (no group name) -> T1069.001 too",
           "T1069.001" in tech)
    _, dlabels, _, tech = classify_discovery(
        "net.exe", "net localgroup administrators evilcorp /add")
    _check("net localgroup ... /add is NOT labeled discovery "
           "(real group-membership change, not enumeration)",
           tech == "" and dlabels == [])
    _, dlabels, _, tech = classify_discovery(
        "net.exe", "net user backdoor P@ss /add")
    _check("net user ... /add is NOT labeled discovery "
           "(already alerted MEDIUM by behavioral_rules net-user-add)",
           tech == "" and dlabels == [])
    _, dlabels, _, tech = classify_discovery("nltest.exe", "nltest /dclist:corp")
    _check("nltest /dclist is NOT double-labeled "
           "(already its own MEDIUM rule in behavioral_rules)",
           tech == "" and dlabels == [])
    _, dlabels, _, tech = classify_discovery("chrome.exe", "chrome.exe --profile-directory=Default")
    _check("unrelated binary -> no label", tech == "" and dlabels == [])

    print("\n[1d] classify_discovery survives trivial cmdline obfuscation "
          "(redteam/evaluation/evasion_harness.py found this gap: the raw-only "
          "keyword check was defeated by exactly the caret-escaping the main "
          "IOA rule engine already survives)")
    _, _, _, tech = classify_discovery("net.exe", "net v^iew /all")
    _check("caret-escaped 'net view' still -> T1018", "T1018" in tech)
    _, _, _, tech = classify_discovery("net.exe", "net u^ser")
    _check("caret-escaped bare 'net user' still -> T1087.001", "T1087.001" in tech)
    _, _, _, tech = classify_discovery("net.exe", "net l^ocalgroup administrators")
    _check("caret-escaped 'net localgroup administrators' still -> T1069.001 "
           "(inherited for free: same de-obfuscated candidates tuple as its siblings)",
           "T1069.001" in tech)
    _, _, _, tech = classify_discovery("net.exe", 'net u"s"er')
    _check("token-split-quote 'net user' still -> T1087.001", "T1087.001" in tech)
    _, _, _, tech = classify_discovery("nltest.exe", "nltest /dcl^ist:corp")
    _check("obfuscation does not break the double-label exclusion either "
           "(nltest /dclist still deliberately unlabeled here)", tech == "")

    print("\n[1e] closing the 5 gaps redteam/evaluation/live_safe.py RUN A "
          "measured (ipconfig/netstat/hostname/reg query/sc query had NO "
          "code path at all before this) — same INFO-only, weak-label, "
          "never-standalone discipline as every entry above")
    sev, dlabels, _, tech = classify_discovery("ipconfig.exe", "ipconfig /all")
    _check("ipconfig -> T1016, still INFO-only",
           sev == T.SEV_INFO and "discovery_command" in dlabels and "T1016" in tech)
    sev, dlabels, _, tech = classify_discovery("netstat.exe", "netstat -ano")
    _check("netstat -> T1049, still INFO-only",
           sev == T.SEV_INFO and "discovery_command" in dlabels and "T1049" in tech)
    sev, dlabels, _, tech = classify_discovery("hostname.exe", "hostname")
    _check("hostname -> T1082, still INFO-only",
           sev == T.SEV_INFO and "discovery_command" in dlabels and "T1082" in tech)
    sev, dlabels, _, tech = classify_discovery(
        "reg.exe", r"reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion")
    _check("reg QUERY -> T1012, still INFO-only",
           sev == T.SEV_INFO and "discovery_command" in dlabels and "T1012" in tech)
    sev, dlabels, _, tech = classify_discovery("sc.exe", "sc query eventlog")
    _check("sc QUERY -> T1007, still INFO-only",
           sev == T.SEV_INFO and "discovery_command" in dlabels and "T1007" in tech)

    print("\n[1f] benign controls — reg/sc MUTATING verbs must NEVER get the "
          "discovery label (query-only, not a general reg.exe/sc.exe label)")
    _, dlabels, _, tech = classify_discovery(
        "reg.exe", r"reg add HKCU\Software\Evil /v x /d y")
    _check("reg add is NOT labeled discovery", tech == "" and dlabels == [])
    _, dlabels, _, tech = classify_discovery(
        "reg.exe", r"reg delete HKCU\Software\Evil /f")
    _check("reg delete is NOT labeled discovery", tech == "" and dlabels == [])
    _, dlabels, _, tech = classify_discovery("sc.exe", "sc stop windefend")
    _check("sc stop windefend is NOT labeled discovery "
           "(already alerted by behavioral_rules.py's own rule)",
           tech == "" and dlabels == [])
    _, dlabels, _, tech = classify_discovery("sc.exe", "sc create evilsvc binPath= evil.exe")
    _check("sc create is NOT labeled discovery "
           "(already alerted by behavioral_rules.py's own rule)",
           tech == "" and dlabels == [])
    _, _, _, tech = classify_discovery("reg.exe", "reg qu^ery HKLM\\Software")
    _check("caret-escaped 'reg query' still -> T1012 (survives obfuscation "
           "the same way net/nltest already do)", "T1012" in tech)

    print("\n[1g] reconnaissance-burst's technique whitelist actually "
          "includes the 4 new ATT&CK ids (labeling alone does not feed the "
          "sequence engine unless Step.techniques also lists them)")
    from valkyrie.behavioral_sequences import SEQUENCES
    burst = next(r for r in SEQUENCES if r.id == "reconnaissance-burst")
    burst_techniques = burst.steps[0].techniques
    for tid in ("T1016", "T1049", "T1012", "T1007"):
        _check(f"{tid} is in reconnaissance-burst's Step.techniques",
               tid in burst_techniques)

    print("\n[2] ProcInfo.to_event()")
    ev = ProcInfo(pid=42, name="powershell.exe", path="C:/ps.exe",
                  ppid=10, parent_name="winword.exe", create_time=123.0).to_event()
    _check("category is process", ev.category == T.CAT_PROCESS)
    _check("activity is exec", ev.activity == "exec")
    _check("high-severity -> action flagged", ev.action == T.ACT_FLAGGED)
    _check("actor + parent carried",
           ev.actor_pid == 42 and ev.fields["parent_name"] == "winword.exe")

    print("\n[2b] A lone discovery command NEVER escalates on its own")
    ev2 = ProcInfo(pid=99, name="tasklist.exe", path="C:/Windows/System32/tasklist.exe",
                   ppid=1, parent_name="cmd.exe", create_time=1.0).to_event()
    _check("stays INFO severity / observed action",
           ev2.severity == T.SEV_INFO and ev2.action == T.ACT_OBSERVED)
    _check("but still carries the label + technique (for the burst combiner)",
           "discovery_command" in ev2.labels and "T1057" in ev2.fields.get("technique", ""))

    print("\n[3] diff_snapshots returns only new keys")
    a = ProcInfo(pid=1, name="a", create_time=1.0)
    b = ProcInfo(pid=2, name="b", create_time=2.0)
    c = ProcInfo(pid=3, name="c", create_time=3.0)
    old = {a.key(): a, b.key(): b}
    new = {b.key(): b, c.key(): c}
    fresh = diff_snapshots(old, new)
    _check("only c is new", [p.pid for p in fresh] == [3])

    print("\n[4] Collector: baseline-then-emit (injected snapshots)")
    emitted: list = []
    col = ProcessCollector(emit=emitted.append)
    # Inject a deterministic snapshot sequence.
    snaps = [
        {a.key(): a, b.key(): b},              # first poll: baseline (no emit)
        {a.key(): a, b.key(): b, c.key(): c},  # second: c appears -> 1 emit
    ]
    seq = iter(snaps)
    col.snapshot = lambda: next(seq)           # type: ignore[assignment]

    n0 = col.poll_once()
    _check("first poll seeds baseline, emits nothing", n0 == 0 and emitted == [])
    n1 = col.poll_once()
    _check("second poll emits exactly the new process", n1 == 1 and len(emitted) == 1)
    _check("emitted a TelemetryEvent for pid 3",
           emitted[0].category == T.CAT_PROCESS and emitted[0].actor_pid == 3)

    print("\n[5b] diff_enrich_emit budget (Beta 0.5.3: the SAME EdrStore-"
          "lock-contention shape found in PersistenceCollector, applied to "
          "ProcessCollector - see docs/BETA_0_5_TELEMETRY_RELIABILITY.md)")
    import time
    emitted3: list = []
    col3 = ProcessCollector(emit=emitted3.append, emit_budget=1.0)
    _check("emit_budget floored at 1.0", col3._emit_budget == 1.0)
    d = ProcInfo(pid=4, name="d", create_time=4.0)
    baseline3 = {a.key(): a, b.key(): b}
    cycle3 = {a.key(): a, b.key(): b, c.key(): c, d.key(): d}   # c, d both new
    col3._last = baseline3
    col3.snapshot = lambda: cycle3             # type: ignore[assignment]

    real_emit = col3._emit
    def _slow_emit(ev):
        real_emit(ev)
        if ev.actor_pid == c.pid:
            time.sleep(1.1)   # simulates a contended/slow ingest_telemetry()
    col3._emit = _slow_emit
    n3 = col3.poll_once()
    _check("exactly one emit before the budget tripped", n3 == 1)
    _check("the emitted one is c, not d",
           len(emitted3) == 1 and emitted3[0].actor_pid == c.pid)
    _check("status() reports the truncation", "diff_enrich_emit" in col3.status()["truncated"])
    _check("deferred process (d) is NOT folded into the new baseline",
           d.key() not in col3._last)
    _check("emitted process (c) IS folded into the new baseline", c.key() in col3._last)

    col3._emit = real_emit
    emitted3.clear()
    col3.snapshot = lambda: cycle3              # type: ignore[assignment]
    n4 = col3.poll_once()
    _check("the deferred process is emitted on the very next poll",
           n4 == 1 and emitted3[0].actor_pid == d.pid)
    _check("truncated clears once a cycle completes without truncation",
           col3.status()["truncated"] == [])

    print("\n[5c] snapshot() reuses an already-known process's path instead "
          "of re-querying it (Beta 0.5.5/.6: a live contention run measured "
          "this exact call - pr.exe() for every running process, every "
          "poll - taking ~3.8s under load and pushing the collector past "
          "its own stale bound; see docs/BETA_0_5_TELEMETRY_RELIABILITY.md)")
    import os
    import psutil as _psutil_mod
    call_count = {"n": 0}
    real_exe = _psutil_mod.Process.exe
    def _counting_exe(self):
        call_count["n"] += 1
        return real_exe(self)
    col4 = ProcessCollector(emit=lambda ev: None)
    me = os.getpid()
    first = col4.snapshot()
    my_key = next((k for k in first if k[0] == me), None)
    if my_key is None:
        print("  SKIP (this test process's own pid not visible via psutil "
              "in this sandbox)")
    else:
        col4._last = first   # simulate this WAS the prior poll's baseline
        _psutil_mod.Process.exe = _counting_exe
        try:
            second = col4.snapshot()
        finally:
            _psutil_mod.Process.exe = real_exe
        _check("already-known process's path is byte-identical across polls "
               "(reused, not merely equal by coincidence)",
               second[my_key].path == first[my_key].path and first[my_key].path != "")
        _check("pr.exe() was NOT called again for the already-known pid "
               "(the exact fix: was O(all running processes) every cycle, "
               "now O(new processes) only)",
               call_count["n"] < len(first))

    print("\n[5] A raising emitter never breaks collection")
    def _boom(_ev):
        raise RuntimeError("bad sink")
    col2 = ProcessCollector(emit=_boom)
    seq2 = iter([{a.key(): a}, {a.key(): a, c.key(): c}])
    col2.snapshot = lambda: next(seq2)         # type: ignore[assignment]
    col2.poll_once()
    try:
        col2.poll_once()
        _check("poll_once swallows emitter exceptions", True)
    except Exception:
        _check("poll_once swallows emitter exceptions", False)

    print("\n" + "=" * 48)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
