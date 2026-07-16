#!/usr/bin/env python3
"""Process telemetry collector — heuristics + diff/emit behavior (ADR-0012)."""

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

    print("\n[2] ProcInfo.to_event()")
    ev = ProcInfo(pid=42, name="powershell.exe", path="C:/ps.exe",
                  ppid=10, parent_name="winword.exe", create_time=123.0).to_event()
    _check("category is process", ev.category == T.CAT_PROCESS)
    _check("activity is exec", ev.activity == "exec")
    _check("high-severity -> action flagged", ev.action == T.ACT_FLAGGED)
    _check("actor + parent carried",
           ev.actor_pid == 42 and ev.fields["parent_name"] == "winword.exe")

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
