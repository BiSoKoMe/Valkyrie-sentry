#!/usr/bin/env python3
"""AMSI content-scanning tests (valkyrie/amsi.py + the PowerShell sensor seam).

AMSI is Valkyrie's only source of *content conviction* — an external engine's
verdict rather than a Valkyrie heuristic. These checks pin the two things that
matter about that: the verdict vocabulary is interpreted exactly as the OS
defines it, and the corroborator is strictly ADDITIVE — a scanner that is
absent, silent, or broken must never change what the sensor would otherwise
have reported.

  [1]  AMSI_RESULT → disposition, including both documented boundaries
  [2]  is_malware is a conviction only — an admin-policy block is not one
  [3]  An unstarted scanner degrades to verdicts, never exceptions
  [4]  Empty content is skipped; oversized content is skipped, never truncated
  [5]  Identical content is served from the verdict cache
  [6]  A conviction re-categorizes a script block to `malware` / critical
  [7]  A non-conviction leaves the heuristic result completely untouched
  [8]  A scanner that raises is isolated — the event is still emitted
  [9]  Sub-threshold script blocks are never submitted to AMSI
  [10] Provider presence is read from the registry, not inferred from a scan
  [11] The self-test is tri-state: a non-conviction is inconclusive, not failure
  [12] Explainability: `malware` has meaning, recommendation, and a technique
  [13] Pipeline: a conviction becomes one `malware` incident via EdrEngine
  [14] LIVE provider round trip — opt-in via VALKYRIE_TEST_LIVE_AMSI=1

The live check is opt-in because a provider that convicts the test marker
records a detection in its own history; the rest of the suite is pure and runs
anywhere, including non-Windows CI.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


# --- a fake provider, so the sensor seam is testable off-Windows -----------

class _FakeScanner:
    """Minimal stand-in for AmsiScanner as the sensor consumes it."""

    def __init__(self, disposition, *, result=0, running=True, raises=False):
        from valkyrie.amsi import AmsiVerdict
        self._verdict = AmsiVerdict(disposition, result=result)
        self._running = running
        self._raises = raises
        self.calls = 0

    def is_running(self) -> bool:
        return self._running

    def scan_string(self, text, content_name="", **kw):
        self.calls += 1
        if self._raises:
            raise RuntimeError("provider exploded")
        return self._verdict


def _emit_and_capture(sensor, script: str):
    """Drive the sensor's emit path for one script block; return the event."""
    captured = []
    sensor.bind(captured.append)
    sensor._emit_event({
        "process_id": 4242,
        "data": {"ScriptBlockText": script, "ScriptBlockId": "sb-1",
                 "MessageNumber": "1", "MessageTotal": "1", "Path": ""},
    })
    return captured[0] if captured else None


def main() -> int:
    from valkyrie import amsi as A
    from valkyrie.amsi import AmsiScanner, AmsiVerdict, classify_amsi_result

    print("\n=== AMSI content scanning ===\n")

    # [1] the enum boundaries, exactly as amsi.h defines them
    table = [
        (0, A.DISP_CLEAN), (1, A.DISP_NOT_DETECTED),
        (0x4000, A.DISP_BLOCKED), (0x4FFF, A.DISP_BLOCKED),
        (0x8000, A.DISP_MALWARE), (0x9999, A.DISP_MALWARE),
        (2, A.DISP_UNKNOWN), (0x3FFF, A.DISP_UNKNOWN),
    ]
    _check("AMSI_RESULT maps to the documented dispositions",
           all(classify_amsi_result(r) == d for r, d in table))
    _check("a non-numeric result degrades to unknown, not malware",
           classify_amsi_result("bogus") == A.DISP_UNKNOWN)

    # [2] a conviction is a conviction; a policy block is not
    _check("only AMSI_RESULT_DETECTED counts as malware",
           AmsiVerdict(A.DISP_MALWARE).is_malware
           and not AmsiVerdict(A.DISP_BLOCKED).is_malware
           and not AmsiVerdict(A.DISP_NOT_DETECTED).is_malware)
    _check("'not detected' is not reported as a clean bill of health",
           "not a clean bill" in AmsiVerdict(A.DISP_NOT_DETECTED).summary())

    # [3] never raise when the provider was never initialized
    cold = AmsiScanner(enabled=True)
    v = cold.scan_string("whatever", content_name="cold")
    _check("an unstarted scanner returns a verdict instead of raising",
           v.disposition == A.DISP_UNAVAILABLE and not v.is_malware)
    _check("a disabled scanner reports unavailable",
           AmsiScanner(enabled=False).scan_string("x").disposition == A.DISP_UNAVAILABLE)
    _check("a cold scanner is not 'running'", cold.is_running() is False)

    # [4] skip rather than mislead
    live = AmsiScanner(max_bytes=64)
    started = live.start()          # False on non-Windows / no amsi.dll
    if started:
        _check("empty content is skipped",
               live.scan_string("").disposition == A.DISP_SKIPPED)
        over = live.scan_bytes(b"A" * 500, content_name="big")
        _check("oversized content is skipped, never silently truncated",
               over.disposition == A.DISP_SKIPPED and "cap" in over.error)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "big.bin"
            p.write_bytes(b"B" * 500)
            fv = live.scan_file(str(p))
            _check("an oversized file is skipped with its real size reported",
                   fv.disposition == A.DISP_SKIPPED and fv.scanned_bytes == 500)
            _check("a missing file is skipped, not an error",
                   live.scan_file(str(Path(td) / "nope")).disposition == A.DISP_SKIPPED)

        # [5] cache
        big = AmsiScanner(max_bytes=1 << 20)
        big.start()
        payload = "Get-Process | Where-Object { $_.CPU -gt 10 }"
        first = big.scan_string(payload, content_name="c")
        second = big.scan_string(payload, content_name="c")
        _check("identical content is served from the verdict cache",
               first.cached is False and second.cached is True
               and big.stats["cache_hits"] >= 1)
        big.stop()
        _check("stop() releases the context", big.is_running() is False)
        live.stop()
    else:
        print("  [~] scanner-live checks skipped (AMSI unavailable on this host)")

    # --- the sensor seam ---------------------------------------------------
    from valkyrie.etw.powershell import PowerShellSensor, _AMSI_MIN_SCRIPT_LEN
    from valkyrie.telemetry import CAT_MALWARE, CAT_PROCESS

    benign = "Get-ChildItem -Path C:\\Users | Select-Object Name, Length"

    # [6] a conviction dominates the heuristic
    convicting = _FakeScanner(A.DISP_MALWARE, result=0x8000)
    ev = _emit_and_capture(PowerShellSensor(scanner=convicting), benign)
    _check("a conviction re-categorizes the event to `malware`",
           ev is not None and ev.category == CAT_MALWARE)
    _check("a conviction escalates severity to critical", ev.severity == "critical")
    _check("a conviction is labelled amsi_detected", "amsi_detected" in ev.labels)
    _check("a conviction carries a technique for kill-chain correlation",
           bool(ev.fields.get("technique")))
    _check("the raw provider result is preserved as evidence",
           ev.fields.get("amsi_result") == 0x8000)
    _check("the reason names the provider, not a Valkyrie guess",
           "antimalware provider" in ev.reason)

    # [7] additive, never load-bearing
    plain = _emit_and_capture(PowerShellSensor(), benign)
    quiet = _emit_and_capture(
        PowerShellSensor(scanner=_FakeScanner(A.DISP_NOT_DETECTED, result=1)), benign)
    _check("a non-conviction leaves category and severity untouched",
           quiet.category == plain.category == CAT_PROCESS
           and quiet.severity == plain.severity)
    _check("a non-conviction adds no amsi_detected label",
           "amsi_detected" not in quiet.labels)
    _check("a non-conviction still records the disposition as evidence",
           quiet.fields.get("amsi_disposition") == A.DISP_NOT_DETECTED)

    # [8] failure isolation
    boom = _FakeScanner(A.DISP_MALWARE, raises=True)
    survived = _emit_and_capture(PowerShellSensor(scanner=boom), benign)
    _check("a scanner that raises does not stop the event being emitted",
           survived is not None and survived.category == CAT_PROCESS)
    stopped = _FakeScanner(A.DISP_MALWARE, result=0x8000, running=False)
    _emit_and_capture(PowerShellSensor(scanner=stopped), benign)
    _check("a stopped scanner is not called at all", stopped.calls == 0)

    # [9] noise floor
    tiny = _FakeScanner(A.DISP_MALWARE, result=0x8000)
    short = "x" * (_AMSI_MIN_SCRIPT_LEN - 1)
    ev_short = _emit_and_capture(PowerShellSensor(scanner=tiny), short)
    _check("script blocks below the length floor are never submitted to AMSI",
           tiny.calls == 0 and ev_short.category == CAT_PROCESS)

    # [10] presence is a fact, not an inference
    providers = A.registered_providers()
    _check("registered_providers() returns a well-formed inventory",
           isinstance(providers, list)
           and all({"clsid", "path", "exists", "loaded"} <= set(p) for p in providers))
    _check("provider_state() is one of the four defined states",
           AmsiScanner().provider_state() in
           ("resident", "registered", "none", "unsupported"))

    # [11] tri-state self-test
    _check("every self-test conclusion has a written explanation",
           set(A._SELFTEST_EXPLAIN) == {A.SELFTEST_CONFIRMED,
                                        A.SELFTEST_INCONCLUSIVE,
                                        A.SELFTEST_NO_PROVIDER})
    _check("an untested scanner reports no self-test result",
           AmsiScanner().last_self_test() is None)
    _check("the inconclusive explanation says it is not a failure",
           "not a failure" in A._SELFTEST_EXPLAIN[A.SELFTEST_INCONCLUSIVE])

    # [12] explainability gate
    from valkyrie.edr.investigate import (_MEANING, _RECOMMEND,
                                          KNOWN_INCIDENT_CATEGORIES)
    from valkyrie.edr.builtin import _TECHNIQUE
    from valkyrie.edr.killchain import tactic_for
    _check("`malware` is a known incident category", "malware" in KNOWN_INCIDENT_CATEGORIES)
    _check("`malware` has an analyst meaning", bool(_MEANING.get("malware")))
    _check("`malware` recommends only shipped responders",
           set(_RECOMMEND.get("malware", [])) <= {"block_domain", "kill_process",
                                                  "isolate_host", "collect_forensics"})
    _check("`malware` maps to a MITRE technique", bool(_TECHNIQUE.get("malware")))
    _check("the meaning states the converse does not hold",
           "not thereby clean" in _MEANING["malware"])
    _check("the conviction technique chains to a tactic",
           tactic_for(_TECHNIQUE["malware"]) is not None)

    # [13] end-to-end through the real engine
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "s.db"); store.start()
        engine = EdrEngine(store); engine.start()
        engine.ingest_telemetry(ev.to_dict())     # the convicted event from [6]
        found = None
        for inc in engine.list_incidents():
            dets = engine.get_incident(inc["id"]).get("detections") or []
            if any(d.get("category") == "malware" for d in dets):
                found = inc
                break
        _check("a conviction becomes a `malware` incident", found is not None)
        if found:
            _check("the malware incident is critical", found["severity"] == "critical")
        engine.stop(); store.stop()

    # [14] live provider — opt-in
    if os.environ.get("VALKYRIE_TEST_LIVE_AMSI") == "1":
        s = AmsiScanner()
        if s.start():
            res = s.self_test()
            _check("live self-test returns a defined conclusion",
                   res["conclusion"] in (A.SELFTEST_CONFIRMED, A.SELFTEST_INCONCLUSIVE,
                                         A.SELFTEST_NO_PROVIDER))
            print(f"      live conclusion: {res['conclusion']}; "
                  f"resident: {res['providers_resident'] or 'none'}")
            s.stop()
        else:
            print("  [~] live AMSI requested but unavailable on this host")
    else:
        print("  [~] live provider check skipped (set VALKYRIE_TEST_LIVE_AMSI=1)")

    print("\n" + "=" * 56)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
