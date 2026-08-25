#!/usr/bin/env python3
"""List-free network decision - the gate that keeps feeds from becoming load-bearing.

The owner's requirement: Valkyrie must make its OWN network decisions, not
depend on someone else's list. That is easy to claim and easy to quietly lose,
so it is enforced here as a mechanical property:

    Score every case TWICE - once with threat intel, once with it forced off.
    The VERDICT must be identical. Only confidence may differ.

If any verdict flips when the feeds are removed, a list has become the thing
creating the decision, and this test fails.

  [1] Resolution log - the signal only Valkyrie can compute
  [2] No single weak signal ever fires (the precision rule, structurally)
  [3] Compounding signals do fire
  [4] Unknown context (feature off) is never scored as bad
  [5] THE GATE: verdicts identical with and without threat intel
  [6] Intel alone can never create a verdict
"""

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
    from valkyrie.resolution_log import ResolutionLog
    from valkyrie.network_score import (ConnFacts, score_connection,
                                        verdict_without_intel, THRESHOLD)

    print("\n=== list-free network decision ===\n")

    # ------------------------------------------------------------------
    print("[1] Resolution log — 'did this machine ever ask for that IP?'")
    log = ResolutionLog(max_entries=64, ttl=100.0)
    log.record("example.com", ["93.184.216.34"], ts=1000.0)
    _check("a resolved IP is known", log.was_resolved("93.184.216.34", now=1010.0))
    _check("domain is recoverable",
           log.domain_for("93.184.216.34", now=1010.0) == "example.com")
    _check("an IP never resolved is unknown",
           not log.was_resolved("45.32.11.9", now=1010.0))
    _check("evidence expires (stale answer cannot justify a connection now)",
           not log.was_resolved("93.184.216.34", now=2000.0))
    # Bounded: must not grow without limit on a long-running agent.
    for i in range(200):
        log.record(f"d{i}.test", [f"10.9.{i // 256}.{i % 256}"], ts=3000.0)
    _check("log stays bounded under load", log.stats()["tracked"] <= 64)
    _check("eviction is counted, not silent", log.stats()["evicted"] > 0)

    # ------------------------------------------------------------------
    print("\n[2] NO SINGLE WEAK SIGNAL FIRES (the cardinal precision rule)")
    singles = [
        ("untrusted actor alone", ConnFacts(process_name="x.exe", actor_trusted=False)),
        ("never-resolved alone",  ConnFacts(process_name="x.exe", resolved=False)),
        ("novelty alone",         ConnFacts(process_name="x.exe", process_net_history=0)),
        ("intel hit alone",       ConnFacts(process_name="x.exe", intel_hit=True)),
        ("protocol mismatch alone",
         ConnFacts(process_name="x.exe", raddr_port=443, tls_expected=True,
                   tls_observed=False)),
    ]
    for label, f in singles:
        r = score_connection(f)
        _check(f"{label} does NOT fire", not r["fires"])

    # ------------------------------------------------------------------
    print("\n[3] Compounding signals DO fire")
    # An unsigned binary from %TEMP%, talking to an address nobody looked up,
    # with no prior network history. Three independent tells.
    bad = ConnFacts(
        process_name="svch0st.exe",
        process_path=r"C:\Users\v\AppData\Local\Temp\svch0st.exe",
        raddr_ip="45.32.11.9", raddr_port=443,
        actor_trusted=False, actor_low_trust_path=True,
        resolved=False, process_net_history=0)
    r = score_connection(bad)
    _check("three compounding signals fire", r["fires"])
    _check("score clears the threshold", r["score"] >= THRESHOLD)
    _check("reason names every signal", len(r["signals"]) >= 3)
    _check("explanation is human-readable", "never resolved" in r["reason"])

    # A signed OS component doing ordinary work must stay silent.
    good = ConnFacts(
        process_name="chrome.exe",
        process_path=r"C:\Program Files\Google\Chrome\chrome.exe",
        raddr_ip="142.250.72.14", raddr_port=443,
        actor_trusted=True, resolved=True,
        process_net_history=50_000, tls_expected=True, tls_observed=True)
    _check("a signed browser doing normal work does NOT fire",
           not score_connection(good)["fires"])

    # ------------------------------------------------------------------
    print("\n[4] UNKNOWN is never scored as BAD (features off must not alarm)")
    # Every derived field None = nothing deployed. Must be inert, or turning a
    # feature off would make every connection on the machine look malicious.
    unknown = ConnFacts(process_name="anything.exe", raddr_ip="8.8.8.8")
    r = score_connection(unknown)
    _check("all-unknown context produces no signals", r["labels"] == [])
    _check("all-unknown context does not fire", not r["fires"])
    _check("resolved=None is inert (distinct from resolved=False)",
           score_connection(ConnFacts(process_name="x.exe", resolved=None))["labels"] == [])

    # ------------------------------------------------------------------
    print("\n[5] THE GATE — verdicts must be identical without threat intel")
    corpus = [bad, good, unknown,
              ConnFacts(process_name="a.exe", actor_trusted=False, resolved=False,
                        intel_hit=True),
              ConnFacts(process_name="b.exe", actor_trusted=False,
                        actor_low_trust_path=True, resolved=False,
                        process_net_history=0, intel_hit=True),
              ConnFacts(process_name="c.exe", actor_trusted=True, resolved=True,
                        intel_hit=True),
              ConnFacts(process_name="d.exe", resolved=False, beacon_interval=60.0,
                        beacon_jitter=0.05, beacon_count=12, intel_hit=True),
              ConnFacts(process_name="e.exe", actor_trusted=False,
                        process_upload_baseline=1000, bytes_sent=50_000_000,
                        resolved=False, intel_hit=True),
              ]
    flips = []
    for i, f in enumerate(corpus):
        with_intel = score_connection(f)
        without    = verdict_without_intel(f)
        if with_intel["fires"] != without["fires"]:
            flips.append((i, f.process_name, with_intel["fires"], without["fires"]))
    _check("no verdict changes when every feed is removed", not flips)
    if flips:
        for i, name, a, b in flips:
            print(f"        case {i} ({name}): fires={a} with intel, {b} without "
                  f"-> a LIST became load-bearing")

    # ------------------------------------------------------------------
    print("\n[6] Intel corroborates, it never decides")
    only_intel = ConnFacts(process_name="x.exe", raddr_ip="45.32.11.9", intel_hit=True)
    _check("intel hit with NO behavioural signal does not fire",
           not score_connection(only_intel)["fires"])
    # It must still add confidence where behaviour already decided.
    behav = ConnFacts(process_name="x.exe", actor_trusted=False, resolved=False)
    _check("intel raises confidence on an already-firing case",
           score_connection(
               ConnFacts(process_name="x.exe", actor_trusted=False,
                         resolved=False, intel_hit=True))["score"]
           > score_connection(behav)["score"])
    _check("...without changing that verdict",
           score_connection(behav)["fires"] ==
           verdict_without_intel(
               ConnFacts(process_name="x.exe", actor_trusted=False,
                         resolved=False, intel_hit=True))["fires"])

    print("\n" + "=" * 58)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED — network decisions do not depend on any list.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
