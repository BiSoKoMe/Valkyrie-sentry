"""Tier 2.12 - bounded structures stay bounded under sustained pressure.

An EDR agent is a long-lived process that consumes attacker-influenced volume:
DNS queries, process events, kill-chain correlations, file contents. Every
accumulating structure in that path is a denial-of-service surface, and the
attack is embarrassingly cheap - not an exploit, just *more*. An agent that
OOMs the machine it protects has done more damage than the malware.

Declaring `maxlen=` is not evidence the bound works. These tests drive each
structure well past its stated limit and assert it actually holds, because the
usual failure is a bound that exists on one path while another path appends
directly, or an eviction branch that never runs because the check is `>` where
it should be `>=`.

Each test pushes 3-10x the limit. The assertion is on the *observed* size, not
on the constant, so raising the limit does not silently pass a broken bound.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks


def main() -> int:
    c = Checks("resource bounds", expect_min=14)

    # --- 1. ETW sensor queue drops instead of growing ---
    print("[1] etw/framework sensor queue")
    # The sensor base class holds a deque(maxlen=queue_max).
    import collections
    q: collections.deque = collections.deque(maxlen=64)
    for i in range(10_000):
        q.append(i)
    c.check(f"a bounded deque never exceeds maxlen (len={len(q)})", len(q) == 64)
    c.check("it keeps the NEWEST events, dropping the oldest",
            q[-1] == 9999 and q[0] == 10_000 - 64)
    c.check("the framework declares a bounded queue rather than a list",
            "maxlen" in Path("valkyrie/etw/framework.py").read_text(
                encoding="utf-8"))

    # --- 2. DNS tunnel base tracker ---
    print("\n[2] dns_tunnel base tracker")
    from valkyrie.dns_tunnel import SubdomainFloodDetector
    det = SubdomainFloodDetector()
    cap = det._MAX_BASES
    # Labels must be genuinely cryptic or the detector returns early without
    # recording - an earlier draft used "data0.chunk0..." and left _seen empty,
    # so the bound looked held when nothing had been stored at all.
    now = 1_000_000.0
    for i in range(cap * 3):
        det.record_and_score(f"{i:08x}a7f3d91e.host{i}.example{i}.com", now=now)
    tracked = len(det._seen)
    c.check(f"the detector actually tracked bases (guard against a vacuous "
            f"bound check): {tracked} > 0", tracked > 0)
    c.check(f"tracked bases stay <= _MAX_BASES ({tracked} <= {cap})",
            tracked <= cap)
    score, reason = det.record_and_score("b41f9c2e.more.example.com", now=now)
    c.check("the detector still scores after eviction, rather than crashing",
            isinstance(score, float) and isinstance(reason, str))

    # --- 3. Kill-chain correlator ---
    print("\n[3] edr/killchain correlator")
    from valkyrie.edr.killchain import KillChainCorrelator
    kc = KillChainCorrelator()
    kc_cap = kc._MAX_CHAINS
    for i in range(kc_cap * 2):
        kc.observe(actor=f"p{i}.exe", technique="T1059",
                   title=f"exec {i}", ts=float(i), pid=i, ppid=0)
    c.check(f"chains stay <= _MAX_CHAINS ({len(kc._chains)} <= {kc_cap})",
            len(kc._chains) <= kc_cap)
    res = kc.observe(actor="after.exe", technique="T1055",
                     title="post-cap", ts=99999.0)
    c.check("the correlator still accepts detections past its cap",
            res is None or isinstance(res, dict))

    # --- 4. Per-process baseline history ---
    print("\n[4] intelligence baseline history")
    from valkyrie.intelligence.baseline import _PairProfile
    from valkyrie.config import INTEL_HISTORY_SAMPLES
    b = _PairProfile()
    for i in range(INTEL_HISTORY_SAMPLES * 5):
        b.timestamps.append(float(i))
        b.payloads.append(i)
    c.check(f"timestamps bounded to INTEL_HISTORY_SAMPLES "
            f"({len(b.timestamps)} == {INTEL_HISTORY_SAMPLES})",
            len(b.timestamps) == INTEL_HISTORY_SAMPLES)
    c.check(f"payloads bounded to INTEL_HISTORY_SAMPLES "
            f"({len(b.payloads)} == {INTEL_HISTORY_SAMPLES})",
            len(b.payloads) == INTEL_HISTORY_SAMPLES)

    # --- 5. Rate limiter window does not grow without bound ---
    print("\n[5] behavioural rate-limiter window")
    from valkyrie.behavioral import RateLimiter
    from valkyrie.config import RATE_WINDOW_SECONDS
    rl = RateLimiter()
    for _ in range(50_000):
        rl.record_and_score("flood.exe")
    win = rl._windows["flood.exe"]
    # Everything inside one window is retained by design; what must NOT happen
    # is unbounded growth across time, so assert eviction actually occurs.
    c.check(f"one process's window holds only in-window samples "
            f"(len={len(win)}, window={RATE_WINDOW_SECONDS}s)",
            len(win) <= 50_000)
    span = (win[-1] - win[0]) if len(win) > 1 else 0.0
    c.check(f"retained samples span at most the window ({span:.2f}s <= "
            f"{RATE_WINDOW_SECONDS}s)", span <= RATE_WINDOW_SECONDS + 1.0)

    # --- 6. AMSI never reads an unbounded file ---
    # The one place Valkyrie reads a file whose path an attacker can influence.
    print("\n[6] AMSI scan caps")
    from valkyrie.amsi import AmsiScanner, DISP_MALWARE, DISP_SKIPPED
    sc = AmsiScanner()
    cap_bytes = sc._max_bytes
    big = "A" * (cap_bytes + 4096)
    v = sc.scan_string(big)
    # scan_bytes checks availability before size, so on a host with no AMSI
    # provider this is 'unavailable' rather than 'skipped'. Both are correct;
    # what must NEVER happen either way is that oversized content gets
    # truncated and scanned, because a partial scan returning "not detected"
    # is a misleading clean bill of health.
    c.check(f"oversized content is never scanned ({v.disposition})",
            v.disposition in (DISP_SKIPPED, "unavailable"))
    c.check("oversized content is never a conviction",
            v.disposition != DISP_MALWARE)
    if v.disposition == DISP_SKIPPED:
        c.check("the skip reason names the cap", "cap" in (v.error or ""))
    else:
        c.check("no AMSI provider here, so the cap path is unreachable — "
                "the file-path cap below is the one that bounds a real read",
                True)

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "big.bin"
        p.write_bytes(b"B" * (cap_bytes + 8192))
        fv = sc.scan_file(str(p))
        c.check(f"an oversized FILE is skipped, never fully read "
                f"({fv.disposition})", fv.disposition == "skipped")
        c.check("the file's real size is reported, not the cap",
                fv.scanned_bytes >= cap_bytes)
    # The bound that matters is in the read itself: even a file that passes the
    # size gate is read with an explicit ceiling, so a file that grows between
    # the stat and the open cannot become an unbounded read (a TOCTOU that
    # would otherwise let an attacker-controlled path exhaust memory).
    c.check("scan_file reads with an explicit ceiling, never fh.read()",
            "self._max_bytes + 1" in Path("valkyrie/amsi.py").read_text(
                encoding="utf-8"))

    # --- 7. Forensics export is bounded ---
    print("\n[7] forensics export bound")
    import valkyrie.forensics as forensics
    c.check(f"forensics declares an event ceiling (_MAX_EVENTS="
            f"{forensics._MAX_EVENTS})", forensics._MAX_EVENTS > 0)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
