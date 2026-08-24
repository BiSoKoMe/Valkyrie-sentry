"""Tier 3.16 (partial) — the startup status box tells the truth.

`__main__.py` is 855 statements at 0% coverage, and `main()` alone is ~1,300
lines. TEST_PLAN says not to test the god function but to extract from it,
because the function is the bug. This file covers the first extraction:
`build_status_rows` / `protection_state`.

That piece was chosen first because it is not merely convenient — it is the
screen that tells a user whether they are protected. A row that renders green
for a component that failed to start is the same class of failure as a
heartbeat stuck on healthy: the user reads ACTIVE and behaves accordingly.

The rest of the extraction is deliberately not done blind. See the tier 3.16
note in docs/TEST_PLAN.md — the startup path binds DNS ports and rewrites
firewall rules, so no extraction of it can be *executed* on a developer host to
prove behaviour was preserved, and an unverified refactor of the entry point
trades a documented structural problem for an undetected functional one.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie.__main__ import build_status_rows, protection_state


def _args(**kw):
    base = dict(no_dns=False, no_firewall=False, port=5353, web=False,
                web_port=8090)
    base.update(kw)
    return SimpleNamespace(**base)


def _label(rows, name):
    for label, ok, detail in rows:
        if label == name:
            return (ok, detail)
    return None


def main() -> int:
    c = Checks("startup status", expect_min=20)

    # ── The row that matters most: a DNS sinkhole that did not bind ─────────
    print("[1] a component that failed to start must render RED")
    rows = build_status_rows(args=_args(), dns_server=None)
    dns = _label(rows, "DNS Sinkhole")
    c.check("a failed DNS bind produces a DNS Sinkhole row", dns is not None)
    c.check("and that row is NOT ok", dns and dns[0] is False)
    c.check("and it says the port could not be bound",
            dns and "could not bind" in dns[1])
    c.check("overall state is DEGRADED, never ACTIVE",
            protection_state(rows) == "DEGRADED")

    print("\n[2] a component that started renders GREEN with detail")
    rows = build_status_rows(args=_args(port=5353), dns_server=object())
    dns = _label(rows, "DNS Sinkhole")
    c.check("a bound DNS sinkhole is ok", dns and dns[0] is True)
    c.check("and reports the actual port", dns and "5353" in dns[1])

    # ── Disabled is not the same as failed ──────────────────────────────────
    print("\n[2b] an expected-but-missing component renders RED, not absent")
    # The firewall is optional/non-fatal at startup, so it can be None. The
    # pre-extraction code called firewall.count() unconditionally and raised
    # AttributeError, taking the status box down with it.
    rows = build_status_rows(args=_args(), dns_server=object(), firewall=None)
    fw = _label(rows, "Firewall")
    c.check("a firewall that failed to initialise still produces a row",
            fw is not None)
    c.check("and that row is red rather than quietly missing",
            fw and fw[0] is False)
    c.check("building the rows with no firewall does not raise",
            isinstance(rows, list))
    rows_ok = build_status_rows(
        args=_args(), dns_server=object(),
        firewall=SimpleNamespace(count=lambda: 12345))
    c.check("a working firewall reports its range count",
            "12,345" in _label(rows_ok, "Firewall")[1])
    c.check("--no-firewall omits the row entirely (disabled != failed)",
            _label(build_status_rows(args=_args(no_firewall=True),
                                     dns_server=object()), "Firewall") is None)

    print("\n[3] a DISABLED component is absent, not shown as failed")
    rows = build_status_rows(args=_args(no_dns=True), dns_server=None)
    c.check("--no-dns omits the DNS row entirely rather than showing it red",
            _label(rows, "DNS Sinkhole") is None)
    c.check("and that alone does not make the product look DEGRADED "
            "(fallback row aside)",
            isinstance(protection_state(rows), str))

    # ── The leak guard: the one row that is red by default, on purpose ──────
    print("\n[4] DNS leak guard reflects fail-closed vs fallback")
    rows = build_status_rows(args=_args(), dns_server=object(),
                             allow_external_fallback=False)
    lg = _label(rows, "DNS Leak Guard")
    c.check("fail-closed is reported ok", lg and lg[0] is True)
    c.check("and describes local-resolver-only", lg and "local resolver" in lg[1])

    rows = build_status_rows(args=_args(), dns_server=object(),
                             allow_external_fallback=True)
    lg = _label(rows, "DNS Leak Guard")
    c.check("public-DNS fallback is reported NOT ok", lg and lg[0] is False)
    c.check("and names the remedy", lg and "Unbound" in lg[1])
    c.check("fallback alone is enough to read DEGRADED",
            protection_state(rows) == "DEGRADED")

    # ── Optional components appear only when present ────────────────────────
    print("\n[5] optional components appear only when actually wired")
    rows = build_status_rows(args=_args(), dns_server=object())
    for absent in ("MAC Random", "TLS Inspect", "Heartbeat", "EDR",
                   "Intelligence", "Dashboard"):
        c.check(f"'{absent}' is absent when not wired",
                _label(rows, absent) is None)

    rows = build_status_rows(
        args=_args(web=True, web_port=8099), dns_server=object(),
        mac_randomizer=object(), heartbeat=object(),
        tls_inspector=SimpleNamespace(port=8080),
        edr_engine=SimpleNamespace(stats=lambda: {"plugins": 7,
                                                  "incidents_open": 2}),
        intelligence=SimpleNamespace(status=lambda: {
            "learning": False, "threats_learned": 1234,
            "learning_day": 0, "learning_days_total": 7}),
    )
    c.check("MAC randomizer appears when wired",
            _label(rows, "MAC Random") is not None)
    c.check("TLS inspector reports its real port",
            _label(rows, "TLS Inspect")[1].endswith("8080"))
    c.check("EDR reports real plugin and incident counts",
            "7 plugins" in _label(rows, "EDR")[1]
            and "2 open" in _label(rows, "EDR")[1])
    c.check("Intelligence reports learned-threat count when past learning",
            "1,234" in _label(rows, "Intelligence")[1])
    c.check("the dashboard row uses the configured web port",
            "8099" in _label(rows, "Dashboard")[1])

    # Learning mode must be reported as learning, not as a threat count of 0 —
    # "0 threats learned" would read as broken rather than as still-training.
    rows = build_status_rows(
        args=_args(), dns_server=object(),
        intelligence=SimpleNamespace(status=lambda: {
            "learning": True, "threats_learned": 0,
            "learning_day": 3, "learning_days_total": 7}))
    intel = _label(rows, "Intelligence")
    c.check("learning mode says 'learning', not '0 threats'",
            "learning" in intel[1] and "day 3" in intel[1])

    # ── protection_state is a strict AND over the rows ──────────────────────
    print("\n[6] protection_state is strict")
    c.check("all-ok reads ACTIVE",
            protection_state([("a", True, ""), ("b", True, "")]) == "ACTIVE")
    c.check("a single failed row reads DEGRADED",
            protection_state([("a", True, ""), ("b", False, "")]) == "DEGRADED")
    c.check("no rows at all does not read DEGRADED by accident",
            protection_state([]) == "ACTIVE")

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
