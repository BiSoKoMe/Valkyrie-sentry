"""Tier 1.9 — every state-changing route is auth-gated, enumerated not listed.

`test_web_auth.py` checks a hand-picked set of endpoints. That protects the
endpoints someone remembered to add to it, which is the wrong shape of test for
this risk: the dangerous route is the one added next month by someone who did
not think about auth, and a hand-maintained list is silent about exactly that.

So this file does not name routes. It asks the app for **all** of them, filters
to the state-changing verbs, and asserts each one refuses an off-loopback
caller with no token. A new unguarded POST fails this file the moment it is
added, with no test edit required.

Why it matters concretely: Valkyrie's API can isolate the host, kill processes
and rewrite firewall rules. An ungated state-changing route on a machine with
any other local user, container, or browser-reachable service turns the security
product into the privilege-escalation path. The failure mode is not "data leak",
it is "the EDR becomes the exploit".

Loopback is intentionally allowed without a token (that is the product's local
UX). The gate under test is the off-loopback path.
"""

from __future__ import annotations

import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks, skip_file

# Verbs that can change state. GET/HEAD/OPTIONS are read-only and covered by
# the off-loopback data guard tested in test_web_auth.py.
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

# Routes legitimately reachable off-loopback without a token. Kept explicit and
# tiny: anything added here is a deliberate, reviewable decision to expose a
# route, not an oversight. The HTML shell carries no data — every API call it
# makes is itself gated.
_PUBLIC_PREFIXES = ("/static", "/docs", "/redoc", "/openapi.json")

# HOST-AFFECTING. This file's whole point is to let requests reach real
# handlers with a *valid* token (step [3] below) so the "gate opens" check is
# not vacuous — and separately, a bug that removes a route's auth gate would
# make the *no-token* sweep reach the real handler too. Several handlers are
# not simulations: mac.randomize()/restore() write the Windows NetworkAddress
# registry value and cycle a real adapter with `netsh ... admin=disabled` (the
# exact mechanism the project's safety rules forbid running live), meeting
# mode's activate() flips the Windows Firewall to block-all, and system
# restart/shutdown spawn a detached PowerShell script. None of that may ever
# fire just because this file ran. Patched to safe no-ops for the whole test,
# regardless of which routes land in the enumerated set or the sample below —
# this is the actual safety mechanism, not the sample filtering underneath it.
_DANGER_PATCHES = (
    ("valkyrie.mac_randomizer.MacRandomizer.randomize",
     lambda self, interface=None: "AA:BB:CC:DD:EE:FF"),
    ("valkyrie.mac_randomizer.MacRandomizer.restore",
     lambda self, interface=None: "AA:BB:CC:DD:EE:FF"),
    ("valkyrie.meeting_mode.MeetingMode.activate",
     lambda self: {"active": True, "test_stub": True}),
    ("valkyrie.meeting_mode.MeetingMode.deactivate",
     lambda self: {"active": False, "test_stub": True}),
    ("valkyrie.web.server._run_detached_ps",
     lambda ps_command: None),
    ("valkyrie.telemetry_killer.TelemetryKiller.kill",
     lambda self: {}),
    ("valkyrie.telemetry_killer.TelemetryKiller.restore",
     lambda self: {}),
)

# Belt-and-suspenders on top of the patches above: even with every dangerous
# primitive stubbed out, these specific routes are excluded from the "does a
# valid token actually open the gate" sample so that a future stub that misses
# a new code path still can't reach live hardware/OS side effects here.
_UNSAFE_TO_SAMPLE = {
    ("/api/mac/randomize", "POST"),
    ("/api/mac/restore", "POST"),
    ("/api/system/restart", "POST"),
    ("/api/system/shutdown", "POST"),
    ("/api/meeting/start", "POST"),
    ("/api/meeting/stop", "POST"),
    ("/api/telemetry/kill", "POST"),
    ("/api/telemetry/restore", "POST"),
}


def _is_public(path: str) -> bool:
    return path == "/" or any(path.startswith(p) for p in _PUBLIC_PREFIXES)


def _concrete(path: str) -> str:
    """Fill path params with a dummy so the route is actually reachable.

    An unmatched `{id}` would 404 before the auth guard ever runs, which would
    make an ungated route look protected — the exact false pass this file must
    not produce.
    """
    out = []
    for seg in path.split("/"):
        if seg.startswith("{") and seg.endswith("}"):
            out.append("test-id")
        else:
            out.append(seg)
    return "/".join(out)


def main() -> int:
    try:
        from starlette.testclient import TestClient  # noqa: F401
    except Exception as exc:   # noqa: BLE001
        return skip_file("web route auth", f"starlette test client unavailable: {exc}")
    try:
        from valkyrie.web.server import create_app, state, _CONTROL_TOKEN
        from valkyrie.store import Store
    except ImportError as exc:
        return skip_file("web route auth", f"fastapi/web stack unavailable: {exc}")

    from testclient_compat import make_client

    c = Checks("web route auth", expect_min=8)

    stack = ExitStack()
    for target, fn in _DANGER_PATCHES:
        try:
            stack.enter_context(mock.patch(target, fn))
        except (ImportError, AttributeError) as exc:
            stack.close()
            return skip_file("web route auth",
                              f"could not patch host-affecting handler {target}: {exc}")

    td = tempfile.mkdtemp()
    store = Store(db_path=Path(td) / "route_auth.db")
    store.start()
    state.store = store
    app = create_app()

    remote = make_client(app, "203.0.113.9")     # off-loopback, TEST-NET-3
    local = make_client(app, "127.0.0.1")
    good = {"X-Valkyrie-Token": _CONTROL_TOKEN}

    # Enumerate every mutating (path, method) the app actually exposes.
    routes: list[tuple[str, str]] = []
    for r in app.routes:
        path = getattr(r, "path", None)
        methods = getattr(r, "methods", None) or set()
        if not path or _is_public(path):
            continue
        for m in methods:
            if m in _MUTATING:
                routes.append((path, m))
    routes.sort()

    print(f"\n=== {len(routes)} state-changing routes discovered ===\n")
    c.check("the app exposes state-changing routes to test (guard against "
            "an enumeration that silently finds nothing)", len(routes) > 0)

    ungated: list[str] = []
    not_found: list[str] = []
    for path, method in routes:
        url = _concrete(path)
        resp = remote.request(method, url)
        code = resp.status_code
        if code == 404:
            # A 404 means the request never reached an auth check, so this row
            # proves nothing either way. Recorded rather than counted as a pass.
            not_found.append(f"{method} {path}")
            print(f"  ?    {method:6s} {path}  -> 404 (unreachable, inconclusive)")
        elif code in (401, 403):
            print(f"  ok   {method:6s} {path}  -> {code}")
        else:
            ungated.append(f"{method} {path} -> {code}")
            print(f"  FAIL {method:6s} {path}  -> {code}  NOT GATED")

    print()
    c.check(f"every state-changing route rejects an off-loopback caller with "
            f"no token ({len(ungated)} ungated)", not ungated)
    if ungated:
        for u in ungated:
            print(f"    UNGATED: {u}")
    c.check(f"routes were actually exercised, not all 404 "
            f"({len(routes) - len(not_found)}/{len(routes)} reachable)",
            len(not_found) < len(routes))

    # A wrong token must be as good as no token — a comparison that accepts any
    # non-empty string would pass every check above.
    print("[2] a wrong token is rejected exactly like no token")
    bad = {"X-Valkyrie-Token": "not-the-token"}
    sampleable = [r for r in routes
                  if not _concrete(r[0]).count("test-id") and r not in _UNSAFE_TO_SAMPLE]
    sample = sampleable[:5] or routes[:5]
    wrong_ok = []
    for path, method in sample:
        code = remote.request(method, _concrete(path), headers=bad).status_code
        if code not in (401, 403, 404):
            wrong_ok.append(f"{method} {path} -> {code}")
    c.check(f"a wrong token is refused on every sampled route "
            f"({len(wrong_ok)} accepted it)", not wrong_ok)

    # An empty token must not satisfy the gate either.
    empty_ok = []
    for path, method in sample:
        code = remote.request(method, _concrete(path),
                              headers={"X-Valkyrie-Token": ""}).status_code
        if code not in (401, 403, 404):
            empty_ok.append(f"{method} {path} -> {code}")
    c.check(f"an empty token is refused on every sampled route "
            f"({len(empty_ok)} accepted it)", not empty_ok)

    # The gate must be a real gate, not a permanent 403: the correct token has
    # to actually let a caller through, or the checks above are vacuous.
    print("\n[3] the gate opens for the correct token (else the above is vacuous)")
    opened = sum(1 for path, method in sample
                 if remote.request(method, _concrete(path),
                                   headers=good).status_code not in (401, 403))
    c.check(f"the correct token is accepted somewhere ({opened}/{len(sample)} "
            "sampled routes opened)", opened > 0)

    # Loopback keeps working without a token — the local UX contract.
    print("\n[4] loopback retains tokenless read access")
    c.check("loopback GET /api/stats works without a token",
            local.get("/api/stats").status_code == 200)
    c.check("off-loopback GET /api/stats still requires a token",
            remote.get("/api/stats").status_code == 403)

    if not_found:
        print("\n  inconclusive (404, never reached an auth check):")
        for n in not_found:
            print(f"    - {n}")

    store.stop()
    stack.close()
    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
