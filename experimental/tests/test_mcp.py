#!/usr/bin/env python3
"""Valkyrie MCP server tests (valkyrie/mcp/).

Covers the JSON-RPC/MCP protocol layer AND — more importantly — the safety
guarantees: an AI agent driving an EDR must not be able to take an enforcement
action that wasn't explicitly enabled, and must be told Valkyrie's real limits
rather than assuming full coverage.

  [1] Protocol: initialize / ping / tools/list / unknown method / notifications
  [2] Tool surface: every tool has a name, description and object schema
  [3] SAFETY: the acting tool is hidden AND refused in a read-only session
  [4] SAFETY: with response enabled, dry_run still defaults to TRUE
  [5] Tool errors come back as isError results, never transport crashes
  [6] Read tools work against a real engine (incidents, hunts, investigate)
  [7] Coverage introspection reports layers AND honest boundaries
  [8] serve(): a full stdio session over newline-delimited JSON-RPC
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def _req(msg_id, method, params=None):
    m = {"jsonrpc": "2.0", "id": msg_id, "method": method}
    if params is not None:
        m["params"] = params
    return m


def _call(ctx, name, args=None):
    from valkyrie.mcp import handle_message
    return handle_message(ctx, _req(9, "tools/call",
                                    {"name": name, "arguments": args or {}}))


def _payload(resp):
    """Decode a tools/call result back into the JSON the tool returned."""
    return json.loads(resp["result"]["content"][0]["text"])


def main() -> int:
    from valkyrie.mcp import (PROTOCOL_VERSION, ToolContext, handle_message,
                              list_tools, serve, TOOLS)

    print("\n=== Valkyrie MCP server ===\n")
    ro = ToolContext(allow_response=False)      # read-only session

    print("[1] Protocol basics")
    r = handle_message(ro, _req(1, "initialize", {"protocolVersion": "2024-11-05"}))
    _check("initialize returns a result", r is not None and "result" in r)
    _check("initialize echoes a protocol version",
           r["result"]["protocolVersion"] == PROTOCOL_VERSION)
    _check("initialize advertises tools capability",
           "tools" in r["result"]["capabilities"])
    _check("initialize names the server",
           r["result"]["serverInfo"]["name"] == "valkyrie")
    _check("instructions steer the agent to the coverage tool",
           "valkyrie_get_detection_coverage" in r["result"].get("instructions", ""))
    _check("ping answers", handle_message(ro, _req(2, "ping"))["result"] == {})
    unknown = handle_message(ro, _req(3, "nope/nope"))
    _check("unknown method is a JSON-RPC error (-32601)",
           unknown["error"]["code"] == -32601)
    _check("a NOTIFICATION is never answered",
           handle_message(ro, {"jsonrpc": "2.0", "method": "notifications/initialized"}) is None)
    _check("non-2.0 message rejected",
           "error" in handle_message(ro, {"id": 1, "method": "x"}))

    print("\n[2] Tool surface")
    listed = handle_message(ro, _req(4, "tools/list"))["result"]["tools"]
    _check("tools/list returns tools", len(listed) >= 7)
    ok_shape = all(t.get("name") and t.get("description")
                   and t.get("inputSchema", {}).get("type") == "object"
                   for t in listed)
    _check("every tool has name + description + object schema", ok_shape)
    _check("tool names follow valkyrie_<action>_<resource>",
           all(t["name"].startswith("valkyrie_") for t in listed))

    print("\n[3] SAFETY — read-only session cannot act")
    names = {t["name"] for t in listed}
    _check("valkyrie_respond is NOT advertised read-only",
           "valkyrie_respond" not in names)
    resp = _call(ro, "valkyrie_respond", {"action": "block_domain", "target": "x.test"})
    _check("calling it anyway is refused", resp["result"]["isError"] is True)
    _check("refusal explains how to enable it",
           "--allow-response" in resp["result"]["content"][0]["text"])

    print("\n[4] SAFETY — response enabled still defaults to dry-run")
    seen = {}

    class _FakeEngine:
        def available_actions(self):
            return ["block_domain", "kill_process", "isolate_host"]

        def respond(self, action, target="", *, dry_run=True, operator="", incident_id=""):
            seen.update({"action": action, "target": target, "dry_run": dry_run,
                         "operator": operator})
            return {"action": action, "status": "ok", "dry_run": dry_run}

    rw = ToolContext(engine=_FakeEngine(), allow_response=True)
    _check("valkyrie_respond IS advertised when enabled",
           "valkyrie_respond" in {t["name"] for t in list_tools(rw)})
    _call(rw, "valkyrie_respond", {"action": "block_domain", "target": "evil.test"})
    _check("dry_run defaults to TRUE when unspecified", seen.get("dry_run") is True)
    _check("operator is attributed to mcp", seen.get("operator") == "mcp")
    _call(rw, "valkyrie_respond", {"action": "block_domain", "target": "evil.test",
                                   "dry_run": False})
    _check("explicit dry_run=false is honoured", seen.get("dry_run") is False)
    bad = _call(rw, "valkyrie_respond", {"action": "rm_rf_everything"})
    _check("an unknown action is refused", bad["result"]["isError"] is True)

    print("\n[5] Tool errors are results, not crashes")
    err = _call(ro, "valkyrie_does_not_exist", {})
    _check("unknown tool → isError result", err["result"]["isError"] is True)
    err2 = _call(ro, "valkyrie_get_incident", {})     # missing required arg
    _check("missing required arg → isError result", err2["result"]["isError"] is True)
    err3 = _call(ToolContext(), "valkyrie_search_incidents", {})
    _check("no engine → isError, not an exception", err3["result"]["isError"] is True)

    print("\n[6] Read tools against a real engine")
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "m.db"); store.start()
        engine = EdrEngine(store); engine.start()
        live = ToolContext(engine=engine, store=store, allow_response=False)
        # Create a real incident through the real pipeline.
        inc_id = engine.ingest_telemetry({
            "category": "process", "activity": "exec", "action": "flagged",
            "severity": "critical", "labels": ["shadow_delete"],
            "reason": "vssadmin delete shadows", "actor_name": "vssadmin.exe",
            "actor_pid": 1234,
            "fields": {"technique": "T1490 — Inhibit System Recovery", "ppid": 1}})
        _check("test incident created", inc_id is not None)

        st = _payload(_call(live, "valkyrie_get_status"))
        _check("status reports the engine running", st["engine"] == "running")
        _check("status reports response disabled", st["response_enabled"] is False)

        found = _payload(_call(live, "valkyrie_search_incidents", {"limit": 10}))
        _check("search_incidents finds it", found["count"] >= 1)
        _check("summaries carry id + severity",
               all("id" in i and "severity" in i for i in found["incidents"]))

        detail = _payload(_call(live, "valkyrie_get_incident", {"incident_id": inc_id}))
        _check("get_incident returns detections", len(detail.get("detections") or []) >= 1)

        rep = _payload(_call(live, "valkyrie_investigate_incident", {"incident_id": inc_id}))
        _check("investigate returns a report", isinstance(rep, dict) and len(rep) > 0)

        hunts = _payload(_call(live, "valkyrie_list_hunts"))
        _check("list_hunts returns saved hunts", len(hunts["hunts"]) >= 3)
        hid = hunts["hunts"][0]["id"]
        hres = _payload(_call(live, "valkyrie_run_hunt", {"hunt_id": hid, "limit": 5}))
        _check(f"run_hunt('{hid}') returns a result set", "rows" in hres or "count" in hres)
        _check("unknown hunt is handled",
               "error" in _payload(_call(live, "valkyrie_run_hunt", {"hunt_id": "nope"})))

        ev = _payload(_call(live, "valkyrie_search_events", {"limit": 5, "since_hours": 24}))
        _check("search_events returns a result set", isinstance(ev, dict))

        print("\n[7] Coverage introspection is honest")
        cov = _payload(_call(live, "valkyrie_get_detection_coverage"))
        _check("reports the IOA rule layer", "ioa_rules" in cov["layers"])
        _check("reports the behavioural sequence layer",
               "behavioral_sequences" in cov["layers"])
        _check("states boundaries", len(cov["boundaries"]) >= 4)
        joined = " ".join(cov["boundaries"]).lower()
        _check("admits detection != prevention", "not prevention" in joined)
        _check("admits the polling gap", "poll" in joined)

        print("\n[8] Full stdio session")
        lines = "\n".join(json.dumps(m) for m in [
            _req(1, "initialize", {"protocolVersion": "2024-11-05"}),
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            _req(2, "tools/list"),
            _req(3, "tools/call", {"name": "valkyrie_get_status", "arguments": {}}),
        ]) + "\n"
        out = io.StringIO()
        rc = serve(live, stdin=io.StringIO(lines), stdout=out)
        replies = [json.loads(l) for l in out.getvalue().strip().splitlines()]
        _check("serve() exits cleanly", rc == 0)
        _check("exactly 3 replies (the notification got none)", len(replies) == 3)
        _check("replies carry matching ids", [r["id"] for r in replies] == [1, 2, 3])
        _check("stdout is pure JSON-RPC (parseable lines)", all("jsonrpc" in r for r in replies))

        engine.stop(); store.stop()

    print("\n" + "=" * 56)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print(f"All checks PASSED ({len(TOOLS)} tools).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
