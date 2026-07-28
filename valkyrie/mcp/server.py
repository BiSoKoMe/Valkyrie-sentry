"""Valkyrie MCP server — Model Context Protocol over stdio (JSON-RPC 2.0).

Lets an AI agent (Claude Desktop/Code, or any MCP client) drive Valkyrie's own
EDR: search incidents, investigate them, run threat hunts, query telemetry, and
introspect what Valkyrie can honestly detect. Modelled on CrowdStrike's
`falcon-mcp`, but for a LOCAL-first product — the data never leaves the machine
and the transport is stdio, not a network socket.

Why hand-rolled JSON-RPC instead of the MCP SDK: Valkyrie ships as a frozen
single exe and holds a stdlib-first line (see valkyrie/etw/framework.py for the
same choice). The stdio protocol is small and stable — newline-delimited
JSON-RPC 2.0 with `initialize` / `tools/list` / `tools/call` — so implementing it
directly costs less than a dependency and keeps the build reproducible.

Safety posture (deliberate, and stricter than the default MCP example):
  * Read-only unless started with ``--allow-response``; the acting tool is not
    even ADVERTISED in a read-only session.
  * stdio transport only — no listening socket, nothing bound to a port, so an
    MCP session can't be reached from the network.
  * Every tool exception becomes a structured MCP tool error, never a crash that
    would leave the client hanging.

Run:  valkyrie.exe --mcp            (read-only)
      valkyrie.exe --mcp --allow-response   (enables guarded, dry-run-by-default
                                             response actions)
"""

from __future__ import annotations

import json
import sys
from typing import Any, Optional

from .tools import ToolContext, call_tool, list_tools

# The protocol revision we implement. Clients send their own; we echo a
# supported one back rather than failing a client that speaks a newer draft.
PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "valkyrie"

# JSON-RPC error codes (spec).
_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INTERNAL_ERROR = -32603


def _version() -> str:
    try:
        from .. import __version__      # type: ignore[attr-defined]
        return str(__version__)
    except Exception:
        return "0.0.0"


def _result(msg_id: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def handle_message(ctx: ToolContext, msg: dict) -> Optional[dict]:
    """Handle one JSON-RPC message. Returns the response, or None for a
    notification (which must NOT be answered). Pure — unit-tested without stdio.
    """
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return _error(msg.get("id") if isinstance(msg, dict) else None,
                      _INVALID_REQUEST, "invalid JSON-RPC 2.0 message")

    method = msg.get("method")
    msg_id = msg.get("id")
    is_notification = "id" not in msg

    # Notifications: acknowledge by silence (per spec).
    if is_notification:
        return None

    if method == "initialize":
        return _result(msg_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": _version()},
            "instructions": (
                "Valkyrie is a local-first EDR running on this machine. Use "
                "valkyrie_get_status to orient, valkyrie_search_incidents then "
                "valkyrie_investigate_incident to triage, and valkyrie_run_hunt "
                "to hunt. IMPORTANT: call valkyrie_get_detection_coverage before "
                "asserting that Valkyrie detects (or prevents) something — it "
                "reports real boundaries, including that Valkyrie is detection, "
                "not prevention."),
        })

    if method == "ping":
        return _result(msg_id, {})

    if method == "tools/list":
        return _result(msg_id, {"tools": list_tools(ctx)})

    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name") or ""
        args = params.get("arguments") or {}
        try:
            payload = call_tool(ctx, name, args)
            text = json.dumps(payload, indent=2, default=str)
            return _result(msg_id, {"content": [{"type": "text", "text": text}],
                                    "isError": False})
        except Exception as exc:
            # Tool failures are RESULTS with isError, not transport errors —
            # this is what lets the agent read the reason and adapt.
            return _result(msg_id, {
                "content": [{"type": "text",
                             "text": f"{type(exc).__name__}: {exc}"}],
                "isError": True})

    return _error(msg_id, _METHOD_NOT_FOUND, f"unknown method '{method}'")


def serve(ctx: ToolContext, stdin=None, stdout=None) -> int:
    """Newline-delimited JSON-RPC loop over stdio. Returns an exit code.

    Never writes anything but protocol JSON to stdout — an MCP client parses
    that stream, so diagnostics go to stderr only.
    """
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            resp = _error(None, _PARSE_ERROR, "invalid JSON")
        else:
            try:
                resp = handle_message(ctx, msg)
            except Exception as exc:      # never die on one bad message
                resp = _error(msg.get("id") if isinstance(msg, dict) else None,
                              _INTERNAL_ERROR, str(exc))
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
    return 0


def run_stdio(allow_response: bool = False) -> int:
    """Stand up the read-only engine and serve MCP on stdio."""
    from ..store import Store
    from ..edr import EdrEngine

    store = Store()
    store.start()
    engine = EdrEngine(store)
    engine.start()
    ctx = ToolContext(engine=engine, store=store, allow_response=allow_response)
    print(f"[valkyrie-mcp] ready (response={'on' if allow_response else 'off'})",
          file=sys.stderr, flush=True)
    try:
        return serve(ctx)
    finally:
        try:
            engine.stop()
            store.stop()
        except Exception:
            pass
