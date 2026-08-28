"""Valkyrie MCP tool surface - the agent-facing capability registry.

Inspired by CrowdStrike's `falcon-mcp`, which exposes Falcon's platform to AI
agents as Model Context Protocol tools so an analyst can investigate, hunt and
triage in natural language. Valkyrie had a rich facade (incidents, hunts,
investigation, response) reachable only from the CLI, the desktop app, or HTTP -
nothing an AI agent could drive. This is that interface, for a local-first EDR:
point an agent at YOUR machine's own security data and ask it questions.

Design rules, in Valkyrie's style:

  * **Read-only by default.** Every tool here observes. The one acting tool
    (`valkyrie_respond`) is unavailable unless the server was started with
    ``--allow-response``, and *even then* defaults to ``dry_run=True`` - the same
    dry-run/enforce discipline the SOAR playbooks use. falcon-mcp makes the same
    call (its Real Time Response module is explicitly read-only triage): an agent
    with a shell on your box is a bigger risk than the threat it is chasing.
  * **Naming mirrors the source of the idea**: ``valkyrie_<action>_<resource>``,
    as falcon-mcp uses ``falcon_<action>_<resource>``.
  * **Pure dispatch.** Tool handlers take a context object, so the whole surface
    is unit-tested without stdio, a socket, or an agent.
  * **Honest introspection.** ``valkyrie_get_detection_coverage`` reports what
    Valkyrie can and cannot see, including its own boundaries, so an agent that
    asks "can you detect X?" gets a truthful answer instead of a guess.

Stdlib-only; no MCP SDK dependency (the protocol layer in server.py speaks
JSON-RPC directly), so this ships inside the frozen exe with no new packages.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass
class ToolContext:
    """What the tool handlers are allowed to touch."""
    engine: Any = None                 # valkyrie.edr.EdrEngine
    store: Any = None                  # valkyrie.store.Store
    allow_response: bool = False       # gate on the one acting tool


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    schema: dict                       # JSON Schema for arguments
    handler: Callable[[ToolContext, dict], Any]


# --- helpers ---

def _need_engine(ctx: ToolContext):
    if ctx.engine is None:
        raise RuntimeError("EDR engine unavailable (Valkyrie store/engine not started)")
    return ctx.engine


def _clamp(v, lo, hi, default):
    try:
        return max(lo, min(int(v), hi))
    except (TypeError, ValueError):
        return default


# --- handlers ---

def _get_status(ctx: ToolContext, args: dict) -> dict:
    """Connectivity + posture: is the engine live, how much has it seen."""
    eng = _need_engine(ctx)
    incidents = eng.list_incidents(limit=200)
    by_sev: dict[str, int] = {}
    open_n = 0
    for i in incidents:
        by_sev[i.get("severity", "unknown")] = by_sev.get(i.get("severity", "unknown"), 0) + 1
        if str(i.get("status", "")).lower() in ("open", "new", ""):
            open_n += 1
    return {
        "engine": "running",
        "incidents_total": len(incidents),
        "incidents_open": open_n,
        "incidents_by_severity": by_sev,
        "response_enabled": bool(ctx.allow_response),
        "note": "read-only session" if not ctx.allow_response
                else "response tools ENABLED (dry_run defaults to true)",
    }


def _search_incidents(ctx: ToolContext, args: dict) -> dict:
    eng = _need_engine(ctx)
    limit = _clamp(args.get("limit", 25), 1, 200, 25)
    status = args.get("status") or None
    severity = args.get("severity") or None
    rows = eng.list_incidents(status=status, severity=severity, limit=limit)
    # Trim to an agent-friendly summary; full detail is one get_incident away.
    out = []
    for i in rows:
        out.append({
            "id": i.get("id"),
            "title": i.get("title"),
            "severity": i.get("severity"),
            "status": i.get("status"),
            "category": i.get("category"),
            "entity": i.get("entity"),
            "technique": i.get("technique"),
            "detections": i.get("detection_count", i.get("detections_count")),
            "first_seen": i.get("first_seen"),
            "last_seen": i.get("last_seen"),
        })
    return {"count": len(out), "incidents": out}


def _get_incident(ctx: ToolContext, args: dict) -> dict:
    eng = _need_engine(ctx)
    inc_id = str(args.get("incident_id") or "").strip()
    if not inc_id:
        raise ValueError("incident_id is required")
    inc = eng.get_incident(inc_id)
    if inc is None:
        raise ValueError(f"unknown incident '{inc_id}'")
    return inc


def _investigate_incident(ctx: ToolContext, args: dict) -> dict:
    """Valkyrie's own analyst: what this means + recommended real actions."""
    eng = _need_engine(ctx)
    inc_id = str(args.get("incident_id") or "").strip()
    if not inc_id:
        raise ValueError("incident_id is required")
    report = eng.investigate(inc_id)
    if report is None:
        raise ValueError(f"unknown incident '{inc_id}'")
    return report


def _list_hunts(ctx: ToolContext, args: dict) -> dict:
    eng = _need_engine(ctx)
    return {"hunts": eng.saved_hunts()}


def _run_hunt(ctx: ToolContext, args: dict) -> dict:
    eng = _need_engine(ctx)
    hunt_id = str(args.get("hunt_id") or "").strip()
    if not hunt_id:
        raise ValueError("hunt_id is required (use valkyrie_list_hunts)")
    limit = _clamp(args.get("limit", 50), 1, 500, 50)
    return eng.run_saved_hunt(hunt_id, limit=limit)


def _search_events(ctx: ToolContext, args: dict) -> dict:
    """Ad-hoc telemetry search - the free-form hunting surface."""
    eng = _need_engine(ctx)
    filters: dict = {}
    if args.get("domain"):
        filters["domain"] = str(args["domain"])
    if args.get("process"):
        filters["process_name"] = str(args["process"])
    if args.get("decision"):
        d = args["decision"]
        filters["decision"] = d if isinstance(d, list) else [str(d)]
    if args.get("since_hours") is not None:
        filters["since_hours"] = _clamp(args["since_hours"], 1, 720, 24)
    if args.get("min_suspicion") is not None:
        try:
            filters["min_suspicion"] = float(args["min_suspicion"])
        except (TypeError, ValueError):
            pass
    limit = _clamp(args.get("limit", 50), 1, 500, 50)
    return eng.hunt(filters=filters, limit=limit)


def _get_detection_coverage(ctx: ToolContext, args: dict) -> dict:
    """Honest capability introspection - what Valkyrie can and cannot see.

    Deliberately includes the BOUNDARIES so an agent asking "can Valkyrie detect
    X?" answers truthfully instead of assuming full coverage.
    """
    cov: dict = {"layers": {}, "boundaries": []}
    try:
        from ..behavioral_rules import RULES
        techs = sorted({r.technique.split(" ")[0] for r in RULES})
        cov["layers"]["ioa_rules"] = {
            "count": len(RULES),
            "description": "Declarative ATT&CK-mapped rules over process image/parent/cmdline",
            "techniques": techs,
        }
    except Exception:
        pass
    try:
        from ..behavior_score import _SIGNALS
        cov["layers"]["anomaly_scorer"] = {
            "signals": len(_SIGNALS),
            "description": "Generalizing weak-signal ensemble (masquerade, obfuscation, "
                           "impossible lineage) — fires on shapes no rule was written for",
        }
    except Exception:
        pass
    try:
        from ..behavioral_sequences import SEQUENCES
        cov["layers"]["behavioral_sequences"] = {
            "count": len(SEQUENCES),
            "description": "Named ordered attack patterns (event-stream IOAs)",
            "sequences": [{"id": s.id, "name": s.name} for s in SEQUENCES],
        }
    except Exception:
        pass
    try:
        from ..cname_uncloak import CNAME_TRACKERS
        cov["layers"]["cname_uncloak"] = {
            "tracker_apexes": len(CNAME_TRACKERS),
            "description": "Defeats CNAME-cloaked first-party-disguised trackers",
        }
    except Exception:
        pass
    # The honest part - stated plainly so an agent repeats it, not hides it.
    cov["boundaries"] = [
        "Detection, not prevention: the kernel driver (prevention/self-protection) "
        "is unbuilt/unsigned source, so Valkyrie alerts but generally does not block "
        "process execution.",
        "The process collector is a ~2s userland poller, not a kernel callback: "
        "short-lived processes can start and exit between polls and be missed.",
        "Memory-level tradecraft (injection, LSASS access) needs Sysmon installed "
        "or the kernel driver; without either it is invisible.",
        "PowerShell script-block detections require Script Block Logging (4104) "
        "to be enabled on the host.",
        "Detection content is finite: rule/sequence coverage is broad, not complete, "
        "and has not been measured against live malware in a VM.",
    ]
    return cov


def _respond(ctx: ToolContext, args: dict) -> dict:
    """The ONLY acting tool - gated, and dry-run unless explicitly told otherwise."""
    if not ctx.allow_response:
        raise PermissionError(
            "Response actions are disabled in this session. Start the MCP server "
            "with --allow-response to enable them (read-only is the default).")
    eng = _need_engine(ctx)
    action = str(args.get("action") or "").strip()
    if not action:
        raise ValueError("action is required (see valkyrie_get_status / available actions)")
    available = eng.available_actions()
    if action not in available:
        raise ValueError(f"unknown action '{action}'; available: {', '.join(available)}")
    target = str(args.get("target") or "")
    # Default TRUE: an agent must opt in to a real enforcement action.
    dry_run = bool(args.get("dry_run", True))
    return eng.respond(action, target, dry_run=dry_run, operator="mcp",
                       incident_id=str(args.get("incident_id") or ""))


# --- the registry ---

_STR = {"type": "string"}
_INT = {"type": "integer"}

TOOLS: tuple = (
    Tool("valkyrie_get_status",
         "Valkyrie engine status and incident posture (counts by severity, whether "
         "response actions are enabled). Start here to orient.",
         {"type": "object", "properties": {}},
         _get_status),

    Tool("valkyrie_search_incidents",
         "Search correlated security incidents. Returns summaries; use "
         "valkyrie_get_incident for full detail. Filter by status/severity.",
         {"type": "object", "properties": {
             "status": dict(_STR, description="e.g. open, closed"),
             "severity": dict(_STR, description="info|low|medium|high|critical"),
             "limit": dict(_INT, description="max results (1-200, default 25)")}},
         _search_incidents),

    Tool("valkyrie_get_incident",
         "Full detail for one incident: every detection, ATT&CK technique, "
         "timeline and any response actions taken.",
         {"type": "object",
          "properties": {"incident_id": dict(_STR, description="incident id")},
          "required": ["incident_id"]},
         _get_incident),

    Tool("valkyrie_investigate_incident",
         "Run Valkyrie's built-in analyst on an incident: what it means in plain "
         "language, the evidence, and recommended response actions.",
         {"type": "object",
          "properties": {"incident_id": dict(_STR, description="incident id")},
          "required": ["incident_id"]},
         _investigate_incident),

    Tool("valkyrie_list_hunts",
         "List saved threat hunts (blocked_recent, beacon_candidates, "
         "high_suspicion, noisy_processes, rare_domains, flagged_anomalies).",
         {"type": "object", "properties": {}},
         _list_hunts),

    Tool("valkyrie_run_hunt",
         "Run a saved threat hunt by id and return its rows.",
         {"type": "object", "properties": {
             "hunt_id": dict(_STR, description="id from valkyrie_list_hunts"),
             "limit": dict(_INT, description="max rows (1-500, default 50)")},
          "required": ["hunt_id"]},
         _run_hunt),

    Tool("valkyrie_search_events",
         "Ad-hoc search over Valkyrie's telemetry (DNS/process events): filter by "
         "domain, process, decision, recency or suspicion score.",
         {"type": "object", "properties": {
             "domain": dict(_STR, description="domain substring"),
             "process": dict(_STR, description="process name"),
             "decision": dict(_STR, description="allowed|blocked|flagged|behavioral"),
             "since_hours": dict(_INT, description="lookback window (1-720)"),
             "min_suspicion": {"type": "number", "description": "0.0-1.0"},
             "limit": dict(_INT, description="max rows (1-500, default 50)")}},
         _search_events),

    Tool("valkyrie_get_detection_coverage",
         "What Valkyrie can and cannot detect: its detection layers (IOA rules, "
         "anomaly scorer, behavioural sequences, CNAME uncloaking) AND its honest "
         "boundaries. Use this before claiming Valkyrie detects something.",
         {"type": "object", "properties": {}},
         _get_detection_coverage),

    Tool("valkyrie_respond",
         "Take a response action (block_domain, kill_process, isolate_host). "
         "DISABLED unless the server was started with --allow-response, and "
         "dry_run defaults to true — pass dry_run=false to actually enforce.",
         {"type": "object", "properties": {
             "action": dict(_STR, description="block_domain|kill_process|isolate_host"),
             "target": dict(_STR, description="domain, pid, or host"),
             "dry_run": {"type": "boolean", "description": "default true (simulate only)"},
             "incident_id": dict(_STR, description="optional incident to attach to")},
          "required": ["action"]},
         _respond),
)

_BY_NAME = {t.name: t for t in TOOLS}


def list_tools(ctx: Optional[ToolContext] = None) -> list[dict]:
    """MCP tool descriptors. The acting tool is hidden entirely in a read-only
    session, so an agent is never tempted by a capability it cannot use."""
    out = []
    for t in TOOLS:
        if t.name == "valkyrie_respond" and (ctx is None or not ctx.allow_response):
            continue
        out.append({"name": t.name, "description": t.description,
                    "inputSchema": t.schema})
    return out


def call_tool(ctx: ToolContext, name: str, args: Optional[dict] = None) -> Any:
    """Dispatch one tool call. Raises on unknown tool / bad args; the protocol
    layer turns exceptions into MCP tool errors."""
    tool = _BY_NAME.get(name)
    if tool is None:
        raise ValueError(f"unknown tool '{name}'")
    return tool.handler(ctx, args or {})
