"""Compliance evidence reports — operational security posture on demand.

Auditors (SOC 2, ISO 27001, insurers, internal GRC) don't ask "are you
secure" — they ask for **evidence of operating controls**: was monitoring
running, were incidents detected AND resolved, how fast, is response
audited, are updates/feeds current. This module assembles that evidence
from data Valkyrie already records, into a JSON document plus a
human-readable Markdown rendering.

Honesty rules (this is the module most tempted to lie):

  * It reports **evidence, not certification**. Framework references
    (SOC 2 CC7.x, ISO 27001 A.5.7/A.5.25-26/A.8.16) label which control a
    section is evidence *toward* — the report never claims compliance.
  * Every number is computed from the store/EDR at generation time; there
    are no hardcoded "OK" fields. Missing subsystems are reported as
    absent, not skipped.
  * Reports are generated locally and stay local.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from . import __version__
from .edr.schema import SEVERITIES

_FRAMEWORK_REFS = {
    "monitoring": ["SOC2 CC7.2", "ISO27001 A.8.16 (monitoring activities)"],
    "detection_response": ["SOC2 CC7.3-CC7.5", "ISO27001 A.5.25-A.5.26 (incident assessment & response)"],
    "threat_intel": ["ISO27001 A.5.7 (threat intelligence)"],
    "audit_trail": ["SOC2 CC7.3", "ISO27001 A.5.28 (evidence collection)"],
}


def _parse_iso(ts: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class ComplianceReporter:
    """Builds a point-in-time evidence report from live services."""

    def __init__(self, ctx) -> None:
        """ctx: AppContext (any subset of services may be wired)."""
        self._ctx = ctx

    # ------------------------------------------------------------------

    def generate(self, period_hours: int = 720) -> dict:
        now = datetime.now(timezone.utc)
        since = now - timedelta(hours=period_hours)
        report = {
            "report_type": "security-operations-evidence",
            "disclaimer": ("Point-in-time operational evidence generated "
                           "locally by Valkyrie. This is evidence toward the "
                           "referenced controls, not a compliance certification."),
            "generated_at": now.isoformat(),
            "period_hours": period_hours,
            "period_start": since.isoformat(),
            "tool_version": __version__,
            "sections": {},
        }
        report["sections"]["monitoring"] = self._monitoring()
        report["sections"]["detection_response"] = self._incidents(since)
        report["sections"]["threat_intel"] = self._intel()
        report["sections"]["audit_trail"] = self._audit()
        for name, sec in report["sections"].items():
            sec["framework_refs"] = _FRAMEWORK_REFS.get(name, [])
        return report

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _monitoring(self) -> dict:
        """Which protection components are actually wired and running now."""
        comps = {}
        try:
            comps = self._ctx.components()
        except Exception:
            pass
        hb = getattr(self._ctx, "heartbeat", None)
        out = {"components_wired": comps,
               "wired_count": sum(1 for v in comps.values() if v),
               "component_total": len(comps)}
        if hb is not None:
            try:
                out["heartbeat"] = hb.status()
            except Exception as exc:
                out["heartbeat_error"] = str(exc)
        return out

    def _incidents(self, since: datetime) -> dict:
        edr = getattr(self._ctx, "edr", None)
        if edr is None:
            return {"available": False}
        incidents = edr.list_incidents(limit=1000)
        in_period = []
        for inc in incidents:
            created = _parse_iso(inc.get("created_at", ""))
            if created is not None and created >= since:
                in_period.append(inc)
        by_sev = {s: 0 for s in SEVERITIES}
        by_status: dict[str, int] = {}
        resolution_minutes: list[float] = []
        for inc in in_period:
            by_sev[inc.get("severity", "info")] = by_sev.get(
                inc.get("severity", "info"), 0) + 1
            st = inc.get("status", "open")
            by_status[st] = by_status.get(st, 0) + 1
            if st in ("resolved", "closed"):
                a = _parse_iso(inc.get("created_at", ""))
                b = _parse_iso(inc.get("updated_at", ""))
                if a and b and b >= a:
                    resolution_minutes.append((b - a).total_seconds() / 60)
        open_high = [i for i in in_period
                     if i.get("status") not in ("resolved", "closed")
                     and i.get("severity") in ("high", "critical")]
        out = {
            "available": True,
            "incidents_in_period": len(in_period),
            "by_severity": by_sev,
            "by_status": by_status,
            "open_high_or_critical": len(open_high),
            "resolved_count": len(resolution_minutes),
        }
        if resolution_minutes:
            resolution_minutes.sort()
            out["mean_time_to_resolve_minutes"] = round(
                sum(resolution_minutes) / len(resolution_minutes), 1)
            out["median_time_to_resolve_minutes"] = round(
                resolution_minutes[len(resolution_minutes) // 2], 1)
        return out

    def _intel(self) -> dict:
        ti = getattr(self._ctx, "threat_intel", None)
        if ti is None:
            return {"available": False}
        try:
            st = ti.status()
        except Exception as exc:
            return {"available": False, "error": str(exc)}
        st["available"] = True
        st["stale_feeds"] = [name for name, f in st.get("feeds", {}).items()
                             if not f.get("fresh")]
        return st

    def _audit(self) -> dict:
        """Response actions are the audit trail of who did what to threats."""
        edr = getattr(self._ctx, "edr", None)
        out: dict = {"response_audit_available": edr is not None}
        if edr is not None:
            try:
                acts = edr._edr.list_responses(limit=1000)   # audited rows
                out["response_actions_recorded"] = len(acts)
                out["by_operator_kind"] = {}
                for a in acts:
                    kind = ("playbook" if str(a.get("operator", "")).startswith(
                        "playbook:") else "human/local")
                    out["by_operator_kind"][kind] = \
                        out["by_operator_kind"].get(kind, 0) + 1
                out["dry_run_count"] = sum(1 for a in acts if a.get("dry_run"))
            except Exception as exc:
                out["error"] = str(exc)
        pb = getattr(self._ctx, "playbooks", None)
        if pb is not None:
            try:
                out["playbooks"] = pb.status()
            except Exception:
                pass
        siem = getattr(self._ctx, "siem", None)
        if siem is not None:
            try:
                out["siem_export"] = siem.status()
            except Exception:
                pass
        return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_markdown(report: dict) -> str:
    """Human-readable rendering of a generated report (pure function)."""
    s = report.get("sections", {})
    lines = [
        "# Valkyrie — Security Operations Evidence Report",
        "",
        f"Generated: {report.get('generated_at')} · "
        f"Period: last {report.get('period_hours')}h · "
        f"Tool: Valkyrie {report.get('tool_version')}",
        "",
        f"> {report.get('disclaimer')}",
        "",
        "## Monitoring coverage",
    ]
    mon = s.get("monitoring", {})
    lines.append(f"- Components wired: **{mon.get('wired_count', 0)}"
                 f"/{mon.get('component_total', 0)}**")
    for name, up in sorted((mon.get("components_wired") or {}).items()):
        lines.append(f"  - {'🟢' if up else '⚪'} {name}")
    dr = s.get("detection_response", {})
    lines += ["", "## Detection & response"]
    if dr.get("available"):
        lines.append(f"- Incidents in period: **{dr.get('incidents_in_period', 0)}** "
                     f"(open high/critical: {dr.get('open_high_or_critical', 0)})")
        lines.append("- By severity: " + ", ".join(
            f"{k}={v}" for k, v in (dr.get("by_severity") or {}).items() if v))
        if "mean_time_to_resolve_minutes" in dr:
            lines.append(f"- MTTR: {dr['mean_time_to_resolve_minutes']} min "
                         f"(median {dr['median_time_to_resolve_minutes']} min, "
                         f"n={dr['resolved_count']})")
    else:
        lines.append("- EDR not active in this deployment")
    ti = s.get("threat_intel", {})
    lines += ["", "## Threat intelligence"]
    if ti.get("available"):
        lines.append(f"- IOCs loaded: **{ti.get('total', 0)}** "
                     f"({ti.get('domains', 0)} domains, {ti.get('ips', 0)} IPs)")
        stale = ti.get("stale_feeds") or []
        lines.append("- Feeds fresh: " + ("yes" if not stale
                                          else f"stale: {', '.join(stale)}"))
    else:
        lines.append("- Threat intel not active in this deployment")
    au = s.get("audit_trail", {})
    lines += ["", "## Response audit trail"]
    lines.append(f"- Audited response actions: "
                 f"{au.get('response_actions_recorded', 0)} "
                 f"({json.dumps(au.get('by_operator_kind') or {})})")
    if "siem_export" in au:
        se = au["siem_export"]
        lines.append(f"- SIEM export: {se.get('format')} → {se.get('url')} "
                     f"(sent {se.get('sent', 0)}, dropped {se.get('dropped', 0)})")
    lines += ["", "### Framework references"]
    for name, sec in s.items():
        refs = sec.get("framework_refs") or []
        if refs:
            lines.append(f"- {name}: {'; '.join(refs)}")
    return "\n".join(lines) + "\n"
