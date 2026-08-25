"""Tests for the EDR layer (valkyrie/edr/).

Standalone (no pytest), matching the rest of tests/. Locks in:
  - the plugin registry runs detections and isolates a broken plugin;
  - built-in detections map the real event stream to the right severities;
  - the correlation engine folds repeat detections into ONE incident and
    escalates its severity (not one incident per event);
  - incident timelines record detections, responses, and status changes;
  - threat-hunting compiles structured filters + saved hunts safely;
  - response actions are dry-run by default, audited, and refuse protected PIDs;
  - offline investigation always returns actionable output; AI stays opt-in/off;
  - EDR state is local only (nothing EDR crosses the fleet privacy boundary).

Usage: python tests/test_edr.py
"""

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PASS = 0
FAIL = 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  + [PASS]  {label}")
    else:
        FAIL += 1
        print(f"  X [FAIL]  {label}" + (f"  ({detail})" if detail else ""))


print("Valkyrie EDR test")
print("=" * 55)

from valkyrie.store import Store, DnsEvent
from valkyrie.edr import (
    Detection, EdrEngine, EdrStore, PluginRegistry, PluginContext,
    DetectionPlugin, ThreatHunter,
)
from valkyrie.edr.builtin import register_builtin
from valkyrie.edr.response import register_responders, ResponseManager
from valkyrie.edr import schema


def _event(**kw) -> dict:
    base = {"domain": "", "decision": "allowed", "process_name": "",
            "process_pid": 0, "category": "", "suspicion": 0.0, "reason": ""}
    base.update(kw)
    return base


with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
    dbp = Path(tmp) / "edr.db"
    store = Store(db_path=dbp)
    store.start()

    # --- Schema primitives ---
    print("\n-- Schema ------------------------------------------")
    check("severity ordering", schema.severity_rank("critical") > schema.severity_rank("low"))
    check("max_severity picks worse", schema.max_severity("low", "high") == "high")
    det = Detection(source="t", severity="high", category="firewall_ip",
                    title="x", entity="bad.example")
    check("detection round-trips via dict", Detection.from_row(det.to_dict()).entity == "bad.example")

    # --- Plugin registry + fault isolation ---
    print("\n-- Plugin architecture -----------------------------")
    reg = PluginRegistry()
    register_builtin(reg)
    register_responders(reg)
    ctx = PluginContext(store=store)
    check("built-ins registered", len(reg.all()) >= 9)

    class _Boom(DetectionPlugin):
        name = "test.boom"
        def analyze(self, event, c):
            raise RuntimeError("boom")

    class _Good(DetectionPlugin):
        name = "test.good"
        def analyze(self, event, c):
            return [Detection(source=self.name, severity="low", category="tracker",
                              title="ok", entity=event.get("domain", ""))]

    reg.register(_Boom())
    reg.register(_Good())
    out = reg.run_detections(_event(domain="x.example", decision="blocked",
                                    category="tracker"), ctx)
    check("broken plugin does not stop the pipeline", any(d.source == "test.good" for d in out))
    check("broken plugin fault is captured", any(e["plugin"] == "test.boom" for e in reg.errors()))
    check("responder actions advertised",
          set(["block_domain", "kill_process", "isolate_host"]) <= set(reg.available_actions()))

    # --- Plugin discovery from a directory ---
    pdir = Path(tmp) / "plugins"
    pdir.mkdir()
    (pdir / "myplugin.py").write_text(
        "from valkyrie.edr.plugins import DetectionPlugin\n"
        "from valkyrie.edr.schema import Detection\n"
        "class P(DetectionPlugin):\n"
        "    name='ext.demo'\n"
        "    def analyze(self, event, ctx):\n"
        "        return []\n"
        "def register(registry):\n"
        "    registry.register(P())\n",
        encoding="utf-8")
    reg2 = PluginRegistry()
    loaded = reg2.discover(pdir)
    check("external plugin discovered", "myplugin" in loaded)
    check("external plugin registered", any(p.name == "ext.demo" for p in reg2.all()))

    # --- Built-in detection mapping ---
    print("\n-- Built-in detections -----------------------------")
    reg3 = PluginRegistry()
    register_builtin(reg3)
    def _detect(ev):
        return reg3.run_detections(ev, ctx)
    malware = _detect(_event(domain="c2.bad", decision="blocked",
                             category="firewall_ip", process_name="evil.exe",
                             reason="answer IP 1.2.3.4 in threat-intel range"))
    check("firewall_ip → high severity", malware and malware[0].severity == "high")
    check("firewall_ip gets a MITRE technique", malware and malware[0].technique.startswith("T1071"))
    beacon = _detect(_event(domain="beacon.bad", decision="blocked",
                            category="intelligence", reason="regular interval beacon detected"))
    check("beacon reason → beacon detection", beacon and beacon[0].source == "dns.beacon")
    tracker = _detect(_event(domain="ads.example", decision="blocked", category="tracker"))
    check("tracker block → low severity", tracker and tracker[0].severity == "low")
    allowed = _detect(_event(domain="good.example", decision="allowed", category=""))
    check("clean allow yields no detection", allowed == [])

    # --- Engine correlation + timelines ---
    print("\n-- Correlation engine ------------------------------")
    engine = EdrEngine(store, correlation_window_seconds=600)
    engine.start()

    pushed = []
    engine.subscribe(lambda p: pushed.append(p))

    ev = _event(domain="c2.evil", decision="blocked", category="firewall_ip",
                process_name="mal.exe", reason="answer IP in threat-intel range")
    # Feed the SAME malicious signal three times.
    for _ in range(3):
        engine._on_store_event({"type": "event", "event": ev})

    incs = engine.list_incidents()
    fw_incs = [i for i in incs if i["category"] == "firewall_ip"]
    check("repeat detections fold into ONE incident", len(fw_incs) == 1,
          f"got {len(fw_incs)}")
    check("incident counts all 3 detections", fw_incs and fw_incs[0]["detection_count"] == 3)
    check("incident severity is high", fw_incs and fw_incs[0]["severity"] == "high")
    check("live incident push emitted", any(p.get("type") == "incident" for p in pushed))

    # A different category opens a separate incident.
    engine._on_store_event({"type": "event", "event": _event(
        domain="ads.co", decision="blocked", category="tracker", process_name="chrome")})
    check("distinct category → separate incident",
          len(engine.list_incidents()) == 2)

    # `technique` was captured per-Detection from day one (edr_detections has
    # had the column since the start) but never copied onto the Incident it
    # correlated into, so a real MITRE id like T1562.001 was computed and
    # then discarded before it ever reached the incident list/API.
    engine.report_detection(schema.Detection(
        source="sensor_tamper_monitor", severity="critical", category="process",
        title="sensor tamper", entity="sysmon", technique="T1562.001"))
    tamper_incs = [i for i in engine.list_incidents() if i["entity"] == "sysmon"]
    check("a new incident carries its detection's technique",
          bool(tamper_incs) and tamper_incs[0]["technique"] == "T1562.001")
    check("the wire format includes an 'explanation' field",
          bool(tamper_incs) and bool(tamper_incs[0].get("explanation")))

    # A second, technique-LESS detection folding into the same incident must
    # not blank out the technique the first detection already established.
    engine.report_detection(schema.Detection(
        source="sensor_tamper_monitor", severity="critical", category="process",
        title="sensor tamper again", entity="sysmon", technique=""))
    tamper_incs2 = [i for i in engine.list_incidents() if i["entity"] == "sysmon"]
    check("still ONE incident (correlated, not duplicated)", len(tamper_incs2) == 1)
    check("a later technique-less detection does not blank an established technique",
          bool(tamper_incs2) and tamper_incs2[0]["technique"] == "T1562.001")

    inc_id = fw_incs[0]["id"]
    detail = engine.get_incident(inc_id)
    check("incident detail carries its detections", len(detail["detections"]) == 3)
    check("incident timeline recorded detections",
          any(t["kind"] == "detection" for t in detail["timeline"]))

    # --- Response actions: dry-run, audit, protected PIDs ---
    print("\n-- Response actions --------------------------------")
    # block_domain / unblock_domain route through the ANALYSIS memory now (no
    # manual rules file). Give the responder a recording intelligence stub.
    class _Intel:
        def __init__(self): self.blocked = set(); self.good = set()
        def remember_block(self, d, r=""): self.blocked.add(d)
        def remember_good(self, d, r=""): self.good.add(d)
    _intel = _Intel()
    engine._ctx.intelligence = _intel
    r1 = engine.respond("block_domain", "c2.evil", dry_run=True, incident_id=inc_id)
    check("block_domain dry-run reports dry_run", r1["status"] == "dry_run")
    r2 = engine.respond("kill_process", "4", dry_run=False, incident_id=inc_id)
    check("kill refuses protected pid 4", r2["status"] == "skipped")
    r3 = engine.respond("kill_process", "not-a-pid", dry_run=True)
    check("kill rejects invalid pid", r3["status"] == "failed")
    r4 = engine.respond("isolate_host", "", dry_run=True, incident_id=inc_id)
    check("isolate_host dry-run describes the commands",
          r4["status"] == "dry_run" and "iptables" in r4["result"].lower()
          or "netsh" in r4["result"].lower())
    r5 = engine.respond("nonexistent_action", "x")
    check("unknown action fails cleanly", r5["status"] == "failed")
    detail = engine.get_incident(inc_id)
    check("responses are audited on the incident", len(detail["responses"]) >= 3)
    check("response recorded in timeline",
          any(t["kind"] == "response" for t in detail["timeline"]))

    # Real block_domain records the domain in analysis memory - NO file written,
    # no manual list. The DNS engine enforces it via that same memory next lookup.
    got = engine.respond("block_domain", "tracker.test", dry_run=False)
    check("real block_domain succeeds", got["status"] == "succeeded")
    check("blocked domain remembered in analysis memory",
          "tracker.test" in _intel.blocked)
    engine.respond("unblock_domain", "tracker.test", dry_run=False)
    check("unblock marks the domain known-good", "tracker.test" in _intel.good)

    # --- Incident lifecycle ---
    print("\n-- Incident lifecycle ------------------------------")
    upd = engine.update_incident(inc_id, status="investigating", notes="triaging",
                                 assignee="alice")
    check("status update sticks", upd["status"] == "investigating")
    check("notes/assignee stick", upd["notes"] == "triaging" and upd["assignee"] == "alice")
    check("status change is in the timeline",
          any(t["kind"] == "status" for t in upd["timeline"]))
    stats = engine.stats()
    check("stats count open incidents", stats["incidents_open"] >= 1)
    check("stats break down by severity", "high" in stats["open_by_severity"])

    # --- Threat hunting ---
    print("\n-- Threat hunting ----------------------------------")
    # Seed the raw event log the hunter reads. Spread the beacon across distinct
    # minutes - a real C2 heartbeat phones home over time, which is exactly what
    # the beacon_candidates hunt keys on (distinct-minute count).
    from datetime import datetime as _dt, timedelta as _td
    _t0 = _dt.utcnow()
    for i in range(8):
        ts = (_t0 - _td(minutes=i)).isoformat(timespec="milliseconds")
        store.log(DnsEvent(timestamp=ts, domain="beacon.evil", decision="blocked",
                           process_name="mal.exe", process_pid=1234, process_path="",
                           reason="beacon", suspicion=0.9, raw_category="intelligence"))
    for i in range(3):
        store.log(DnsEvent.now(domain=f"rare{i}.example", decision="allowed",
                               process_name="chrome", process_pid=0, process_path="",
                               reason="", raw_category=""))
    time.sleep(0.4)   # let the writer flush

    hunter = ThreatHunter(store)
    res = hunter.run({"decision": ["blocked"], "process": "mal.exe"}, limit=50)
    check("structured hunt filters by process+decision", res["count"] >= 8)
    check("hunt rejects unknown decision safely",
          hunter.run({"decision": ["DROP TABLE"]}, 10)["count"] >= 0)
    hs = hunter.run_saved("high_suspicion", 50)
    check("saved hunt 'high_suspicion' returns rows", hs["count"] >= 8)
    beacon_hunt = hunter.run_saved("beacon_candidates", 50)
    check("saved hunt 'beacon_candidates' finds the beacon",
          any(r["domain"] == "beacon.evil" for r in beacon_hunt["rows"]))
    check("unknown saved hunt is handled", "error" in hunter.run_saved("nope", 5))
    facets = hunter.facets(24)
    check("facets return top processes", any(p["process_name"] == "mal.exe"
                                             for p in facets["top_processes"]))

    # --- Investigation (offline default, AI opt-in/off) ---
    print("\n-- Investigation -----------------------------------")
    report = engine.investigate(inc_id, use_ai=False)
    check("offline analyst always runs", report["analyst"] == "offline")
    check("investigation recommends actions", len(report["recommended_actions"]) >= 1)
    check("investigation lists MITRE techniques", len(report["techniques"]) >= 1)
    check("investigation has a human summary", len(report["summary"]) > 20)
    # AI stays off unless explicitly enabled AND a provider is configured.
    from valkyrie.edr.ai_provider import get_provider
    had_provider = get_provider().available()
    report_ai = engine.investigate(inc_id, use_ai=True)
    if had_provider:
        check("AI path attempted when a provider is configured", "analyst" in report_ai)
    else:
        check("AI opt-in without a key falls back to offline",
              report_ai["analyst"] == "offline" and "ai_error" in report_ai)

    # --- Plugins introspection ---
    print("\n-- Plugin introspection ----------------------------")
    pinfo = engine.plugins()
    check("engine lists its plugins", len(pinfo["plugins"]) >= 9)
    check("engine advertises response actions", "block_domain" in pinfo["actions"])

    # --- Privacy: EDR data is local only ---
    print("\n-- Privacy invariant -------------------------------")
    # The fleet-heartbeat version of this invariant moved with the fleet code
    # to experimental/tests/test_fleet.py (ADR 0044). What remains here is the
    # invariant that still applies to CORE: the EDR engine has no egress of its
    # own. Incident data reaches the network only through an explicitly wired,
    # opt-in exporter (siem.py) - the engine itself must expose no transport.
    import inspect as _inspect
    import valkyrie.edr.engine as _eng
    _src = _inspect.getsource(_eng)
    check("EDR engine imports no network transport",
          not any(m in _src for m in ("import socket", "import requests",
                                      "urllib.request", "http.client")))
    # Subscribers receive incidents; nothing in that path writes to a socket.
    check("engine fan-out is in-process only (EventBus, not a client)",
          "EventBus" in _src)

    engine.stop()
    store.stop()

print(f"\n{'=' * 55}")
print(f"  {PASS} passed  /  {FAIL} failed")
if FAIL:
    print("  RESULT: SOME TESTS FAILED")
    sys.exit(1)
else:
    print("  RESULT: ALL TESTS PASSED")
    sys.exit(0)
