"""Start Valkyrie's EDR layer and exercise EVERY new feature end-to-end.

Runs the REAL production objects (Store + EdrEngine), feeds a handful of
realistic threat scenarios through the actual live event pipeline, then walks
through every capability: incidents, timelines, threat hunting, response
actions, AI-assisted investigation, and plugins.

    python scripts/edr_demo.py

It seeds the real data/ database, so afterwards you can start the web UI
(`python -m valkyrie --web`) and the same incidents show up in the /edr console.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.store import Store, DnsEvent
from valkyrie.edr import EdrEngine


def hr(title):
    print("\n" + "=" * 64)
    print(f"  {title}")
    print("=" * 64)


def ev(**kw):
    kw.setdefault("process_pid", 0)
    kw.setdefault("process_path", "")
    kw.setdefault("reason", "")
    kw.setdefault("suspicion", 0.0)
    kw.setdefault("raw_category", "")
    ts = kw.pop("ts", None)
    if ts:
        return DnsEvent(timestamp=ts, **kw)
    return DnsEvent.now(**kw)


def main():
    hr("STARTING VALKYRIE EDR ENGINE")
    store = Store()
    store.start()
    engine = EdrEngine(store)
    engine.start()
    pi = engine.plugins()
    print(f"  Engine online. {len(pi['plugins'])} plugins loaded, "
          f"response actions: {', '.join(pi['actions'])}")

    hr("INJECTING REALISTIC THREAT ACTIVITY (real pipeline)")
    now = datetime.now(timezone.utc)
    # 1) A process beaconing to C2 that resolves into a threat-intel IP range.
    for i in range(5):
        ts = (now - timedelta(minutes=i * 2)).isoformat(timespec="milliseconds")
        store.log(ev(ts=ts, domain="cdn-sync-telemetry.top", decision="blocked",
                     process_name="svchost.exe", process_pid=1044,
                     reason="answer IP 185.220.101.44 in threat-intel range",
                     suspicion=1.0, raw_category="firewall_ip"))
    # 2) Learned-threat beacon (regular interval, small payload).
    for i in range(6):
        ts = (now - timedelta(minutes=i * 3)).isoformat(timespec="milliseconds")
        store.log(ev(ts=ts, domain="beacon.evil-c2.xyz", decision="blocked",
                     process_name="updater.exe", process_pid=6620,
                     reason="regular interval beacon detected (cv=0.08)",
                     suspicion=0.95, raw_category="intelligence"))
    # 3) DoH-bypass evasion attempt.
    store.log(ev(domain="dns.google", decision="flagged", process_name="chrome.exe",
                 process_pid=8100, reason="DoH bypass attempt to 8.8.8.8:443",
                 raw_category="doh_bypass"))
    # 4) DGA-looking domain (high entropy).
    store.log(ev(domain="x7f3k9qz2v.biz", decision="behavioral", process_name="malware.exe",
                 process_pid=9001, reason="high subdomain entropy (4.85 bits)",
                 suspicion=0.8, raw_category="behavioral"))
    # 5) Ordinary tracker (privacy signal, low severity).
    for i in range(3):
        store.log(ev(domain="ads.doubleclick.net", decision="blocked",
                     process_name="chrome.exe", process_pid=8100,
                     reason="tracker SLD", raw_category="tracker"))
    print("  Fed 20 events (C2 beacon x5, learned beacon x6, DoH bypass, DGA, tracker x3)")
    print("  Waiting for the live correlation pipeline to process them...")
    time.sleep(1.2)   # let the async writer flush → engine correlates

    # 1. STATS ---------------------------------------------------------------
    hr("1. OVERVIEW  (GET /api/edr/stats)")
    s = engine.stats()
    print(f"  Open incidents : {s['incidents_open']}")
    print(f"  By severity    : {s['open_by_severity']}")
    print(f"  Detections     : {s['detections_total']}")
    print(f"  Plugins        : {s['plugins']}")

    # 2. INCIDENTS -----------------------------------------------------------
    hr("2. INCIDENTS  (GET /api/edr/incidents)")
    incs = engine.list_incidents()
    for i in incs:
        print(f"  [{i['severity'].upper():8}] {i['status']:9} {i['title'][:46]:46} "
              f"({i['detection_count']} det)")
    if not incs:
        print("  (no incidents)")
        engine.stop(); store.stop(); return

    # Pick the worst incident to drill into.
    worst = sorted(incs, key=lambda x: {"critical":4,"high":3,"medium":2,"low":1,"info":0}
                   .get(x["severity"], 0), reverse=True)[0]
    iid = worst["id"]

    # 3. TIMELINE ------------------------------------------------------------
    hr(f"3. INCIDENT TIMELINE  (GET /api/edr/incidents/{{id}})  →  {worst['title'][:40]}")
    d = engine.get_incident(iid)
    print(f"  Entity: {d['entity']}   Process: {d['process_name']}   "
          f"Detections: {d['detection_count']}")
    print("  Timeline:")
    for t in d["timeline"][-6:]:
        print(f"    · {t['timestamp'][11:19]}  [{t['kind']}]  {t['summary']}")

    # 4. INVESTIGATION -------------------------------------------------------
    hr("4. AI-ASSISTED INVESTIGATION  (offline analyst — always local)")
    rep = engine.investigate(iid, use_ai=False)
    print(f"  Analyst  : {rep['analyst']}")
    print(f"  Summary  : {rep['summary']}")
    print(f"  Technique: {', '.join(rep['techniques']) or '—'}")
    print("  Recommended response actions:")
    for a in rep["recommended_actions"]:
        print(f"    → {a['action']:14} {a['target'] or '':24} {a['rationale']}")
    print(f"  (AI narrative available: {rep['ai_available']} — set ANTHROPIC_API_KEY + use_ai=true)")

    # 5. RESPONSE ------------------------------------------------------------
    hr("5. RESPONSE ACTION  (POST /api/edr/respond — dry-run first, always audited)")
    dry = engine.respond("block_domain", d["entity"], dry_run=True, incident_id=iid)
    print(f"  block_domain (dry-run) → {dry['status']}: {dry['result']}")
    iso = engine.respond("isolate_host", "", dry_run=True, incident_id=iid)
    print(f"  isolate_host (dry-run) → {iso['status']}:")
    for line in iso["result"].splitlines():
        print(f"      {line}")

    # 6. THREAT HUNTING ------------------------------------------------------
    hr("6. THREAT HUNTING  (POST /api/edr/hunt)")
    for hunt in ("beacon_candidates", "high_suspicion", "noisy_processes"):
        r = engine.run_saved_hunt(hunt, limit=10)
        print(f"  · {hunt:20} → {r.get('count', 0)} result(s)")
        for row in r.get("rows", [])[:3]:
            print(f"        {row}")

    # 7. PLUGINS -------------------------------------------------------------
    hr("7. PLUGINS  (GET /api/edr/plugins)")
    for p in engine.plugins()["plugins"]:
        print(f"  [{p['kind']:10}] {p['name']:20} {p['description'][:40]}")

    hr("DONE — every EDR feature exercised on the real engine")
    print("  Incidents are now in data/valkyrie.db. Start the web UI to explore:")
    print("      python -m valkyrie --web        →  http://localhost:8080/edr")
    engine.stop()
    store.stop()


if __name__ == "__main__":
    main()
