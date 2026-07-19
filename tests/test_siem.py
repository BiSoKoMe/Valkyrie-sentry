#!/usr/bin/env python3
"""SIEM export — offline unit + transport + EDR integration tests.

  [1] CEF formatting: header escaping, severity scale, extension escaping
  [2] JSONL formatting: valid single-line JSON with vendor fields
  [3] Record normalization: incident payloads export, others don't;
      DNS path exports blocks/flags only (never allowed traffic)
  [4] UDP transport: real loopback datagram received
  [5] TCP transport: newline-framed stream received; reconnect after
      receiver restart (fault recovery)
  [6] file transport: JSONL appended to disk
  [7] Bounded queue: overflow drops oldest, counts drops, never raises
  [8] EDR integration: report_detection -> exporter -> wire, end to end
  [9] Throughput benchmark: enqueue path budget (hot pipeline thread)
"""

from __future__ import annotations

import json
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def _wait(pred, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def main() -> int:
    from valkyrie.siem import (
        SiemExporter, dns_block_record, format_cef, format_jsonl,
        incident_record,
    )

    print("\n=== SIEM export engine ===\n")

    print("[1] CEF formatting")
    rec = {"event_type": "incident", "id": "abc-1",
           "title": "Ransomware|behavior detected", "severity": "critical",
           "category": "ransomware", "entity": "C:\\Users\\x",
           "process_name": "evil.exe", "detection_count": 3,
           "created_at": "2026-07-19T00:00:00Z",
           "extra": {"note": "a=b"}}
    cef = format_cef(rec)
    _check("starts with CEF:0|Valkyrie|Valkyrie|", cef.startswith("CEF:0|Valkyrie|Valkyrie|"))
    _check("pipe escaped in name field", "Ransomware\\|behavior detected" in cef)
    _check("critical maps to severity 10", "|10|" in cef)
    _check("equals escaped in extension", "note=a\\=b" in cef)
    _check("backslash escaped in extension", "cs1=C:\\\\Users\\\\x" in cef)
    _check("externalId + sproc present", "externalId=abc-1" in cef and "sproc=evil.exe" in cef)
    low = format_cef({"event_type": "e", "title": "t", "severity": "nonsense"})
    _check("unknown severity defaults to 2", "|2|" in low)

    print("\n[2] JSONL formatting")
    line = format_jsonl(rec)
    _check("single line", "\n" not in line)
    obj = json.loads(line)
    _check("vendor + flattened extra fields",
           obj.get("vendor") == "Valkyrie" and obj.get("note") == "a=b"
           and obj.get("severity") == "critical")

    print("\n[3] Record normalization")
    inc_payload = {"type": "incident", "new": True,
                   "incident": {"id": "i1", "title": "T", "severity": "high",
                                "category": "c2", "entity": "bad.example",
                                "process_name": "x.exe", "detection_count": 1,
                                "created_at": "now", "status": "open"}}
    _check("incident payload normalizes", incident_record(inc_payload) is not None)
    _check("non-incident payload ignored",
           incident_record({"type": "detection"}) is None)
    _check("blocked DNS event exports",
           dns_block_record({"event": {"decision": "blocked", "domain": "d.x",
                                       "timestamp": "t"}}) is not None)
    _check("allowed DNS event NEVER exports",
           dns_block_record({"event": {"decision": "allowed",
                                       "domain": "private.example"}}) is None)

    print("\n[4] UDP transport (loopback)")
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(5)
    port = rx.getsockname()[1]
    exp = SiemExporter(f"udp://127.0.0.1:{port}", fmt="cef")
    exp.start()
    exp.export_incident(inc_payload)
    try:
        data, _ = rx.recvfrom(65535)
        text = data.decode()
        _check("datagram received as CEF", text.startswith("CEF:0|Valkyrie"))
        _check("carries the incident id", "externalId=i1" in text)
    except socket.timeout:
        _check("datagram received as CEF (timeout)", False)
    # The datagram can arrive before the sender thread increments the
    # counter — wait for the count rather than racing it.
    _check("status counts the send",
           _wait(lambda: exp.status()["sent"] == 1)
           and exp.status()["errors"] == 0)
    exp.stop()
    rx.close()

    print("\n[5] TCP transport + reconnect after receiver restart")
    got: list[str] = []
    def _serve(sock):
        try:
            conn, _ = sock.accept()
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            got.append(buf.decode().strip())
            conn.close()
        except Exception:
            pass
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    tport = srv.getsockname()[1]
    t = threading.Thread(target=_serve, args=(srv,), daemon=True); t.start()
    exp2 = SiemExporter(f"tcp://127.0.0.1:{tport}", fmt="json")
    exp2.start()
    exp2.export_incident(inc_payload)
    _check("TCP line received", _wait(lambda: len(got) == 1)
           and json.loads(got[0]).get("id") == "i1")
    # Receiver "restarts": old conn is gone; a new accept loop takes over.
    t.join(timeout=5)
    t2 = threading.Thread(target=_serve, args=(srv,), daemon=True); t2.start()
    exp2.export_incident(inc_payload)
    _check("reconnects and delivers after receiver restart",
           _wait(lambda: len(got) == 2, timeout=10))
    exp2.stop()
    srv.close()

    print("\n[6] file transport")
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "siem" / "valkyrie.jsonl"
        exp3 = SiemExporter(out.as_uri(), fmt="json")
        exp3.start()
        exp3.export_incident(inc_payload)
        exp3.export_incident(inc_payload)
        _check("two JSONL lines appended",
               _wait(lambda: out.exists()
                     and len(out.read_text(encoding="utf-8").splitlines()) == 2))
        exp3.stop()

    print("\n[7] Bounded queue overflow (unstarted exporter, no consumer)")
    exp4 = SiemExporter("udp://127.0.0.1:9", fmt="cef")   # never started
    for i in range(3000):
        exp4.export_incident({"type": "incident",
                              "incident": {"id": f"i{i}", "title": "t",
                                           "severity": "low"}})
    st4 = exp4.status()
    _check("queue stayed bounded", st4["queued"] <= 2048)
    _check("drops counted", st4["dropped"] >= 3000 - 2048 - 1)

    print("\n[8] EDR integration: detection -> incident -> SIEM wire")
    from valkyrie.store import Store
    from valkyrie.edr import EdrEngine
    from valkyrie.edr.schema import Detection
    rx2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx2.bind(("127.0.0.1", 0)); rx2.settimeout(5)
    uport = rx2.getsockname()[1]
    with tempfile.TemporaryDirectory() as td:
        store = Store(db_path=Path(td) / "siem_edr.db")
        store.start()
        engine = EdrEngine(store)
        engine.start()
        exp5 = SiemExporter(f"udp://127.0.0.1:{uport}", fmt="cef")
        exp5.start()
        engine.subscribe(exp5.export_incident)
        engine.report_detection(Detection(
            source="test", severity="critical", category="ransomware",
            title="canary tripped", entity="C:/Users/x", process_name="bad.exe"))
        try:
            data, _ = rx2.recvfrom(65535)
            text = data.decode()
            _check("incident reached the SIEM socket",
                   "canary tripped" in text and "|10|" in text)
        except socket.timeout:
            _check("incident reached the SIEM socket (timeout)", False)
        exp5.stop()
        engine.stop()
        store.stop()
    rx2.close()

    print("\n[9] Enqueue-path benchmark (pipeline-thread budget)")
    exp6 = SiemExporter("udp://127.0.0.1:9", fmt="cef")
    n = 20_000
    t0 = time.perf_counter()
    for i in range(n):
        exp6.export_incident(inc_payload)
    dt = time.perf_counter() - t0
    per_us = dt / n * 1e6
    print(f"      {n:,} enqueues in {dt*1000:.1f} ms — {per_us:.1f} µs/event")
    _check("enqueue under 100 µs", per_us < 100)

    print("\n" + "=" * 48)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
