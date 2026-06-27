#!/usr/bin/env python3
"""
valkyrie_api.py — FastAPI backend for the Valkyrie web dashboard.

Features:
  - REST API to start/stop Valkyrie modes (sinkhole, monitor, watch, scan)
  - WebSocket endpoint for real-time log streaming
  - Serves the React frontend build from /ui/dist
  - Reads valkyrie_events.db for stats and history

Run:
  uvicorn valkyrie_api:app --host 0.0.0.0 --port 8000
"""

import asyncio
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import contextlib
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

SCRIPT_DIR = Path(__file__).resolve().parent
PYTHON = sys.executable
VALKYRIE_PY = SCRIPT_DIR / "valkyrie.py"
DB_PATH = SCRIPT_DIR / "valkyrie_events.db"
BLOCKLIST_DIR = SCRIPT_DIR / "blocklists"
UI_DIST = SCRIPT_DIR / "ui" / "dist"

app = FastAPI(title="Valkyrie API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@contextlib.asynccontextmanager
async def lifespan(app):
    asyncio.create_task(log_tailer())
    yield

app.router.lifespan_context = lifespan

# ── Process State ──────────────────────────────────────────────────────────────
class ValkyrieProcess:
    def __init__(self):
        self.proc: Optional[subprocess.Popen] = None
        self.mode: str = "idle"
        self.log_file: Optional[Path] = None
        self.started_at: Optional[datetime] = None
        self.pid: Optional[int] = None

proc_state = ValkyrieProcess()

# ── Pydantic Models ────────────────────────────────────────────────────────────
class StartRequest(BaseModel):
    mode: str  # sinkhole | monitor | watch | scan
    dns_port: int = 5353
    api_bind: str = "127.0.0.1"
    with_dns: bool = False

class StopResponse(BaseModel):
    status: str
    mode: str
    message: str

# ── Subprocess Helpers ─────────────────────────────────────────────────────────
def _build_cmd(mode: str, dns_port: int = 5353, api_bind: str = "127.0.0.1", with_dns: bool = False) -> list[str]:
    cmd = [PYTHON, str(VALKYRIE_PY)]
    if mode in ("sinkhole", "dns"):
        cmd.append("dns")
        cmd += [f"--dns-port", str(dns_port), f"--api-bind", api_bind]
    elif mode == "monitor":
        cmd.append("monitor")
        cmd += [f"--dns-port", str(dns_port), f"--api-bind", api_bind]
    elif mode == "watch":
        cmd.append("watch")
        if with_dns:
            cmd.append("--dns")
        cmd += [f"--dns-port", str(dns_port), f"--api-bind", api_bind]
    elif mode == "scan":
        cmd.append("scan")
    else:
        raise ValueError(f"Unknown mode: {mode}")
    return cmd

def _kill_process():
    global proc_state
    if proc_state.proc:
        try:
            proc_state.proc.kill()
        except Exception:
            pass
        try:
            proc_state.proc.wait(timeout=5)
        except Exception:
            pass
        proc_state.proc = None
        proc_state.mode = "idle"
        proc_state.pid = None

# ── Log Tail Helper ────────────────────────────────────────────────────────────
def tail_log(path: Path, lines: int = 200) -> list[str]:
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
        return all_lines[-lines:]
    except Exception:
        return []

# ── REST API ───────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "valkyrie_mode": proc_state.mode,
        "valkyrie_pid": proc_state.pid,
        "uptime": (datetime.now() - proc_state.started_at).total_seconds() if proc_state.started_at else 0,
    }

@app.post("/api/start")
async def start_mode(req: StartRequest):
    global proc_state
    if proc_state.proc and proc_state.proc.poll() is None:
        raise HTTPException(status_code=400, detail=f"Valkyrie already running in {proc_state.mode} mode (PID {proc_state.pid})")

    cmd = _build_cmd(req.mode, req.dns_port, req.api_bind, req.with_dns)
    log_path = SCRIPT_DIR / f"valkyrie_{req.mode}_{int(time.time())}.log"

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=open(log_path, "w", encoding="utf-8", buffering=1),
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(SCRIPT_DIR),
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to start: {exc}")

    proc_state.proc = proc
    proc_state.mode = req.mode
    proc_state.log_file = log_path
    proc_state.started_at = datetime.now()
    proc_state.pid = proc.pid

    return {
        "status": "started",
        "mode": req.mode,
        "pid": proc.pid,
        "cmd": " ".join(cmd),
        "log_file": str(log_path),
    }

@app.post("/api/stop")
async def stop_mode():
    global proc_state
    if not proc_state.proc:
        return {"status": "idle", "mode": "idle", "message": "No process running"}

    mode = proc_state.mode
    _kill_process()
    return {"status": "stopped", "mode": mode, "message": f"{mode} process terminated"}

@app.get("/api/status")
async def get_status():
    global proc_state
    pid = proc_state.pid
    running = False
    if proc_state.proc:
        running = proc_state.proc.poll() is None
        if not running:
            proc_state.mode = "idle"
            proc_state.log_file = None
            proc_state.pid = None
            pid = None

    log_lines = tail_log(proc_state.log_file, lines=50) if proc_state.log_file else []

    return {
        "running": running,
        "mode": proc_state.mode,
        "pid": pid,
        "uptime": (datetime.now() - proc_state.started_at).total_seconds() if proc_state.started_at and running else 0,
        "log_tail": log_lines,
    }

@app.get("/api/stats")
async def get_stats(hours: int = 24):
    if not DB_PATH.exists():
        return {
            "total_events": 0,
            "active_connections": 0,
            "tracking_alerts": 0,
            "dns_blocked": 0,
            "dns_allowed": 0,
            "connections_flagged": 0,
            "firewall_blocks": 0,
            "db_path": str(DB_PATH),
        }

    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            total = conn.execute("SELECT COUNT(*) FROM events WHERE ts >= ?", (cutoff,)).fetchone()[0]
            tracking = conn.execute("SELECT COUNT(*) FROM events WHERE action='tracking_alert' AND ts >= ?", (cutoff,)).fetchone()[0]
            blocked = conn.execute("SELECT COUNT(*) FROM events WHERE action='blocked_dns' AND ts >= ?", (cutoff,)).fetchone()[0]
            detected = conn.execute("SELECT COUNT(*) FROM events WHERE action='detected' AND ts >= ?", (cutoff,)).fetchone()[0]
            fw = conn.execute("SELECT COUNT(*) FROM events WHERE action='firewall_block' AND ts >= ?", (cutoff,)).fetchone()[0]
    except Exception:
        total = tracking = blocked = detected = fw = 0

    return {
        "total_events": total,
        "active_connections": total,
        "tracking_alerts": tracking,
        "dns_blocked": blocked,
        "dns_allowed": max(0, total - blocked),
        "connections_flagged": detected,
        "firewall_blocks": fw,
        "db_path": str(DB_PATH),
    }

@app.get("/api/alerts")
async def get_alerts(hours: int = 24, limit: int = 100):
    if not DB_PATH.exists():
        return {"count": 0, "alerts": []}
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT ts, domain, process_name, category, severity, details FROM events WHERE action='tracking_alert' AND ts >= ? ORDER BY ts DESC LIMIT ?",
                (cutoff, limit),
            ).fetchall()
        alerts = [dict(r) for r in rows]
    except Exception:
        alerts = []
    return {"count": len(alerts), "alerts": alerts}

@app.get("/api/mitigations")
async def get_mitigations(hours: int = 24, limit: int = 100):
    if not DB_PATH.exists():
        return {"count": 0, "mitigations": []}
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT ts, domain, process_name, remote_ip, category, severity, details FROM events WHERE action='firewall_block' AND ts >= ? ORDER BY ts DESC LIMIT ?",
                (cutoff, limit),
            ).fetchall()
        items = [dict(r) for r in rows]
    except Exception:
        items = []
    return {"count": len(items), "mitigations": items}

@app.get("/api/devices")
async def get_devices():
    if not DB_PATH.exists():
        return {"count": 0, "devices": []}
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT DISTINCT remote_ip as ip, process_name as hostname, category, COUNT(*) as event_count,
                       MAX(ts) as last_seen
                FROM events WHERE remote_ip IS NOT NULL AND remote_ip != ''
                GROUP BY remote_ip ORDER BY event_count DESC LIMIT 50
            """).fetchall()
        devices = []
        for r in rows:
            devices.append({
                "ip": r["ip"],
                "mac": "unknown",
                "hostname": r["hostname"] or "unknown",
                "vendor": "unknown",
                "privacy_score": max(0, 100 - (r["event_count"] * 5)),
                "event_count": r["event_count"],
                "last_seen": r["last_seen"],
            })
    except Exception:
        devices = []
    return {"count": len(devices), "devices": devices}

@app.get("/api/applications")
async def get_applications():
    if not DB_PATH.exists():
        return {"count": 0, "applications": []}
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT process_name, COUNT(*) as connection_count,
                       SUM(CASE WHEN action IN ('blocked_dns','detected','firewall_block') THEN 1 ELSE 0 END) as flagged,
                       SUM(CASE WHEN action='tracking_alert' THEN 1 ELSE 0 END) as tracker_alerts
                FROM events WHERE process_name IS NOT NULL AND process_name != ''
                GROUP BY process_name ORDER BY flagged DESC LIMIT 50
            """).fetchall()
        apps = []
        for r in rows:
            score = max(0, min(100, 100 - (r["flagged"] * 10) - (r["tracker_alerts"] * 5)))
            apps.append({
                "process_name": r["process_name"],
                "pid": 0,
                "connections": r["connection_count"],
                "flagged": r["flagged"],
                "tracker_alerts": r["tracker_alerts"],
                "risk_score": score,
            })
    except Exception:
        apps = []
    return {"count": len(apps), "applications": apps}

@app.post("/api/blocklist/add")
async def add_domain(domain: str, category: str = "AD-TRACKER"):
    bl_path = BLOCKLIST_DIR / "custom.txt"
    try:
        with open(bl_path, "a", encoding="utf-8") as f:
            f.write(f"\n{domain}\n")
        return {"status": "added", "domain": domain, "file": str(bl_path)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.post("/api/blocklist/remove")
async def remove_domain(domain: str):
    bl_path = BLOCKLIST_DIR / "custom.txt"
    if not bl_path.exists():
        return {"status": "not_found", "domain": domain}
    try:
        lines = bl_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        new_lines = [l for l in lines if domain.lower() not in l.lower() and l.strip() != domain.strip()]
        bl_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        return {"status": "removed", "domain": domain}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.post("/api/blocklist/reload")
async def reload_blocklists():
    return {"status": "reloaded", "message": "Blocklists will be reloaded on next Valkyrie start"}

@app.post("/api/blocklist/update")
async def update_blocklists():
    try:
        proc = subprocess.Popen(
            [PYTHON, str(VALKYRIE_PY), "update"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(SCRIPT_DIR),
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return {
            "status": "updating",
            "pid": proc.pid,
            "message": "Downloading Steven Black + OISD community blocklists (~100k+ domains). Restart Valkyrie when complete.",
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/api/blocklist/domains")
async def get_blocked_domains(limit: int = 100):
    if not DB_PATH.exists():
        return {"count": 0, "domains": []}
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT domain, action, category, COUNT(*) as count, MAX(ts) as last_seen
                FROM events WHERE domain IS NOT NULL AND domain != ''
                GROUP BY domain ORDER BY count DESC LIMIT ?
            """, (limit,)).fetchall()
        domains = [dict(r) for r in rows]
    except Exception:
        domains = []
    return {"count": len(domains), "domains": domains}

@app.get("/api/dns-log")
async def get_dns_log(hours: int = 1, limit: int = 500):
    if not DB_PATH.exists():
        return {"count": 0, "events": []}
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT ts, action, domain, category, severity, details "
                "FROM events "
                "WHERE action IN ('dns_query', 'blocked_dns', 'tracking_alert') "
                "AND ts >= ? ORDER BY ts DESC LIMIT ?",
                (cutoff, limit),
            ).fetchall()
        events = [dict(r) for r in rows]
    except Exception:
        events = []
    return {"count": len(events), "events": events}

@app.get("/api/settings")
async def get_settings():
    return {
        "dns_upstream": "8.8.8.8",
        "dns_port": 5353,
        "alert_cooldown": 90,
        "api_bind": "127.0.0.1",
        "api_port": 8000,
        "blocklist_dir": str(BLOCKLIST_DIR),
        "db_path": str(DB_PATH),
    }

# ── WebSocket ──────────────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: str):
        for ws in self.active:
            try:
                await ws.send_text(message)
            except Exception:
                pass

manager = ConnectionManager()

@app.websocket("/ws/logs")
async def websocket_logs(ws: WebSocket):
    await manager.connect(ws)
    try:
        # Send initial log tail
        if proc_state.log_file and proc_state.log_file.exists():
            lines = tail_log(proc_state.log_file, lines=100)
            for line in lines:
                await ws.send_text(json.dumps({"type": "log", "data": line.rstrip()}))
        else:
            await ws.send_text(json.dumps({"type": "log", "data": "Valkyrie idle — start a mode to see logs"}))

        # Keep-alive + command channel
        while True:
            try:
                msg = await asyncio.wait_for(ws.receive_text(), timeout=30.0)
                if msg == "ping":
                    await ws.send_text(json.dumps({"type": "pong"}))
            except asyncio.TimeoutError:
                await ws.send_text(json.dumps({"type": "heartbeat"}))
    except WebSocketDisconnect:
        manager.disconnect(ws)

# Background task: tail log file and broadcast
async def log_tailer():
    last_size = 0
    last_lines_sent = 0
    while True:
        await asyncio.sleep(0.5)
        if not proc_state.log_file or not proc_state.log_file.exists():
            continue
        try:
            size = proc_state.log_file.stat().st_size
            if size > last_size:
                with open(proc_state.log_file, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(last_size)
                    new_data = f.read()
                new_lines = new_data.splitlines()
                for line in new_lines:
                    if line.strip():
                        await manager.broadcast(json.dumps({"type": "log", "data": line.rstrip()}))
                last_size = size
                last_lines_sent += len(new_lines)
        except Exception:
            pass

# ── Serve Frontend ─────────────────────────────────────────────────────────────

@app.get("/api/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    if UI_DIST.exists():
        index = UI_DIST / "index.html"
        if index.exists():
            return FileResponse(index)
    return HTMLResponse("<h1>Valkyrie Dashboard — build UI first: cd ui && npm install && npm run build</h1>", status_code=503)

@app.get("/api/dashboard/assets/{path:path}")
async def serve_ui_assets(path: str):
    asset = UI_DIST / "assets" / path
    if asset.exists():
        return FileResponse(asset)
    raise HTTPException(status_code=404)


if __name__ == "__main__":
    import uvicorn
    import socket

    def find_free_port(start=8000, max_tries=10):
        for port in range(start, start + max_tries):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("0.0.0.0", port))
                    return port
                except OSError:
                    continue
        return start

    port = find_free_port()
    if port != 8000:
        print(f"  Port 8000 busy, using port {port} instead")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
