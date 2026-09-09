#!/usr/bin/env python3
"""Capture REAL causality subgraphs from this machine, for ablation input.

Why this exists: `docs/CONSEQUENCE_ABLATION.md` measured three decision rules
against an AUTHORED corpus and named that the largest threat to the result's
validity. This tool replaces the authored benign population with structures
actually produced by a running Windows desktop.

What it does: builds a real `CausalityGraph`, seeds it with this machine's
live process ancestry, then runs the REAL `ProcessCollector` and
`NetworkCollector` for a bounded window and records what they attribute.

Safety: strictly read-only observation. It polls the process and socket tables
through psutil. It starts no service, opens no listener, writes no firewall or
DNS state, and makes no network request of its own. Nothing here can modify
the host.

Privacy: the capture is structure, not content. Process NAMES, parent/child
edges and artifact KINDS are kept because they are what the rules read.
Command lines and executable paths are dropped. Egress destinations are
replaced with a per-run salted hash: the rules under test never inspect a
destination's value (rarity is keyed on process name and artifact kind), so
distinctness is all that is needed and the machine's actual browsing history
is never written to disk.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.edr.causality import CausalityGraph          # noqa: E402
from valkyrie.network_telemetry import NetworkCollector    # noqa: E402
from valkyrie.process_telemetry import ProcessCollector    # noqa: E402

_SALT = os.urandom(16)          # per-run; destinations are not correlatable
                                # across captures, and never reversible.


def _redact(value: str) -> str:
    if not value:
        return ""
    return "h:" + hashlib.sha256(_SALT + value.encode("utf-8", "replace")).hexdigest()[:16]


class Capture:
    def __init__(self) -> None:
        self.graph = CausalityGraph()
        self.pids: set[int] = set()
        self.events = 0
        self.network_artifacts = 0
        self._lock = threading.Lock()

    # -- ingest ---------------------------------------------------------
    def seed_live_process_tree(self) -> int:
        """Record the ancestry of everything currently running. This is real
        observed structure, not a guess: each entry carries the pid, ppid,
        name and creation time the OS reports right now."""
        try:
            import psutil
        except ImportError:
            return 0
        seeded = 0
        procs = {}
        for p in psutil.process_iter(["pid", "name", "ppid", "create_time"]):
            try:
                procs[p.info["pid"]] = p.info
            except Exception:
                continue
        for pid, info in procs.items():
            try:
                parent = procs.get(info.get("ppid") or 0) or {}
                self.graph.observe_process(
                    pid=int(pid), name=str(info.get("name") or ""),
                    ppid=int(info.get("ppid") or 0),
                    create_time=float(info.get("create_time") or 0.0),
                    parent_name=str(parent.get("name") or ""),
                    ts=float(info.get("create_time") or 0.0))
                self.pids.add(int(pid))
                seeded += 1
            except Exception:
                continue
        return seeded

    def seed_live_connections(self) -> int:
        """Attribute the socket table as it stands right now. Same rationale as
        seeding the process tree: these are connections the OS reports as
        currently established, not inferred ones. Without this the capture only
        sees whatever churns during the window, which under-represents which
        processes on this host normally talk to the network - and that
        distribution is exactly what the endpoint arm's rarity reads."""
        try:
            import psutil
        except ImportError:
            return 0
        seeded = 0
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return 0            # access denied -> capture without it, honestly
        names: dict[int, str] = {}
        for c in conns:
            try:
                if not c.raddr or c.pid is None:
                    continue
                pid = int(c.pid)
                if pid not in names:
                    try:
                        names[pid] = psutil.Process(pid).name()
                    except Exception:
                        names[pid] = ""
                ok = self.graph.attribute(
                    pid, "network", "network connection observed",
                    name=names.get(pid, ""),
                    data={"subject": _redact(f"{c.raddr.ip}:{c.raddr.port}")})
                if ok:
                    self.pids.add(pid)
                    self.network_artifacts += 1
                    seeded += 1
            except Exception:
                continue
        return seeded

    def on_event(self, ev) -> None:
        """Wired as the collectors' `emit`. Mirrors what the engine does with
        the same events: process starts become nodes, everything else becomes
        an artifact attributed to its actor."""
        try:
            with self._lock:
                self.events += 1
                pid = int(getattr(ev, "actor_pid", 0) or 0)
                name = str(getattr(ev, "actor_name", "") or "")
                category = str(getattr(ev, "category", "") or "").lower()
                fields = dict(getattr(ev, "fields", None) or {})
                if pid <= 0:
                    return
                self.pids.add(pid)
                if category == "process":
                    self.graph.observe_process(
                        pid=pid, name=name, ppid=int(fields.get("ppid") or 0),
                        parent_name=str(fields.get("parent_name") or ""),
                        ts=float(getattr(ev, "ts", 0.0) or 0.0))
                    return
                target = getattr(ev, "target", None) or {}
                subject = ""
                if isinstance(target, dict):
                    subject = str(target.get("ip") or target.get("domain") or "")
                self.graph.attribute(
                    pid, category or "event",
                    f"{category} observed",
                    name=name, ts=float(getattr(ev, "ts", 0.0) or 0.0),
                    data={"subject": _redact(subject)})
                self.network_artifacts += 1
        except Exception:
            return          # a capture bug must never take down the collectors

    # -- export ---------------------------------------------------------
    def export(self) -> list[dict]:
        """One subgraph per distinct causality group owner, redacted."""
        seen_owner: set[str] = set()
        out: list[dict] = []
        for pid in sorted(self.pids):
            try:
                owner = self.graph.cgo(pid)
                if owner is None:
                    continue
                if owner.key in seen_owner:
                    continue
                seen_owner.add(owner.key)
                sub = self.graph.subgraph(owner.pid, owner.create_time)
                if sub and sub.get("found"):
                    out.append(_scrub(sub))
            except Exception:
                continue
        return out


def _scrub(sub: dict) -> dict:
    """Drop content-bearing fields; keep only what the rules actually read."""
    def node(n: dict) -> dict:
        return {"key": n.get("key"), "pid": n.get("pid"), "name": n.get("name"),
                "parent_key": n.get("parent_key", ""),
                "inferred": bool(n.get("inferred"))}

    artifacts = []
    for a in sub.get("artifacts") or []:
        data = a.get("data") or {}
        subject = data.get("subject") if isinstance(data, dict) else ""
        artifacts.append({"kind": a.get("kind"), "process": a.get("process", ""),
                          "data": {"subject": subject or ""}})
    return {
        "found": True,
        "cgo": node(sub.get("cgo") or {}),
        "chain": [node(n) for n in (sub.get("chain") or [])],
        "tree": [node(n) for n in (sub.get("tree") or [])],
        "artifacts": artifacts,
        "truncated": bool(sub.get("truncated")),
        "evicted": int(sub.get("evicted") or 0),
        "inferred_nodes": int(sub.get("inferred_nodes") or 0),
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seconds", type=float, default=120.0,
                    help="observation window (default 120)")
    ap.add_argument("--out", default="redteam/evaluation/real_causal_corpus.json")
    args = ap.parse_args(argv)

    cap = Capture()
    print(f"[capture] read-only observation for {args.seconds:.0f}s "
          f"on {platform.system()} {platform.release()}")
    seeded = cap.seed_live_process_tree()
    print(f"[capture] seeded {seeded} live processes (real ancestry)")
    seeded_conns = cap.seed_live_connections()
    print(f"[capture] seeded {seeded_conns} live connections (real socket table)")

    procs = ProcessCollector(emit=cap.on_event, interval=2.0)
    # ip_reputation always False: this capture must never consult or mutate
    # threat-intel state. emit_all so ordinary connections are recorded too -
    # ordinary is exactly the population being measured.
    nets = NetworkCollector(emit=cap.on_event, ip_reputation=lambda _ip: False,
                            interval=3.0, emit_all=True)
    procs.start()
    nets.start()
    deadline = time.time() + args.seconds
    try:
        while time.time() < deadline:
            time.sleep(2.0)
            left = deadline - time.time()
            print(f"[capture] {left:5.0f}s left  events={cap.events} "
                  f"artifacts={cap.network_artifacts} pids={len(cap.pids)}",
                  flush=True)
    except KeyboardInterrupt:
        print("[capture] interrupted - exporting what was seen")
    finally:
        try:
            procs.stop()
        except Exception:
            pass
        try:
            nets.stop()
        except Exception:
            pass

    corpus = cap.export()
    stats = cap.graph.stats()
    payload = {
        "capture": {
            "host_os": f"{platform.system()} {platform.release()}",
            "seconds": args.seconds, "seeded_processes": seeded, "seeded_connections": seeded_conns,
            "events": cap.events, "network_artifacts": cap.network_artifacts,
            "graph": stats,
            "redaction": "destinations salted-hashed per run; no cmdlines or paths",
        },
        "subgraphs": corpus,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    print(f"\n[capture] {len(corpus)} distinct owner subgraphs -> {out}")
    print(f"[capture] graph: {stats}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
