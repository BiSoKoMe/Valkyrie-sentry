"""Behavioral sequence IOAs — CrowdStrike-style Event Stream Processing.

The kill-chain correlator (killchain.py) scores an actor GENERICALLY: three or
more distinct ATT&CK tactics on one lineage = an attack chain. That catches
"a lot is happening here," but it doesn't recognise a *specific* attack pattern.

CrowdStrike's signature capability is different and complementary — Event Stream
Processing (ESP) IOAs: hold only the *relevant* prior behaviours in memory and,
when a later behaviour completes a known **ordered sequence** on the same
process lineage, fire ONE named, high-confidence indicator — "credential theft
from a reflectively-injected module in PowerShell," regardless of the tools
used. It is stateful, single-pass, and tool-agnostic: it keys on the *shape* of
the sequence (inject → read LSASS), never on a specific binary.

This module is that engine, kept to Valkyrie's honest, testable style:

  * A `SequenceRule` is an ORDERED list of `Step` behaviour-predicates plus a
    time window. A step matches a behaviour by ATT&CK technique, by label, or by
    activity — never by tool name, so a brand-new tool that performs the same
    behaviour still advances the sequence.
  * `SequenceEngine.observe()` is the ESP core: it holds partial matches per
    process-lineage root, advances them as matching behaviours arrive in order
    within the window, and emits a named IOA the instant a sequence completes.
  * Lineage-aware exactly like the ESP worked example ("store iexplore's pid;
    when cmd.exe appears, check its parent"): a child process's behaviour
    advances its parent's sequence via the ppid edge.

It complements — does not replace — the generic kill-chain: a completed sequence
is a specific, higher-confidence claim ("this IS credential-dump-then-exfil"),
where the kill-chain says "many tactics, probably an intrusion." Pure and
deterministic given timestamps, so it is unit-tested independently of the engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

_TID_RE = re.compile(r"T1[0-9]{3}(?:\.[0-9]{3})?")


def _tid(technique: str) -> str:
    """Extract the bare ATT&CK id (e.g. 'T1003.001') from a full label."""
    m = _TID_RE.search(technique or "")
    return m.group(0) if m else ""


@dataclass(frozen=True)
class Step:
    """One behaviour in a sequence. Matches on ANY of technique/label/activity —
    all tool-agnostic. `techniques` match by prefix so a base id (T1003) also
    matches its sub-techniques (T1003.001)."""
    label: str
    techniques: tuple = ()
    labels: tuple = ()
    activities: tuple = ()

    def matches(self, tid: str, labels: frozenset, activity: str) -> bool:
        # technique match by prefix: step 'T1003' matches behaviour 'T1003.001'.
        if self.techniques and tid and any(
                tid == t or tid.startswith(t + ".") for t in self.techniques):
            return True
        if self.labels and labels and any(l in labels for l in self.labels):
            return True
        if self.activities and activity and activity in self.activities:
            return True
        return False


@dataclass(frozen=True)
class SequenceRule:
    id: str
    name: str
    severity: str            # 'high' | 'critical'
    technique: str           # culminating ATT&CK id (for tactic mapping)
    window: float            # seconds; the whole sequence must complete within
    steps: tuple             # ordered tuple[Step, ...] (len >= 2)
    reason: str


# ── The shipped named sequences (ESP-style behavioural IOAs) ─────────────────
# Each is a SPECIFIC, ordered attack pattern — the thing a generic tactic count
# can't name. Extend by appending; steps key on behaviour shape, never tooling.
SEQUENCES: tuple = (
    # The CrowdStrike worked example: inject into a process, then read creds.
    SequenceRule(
        "inject-then-creds", "Process injection followed by credential access",
        "critical", "T1003.001 — LSASS Memory", 300.0,
        (Step("code injection into another process",
              techniques=("T1055",), labels=("remote_thread", "process_injection")),
         Step("credential access (LSASS / SAM)",
              techniques=("T1003",), labels=("lsass_access", "sam_dump", "ntds_dump"))),
        "A process injected code into another process and then accessed "
        "credential stores — reflective-injection credential theft."),

    # Credential dump immediately followed by network egress = likely exfil.
    SequenceRule(
        "creds-then-exfil", "Credential access followed by network exfiltration",
        "critical", "T1041 — Exfiltration Over C2 Channel", 300.0,
        (Step("credential access",
              techniques=("T1003",), labels=("lsass_access", "sam_dump", "ntds_dump",
                                             "vault_enum")),
         Step("outbound network / C2",
              techniques=("T1041", "T1071", "T1048", "T1567", "T1105"),
              labels=("download_cradle", "lolbin_network_fetch", "c2", "beacon"))),
        "Credentials were accessed and the same lineage then made an outbound "
        "connection — credential exfiltration in progress."),

    # Macro/exploit foothold: document spawns a shell, which then pulls a payload.
    SequenceRule(
        "macro-dropper-c2", "Document-spawned shell fetched a remote payload",
        "high", "T1105 — Ingress Tool Transfer", 180.0,
        (Step("document/browser spawned an interpreter",
              techniques=("T1059",),
              labels=("office_child_shell", "document_spawned_interpreter")),
         Step("remote payload fetch",
              techniques=("T1105",),
              labels=("download_cradle", "certutil_download", "bitsadmin_transfer",
                      "lolbin_network_fetch", "mshta_exec", "regsvr32_scriptlet"))),
        "An application that opens untrusted content spawned a shell that then "
        "fetched a remote payload — the classic macro/exploit dropper chain."),

    # Ransomware objective: kill recovery, then mass-encrypt.
    SequenceRule(
        "ransomware-detonation", "Recovery inhibited then mass file encryption",
        "critical", "T1486 — Data Encrypted for Impact", 300.0,
        (Step("inhibit system recovery",
              techniques=("T1490",),
              labels=("shadow_delete", "backup_delete", "recovery_disabled")),
         Step("mass file encryption",
              techniques=("T1486",), labels=("mass_encryption", "ransomware",
                                             "canary_tripped"))),
        "Volume shadow copies / backups were destroyed and the same lineage "
        "began mass file encryption — ransomware detonating."),

    # Download a tool, then establish persistence with it.
    SequenceRule(
        "download-then-persist", "Downloaded tool established persistence",
        "high", "T1547.001 — Registry Run Keys / Startup", 300.0,
        (Step("ingress tool transfer",
              techniques=("T1105",),
              labels=("download_cradle", "certutil_download", "bitsadmin_transfer")),
         Step("persistence established",
              techniques=("T1547", "T1053", "T1543", "T1546"),
              labels=("persistence_runkey", "autostart_registry", "persistence_task",
                      "persistence_service", "persistence_wmi"))),
        "A tool was fetched from the network and the same lineage then wrote an "
        "autostart/persistence mechanism."),
)


@dataclass
class _Partial:
    rule: SequenceRule
    step_index: int          # index of the NEXT step to match
    first_ts: float
    last_ts: float
    pids: list


class SequenceEngine:
    """Stateful ESP-style matcher for named behavioural sequences.

    Feed it every detection via ``observe``; it returns a completed-sequence
    dict the instant a rule's ordered steps all match on one process lineage
    within the rule window, else None. In-memory, single-pass, bounded.
    """

    def __init__(self, rules: tuple = SEQUENCES, max_tracked: int = 4096) -> None:
        self._rules = rules
        self._max_tracked = max_tracked
        self._ppid: dict[int, int] = {}          # pid -> ppid (lineage)
        self._name: dict[int, str] = {}          # pid -> actor name
        self._partials: dict[str, list[_Partial]] = {}   # root key -> partials

    # -- lineage -----------------------------------------------------------
    def _root_key(self, pid: int, actor: str) -> str:
        """Resolve a process to its oldest tracked ancestor — so a child's
        behaviour advances its parent's sequence (the ESP parent-pid match)."""
        if not pid:
            return f"name:{(actor or '').lower()}"
        seen: set[int] = set()
        cur = pid
        depth = 0
        while cur in self._ppid and self._ppid[cur] and depth < 16:
            if cur in seen:
                break
            seen.add(cur)
            parent = self._ppid[cur]
            if parent not in self._ppid and parent not in self._name:
                break                             # parent not tracked → stop here
            cur = parent
            depth += 1
        return f"pid:{cur}"

    def _track(self, pid: int, ppid: int, actor: str) -> None:
        if not pid:
            return
        if len(self._ppid) >= self._max_tracked and pid not in self._ppid:
            # Bounded: drop the oldest-inserted entry (cheap, rare).
            old = next(iter(self._ppid))
            self._ppid.pop(old, None)
            self._name.pop(old, None)
        self._ppid[pid] = ppid
        self._name[pid] = actor or ""

    # -- core --------------------------------------------------------------
    def observe(self, actor: str, technique: str, labels, activity: str,
                ts: float, pid: int = 0, ppid: int = 0) -> Optional[dict]:
        """Advance sequence state with one behaviour. Returns a completed
        sequence dict, or None."""
        self._track(pid, ppid, actor)
        root = self._root_key(pid, actor)
        tid = _tid(technique)
        lset = frozenset(labels or ())
        act = activity or ""

        partials = self._partials.get(root, [])
        # 1. Evict partials whose window has expired (hold only relevant state).
        partials = [p for p in partials if ts - p.first_ts <= p.rule.window]

        completed: Optional[dict] = None
        # 2. Advance existing partials (in order) that this behaviour continues.
        for p in partials:
            step = p.rule.steps[p.step_index]
            if step.matches(tid, lset, act):
                p.step_index += 1
                p.last_ts = ts
                if pid and pid not in p.pids:
                    p.pids.append(pid)
                if p.step_index >= len(p.rule.steps):
                    completed = self._complete(p, root)
        # Drop any partial that completed this round.
        partials = [p for p in partials if p.step_index < len(p.rule.steps)]

        # 3. Start new partials whose FIRST step matches — but not for a rule
        #    that already has an active partial on this root (no duplicate
        #    explosions), and never advanced by the same event that started it.
        active_rules = {p.rule.id for p in partials}
        for rule in self._rules:
            if rule.id in active_rules:
                continue
            if rule.steps[0].matches(tid, lset, act):
                partials.append(_Partial(rule=rule, step_index=1, first_ts=ts,
                                         last_ts=ts, pids=[pid] if pid else []))

        if partials:
            self._partials[root] = partials
        else:
            self._partials.pop(root, None)
        return completed

    def _complete(self, p: _Partial, root: str) -> dict:
        rule = p.rule
        score = 0.95 if rule.severity == "critical" else 0.85
        return {
            "rule_id": rule.id,
            "name": rule.name,
            "severity": rule.severity,
            "technique": rule.technique,
            "reason": rule.reason,
            "root": root,
            "actor": self._name.get(p.pids[0], "") if p.pids else root.split(":", 1)[-1],
            "pids": list(p.pids),
            "steps": [s.label for s in rule.steps],
            "span_seconds": round(p.last_ts - p.first_ts, 3),
            "score": score,
            "explanation": rule.reason + " (" + " → ".join(s.label for s in rule.steps) + ")",
        }
