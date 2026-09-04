"""Behavioral sequence IOAs - CrowdStrike-style Event Stream Processing.

The kill-chain correlator (killchain.py) scores an actor GENERICALLY: three or
more distinct ATT&CK tactics on one lineage = an attack chain. That catches
"a lot is happening here," but it doesn't recognise a *specific* attack pattern.

CrowdStrike's signature capability is different and complementary - Event Stream
Processing (ESP) IOAs: hold only the *relevant* prior behaviours in memory and,
when a later behaviour completes a known **ordered sequence** on the same
process lineage, fire ONE named, high-confidence indicator - "credential theft
from a reflectively-injected module in PowerShell," regardless of the tools
used. It is stateful, single-pass, and tool-agnostic: it keys on the *shape* of
the sequence (inject -> read LSASS), never on a specific binary.

This module is that engine, kept to Valkyrie's honest, testable style:

  * A `SequenceRule` is an ORDERED list of `Step` behaviour-predicates plus a
    time window. A step matches a behaviour by ATT&CK technique, by label, or by
    activity - never by tool name, so a brand-new tool that performs the same
    behaviour still advances the sequence.
  * `SequenceEngine.observe()` is the ESP core: it holds partial matches per
    process-lineage root, advances them as matching behaviours arrive in order
    within the window, and emits a named IOA the instant a sequence completes.
  * Lineage-aware exactly like the ESP worked example ("store iexplore's pid;
    when cmd.exe appears, check its parent"): a child process's behaviour
    advances its parent's sequence via the ppid edge.

It complements - does not replace - the generic kill-chain: a completed sequence
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
    """One behaviour in a sequence. Matches on ANY of technique/label/activity -
    all tool-agnostic. `techniques` match by prefix so a base id (T1003) also
    matches its sub-techniques (T1003.001).

    `min_distinct` (default 1 - today's behaviour, unchanged): how many
    DISTINCT matching signals must be observed before this step is satisfied.
    A step with min_distinct > 1 does not advance on the first match; it
    accumulates distinct hits (by technique id, or by whichever label/activity
    matched) until enough have been seen. This is how a "breadth, not order"
    rule - several different weak signals rather than two specific ones in
    sequence - is expressed inside an otherwise strictly-ordered engine (see
    the single-step 'reconnaissance-burst' rule below)."""
    label: str
    techniques: tuple = ()
    labels: tuple = ()
    activities: tuple = ()
    min_distinct: int = 1

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

    def match_key(self, tid: str, labels: frozenset, activity: str) -> str:
        """A key identifying WHAT matched, for min_distinct counting - prefers
        the technique id (most specific), then whichever label matched, then
        the activity. Only meaningful when matches() is already True."""
        if self.techniques and tid and any(
                tid == t or tid.startswith(t + ".") for t in self.techniques):
            return "t:" + tid
        if self.labels and labels:
            hit = labels & set(self.labels)
            if hit:
                return "l:" + sorted(hit)[0]
        if self.activities and activity and activity in self.activities:
            return "a:" + activity
        return ""


@dataclass(frozen=True)
class SequenceRule:
    id: str
    name: str
    severity: str            # 'medium' | 'high' | 'critical'
    technique: str           # culminating ATT&CK id (for tactic mapping)
    window: float            # seconds; the whole sequence must complete within
    steps: tuple             # ordered tuple[Step, ...] - usually len >= 2; a
                              # single step with min_distinct > 1 expresses
                              # "breadth" (several distinct signals) instead
                              # of "order" (see reconnaissance-burst below)
    reason: str


# --- The shipped named sequences (ESP-style behavioural IOAs) ---
# Each is a SPECIFIC, ordered attack pattern - the thing a generic tactic count
# can't name. Extend by appending; steps key on behaviour shape, never tooling.
SEQUENCES: tuple = (
    # The CrowdStrike worked example: inject into a process, then read creds.
    SequenceRule(
        "inject-then-creds", "Process injection followed by credential access",
        "critical", "T1003.001 — LSASS Memory", 300.0,
        (Step("code injection into another process",
              techniques=("T1055",), labels=("remote_thread", "process_injection")),
         Step("credential access (LSASS / SAM)",
              techniques=("T1003",), labels=("lsass_access", "sam_dump", "lsa_secrets_dump", "ntds_dump"))),
        "A process injected code into another process and then accessed "
        "credential stores — reflective-injection credential theft."),

    # Credential dump immediately followed by network egress = likely exfil.
    SequenceRule(
        "creds-then-exfil", "Credential access followed by network exfiltration",
        "critical", "T1041 — Exfiltration Over C2 Channel", 300.0,
        (Step("credential access",
              techniques=("T1003",), labels=("lsass_access", "sam_dump", "lsa_secrets_dump",
                                             "ntds_dump", "vault_enum")),
         Step("outbound network / C2",
              techniques=("T1041", "T1071", "T1048", "T1567", "T1105"),
              labels=("download_cradle", "lolbin_network_fetch", "c2", "beacon"))),
        "Credentials were accessed and the same lineage then made an outbound "
        "connection — credential exfiltration in progress."),

    # Macro/exploit foothold: document spawns a shell, which then pulls a payload.
    SequenceRule(
        "macro-dropper-c2", "Document-spawned shell fetched a remote payload",
        "high", "T1105 — Ingress Tool Transfer", 180.0,
        # Step 1 keys ONLY on the document-parent label, never on bare T1059:
        # T1059 is "any script interpreter ran," which every benign powershell
        # session satisfies. Requiring the office_child_shell discriminator (emitted
        # only when a real Office/document process spawns a shell - process_telemetry
        # `par in _OFFICE and n in _SHELLS`) is what makes this the *dropper* chain
        # and not "powershell exists, then powershell made a network call."
        (Step("document/browser spawned an interpreter",
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

    # Reconnaissance burst - BREADTH, not order. whoami/systeminfo/tasklist/
    # net view/net user are each individually indistinguishable from routine
    # administration (found the hard way: redteam/evaluation's disc-* findings
    # - Discovery is architecturally the tactic where firing on a single
    # command is a guaranteed false-positive generator). The tell is several
    # DIFFERENT discovery techniques from the same actor close together, which
    # is why this is a single step with min_distinct=3 rather than an ordered
    # pair: a real recon sweep runs these in whatever order the operator (or
    # script) happens to reach for them, not a fixed A-then-B shape.
    SequenceRule(
        "reconnaissance-burst", "Reconnaissance burst (multiple discovery techniques)",
        # Window widened 120s -> 300s on 2026-08-24 after a live Tier B run
        # (run 32681983369) MISSED all 6 discovery techniques it fired. Root
        # cause: they executed ~77s apart, so a 120s window never held the 3
        # distinct techniques min_distinct needs (2*77=154s > 120) - the burst
        # could not physically complete. This was not a detection weakness; the
        # window was tuned for the tight offline live_safe cluster and was too
        # small for realistic pacing. 300s also HARDENS against a real attacker
        # who deliberately paces recon to slip under a short window - the very
        # evasion a 120s budget invited. The FP guard is unchanged and remains
        # min_distinct=3 (three DIFFERENT techniques), not the window.
        "medium", "T1087.001 — Account Discovery: Local Account", 300.0,
        (Step("distinct discovery technique",
              # T1016/T1049/T1012/T1007 added 2026-08-05 alongside
              # process_telemetry.classify_discovery's ipconfig/netstat/
              # reg-query/sc-query labels (redteam/evaluation/live_safe.py
              # RUN A closed gaps) - without listing them here too, Step.
              # matches() would silently never count them (found the hard
              # way: a technique's classify_discovery label alone does NOT
              # feed this rule unless its id is also in this tuple).
              # T1069 added 2026-08-26 alongside process_telemetry's
              # net-localgroup relabeling fix (Detection Coverage milestone) -
              # same "silently never counted otherwise" trap this comment
              # already warns about.
              # T1201/T1518 added 2026-08-27 closing confirmed generalization
              # gaps (PowerShell/net.exe-verb equivalents of already-covered
              # native-binary techniques) - same trap again: T1518.001 is
              # covered too via Step.matches' startswith(t + ".") prefix rule.
              techniques=("T1082", "T1057", "T1018", "T1087", "T1033", "T1482",
                         "T1016", "T1049", "T1012", "T1007", "T1069",
                         "T1201", "T1518"),
              min_distinct=3),),
        "Several DIFFERENT discovery techniques (system/process/account/network "
        "enumeration) were observed from the same actor within a short window. "
        "Any ONE of these alone is routine administration; this many together, "
        "this close together, is reconnaissance."),
)


@dataclass
class _Partial:
    rule: SequenceRule
    step_index: int          # index of the NEXT step to match
    first_ts: float
    last_ts: float
    pids: list
    distinct: set = field(default_factory=set)   # min_distinct accumulator
                                                   # for the CURRENT step only


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
    def _root_key(self, pid: int, actor: str, parent_name: str = "") -> str:
        """Resolve a process to its oldest tracked ancestor - so a child's
        behaviour advances its parent's sequence (the ESP parent-pid match).

        Falls back to grouping by PARENT NAME when no numeric lineage is
        resolvable but a parent name is known - the Security-log 4688 path
        (native_process sensor, no Sysmon) has no ParentProcessId field at
        all, only ParentProcessName, so `ppid` is always 0 for events from
        that source. Without this fallback every process from that source
        resolves to `pid:<its own pid>` - a root key unique to itself - so
        no two commands can ever be recognised as the same actor and a
        sequence like reconnaissance-burst (min_distinct=3 on one actor) can
        never complete on a non-Sysmon host, no matter how many discovery
        commands run together (found 2026-08-05, ADR 0048 Part 2 RUN A: 0/12
        captured). Coarser than real pid-based lineage - two unrelated
        processes that happen to share a same-named parent (two different
        cmd.exe sessions, say) will incorrectly merge - but that is a real
        signal in the wrong bucket, not silence pretending to be absence.
        """
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
                break                             # parent not tracked -> stop here
            cur = parent
            depth += 1
        if cur == pid and parent_name:
            return f"parent_name:{parent_name.lower()}"
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
                ts: float, pid: int = 0, ppid: int = 0,
                parent_name: str = "") -> Optional[dict]:
        """Advance sequence state with one behaviour. Returns a completed
        sequence dict, or None."""
        self._track(pid, ppid, actor)
        root = self._root_key(pid, actor, parent_name)
        tid = _tid(technique)
        lset = frozenset(labels or ())
        act = activity or ""

        partials = self._partials.get(root, [])
        # 1. Evict partials whose window has expired (hold only relevant state).
        partials = [p for p in partials if ts - p.first_ts <= p.rule.window]

        completed: Optional[dict] = None
        # 2. Advance existing partials (in order) that this behaviour continues.
        #    A min_distinct>1 step accumulates distinct hits instead of
        #    advancing on the first match (see Step.min_distinct); a
        #    min_distinct==1 step behaves EXACTLY as before (unconditional
        #    advance), so the 5 original ordered rules are untouched by this
        #    branch.
        kept: list[_Partial] = []
        for p in partials:
            step = p.rule.steps[p.step_index]
            if step.matches(tid, lset, act):
                p.last_ts = ts
                if pid and pid not in p.pids:
                    p.pids.append(pid)
                if step.min_distinct > 1:
                    key = step.match_key(tid, lset, act)
                    if key:
                        p.distinct.add(key)
                    if len(p.distinct) >= step.min_distinct:
                        # Snapshot BEFORE the reset below empties it - this is
                        # the only record of WHICH distinct techniques actually
                        # satisfied a breadth step (e.g. reconnaissance-burst's
                        # T1082/T1057/T1018 trio), and _complete() needs it to
                        # report per-contributor credit, not just the sequence's
                        # own culminating technique.
                        contributing = set(p.distinct)
                        p.step_index += 1
                        p.distinct = set()
                    else:
                        contributing = None
                else:
                    p.step_index += 1
                    contributing = None
                if p.step_index >= len(p.rule.steps):
                    completed = self._complete(p, root, contributing)
                    continue          # completed - do not keep as an open partial
            kept.append(p)
        partials = kept

        # 3. Start new partials whose FIRST step matches - but not for a rule
        #    that already has an active partial on this root (no duplicate
        #    explosions), and never advanced by the same event that started it.
        active_rules = {p.rule.id for p in partials}
        for rule in self._rules:
            if rule.id in active_rules:
                continue
            step0 = rule.steps[0]
            if not step0.matches(tid, lset, act):
                continue
            p = _Partial(rule=rule, step_index=0, first_ts=ts, last_ts=ts,
                        pids=[pid] if pid else [])
            new_contributing = None
            if step0.min_distinct > 1:
                key = step0.match_key(tid, lset, act)
                if key:
                    p.distinct.add(key)
                if len(p.distinct) >= step0.min_distinct:
                    new_contributing = set(p.distinct)
                    p.step_index = 1
                    p.distinct = set()
            else:
                p.step_index = 1
            # A single-step rule (min_distinct==1, len(steps)==1) or a
            # min_distinct>1 step satisfied on its very first observation both
            # complete immediately rather than sitting in partials forever -
            # no existing rule has fewer than 2 steps, so this is new behaviour
            # only for reconnaissance-burst-shaped rules, never a regression.
            if p.step_index >= len(rule.steps):
                completed = self._complete(p, root, new_contributing)
                continue
            partials.append(p)

        if partials:
            self._partials[root] = partials
        else:
            self._partials.pop(root, None)
        return completed

    def _complete(self, p: _Partial, root: str,
                  contributing: Optional[set] = None) -> dict:
        rule = p.rule
        score = {"critical": 0.95, "high": 0.85, "medium": 0.70}.get(rule.severity, 0.85)
        # contributing holds match_key() strings ('t:T1082', 'l:label', 'a:act')
        # from the breadth step that just completed (see min_distinct in
        # Step) - only the 't:' (technique) ones name a specific ATT&CK id.
        # Exposing these lets a consumer (analyst UI, the live-eval scorer)
        # credit each contributing technique individually instead of only the
        # sequence's own culminating technique - e.g. reconnaissance-burst
        # names ONE technique (T1087.001) but the 3+ discovery techniques that
        # actually built the breadth (T1082/T1057/T1018/...) were real,
        # distinct detections and deserve to be visible, not folded away.
        contributing_techniques = sorted(
            k[2:] for k in (contributing or ()) if k.startswith("t:"))
        return {
            "rule_id": rule.id,
            "name": rule.name,
            "severity": rule.severity,
            "technique": rule.technique,
            "contributing_techniques": contributing_techniques,
            "reason": rule.reason,
            "root": root,
            "actor": self._name.get(p.pids[0], "") if p.pids else root.split(":", 1)[-1],
            "pids": list(p.pids),
            "steps": [s.label for s in rule.steps],
            "span_seconds": round(p.last_ts - p.first_ts, 3),
            "score": score,
            "explanation": rule.reason + " (" + " → ".join(s.label for s in rule.steps) + ")",
        }
