"""Causality graph - process ancestry as a first-class, queryable structure.

WHAT THIS ADDS THAT VALKYRIE DID NOT HAVE
-----------------------------------------
``killchain.py`` already folds a child process into its parent's chain via the
parent->child PID edge, but it does that at *scoring* time and keeps only a flat
deque of tactic steps. The structure - who spawned whom, what each process
touched - is computed and thrown away. Nothing persists ancestry, so there is
no tree to query, no way to ask "what else did this attack do?", and nothing to
render.

This module keeps the structure. It is the layer both major commercial EDRs are
built on: Cortex XDR calls it the *causality chain* and names its root the
**Causality Group Owner (CGO)**; Falcon calls the same thing the process tree /
threat graph. Every process becomes a node, every parent->child relationship an
edge, and every non-process observation (a network connection, a DNS query, a
file write, a detection) is *attributed* to the process that caused it.

    explorer.exe                     <- causality terminator, chain stops here
      └- winword.exe                 <- CGO: the process that owns this chain
           └- cmd.exe
                └- powershell.exe    <- the process a detection fired on
                     ├- [dns]    c2.example.test
                     └- [detect] Encoded PowerShell command

Asking "what is the CGO of this alert" answers the question an analyst actually
has - *what started this* - which a bare pid/ppid pair cannot.

WHY A TERMINATOR LIST IS THE WHOLE TRICK
----------------------------------------
Naively walking ppid links upward always ends at the same place: every process
on Windows descends from ``System``. A chain rooted at ``System`` tells you
nothing. What makes the CGO meaningful is stopping the walk at OS
*infrastructure* - the processes whose job is to spawn unrelated work
(``explorer.exe`` launches whatever the user clicks, ``services.exe`` launches
every service, ``svchost.exe`` hosts scheduled tasks). Those are causality
terminators: the walk stops below them, so the CGO is the first process that
represents a real actor rather than a launcher.

Terminator status is PATH-AWARE, which matters for evasion. A process named
``svchost.exe`` running out of ``%TEMP%`` is not the service host, it is a
masquerade - and if its name alone terminated the walk, the graph would hide
exactly the ancestry worth seeing. So a terminator name only terminates from a
trusted OS path (``trust.is_trusted_os_path``). See ``is_terminator``.

HONEST BOUNDARIES (read these before trusting a chain)
------------------------------------------------------
  * This graph is only as complete as the collectors feeding it. Valkyrie's
    process collector is a **userland psutil poller**, so a process that starts
    and exits between two polls is never seen, and its children will attach to
    an inferred placeholder (or to nothing) instead of to it. A kernel/ETW
    process sensor would close that gap; until one feeds this, chains can have
    holes. ``ProcessNode.inferred`` marks every node the graph guessed at
    rather than observed, and ``subgraph()`` reports ``inferred_nodes`` so a
    caller can never silently present a guess as an observation.
  * PIDs are reused. Nodes are keyed on ``(pid, create_time)``, and parent
    resolution rejects a candidate parent that started AFTER its supposed child
    (``_resolve_parent``) - a reused PID cannot be the parent. Where a
    collector supplies no create_time the key degrades to the pid alone and
    that protection is unavailable; such nodes are marked inferred.
  * Ancestry above Valkyrie's own start time is unobservable - processes that
    were already running are picked up by the poller with their ppid, but their
    parents may have long exited. Those resolve to inferred placeholders.
  * This module raises NO detections and changes no verdict. It is structure,
    not judgment. Nothing here can make Valkyrie detect something it did not
    already detect; it makes what was detected explicable.

Pure and deterministic: every method takes its timestamps from the caller and
reads no clock, so the whole module is unit-testable without sleeping. Bounded:
node count is capped and evicted oldest-last-seen-first, so a long-running
sensor cannot grow this without limit.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional

from ..trust import is_trusted_os_path

# ---------------------------------------------------------------------------
# Causality terminators - OS infrastructure whose job is to launch unrelated
# work. The upward walk stops BELOW these, so the CGO is the first process that
# represents an actor instead of a launcher.
#
# Scoped deliberately narrow: only processes that genuinely spawn work on behalf
# of something else. cmd.exe / powershell.exe / wscript.exe are NOT here - they
# are the interesting middle of a chain and truncating there would discard the
# ancestry that explains them.
# ---------------------------------------------------------------------------
CAUSALITY_TERMINATORS: frozenset[str] = frozenset({
    # Session / kernel boot chain
    "system", "registry", "memory compression", "idle",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "userinit.exe",
    "lsass.exe", "services.exe",
    # Generic service / task hosts: one host launches many unrelated payloads
    "svchost.exe", "taskeng.exe", "taskhost.exe", "taskhostw.exe",
    # Shell and shell infrastructure: launches whatever the user picks
    "explorer.exe", "sihost.exe", "runtimebroker.exe", "dwm.exe",
    "fontdrvhost.exe", "ctfmon.exe", "searchindexer.exe",
    # WMI provider host: remote WMI execution surfaces here, and the spawned
    # process (not the host) is the actor worth naming as CGO.
    "wmiprvse.exe",
})

# Depth guard for the upward walk. Real ancestry is shallow; anything deeper is
# a cycle or corrupt ppid data, and the walk must terminate regardless.
_MAX_CHAIN_DEPTH = 32

# Artifacts retained per process. A beaconing implant emits thousands of
# connections and the graph must not become the memory leak that takes the
# sensor down; the oldest beacon of ten thousand is the least interesting thing
# in the graph, so the cap keeps the most recent.
_MAX_ARTIFACTS_PER_NODE = 200


def _norm_name(name: str) -> str:
    """Process name, lowercased and stripped of any directory part."""
    n = str(name or "").strip().strip('"').replace("\\", "/")
    if "/" in n:
        n = n.rsplit("/", 1)[-1]
    return n.lower()


def is_terminator(name: str, path: str = "") -> bool:
    """Is this process a causality terminator (stop the upward walk below it)?

    PATH-AWARE ON PURPOSE. A terminator NAME only terminates when the binary
    actually lives in a trusted OS location, because the alternative is an
    evasion: ``C:\\Users\\x\\AppData\\Local\\Temp\\svchost.exe`` is a masquerade,
    and letting its name truncate the chain would hide the very ancestry that
    exposes it.

    An UNKNOWN path is treated as trusted for this purpose. That is not
    sloppiness - the processes whose paths Valkyrie's non-elevated userland
    poller cannot read are overwhelmingly the protected system processes that
    genuinely are terminators. The alternative default (unknown -> not a
    terminator) would root nearly every chain at ``System`` on an unprivileged
    install, which is the failure mode this list exists to prevent.
    """
    if _norm_name(name) not in CAUSALITY_TERMINATORS:
        return False
    p = str(path or "").strip()
    if not p:
        return True                       # unreadable path -> assume the real one
    return is_trusted_os_path(p)


# ---------------------------------------------------------------------------
# Nodes and artifacts
# ---------------------------------------------------------------------------

@dataclass
class Artifact:
    """One non-process observation attributed to the process that caused it.

    ``kind`` is a free-form but conventional label - ``dns``, ``network``,
    ``file``, ``registry``, ``detection`` - matching the collector vocabulary
    already used elsewhere in Valkyrie.
    """
    kind:    str
    summary: str
    ts:      float = 0.0
    data:    dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "summary": self.summary, "ts": self.ts,
                "data": dict(self.data)}


@dataclass
class ProcessNode:
    """One process instance in the graph.

    Identity is ``(pid, create_time)``, not pid - see the PID-reuse note in the
    module docstring. ``inferred`` is True when the graph created this node to
    fill an ancestry hole (a ppid referencing a process no collector reported)
    rather than from a real observation; callers must never present an inferred
    node as an observed fact.
    """
    pid:         int
    name:        str
    ppid:        int = 0
    path:        str = ""
    cmdline:     str = ""
    create_time: float = 0.0
    first_seen:  float = 0.0
    last_seen:   float = 0.0
    inferred:    bool = False
    artifacts:   list = field(default_factory=list)   # list[Artifact]
    # Key of the parent node, resolved ONCE when this process was first linked
    # and then held. Deriving it afresh on every walk (from ``_latest``) meant a
    # later process recycling the parent's pid could retroactively sever an edge
    # that was correctly established when the parent was still live.
    parent_key:  str = ""

    @property
    def key(self) -> str:
        return node_key(self.pid, self.create_time)

    @property
    def terminator(self) -> bool:
        return is_terminator(self.name, self.path)

    def to_dict(self, *, with_artifacts: bool = False) -> dict:
        d = {
            "key": self.key, "pid": self.pid, "ppid": self.ppid,
            "name": self.name, "path": self.path, "cmdline": self.cmdline,
            "create_time": self.create_time,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "inferred": self.inferred, "terminator": self.terminator,
            "parent_key": self.parent_key,
            "artifact_count": len(self.artifacts),
        }
        if with_artifacts:
            d["artifacts"] = [a.to_dict() for a in self.artifacts]
        return d


def node_key(pid: int, create_time: float = 0.0) -> str:
    """Canonical node identity.

    ``create_time`` is what makes this safe against PID reuse. When a collector
    cannot supply one the key degrades to ``"<pid>/~"``, which is honest about
    being a weaker identity - two different processes that reused a pid will
    collide in that namespace, and the node is marked inferred as a result.
    """
    p = int(pid or 0)
    return f"{p}/{float(create_time):.3f}" if create_time else f"{p}/~"


# ---------------------------------------------------------------------------
# The graph
# ---------------------------------------------------------------------------

class CausalityGraph:
    """Thread-safe, bounded process-ancestry graph with artifact attribution.

    Fed from the collector hot path (``observe_process``) and from the detection
    path (``attribute``). Queried by the API / analyst surface (``chain``,
    ``cgo``, ``subgraph``).

    Bounded by ``max_nodes``; when full, the least-recently-seen nodes are
    evicted first. Eviction can orphan a child whose parent was dropped - the
    child's chain then simply starts at the child, and ``subgraph()`` reports
    ``evicted`` so the truncation is visible rather than silent.
    """

    def __init__(self, max_nodes: int = 8192) -> None:
        self._max = max(64, int(max_nodes))
        self._nodes: dict[str, ProcessNode] = {}
        # pid -> key of the most recently STARTED instance of that pid. Parent
        # lookup goes through here because a child knows its ppid but not its
        # parent's create_time.
        self._latest: dict[int, str] = {}
        # parent key -> set of child keys (maintained incrementally so descendant
        # walks don't have to scan every node).
        self._children: dict[str, set] = {}
        self._evicted = 0
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------

    def observe_process(self, pid: int, name: str, *, ppid: int = 0,
                        path: str = "", cmdline: str = "",
                        create_time: float = 0.0, parent_name: str = "",
                        ts: float = 0.0) -> str:
        """Record a process (idempotent) and return its node key.

        Called for EVERY process the collector sees, not just suspicious ones -
        a causality chain is useless if the benign ancestors are missing, and
        the ancestors of an attack are benign by definition until the moment
        they are not.

        ``parent_name`` (which Valkyrie's process collector already carries on
        ``ProcInfo``) is used to give an unobserved parent a *named* inferred
        placeholder instead of an anonymous one - the difference between a chain
        reading ``winword.exe -> cmd.exe`` and one reading ``? -> cmd.exe``.
        """
        pid = int(pid or 0)
        if pid <= 0:
            return ""
        ts = float(ts or create_time or 0.0)
        key = node_key(pid, create_time)
        with self._lock:
            node = self._nodes.get(key)
            if node is None:
                node = ProcessNode(pid=pid, name=str(name or ""),
                                   ppid=int(ppid or 0), path=str(path or ""),
                                   cmdline=str(cmdline or ""),
                                   create_time=float(create_time or 0.0),
                                   first_seen=ts, last_seen=ts,
                                   # No create_time means the identity is the
                                   # bare pid, which PID reuse can collide.
                                   inferred=not create_time)
                self._nodes[key] = node
                if create_time:
                    self._absorb_placeholder(pid, key)
            else:
                # Re-observation: fill in anything the first sighting lacked.
                # A later poll often has a cmdline/path the first one could not
                # read, and an inferred placeholder gets PROMOTED to observed
                # the moment a real observation for it arrives.
                node.last_seen = max(node.last_seen, ts)
                if name and not node.name:
                    node.name = str(name)
                if path and not node.path:
                    node.path = str(path)
                if cmdline and not node.cmdline:
                    node.cmdline = str(cmdline)
                if ppid and not node.ppid:
                    node.ppid = int(ppid)
                if create_time:
                    node.inferred = False

            # Track the newest instance of this pid for parent resolution.
            prev = self._latest.get(pid)
            if prev is None or self._start_of(prev) <= node.create_time:
                self._latest[pid] = key

            self._link_parent(node, parent_name, ts)
            self._enforce_bounds()
            return key

    def attribute(self, pid: int, kind: str, summary: str, *,
                  create_time: float = 0.0, ts: float = 0.0,
                  data: Optional[dict] = None, name: str = "",
                  ppid: int = 0,
                  max_per_node: int = _MAX_ARTIFACTS_PER_NODE) -> bool:
        """Attach a non-process observation to the process that caused it.

        Returns False when the pid is unknown AND no ``name`` was supplied to
        create a node from - an unattributable observation (a DNS query the
        resolver could not map to a process, say) is dropped rather than
        guessed at. That is the same honest limit killchain.py documents; the
        graph does not paper over it.

        ``max_per_node`` bounds artifact growth per process. A beaconing implant
        can emit thousands of connections and the graph must not become the
        memory leak that takes the sensor down.
        """
        pid = int(pid or 0)
        if pid <= 0:
            return False
        with self._lock:
            key = self._key_for(pid, create_time)
            node = self._nodes.get(key) if key else None
            if node is None:
                if not name:
                    return False           # unattributable -> dropped, not guessed
                key = self.observe_process(pid, name, ppid=ppid,
                                           create_time=create_time, ts=ts)
                node = self._nodes.get(key)
                if node is None:
                    return False
            node.artifacts.append(Artifact(kind=str(kind or "event"),
                                           summary=str(summary or ""),
                                           ts=float(ts or 0.0),
                                           data=dict(data or {})))
            if len(node.artifacts) > max_per_node:
                # Keep the most recent; the oldest beacon of ten thousand is the
                # least interesting thing in the graph.
                del node.artifacts[: len(node.artifacts) - max_per_node]
            if ts:
                node.last_seen = max(node.last_seen, float(ts))
            return True

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def node(self, pid: int, create_time: float = 0.0) -> Optional[ProcessNode]:
        """The node for a pid (newest instance when create_time is omitted)."""
        with self._lock:
            key = self._key_for(int(pid or 0), create_time)
            return self._nodes.get(key) if key else None

    def chain(self, pid: int, create_time: float = 0.0) -> list:
        """The causality chain, CGO first and the named process last.

        Walks parent links upward, stopping below the first causality
        terminator (or at an unresolvable parent, or at the depth guard). The
        returned list always contains at least the process itself, so callers
        never have to special-case an empty chain.
        """
        with self._lock:
            node = self.node(pid, create_time)
            if node is None:
                return []
            return list(reversed(self._walk_up(node)))

    def cgo(self, pid: int, create_time: float = 0.0) -> Optional[ProcessNode]:
        """The Causality Group Owner - the process that owns this chain.

        This is the answer to "what started this?". For an alert on
        ``powershell.exe`` spawned by ``cmd.exe`` spawned by ``winword.exe``
        spawned by ``explorer.exe``, the CGO is ``winword.exe``: the document
        the user opened, not the shell that ran nor the desktop that launched it.
        """
        c = self.chain(pid, create_time)
        return c[0] if c else None

    def descendants(self, pid: int, create_time: float = 0.0, *,
                    max_nodes: int = 512) -> list:
        """Every process below this one, breadth-first (excludes the root).

        Bounded: a fork bomb or a build system must not be able to make this
        walk unbounded. Truncation is reported by ``subgraph()``.
        """
        with self._lock:
            root = self.node(pid, create_time)
            if root is None:
                return []
            out: list = []
            seen = {root.key}
            queue = [root.key]
            while queue and len(out) < max_nodes:
                cur = queue.pop(0)
                for ck in sorted(self._children.get(cur, ())):
                    if ck in seen:
                        continue           # cycle guard: corrupt ppid data
                    seen.add(ck)
                    child = self._nodes.get(ck)
                    if child is None:
                        continue
                    out.append(child)
                    queue.append(ck)
                    if len(out) >= max_nodes:
                        break
            return out

    def subgraph(self, pid: int, create_time: float = 0.0, *,
                 max_nodes: int = 512) -> dict:
        """Wire-format causality subgraph for one process - what a console draws.

        Contains the upward chain (CGO -> target), the full descendant tree under
        the CGO (so sibling branches of the same attack are visible, not just
        the one process that happened to alert), and every artifact attributed
        anywhere in that tree.

        Every honesty flag the module can raise is on this payload:
        ``inferred_nodes`` counts guessed ancestry, ``truncated`` says the walk
        hit its bound, and ``evicted`` says nodes were dropped for memory before
        this query ran - so a UI can render "partial chain" instead of
        presenting a hole as the whole story.
        """
        with self._lock:
            target = self.node(pid, create_time)
            if target is None:
                return {"found": False, "chain": [], "cgo": None,
                        "target": None, "tree": [], "artifacts": [],
                        "inferred_nodes": 0, "truncated": False,
                        "evicted": self._evicted}
            chain = list(reversed(self._walk_up(target)))
            owner = chain[0]
            tree = self.descendants(owner.pid, owner.create_time,
                                    max_nodes=max_nodes)
            members = [owner] + tree
            artifacts = []
            for n in members:
                for a in n.artifacts:
                    d = a.to_dict()
                    d["process"] = n.name
                    d["pid"] = n.pid
                    artifacts.append(d)
            artifacts.sort(key=lambda a: a.get("ts") or 0.0)
            return {
                "found": True,
                "cgo": owner.to_dict(),
                "chain": [n.to_dict() for n in chain],
                "target": target.to_dict(),
                "tree": [n.to_dict() for n in tree],
                "artifacts": artifacts,
                "depth": len(chain),
                "inferred_nodes": sum(1 for n in members if n.inferred),
                "truncated": len(tree) >= max_nodes,
                "evicted": self._evicted,
            }

    def stats(self) -> dict:
        """Graph size and health - for the components/coverage surface."""
        with self._lock:
            inferred = sum(1 for n in self._nodes.values() if n.inferred)
            artifacts = sum(len(n.artifacts) for n in self._nodes.values())
            return {"nodes": len(self._nodes), "inferred": inferred,
                    "artifacts": artifacts, "evicted": self._evicted,
                    "capacity": self._max}

    # ------------------------------------------------------------------
    # Internals (all called under lock)
    # ------------------------------------------------------------------

    def _key_for(self, pid: int, create_time: float) -> str:
        """Resolve a (pid, create_time) pair to a live node key.

        An explicit create_time addresses one exact instance. Without one, the
        newest instance of that pid is the best available answer.
        """
        if create_time:
            k = node_key(pid, create_time)
            if k in self._nodes:
                return k
        k = self._latest.get(pid)
        if k and k in self._nodes:
            return k
        k = node_key(pid, 0.0)
        return k if k in self._nodes else ""

    def _start_of(self, key: str) -> float:
        n = self._nodes.get(key)
        return n.create_time if n else 0.0

    def _resolve_parent(self, node: ProcessNode) -> Optional[ProcessNode]:
        """The parent node for ``node``, or None if it cannot be established.

        An edge already established (``parent_key``) WINS. It was resolved when
        the parent was still the live holder of that pid, and nothing that
        happens to the pid afterwards can make it retroactively untrue. Deriving
        the edge from ``_latest`` on every walk instead was a real bug: a later,
        unrelated process recycling the parent's pid would trip the reuse guard
        below and silently sever a correct chain.

        THE PID-REUSE GUARD applies to the fallback path, where all we have is a
        ppid. If the process currently holding that pid started AFTER this child
        did, it demonstrably cannot be its parent - the pid was recycled.
        Returning None there is correct: an honest hole beats a fabricated edge
        that would put an unrelated process at the head of an attack chain.
        """
        if node.ppid <= 0 or node.ppid == node.pid:
            return None
        if node.parent_key:
            established = self._nodes.get(node.parent_key)
            if established is not None:
                return established
            # Parent was evicted for memory; fall through and try to re-resolve.
        pkey = self._latest.get(node.ppid)
        if not pkey:
            return None
        parent = self._nodes.get(pkey)
        if parent is None:
            return None
        if (parent.create_time and node.create_time
                and parent.create_time > node.create_time):
            return None                    # recycled pid - not the real parent
        return parent

    def _link_parent(self, node: ProcessNode, parent_name: str,
                     ts: float) -> None:
        """Attach ``node`` to its parent, materialising an inferred placeholder
        when the parent was never observed.

        The placeholder is what keeps a chain readable across the poller's blind
        spot: the collector hands us ``parent_name`` even when the parent
        process itself exited before any poll saw it, so the chain can still say
        ``winword.exe -> cmd.exe`` rather than dead-ending. The node is flagged
        ``inferred`` and counted in ``subgraph()['inferred_nodes']``, so the
        guess is always distinguishable from an observation.
        """
        if node.ppid <= 0 or node.ppid == node.pid:
            return
        if node.parent_key and node.parent_key in self._nodes:
            return                         # already linked; edges are set once
        parent = self._resolve_parent(node)
        if parent is None and parent_name:
            pkey = node_key(node.ppid, 0.0)
            parent = self._nodes.get(pkey)
            if parent is None:
                parent = ProcessNode(pid=node.ppid, name=str(parent_name),
                                     first_seen=ts, last_seen=ts, inferred=True)
                self._nodes[pkey] = parent
                self._latest.setdefault(node.ppid, pkey)
        if parent is None:
            return
        node.parent_key = parent.key
        self._children.setdefault(parent.key, set()).add(node.key)

    def _absorb_placeholder(self, pid: int, key: str) -> None:
        """Fold a pid-only placeholder into the real node just observed for it.

        Without this the graph silently forks. A child that named an unobserved
        parent creates a ``"<pid>/~"`` placeholder and hangs itself off that;
        when the parent is later observed for real it gets a ``"<pid>/<ctime>"``
        key, and the graph now holds two nodes for one process - parent lookups
        follow ``_latest`` to the real one while the child edges still point at
        the ghost, so ``chain()`` and ``descendants()`` disagree about the same
        process. Merging on promotion is what keeps those two views consistent.

        MERGE ONLY ON A NAME MATCH. The ghost is a guess, and the one way it can
        be a *wrong* guess is pid reuse: the ghost described the process that
        held this pid earlier, and what we are now observing is a different
        process that inherited it. Names differing is the cheap, sound signal
        for exactly that case - so when they differ the two nodes stay separate
        and the graph carries an honest fork instead of a fabricated identity.
        """
        ghost_key = node_key(pid, 0.0)
        if ghost_key == key:
            return
        ghost = self._nodes.get(ghost_key)
        node = self._nodes.get(key)
        if ghost is None or node is None or not ghost.inferred:
            return
        if ghost.name and node.name and _norm_name(ghost.name) != _norm_name(node.name):
            return                         # different process, recycled pid
        if ghost.name and not node.name:
            node.name = ghost.name
        if ghost.ppid and not node.ppid:
            node.ppid = ghost.ppid
        if ghost.path and not node.path:
            node.path = ghost.path
        if ghost.cmdline and not node.cmdline:
            node.cmdline = ghost.cmdline
        node.first_seen = min(x for x in (node.first_seen, ghost.first_seen) if x) \
            if (node.first_seen or ghost.first_seen) else 0.0
        node.last_seen = max(node.last_seen, ghost.last_seen)
        node.artifacts = (ghost.artifacts + node.artifacts)[-_MAX_ARTIFACTS_PER_NODE:]
        if ghost.parent_key and not node.parent_key:
            node.parent_key = ghost.parent_key
        # Re-parent the ghost's children, and re-point any edge INTO the ghost.
        kids = self._children.pop(ghost_key, set())
        if kids:
            self._children.setdefault(key, set()).update(kids)
            for ck in kids:                # the child's own back-pointer too
                child = self._nodes.get(ck)
                if child is not None and child.parent_key == ghost_key:
                    child.parent_key = key
        for sibs in self._children.values():
            if ghost_key in sibs:
                sibs.discard(ghost_key)
                sibs.add(key)
        self._nodes.pop(ghost_key, None)
        if self._latest.get(pid) == ghost_key:
            self._latest[pid] = key

    def _walk_up(self, node: ProcessNode) -> list:
        """Ancestors from ``node`` upward, stopping below the first terminator.

        Returns node-first order (caller reverses for CGO-first). The seen-set
        is a hard cycle guard: corrupt or spoofed ppid data can describe a loop,
        and this must terminate on any input.
        """
        out = [node]
        seen = {node.key}
        cur = node
        for _ in range(_MAX_CHAIN_DEPTH):
            if cur.terminator:
                break                      # a terminator owns itself; go no higher
            parent = self._resolve_parent(cur)
            if parent is None or parent.key in seen:
                break
            if parent.terminator:
                break                      # stop BELOW the terminator - cur is CGO
            out.append(parent)
            seen.add(parent.key)
            cur = parent
        return out

    def _enforce_bounds(self) -> None:
        """Evict least-recently-seen nodes once over capacity.

        Eviction is the only way this module loses information, so it is counted
        (``_evicted``) and surfaced on every ``subgraph()`` rather than being
        silent - a chain that looks short because its head was evicted must be
        distinguishable from one that is genuinely short.
        """
        over = len(self._nodes) - self._max
        if over <= 0:
            return
        victims = sorted(self._nodes.values(),
                         key=lambda n: (n.last_seen, n.first_seen))[:over]
        for n in victims:
            self._drop(n.key, n.pid)
        self._evicted += len(victims)

    def _drop(self, key: str, pid: int) -> None:
        self._nodes.pop(key, None)
        self._children.pop(key, None)
        for kids in self._children.values():
            kids.discard(key)
        if self._latest.get(pid) == key:
            self._latest.pop(pid, None)
