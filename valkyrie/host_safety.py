"""Host safety — Valkyrie must never leave the machine worse than it found it.

THE PRIME DIRECTIVE, EXTENDED TO THE NETWORK
--------------------------------------------
Valkyrie's privacy core already lives by one rule: *protection must never break
the page.* This module extends that rule to its most dangerous consequence -
**protection must never break the host's connectivity** - and makes it a
self-healing invariant rather than a hope.

It exists because on 2026-08-23 Valkyrie's DNS interception left a real machine's
Wi-Fi adapter pointed at 127.0.0.1 with no local resolver answering: the link was
up at 1.2 Gbps, every name lookup failed, and the host looked "offline." For a
consumer/enterprise privacy tool that sits in front of all DNS, that is a
disqualifying failure - a paying client whose internet dies blames the tool,
uninstalls it, and tells everyone. No detection number matters if the tool can
strand the host.

WHY A WATCHDOG, NOT A CLEANUP HANDLER
-------------------------------------
A `stop()` cleanup that restores DNS only fires on a *graceful* stop. It does
nothing for the cases that actually strand people: a crash, a `kill -9`, a power
loss mid-redirect, a Windows Update reboot, or a legacy build that set the
redirect and was replaced. The only design that truly guarantees the host
survives is a watchdog whose correctness does NOT depend on how the bad state
arose:

  observe the adapter's DNS  ->  is it pointed at a Valkyrie loopback?
  ->  is that loopback resolver actually answering?
  ->  if pointed at us AND we're not answering, RESTORE connectivity.

Fail-safe, always toward connectivity. When in doubt, the host gets its network
back; interception is re-established only when the resolver is proven alive.

PURE CORE, INJECTED EXECUTOR
----------------------------
`decide_dns_action` is a pure function of (current servers, resolver alive?,
saved original). It performs no I/O and never raises, so the safety logic - the
part that must be provably correct - is exhaustively testable offline
(test_host_safety.py). The actual OS calls (read adapter DNS, set/reset it) live
behind a small injected executor, the same separation `authority.py` uses for
its gates: policy is decided here, the cost of acting is paid by a thin,
reviewed shim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class DnsActionKind(str, Enum):
    LEAVE = "leave"                       # host is fine; do nothing
    SAVE_ORIGINAL = "save_original"       # record the real DNS before any redirect
    RESTORE_ORIGINAL = "restore_original" # put back the exact pre-redirect servers
    RESET_TO_AUTO = "reset_to_auto"       # DHCP/automatic - the universal safe state


# Addresses that mean "traffic is being routed through a local resolver" - i.e.
# through Valkyrie. If the adapter points here and nothing answers, the host is
# stranded. IPv6 loopback included; ::1 strands exactly the same way.
_LOOPBACK = frozenset({"127.0.0.1", "::1", "0.0.0.0", "localhost"})


def is_loopback_redirect(servers: tuple) -> bool:
    """True when every configured DNS server is a loopback address - the shape
    that routes all name resolution through a local resolver (Valkyrie).

    ALL, not ANY, on purpose: a mixed config (127.0.0.1 + 8.8.8.8) still resolves
    via the public server, so the host is not stranded and must be left alone.
    An empty list is 'automatic' (DHCP), which is the safe state, not a redirect.
    """
    servers = tuple(s.strip().lower() for s in servers if str(s).strip())
    if not servers:
        return False
    return all(s in _LOOPBACK for s in servers)


@dataclass
class DnsAction:
    kind: DnsActionKind
    servers: tuple = ()          # for RESTORE_ORIGINAL: what to set them back to
    reason: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind.value, "servers": list(self.servers),
                "reason": self.reason}


def decide_dns_action(current_servers: tuple,
                      resolver_alive: bool,
                      saved_original: Optional[tuple]) -> DnsAction:
    """Decide the ONE safe action for the adapter's current DNS state. Pure.

    ``current_servers``  what the adapter's DNS is set to right now.
    ``resolver_alive``   is Valkyrie's local resolver actually answering?
    ``saved_original``   the pre-redirect servers we recorded, or None.

    The decision tree, biased toward connectivity at every branch:
    """
    redirected = is_loopback_redirect(current_servers)

    # --- not routed through us: the host is not at risk from Valkyrie ---
    if not redirected:
        # If these are real servers and we have nothing saved, remember them:
        # this is the only safe moment to learn the user's true DNS, BEFORE any
        # future redirect, so a later restore is exact rather than guessed.
        if current_servers and not saved_original:
            return DnsAction(DnsActionKind.SAVE_ORIGINAL, tuple(current_servers),
                             "recording the host's real DNS before any redirect "
                             "so it can be restored exactly later")
        return DnsAction(DnsActionKind.LEAVE, (),
                         "adapter DNS is not routed through a local resolver; "
                         "host connectivity does not depend on Valkyrie")

    # --- routed through us AND we are answering: working as intended ---
    if resolver_alive:
        return DnsAction(DnsActionKind.LEAVE, (),
                         "adapter is routed through Valkyrie's resolver and the "
                         "resolver is answering; interception is healthy")

    # --- routed through us AND we are NOT answering: the strand condition ---
    # This is the exact 2026-08-23 failure. Restore connectivity NOW.
    if saved_original and not is_loopback_redirect(saved_original):
        return DnsAction(DnsActionKind.RESTORE_ORIGINAL, tuple(saved_original),
                         "adapter is routed through Valkyrie but the resolver is "
                         "not answering (host is stranded); restoring the exact "
                         "pre-redirect DNS")
    # No trustworthy saved original -> DHCP/automatic is the universal safe state.
    return DnsAction(DnsActionKind.RESET_TO_AUTO, (),
                     "adapter is routed through Valkyrie, the resolver is not "
                     "answering, and no clean pre-redirect DNS was recorded; "
                     "resetting to automatic (DHCP) so the host regains name "
                     "resolution from its router/ISP")


# ---------------------------------------------------------------------------
# The watchdog - drives the pure decision with an injected OS executor.
# ---------------------------------------------------------------------------
@dataclass
class DnsExecutor:
    """The thin OS shim. Every callable is injected so the watchdog is testable
    with fakes and the real netsh / Set-DnsClientServerAddress calls live in ONE
    reviewed place (dns_os.py), never scattered."""
    read_servers:   Callable[[], tuple]          # -> current adapter DNS servers
    resolver_alive: Callable[[], bool]           # -> is the local resolver answering?
    set_servers:    Callable[[tuple], bool]      # restore exact servers; True on success
    reset_auto:     Callable[[], bool]           # set adapter to DHCP/automatic


@dataclass
class DnsWatchdog:
    """Fail-safe DNS guard. Records the host's real DNS once, and on every tick
    restores connectivity the instant the adapter is routed through a Valkyrie
    resolver that has stopped answering.

    State is intentionally minimal and in-memory; the watchdog's correctness
    does not depend on persistence, because its whole job is to recover a host
    whose prior Valkyrie process may have died without cleaning up. Even with an
    empty saved_original it still frees the host (RESET_TO_AUTO)."""
    executor: DnsExecutor
    saved_original: Optional[tuple] = None
    last_action: Optional[DnsAction] = None
    heals: int = 0                               # count of connectivity rescues
    _log: list = field(default_factory=list)

    def tick(self) -> DnsAction:
        """One observe->decide->act cycle. Never raises: a watchdog that can
        crash is not a safety device."""
        try:
            current = tuple(self.executor.read_servers() or ())
        except Exception:
            # If we cannot even read the adapter, do nothing this tick rather
            # than act on unknown state - acting blind could strand a host that
            # was fine.
            return DnsAction(DnsActionKind.LEAVE, (), "could not read adapter DNS")

        try:
            alive = bool(self.executor.resolver_alive())
        except Exception:
            alive = False   # unknown resolver == treat as dead == bias to restore

        action = decide_dns_action(current, alive, self.saved_original)
        self.last_action = action

        try:
            if action.kind == DnsActionKind.SAVE_ORIGINAL:
                self.saved_original = action.servers
            elif action.kind == DnsActionKind.RESTORE_ORIGINAL:
                if self.executor.set_servers(action.servers):
                    self.heals += 1
            elif action.kind == DnsActionKind.RESET_TO_AUTO:
                if self.executor.reset_auto():
                    self.heals += 1
        except Exception as exc:  # noqa: BLE001
            self._log.append(f"executor error on {action.kind.value}: {exc}")

        return action

    def restore_on_stop(self) -> DnsAction:
        """Called from a graceful shutdown. Forces the adapter back to a safe
        state: exact original if known, else automatic. Idempotent - safe to
        call even if the adapter was never redirected."""
        target = self.saved_original
        try:
            current = tuple(self.executor.read_servers() or ())
        except Exception:
            current = ()
        if current and not is_loopback_redirect(current):
            return DnsAction(DnsActionKind.LEAVE, (),
                             "adapter already on non-loopback DNS at shutdown")
        try:
            if target and not is_loopback_redirect(target):
                self.executor.set_servers(target)
                self.heals += 1
                return DnsAction(DnsActionKind.RESTORE_ORIGINAL, target,
                                 "graceful stop: restored pre-redirect DNS")
            self.executor.reset_auto()
            self.heals += 1
            return DnsAction(DnsActionKind.RESET_TO_AUTO, (),
                             "graceful stop: no saved original; reset to automatic")
        except Exception as exc:  # noqa: BLE001
            self._log.append(f"restore_on_stop error: {exc}")
            return DnsAction(DnsActionKind.LEAVE, (), f"restore failed: {exc}")

    def status(self) -> dict:
        return {"saved_original": list(self.saved_original or ()),
                "heals": self.heals,
                "last_action": self.last_action.to_dict() if self.last_action else None,
                "errors": list(self._log)}
