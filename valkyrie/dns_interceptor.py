"""DNS sinkhole core.

Listens on UDP (and optionally TCP) for DNS queries, applies the decision
pipeline, and either:
  - Returns a NXDOMAIN / sinkhole response (blocked)
  - Forwards the query to the upstream resolver and relays the real answer

Decision pipeline (in order):
  1. User rules — always_allow / always_block take priority
  2. Intelligence memory — verdicts Valkyrie already learned (fast path)
  3. Blocklist / scanner — known-bad domains + positive tracker signals
  4. Threat classifier — behavioural intelligence (anomaly + threat graph)
  5. Baseline anomaly check — post-profiling phase

Every query is also recorded into the intelligence layer's baseline so
the machine's "normal" keeps being learned; blocks feed the threat graph
so related infrastructure is caught automatically.  The intelligence
steps are additive — with intelligence=None the pipeline behaves exactly
as before.

OS-specific setup (NOT handled here — must be done externally):
  Linux:
    iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 5353
    iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-port 5353
  Windows:
    Route DNS to 127.0.0.1:5353 via netsh or a loopback adapter.
  macOS:
    /etc/resolver/ directory pointing at 127.0.0.1 port 5353.

Root / admin requirement:
  Ports < 1024 need root on Linux/macOS.  Default port is 5353 (unprivileged).
"""

from __future__ import annotations

import platform
import socket
import threading
import time
from typing import Optional

from .behavioral import BehavioralEngine
from .blocklist import BlocklistManager
from .site_scanner import SiteScanner
from .config import (
    DNS_LISTEN_HOST,
    DNS_LISTEN_PORT,
    DNS_TIMEOUT,
    DNS_UPSTREAM,
    DNS_UPSTREAM_PORT,
    SINKHOLE_IPV4,
    SINKHOLE_IPV6,
    UPSTREAM_SERVERS,
)
from .process_watcher import ProcessInfo, ProcessWatcher, _UNKNOWN
from .rules import RulesLoader
from .store import DnsEvent, Store

import struct


def _fix_transaction_id(response_wire: bytes, original_id: int) -> bytes:
    """Rewrite the DNS transaction ID (first 2 bytes of the header) to match
    the ORIGINAL client's request ID, regardless of what ID was used to
    query upstream internally."""
    if len(response_wire) < 2:
        return response_wire
    return struct.pack("!H", original_id) + response_wire[2:]

try:
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.rcode
    import dns.rrset
    import dns.name
    import dns.rdtypes.IN.A
    import dns.rdtypes.IN.AAAA
    _DNSLIB = True
except ImportError:
    _DNSLIB = False


class DNSInterceptor:
    """UDP DNS sinkhole server.

    Abstracts OS-specific parts behind this interface so Windows/macOS
    support can be added by subclassing without touching the pipeline.
    """

    def __init__(
        self,
        store: Store,
        blocklist: BlocklistManager,
        behavioral: BehavioralEngine,
        rules: RulesLoader,
        process_watcher: ProcessWatcher,
        scanner: Optional[SiteScanner] = None,
        intelligence=None,          # valkyrie.intelligence.Intelligence (optional)
        strict: bool = False,
        host: str          = DNS_LISTEN_HOST,
        port: int          = DNS_LISTEN_PORT,
        upstream_host: str = DNS_UPSTREAM,
        upstream_port: int = DNS_UPSTREAM_PORT,
        allow_external_fallback: bool = True,
        debug: bool        = False,
    ) -> None:
        self._store         = store
        self._blocklist     = blocklist
        self._behavioral    = behavioral
        self._rules         = rules
        self._watcher       = process_watcher
        self._scanner       = scanner
        self._intelligence  = intelligence
        self._strict        = strict  # if True: also check blocklist after scanner "allow"
        self._host          = host
        self._port          = port
        self._upstream_host = upstream_host
        self._upstream_port = upstream_port
        # When False, allowed queries go ONLY to the configured local upstream
        # (e.g. Unbound on 127.0.0.1) and never fall back to public resolvers —
        # fail-closed, no DNS leak.  See config.DNS_LOCAL_ONLY.
        self._allow_external_fallback = allow_external_fallback
        self._debug         = debug
        self._sock: Optional[socket.socket] = None
        self._running   = False
        self._thread    = threading.Thread(
            target=self._serve_loop, daemon=True, name="dns-interceptor"
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if not _DNSLIB:
            raise RuntimeError("dnspython is not installed. Run: pip install dnspython")
        # On Windows, binding to 127.0.0.1 silently drops queries that
        # arrive via the loopback adapter with a different source path.
        # Binding to 0.0.0.0 accepts on all interfaces and fixes this.
        bind_host = "0.0.0.0" if platform.system() == "Windows" else self._host
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Do NOT set SO_REUSEADDR on Windows — mDNS processes (Brave, svchost)
        # share port 5353 via REUSEADDR and will steal our packets.
        if platform.system() != "Windows":
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((bind_host, self._port))
        self._sock.settimeout(1.0)
        self._running = True
        try:
            self._thread.start()
        except RuntimeError:
            # Thread objects are single-use — after a stop()/start() cycle
            # (e.g. self-healing recovery) a fresh serve thread is needed.
            self._thread = threading.Thread(
                target=self._serve_loop, daemon=True, name="dns-interceptor"
            )
            self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._sock:
            self._sock.close()
        self._thread.join(timeout=3)

    def is_listening(self) -> bool:
        """Lightweight liveness probe for the self-healing watchdog.

        True while the serve loop is running with a bound socket.  Does not
        depend on upstream reachability — an offline upstream must not be
        mistaken for a dead interceptor.
        """
        return self._running and self._sock is not None and self._thread.is_alive()

    def self_test(self, domain: str = "google.com", timeout: float = 3.0) -> dict:
        """Send a test query to ourselves and return result details.

        Returns a dict with keys: domain, decision (PASS/FAIL), ip, raw_rcode.
        Safe to call while the interceptor is running.
        """
        import dns.message
        import dns.rdatatype

        query = dns.message.make_query(domain, dns.rdatatype.A)
        wire  = query.to_wire()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(wire, ("127.0.0.1", self._port))
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            return {"domain": domain, "decision": "FAIL", "ip": None, "error": "timeout"}
        except OSError as exc:
            return {"domain": domain, "decision": "FAIL", "ip": None, "error": str(exc)}
        finally:
            sock.close()

        try:
            response = dns.message.from_wire(data)
            ip = None
            for rrset in response.answer:
                for rdata in rrset:
                    ip = str(rdata)
                    break
                if ip:
                    break
            return {
                "domain":   domain,
                "decision": "PASS",
                "ip":       ip,
                "rcode":    dns.rcode.to_text(response.rcode()),
                "answers":  len(response.answer),
            }
        except Exception as exc:
            return {"domain": domain, "decision": "FAIL", "ip": None, "error": str(exc)}

    # ------------------------------------------------------------------
    # Serve loop
    # ------------------------------------------------------------------

    def _serve_loop(self) -> None:
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            # Handle each query in its own thread to avoid head-of-line blocking
            threading.Thread(
                target=self._handle, args=(data, addr), daemon=True
            ).start()

    def _handle(self, data: bytes, addr: tuple[str, int]) -> None:
        src_ip, src_port = addr
        try:
            request = dns.message.from_wire(data)
        except Exception:
            return

        if not request.question:
            return

        qname    = str(request.question[0].name).rstrip(".")
        qtype    = request.question[0].rdtype
        proc     = self._watcher.lookup(src_ip, src_port)

        decision, reason, suspicion, category = self._decide(
            qname, qtype, proc, payload_size=len(data)
        )

        if self._debug:
            print(f"[dns] {qname}  decision={decision}  proc={proc.name}  reason={reason or '-'}")

        response = self._build_response(request, qname, qtype, decision)

        # Defensive: guarantee the reply's transaction ID matches the
        # original client request, regardless of what ID was used internally
        # to reach upstream. A mismatched ID makes the client silently
        # discard the reply — indistinguishable from a timeout.
        if response:
            response = _fix_transaction_id(response, request.id)

        if self._debug:
            resp_id = struct.unpack("!H", response[:2])[0] if len(response) >= 2 else None
            print(f"  [reply] original_id={request.id} response_id={resp_id}")

        if not response:
            if self._debug:
                print(f"  [reply] empty response for {qname} — not sending")
            return

        try:
            if self._debug:
                print(f"  [reply] forwarding {len(response)} bytes back to {addr}")
            self._sock.sendto(response, addr)
        except OSError as e:
            if self._debug:
                print(f"  [reply] sendto failed: {e}")

        self._store.log(DnsEvent.now(
            domain       = qname,
            decision     = decision,
            process_name = proc.name,
            process_pid  = proc.pid,
            process_path = proc.path,
            reason       = reason,
            suspicion    = suspicion,
            raw_category = category,
        ))

    # ------------------------------------------------------------------
    # Decision pipeline
    # ------------------------------------------------------------------

    def _decide(
        self, domain: str, qtype: int, proc: ProcessInfo, payload_size: int = 0
    ) -> tuple[str, str, float, str]:
        """Return (decision, reason, suspicion_score, category)."""
        rules = self._rules.get()
        intel = self._intelligence

        # 1. User always_allow
        if rules.is_always_allowed(domain, proc.name):
            return "allowed", "user:always_allow", 0.0, "user_rule"

        # 2. User always_block
        if rules.is_always_blocked(domain, proc.name):
            return "blocked", "user:always_block", 1.0, "user_rule"

        # 2b. Intelligence: observe, then take the fast path if this domain
        #     was already decided.  Known-good domains were promoted only
        #     after repeatedly passing the full pipeline.
        now = time.time()
        if intel is not None:
            intel.record(proc.name, domain, now, payload_size)
            verdict = intel.check_memory(domain)
            if verdict == "bad":
                reason = intel.memory_reason(domain) or "learned threat"
                return "blocked", f"intelligence:{reason}", 1.0, "intelligence"
            if verdict == "good":
                return "allowed", "intelligence:known_good", 0.0, "intelligence"

        # 3. Scanner (replaces blocklist + behavioral as default pipeline)
        if self._scanner is not None:
            result = self._scanner.analyze(domain, proc.name)
            if result.decision == "block":
                reason = "; ".join(result.reasons)
                if intel is not None:
                    intel.remember_block(domain, reason)
                return "blocked", reason, result.confidence, result.category
            if result.decision == "flag":
                return "flagged", "; ".join(result.reasons), result.confidence, result.category
            # Scanner says "allow" — fall through to strict/anomaly checks below
            score = result.confidence
        else:
            # Fallback: legacy blocklist + behavioral (when scanner not wired in)
            if self._blocklist.is_blocked(domain):
                if intel is not None:
                    intel.remember_block(domain, "blocklist")
                return "blocked", "blocklist", 0.0, "blocklist"
            block_beh, score, beh_reason = self._behavioral.should_block(domain, proc.name)
            if block_beh:
                if intel is not None:
                    intel.remember_block(domain, beh_reason)
                return "behavioral", beh_reason, score, "behavioral"

        # 3b. Blocklist on top of scanner "allow" — since the cutover to the
        #     built-in seed list this is always enforced (the seed is small,
        #     curated, and safe); --strict is therefore implied nowadays.
        if self._blocklist.is_blocked(domain):
            if intel is not None:
                intel.remember_block(domain, "blocklist")
            return "blocked", "blocklist", 1.0, "blocklist"

        # 3c. Threat classifier — behavioural intelligence on top of the
        #     list-based checks.  Blocks feed memory + threat graph so the
        #     next hit takes the fast path and related infra is caught.
        if intel is not None:
            verdict = intel.classify(proc.name, domain, now, payload_size)
            if verdict["decision"] == "block":
                intel.remember_block(domain, verdict["reason"])
                return "blocked", verdict["reason"], verdict["score"], "intelligence"
            if verdict["decision"] == "flag":
                return "flagged", verdict["reason"], verdict["score"], "intelligence"
            score = max(score, verdict["score"])

        # 4. Baseline anomaly (flagged but not blocked)
        if self._store.is_anomaly(proc.name, domain):
            return "flagged", "baseline:anomaly", score, "anomaly"

        return "allowed", "", score, ""

    # ------------------------------------------------------------------
    # Response builder
    # ------------------------------------------------------------------

    def _build_response(
        self, request: "dns.message.Message", qname: str, qtype: int, decision: str
    ) -> bytes:
        if decision in ("blocked", "behavioral"):
            return self._sinkhole_response(request, qname, qtype)
        else:
            return self._forward(request)

    def _sinkhole_response(
        self, request: "dns.message.Message", qname: str, qtype: int
    ) -> bytes:
        response = dns.message.make_response(request)
        response.flags |= dns.flags.AA

        name = dns.name.from_text(qname)
        if qtype == dns.rdatatype.AAAA:
            rrset = response.find_rrset(
                response.answer, name, dns.rdataclass.IN, dns.rdatatype.AAAA, create=True
            )
            rdata = dns.rdtypes.IN.AAAA.AAAA(dns.rdataclass.IN, dns.rdatatype.AAAA, SINKHOLE_IPV6)
            rrset.add(rdata, ttl=60)
        else:
            rrset = response.find_rrset(
                response.answer, name, dns.rdataclass.IN, dns.rdatatype.A, create=True
            )
            rdata = dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, SINKHOLE_IPV4)
            rrset.add(rdata, ttl=60)

        return response.to_wire()

    def _forward(self, request: "dns.message.Message") -> bytes:
        import socket as _socket
        import struct

        wire  = request.to_wire()
        qname = str(request.question[0].name).rstrip(".") if request.question else "?"

        # Try the configured upstream first (e.g. local Unbound on 127.0.0.1:53
        # for fully local recursive resolution), then fall back to the public
        # resolver list if it's unreachable. Without this, the configured
        # upstream_host/upstream_port were silently ignored and every query
        # went straight to public DNS regardless of what Unbound integration
        # had set up.
        #
        # No-leak mode (allow_external_fallback=False, auto-enabled when Unbound
        # is the upstream): the public-resolver fallback is omitted entirely, so
        # a plaintext query can NEVER reach a third-party resolver. If the local
        # upstream is unreachable the loop exhausts and we return SERVFAIL below
        # (fail-closed) rather than leaking the query to 8.8.8.8/1.1.1.1/etc.
        servers: list[tuple[str, int]] = [(self._upstream_host, self._upstream_port)]
        if self._allow_external_fallback:
            servers += [(s, 53) for s in UPSTREAM_SERVERS if s != self._upstream_host]
        elif self._debug:
            print(f"  [no-leak] {qname}: local upstream only "
                  f"({self._upstream_host}:{self._upstream_port}), no external fallback")

        for upstream, port in servers:
            # ── UDP ──────────────────────────────────────────────────────────
            if self._debug:
                print(f"  → forwarding {qname} to {upstream}:{port} (UDP)")
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            try:
                sock.settimeout(1.0)
                sock.sendto(wire, (upstream, port))
                data, _ = sock.recvfrom(4096)
                if self._debug:
                    print(f"  ✓ {qname} resolved via UDP/{upstream}:{port}")
                return data
            except Exception as e:
                if self._debug:
                    print(f"  ✗ UDP/{upstream}:{port} failed: {e}")
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

            # ── TCP (DNS-over-TCP: 2-byte length prefix) ──────────────────
            if self._debug:
                print(f"  → forwarding {qname} to {upstream}:{port} (TCP)")
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            try:
                sock.settimeout(1.0)
                sock.connect((upstream, port))
                sock.sendall(struct.pack("!H", len(wire)) + wire)
                length_data = sock.recv(2)
                if len(length_data) == 2:
                    length = struct.unpack("!H", length_data)[0]
                    data = b""
                    while len(data) < length:
                        chunk = sock.recv(length - len(data))
                        if not chunk:
                            break
                        data += chunk
                    if data:
                        if self._debug:
                            print(f"  ✓ {qname} resolved via TCP/{upstream}:{port}")
                        return data
            except Exception as e:
                if self._debug:
                    print(f"  ✗ TCP/{upstream}:{port} failed: {e}")
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        # All upstreams exhausted
        if self._debug:
            print(f"  ✗ {qname} all upstreams failed — returning SERVFAIL")
        response = dns.message.make_response(request)
        response.set_rcode(dns.rcode.SERVFAIL)
        return response.to_wire()
