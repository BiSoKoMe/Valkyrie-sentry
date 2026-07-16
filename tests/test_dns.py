"""Standalone DNS test script — stdlib only, no dnspython required.

Sends a raw UDP DNS A-record query to Valkyrie and prints whether the
domain was ALLOWED (real IP) or BLOCKED (0.0.0.0).

Usage:
    python test_dns.py google.com
    python test_dns.py doubleclick.net
    python test_dns.py example.com --port 53
    python test_dns.py example.com --debug
"""

import argparse
import socket
import struct
import sys


# ---------------------------------------------------------------------------
# DNS wire encoder/decoder
# ---------------------------------------------------------------------------

def _encode_name(name: str) -> bytes:
    buf = b""
    for label in name.rstrip(".").split("."):
        enc = label.encode()
        buf += bytes([len(enc)]) + enc
    return buf + b"\x00"


def _build_query(domain: str, txid: int = 0x1337) -> bytes:
    flags    = 0x0100   # recursion desired
    header   = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    question = _encode_name(domain) + struct.pack("!HH", 1, 1)   # A, IN
    return header + question


def _parse_ips(data: bytes) -> list[str]:
    """Extract all A-record IPs from a DNS response wire packet."""
    if len(data) < 12:
        return []
    _, _, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    offset = 12

    def skip_name(off: int) -> int:
        while off < len(data):
            ln = data[off]
            if ln == 0:
                return off + 1
            if ln & 0xC0 == 0xC0:
                return off + 2
            off += ln + 1
        return off

    for _ in range(qdcount):
        offset = skip_name(offset)
        offset += 4     # QTYPE + QCLASS

    ips = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        offset = skip_name(offset)
        if offset + 10 > len(data):
            break
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata   = data[offset:offset + rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(rdata))
        elif rtype == 28 and rdlen == 16:
            ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
    return ips


# ---------------------------------------------------------------------------
# Send + receive with fallback targets
# ---------------------------------------------------------------------------

def _try_send(query: bytes, target_ip: str, port: int, timeout: float, debug: bool) -> bytes | None:
    """Attempt one UDP send/recv.  Returns raw response bytes or None on failure."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    # Bind to 0.0.0.0 so the OS picks the right outbound interface
    sock.bind(("0.0.0.0", 0))
    if debug:
        bound = sock.getsockname()
        print(f"  [debug] socket bound to {bound[0]}:{bound[1]}")
        print(f"  [debug] sending {len(query)} bytes to {target_ip}:{port}")
        print(f"  [debug] hex: {query.hex()}")
    try:
        sock.sendto(query, (target_ip, port))
        data, src = sock.recvfrom(4096)
        if debug:
            print(f"  [debug] got {len(data)} bytes from {src[0]}:{src[1]}")
        return data
    except socket.timeout:
        if debug:
            print(f"  [debug] timeout from {target_ip}:{port}")
        return None
    except OSError as exc:
        if debug:
            print(f"  [debug] error from {target_ip}:{port}: {exc}")
        return None
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Test Valkyrie DNS sinkhole")
    parser.add_argument("domain", help="Domain to query")
    parser.add_argument("--port",    type=int, default=5300, help="Valkyrie DNS port (default: 5300)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-attempt timeout in seconds")
    parser.add_argument("--debug",   action="store_true",    help="Print raw bytes and socket details")
    args = parser.parse_args()

    domain = args.domain
    port   = args.port
    query  = _build_query(domain)

    print(f"\nValkyrie DNS test — domain: {domain}  port: {port}")
    print("-" * 50)

    # Try 127.0.0.1 first, then 0.0.0.0 as fallback (some Windows configs
    # route loopback traffic differently depending on interface binding)
    targets = ["127.0.0.1", "0.0.0.0"]
    data    = None
    used    = None

    for target in targets:
        print(f"Trying {target}:{port} …", end=" ", flush=True)
        data = _try_send(query, target, port, args.timeout, args.debug)
        if data is not None:
            print("OK")
            used = target
            break
        print("timeout")

    if data is None:
        print("\nFAIL — no response from any target.")
        print("Checklist:")
        print(f"  1. Is Valkyrie running?     python -m valkyrie --port {port}")
        print(f"  2. What is bound on {port}?  netstat -aon | findstr :{port}")
        if port == 5353:
            print("  !! Port 5353 is mDNS — Brave/Chrome/svchost already own it.")
            print("     Valkyrie shares the port but loses the packet race.")
            print(f"     Use port 5300 instead:  python -m valkyrie --port 5300")
            print(f"     Then:                   python test_dns.py {args.domain} --port 5300")
        print( "  3. Run as Administrator (required for port 53)")
        print(f"  4. Self-test: python -m valkyrie --test-dns --port {port}")
        sys.exit(2)

    ips = _parse_ips(data)
    if not ips:
        print(f"\nFAIL — response received from {used}:{port} but no A records parsed")
        if args.debug:
            print(f"  raw hex: {data.hex()}")
        sys.exit(2)

    sinkholed = all(ip in ("0.0.0.0", "::", "0:0:0:0:0:0:0:0") for ip in ips)
    verdict   = "BLOCKED" if sinkholed else "ALLOWED"
    sep       = "=" * 50
    print(f"\n{sep}")
    print(f"  {verdict}  —  {', '.join(ips)}")
    print(sep)


if __name__ == "__main__":
    main()
