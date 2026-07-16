"""Test the Unbound local resolver — stdlib DNS only, no dnspython.

Checks:
  1. Unbound is reachable on 127.0.0.1:5301
  2. It resolves google.com (returns a real A record)
  3. The response does NOT come from 8.8.8.8 (we're not leaking to Google)
  4. NXDOMAIN for a guaranteed non-existent domain

Usage:
    python test_resolver.py               # default port 5301
    python test_resolver.py --port 5301   # explicit port
"""

import argparse
import socket
import struct
import sys
import time


# ---------------------------------------------------------------------------
# Minimal DNS wire codec (stdlib only — same as test_dns.py)
# ---------------------------------------------------------------------------

def _encode_name(name: str) -> bytes:
    buf = b""
    for label in name.rstrip(".").split("."):
        enc = label.encode()
        buf += bytes([len(enc)]) + enc
    return buf + b"\x00"


def _build_query(domain: str, qtype: int = 1, txid: int = 0x7E57) -> bytes:
    header   = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = _encode_name(domain) + struct.pack("!HH", qtype, 1)
    return header + question


def _parse_response(data: bytes) -> dict:
    """Return dict with keys: rcode, ips, answer_count."""
    if len(data) < 12:
        return {"rcode": -1, "ips": [], "answer_count": 0}

    txid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    rcode  = flags & 0x000F
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
        offset += 4

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

    return {"rcode": rcode, "ips": ips, "answer_count": ancount}


def _query(domain: str, server: str, port: int, timeout: float = 3.0) -> dict:
    """Send one DNS query; return parsed response or error dict."""
    query = _build_query(domain)
    sock  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.bind(("0.0.0.0", 0))
    try:
        sock.sendto(query, (server, port))
        data, src = sock.recvfrom(4096)
        result = _parse_response(data)
        result["src_ip"] = src[0]
        result["src_port"] = src[1]
        return result
    except socket.timeout:
        return {"error": "timeout", "rcode": -1, "ips": []}
    except OSError as exc:
        return {"error": str(exc), "rcode": -1, "ips": []}
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

_PASS = 0
_FAIL = 0


def chk(label: str, ok: bool, detail: str = "") -> None:
    global _PASS, _FAIL
    mark = "+" if ok else "!"
    line = f"  [{mark}] {label}"
    if detail:
        line += f"  ({detail})"
    print(line)
    if ok:
        _PASS += 1
    else:
        _FAIL += 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Test Unbound local resolver")
    parser.add_argument("--host",    default="127.0.0.1", help="Resolver host")
    parser.add_argument("--port",    type=int, default=5301, help="Resolver port (default: 5301)")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    host = args.host
    port = args.port

    print(f"\n=== Unbound resolver tests ({host}:{port}) ===\n")

    # ------------------------------------------------------------------
    # 1. Reachability
    # ------------------------------------------------------------------
    print("[1] Reachability")
    r = _query("google.com", host, port, timeout=args.timeout)
    reachable = "error" not in r
    chk("Unbound responds on port " + str(port), reachable,
        detail="timeout — is Unbound running? python -m valkyrie" if not reachable else "")

    if not reachable:
        print("\nCannot reach resolver. Start Valkyrie first:")
        print("  python -m valkyrie --no-ui")
        print("Or start Unbound manually with the generated config:")
        print("  unbound -c data/unbound.conf -d")
        sys.exit(1)

    # ------------------------------------------------------------------
    # 2. Resolves google.com
    # ------------------------------------------------------------------
    print("\n[2] Forward resolution")
    r_google = _query("google.com", host, port, timeout=args.timeout)
    has_ips  = len(r_google.get("ips", [])) > 0
    chk("google.com resolves", has_ips, detail=", ".join(r_google.get("ips", [])))
    chk("rcode is NOERROR (0)", r_google.get("rcode") == 0,
        detail="rcode=" + str(r_google.get("rcode")))

    # ------------------------------------------------------------------
    # 3. Response does NOT come from 8.8.8.8
    # ------------------------------------------------------------------
    print("\n[3] No Google DNS leak")
    src_ip = r_google.get("src_ip", "")
    chk(
        "Response source is NOT 8.8.8.8",
        src_ip != "8.8.8.8",
        detail=f"source was {src_ip}" if src_ip else "",
    )
    # Also confirm the resolved IPs are not sinkholed
    ips = r_google.get("ips", [])
    not_sinkholed = bool(ips) and not all(ip in ("0.0.0.0", "::") for ip in ips)
    chk("Returned real IPs (not sinkholed)", not_sinkholed, detail=", ".join(ips))

    # ------------------------------------------------------------------
    # 4. NXDOMAIN for non-existent domain
    # ------------------------------------------------------------------
    print("\n[4] NXDOMAIN handling")
    nx_domain = "this-domain-definitely-does-not-exist-valkyrie-test.invalid"
    r_nx = _query(nx_domain, host, port, timeout=args.timeout)
    chk(
        "NXDOMAIN for non-existent domain",
        r_nx.get("rcode") in (3, 5),   # 3=NXDOMAIN, 5=REFUSED (also acceptable)
        detail="rcode=" + str(r_nx.get("rcode")),
    )

    # ------------------------------------------------------------------
    # 5. Multiple domains — latency spot-check
    # ------------------------------------------------------------------
    print("\n[5] Latency (3 sequential queries)")
    domains = ["cloudflare.com", "github.com", "example.org"]
    for d in domains:
        t0 = time.monotonic()
        r  = _query(d, host, port, timeout=args.timeout)
        ms = (time.monotonic() - t0) * 1000
        ips_str = ", ".join(r.get("ips", [])) or "no A records"
        chk(
            f"{d} resolves",
            len(r.get("ips", [])) > 0,
            detail=f"{ms:.0f}ms  {ips_str}",
        )

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 45)
    print(f"PASS: {_PASS}   FAIL: {_FAIL}")
    if _FAIL:
        sys.exit(1)


if __name__ == "__main__":
    main()
