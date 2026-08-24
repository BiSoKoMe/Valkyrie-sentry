"""Deception endpoint — answer tracker beacons instead of failing them.

WHAT WAS WRONG BEFORE
---------------------
DECEIVE resolved to `0.0.0.0`. That is BLOCK with a different label in the UI.
The tracker's request fails at connect; nothing false is ever said. And a
machine whose beacons reliably fail while the rest of its traffic succeeds is
wearing a sign that reads "runs a blocker" — a small, stable, high-entropy
population that is *easier* to single out than the default one.

WHAT THIS DOES
--------------
DECEIVE now resolves to a loopback address where this server is listening. The
beacon connects, gets a well-formed reply of the shape its family expects, and
goes away satisfied. The data it carries home is fabricated — but coherent,
and identical to what it was told last week, because every persona-derived
value comes from `persona.py`'s single stable identity.

The two failure modes this is built around:

  * A lie that is INCONSISTENT is worse than silence. If /collect reports
    timezone America/New_York and /pixel reports Europe/Berlin, the pair is
    unique to synthetic traffic. Real clients do not contradict themselves. So
    every field here is read from ONE `Persona` object per reply — there is no
    second source that could drift.
  * A lie that is IMPLAUSIBLE is also a fingerprint. Empty JSON, HTTP 204 for
    everything, or a body of literal zeros is not what these services return.
    Each family gets the shape that family actually uses.

`build_reply()` is a pure function — method/path/query/headers in, status +
headers + body out. The socket server is a thin wrapper over it, so the
interesting behaviour is testable without binding a port.

HONEST BOUNDARIES — read before believing this hides anything
-------------------------------------------------------------
* **HTTPS is not solved here.** Nearly all real beacons are HTTPS. A TLS
  handshake against this endpoint fails unless Valkyrie's mitmproxy CA
  (`tls_inspector.py`) is installed AND trusted on the device, which is opt-in
  and off by default. Without it, an HTTPS beacon pointed here fails at
  handshake rather than at connect — better than `0.0.0.0` (the connection is
  accepted, so the "blocker" signal is weaker) but it is NOT a served lie.
  Plain-HTTP beacons are fully served. I have tested the HTTP path; I have not
  tested an end-to-end HTTPS beacon through the CA.
* This does not defeat first-party cookies, logins, or IP-address tracking.
  None of those pass through here.
* The reply bodies are modelled on the SHAPE of common beacon responses, not
  captured from any specific vendor's live API. A vendor that validates a
  signed/nonce'd response will notice. The goal is to satisfy fire-and-forget
  telemetry, which is the overwhelming majority of it — not to defeat an
  adversary who is actively probing for a deception endpoint.
* Serving on loopback means only this machine reaches it. It is not a network
  service and must never be bound off-loopback.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from .persona import Persona, current_persona

# A real 1x1 transparent GIF. Tracking pixels genuinely return this exact kind
# of payload; returning zero bytes or a 204 where a GIF is expected is a tell.
_PIXEL_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01"
    b"\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)

# Beacon families, in match order. Ordering matters: /collect on an ad host
# should still be treated as analytics, so the more specific path markers are
# tested before the host-shaped ones.
FAMILY_PIXEL = "pixel"
FAMILY_ANALYTICS = "analytics"
FAMILY_AD = "ad"
FAMILY_CONSENT = "consent"
FAMILY_CONFIG = "config"
FAMILY_GENERIC = "generic"

_PIXEL_MARKERS = (".gif", ".png", "/pixel", "/px", "/b.gif", "/beacon",
                  "/imp", "/impression", "/track.gif", "/p.gif", "/1x1")
_ANALYTICS_MARKERS = ("/collect", "/analytics", "/batch", "/event", "/events",
                      "/track", "/stats", "/telemetry", "/log", "/metrics",
                      "/v1/t", "/j/collect", "/g/collect", "/i/adsct")
_AD_MARKERS = ("/ad", "/ads", "/adx", "/bid", "/rtb", "/openrtb", "/pagead",
               "/adserver", "/prebid", "/vast", "/gampad", "/doubleclick")
_CONSENT_MARKERS = ("/consent", "/cmp", "/gdpr", "/tcf", "/privacy")
_CONFIG_MARKERS = ("/config", "/settings", "/init", "/bootstrap", "/sdk")


def classify_beacon(path: str, query: str = "") -> str:
    """Which family of reply does this request expect?

    Path-shape only. Deliberately NOT dependent on the Host header: the same
    beacon endpoint is reachable under many hostnames (and under a CNAME
    cloak), and keying off host would make the reply differ depending on which
    alias was used — a self-inconsistency of exactly the kind this module
    exists to avoid.
    """
    p = (path or "/").lower()
    blob = f"{p}?{(query or '').lower()}"

    for m in _PIXEL_MARKERS:
        if m in p:
            return FAMILY_PIXEL
    for m in _CONSENT_MARKERS:
        if m in blob:
            return FAMILY_CONSENT
    for m in _ANALYTICS_MARKERS:
        if m in blob:
            return FAMILY_ANALYTICS
    for m in _AD_MARKERS:
        if m in blob:
            return FAMILY_AD
    for m in _CONFIG_MARKERS:
        if m in blob:
            return FAMILY_CONFIG
    return FAMILY_GENERIC


@dataclass(frozen=True)
class Reply:
    status: int
    headers: dict
    body: bytes
    family: str

    def json_body(self) -> Optional[dict]:
        try:
            return json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None


def _persona_block(p: Persona) -> dict:
    """The persona fields a beacon reply might echo back.

    ONE function, used by every family. That is the whole consistency
    mechanism: there is no second place where a locale or timezone could be
    produced, so no two families can disagree about them.
    """
    return {
        "id": p.advertising_id,
        "locale": p.locale,
        "lang": p.languages[0],
        "tz": p.timezone,
        "tz_offset": p.std_utc_offset_minutes,
        "country": p.country,
        "screen": {"w": p.screen_width, "h": p.screen_height,
                   "aw": p.avail_width, "ah": p.avail_height,
                   "depth": p.color_depth, "dpr": p.pixel_ratio},
        "cores": p.hardware_concurrency,
        "mem": p.device_memory,
        "platform": p.platform,
        # Coarse geo (city-level, from the SAME persona row as tz/country --
        # see persona.py) and OS/browser hints. Every field below still comes
        # from this one Persona object, so adding them cannot introduce a
        # second source of truth for any beacon family to disagree through.
        "geo": {"region": p.region, "city": p.city, "lat": p.lat, "lon": p.lon},
        "os": {"name": p.os_name, "version": p.os_version},
        "browser": {"name": p.browser, "version": p.browser_version},
    }


def build_reply(method: str, path: str, query: str = "",
                headers: Optional[dict] = None,
                persona: Optional[Persona] = None) -> Reply:
    """Pure: produce the reply for one intercepted beacon.

    No sockets, no clock, no randomness. Given the same request and persona
    this returns byte-identical output — which is both what makes it testable
    and what makes the lie stable across sessions.
    """
    p = persona if persona is not None else current_persona()
    fam = classify_beacon(path, query)
    pb = _persona_block(p)

    common = {
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
        # No Server header naming Valkyrie: identifying the deception endpoint
        # would hand back the exact "runs a blocker" signal this removes.
        "Server": "nginx",
    }

    if fam == FAMILY_PIXEL:
        h = dict(common)
        h["Content-Type"] = "image/gif"
        h["Content-Length"] = str(len(_PIXEL_GIF))
        return Reply(200, h, _PIXEL_GIF, fam)

    if fam == FAMILY_ANALYTICS:
        # Analytics collectors overwhelmingly return a tiny ack. 200 + a small
        # JSON ack is the common shape; the persona travels in it so a
        # collector that stores the echo stores a consistent story.
        body = {"status": "ok", "received": 1, "client": pb}
        return _json_reply(200, common, body, fam)

    if fam == FAMILY_AD:
        # A no-fill is the single most common real ad response, and it is fully
        # benign: nothing renders, no creative is fetched, and the exchange
        # treats it as ordinary inventory with no demand. Critically it is NOT
        # an error — an error would look like interference.
        body = {"id": pb["id"], "seatbid": [], "nbr": 3,
                "cur": "USD", "ext": {"client": pb}}
        return _json_reply(200, common, body, fam)

    if fam == FAMILY_CONSENT:
        # Report consent DENIED, coherently. This is the one place the lie is
        # also the user's actual preference, so it costs nothing to be honest.
        body = {"gdprApplies": True, "hasGlobalScope": False,
                "tcString": "", "purposeConsents": {}, "vendorConsents": {},
                "eventStatus": "useractioncomplete", "cmpStatus": "loaded",
                "client": {"country": pb["country"], "locale": pb["locale"]}}
        return _json_reply(200, common, body, fam)

    if fam == FAMILY_CONFIG:
        # An SDK asking for config gets a valid config that switches everything
        # off. A malformed/empty config often makes SDKs retry in a loop, which
        # is noisy and itself anomalous.
        body = {"enabled": False, "sampleRate": 0, "flushIntervalMs": 86400000,
                "endpoints": {}, "features": {}, "client": pb}
        return _json_reply(200, common, body, fam)

    # Generic: a plain 200 with a minimal ack. Not 404 — a 404 for every path
    # on a host that resolves is anomalous, and not 204 either, because some
    # SDKs treat an empty body as a transport failure and retry.
    return _json_reply(200, common, {"status": "ok", "client": pb}, FAMILY_GENERIC)


def _json_reply(status: int, common: dict, body: dict, fam: str) -> Reply:
    raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    h = dict(common)
    h["Content-Type"] = "application/json"
    h["Content-Length"] = str(len(raw))
    return Reply(status, h, raw, fam)


# ---------------------------------------------------------------------------
# The server. A thin shell over build_reply().
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    # Speak HTTP/1.1 so keep-alive works; a server that closes every connection
    # is unusual enough to be noticeable.
    protocol_version = "HTTP/1.1"
    server_version = "nginx"
    sys_version = ""

    def _respond(self, method: str) -> None:
        parsed = urlparse(self.path or "/")
        persona = getattr(self.server, "persona_override", None)
        reply = build_reply(method, parsed.path, parsed.query,
                            dict(self.headers), persona)

        # Drain any request body so keep-alive stays in sync. Beacons very
        # often POST; leaving the body unread desynchronises the connection and
        # the next request on it fails, which looks like a broken server.
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            n = 0
        if n > 0:
            try:
                self.rfile.read(min(n, 1 << 20))
            except OSError:
                pass

        self.send_response(reply.status)
        for k, v in reply.headers.items():
            self.send_header(k, v)
        self.end_headers()
        if method != "HEAD":
            try:
                self.wfile.write(reply.body)
            except OSError:
                pass

    def do_GET(self):     self._respond("GET")        # noqa: E704
    def do_POST(self):    self._respond("POST")       # noqa: E704
    def do_HEAD(self):    self._respond("HEAD")       # noqa: E704
    def do_PUT(self):     self._respond("PUT")        # noqa: E704
    def do_OPTIONS(self):
        # CORS-preflight: beacons are cross-origin by nature. Refusing the
        # preflight makes the real request never fire, which is a block again.
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        # Never write beacon URLs to a log. Recording what the user's software
        # tried to phone home about would recreate the tracking database this
        # is meant to starve.
        return


class DeceptionEndpoint:
    """Loopback HTTP server that answers intercepted beacons."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8181,
                 persona: Optional[Persona] = None):
        if host not in ("127.0.0.1", "localhost", "::1"):
            # Binding this off-loopback would turn a private deception surface
            # into a service other machines can query and fingerprint.
            raise ValueError(f"deception endpoint must bind loopback, got {host!r}")
        self._host, self._port = host, port
        self._persona = persona
        self._srv: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def port(self) -> int:
        return self._srv.server_address[1] if self._srv else self._port

    @property
    def running(self) -> bool:
        return self._srv is not None and self._thread is not None \
            and self._thread.is_alive()

    def start(self) -> bool:
        if self._srv is not None:
            return True
        try:
            self._srv = ThreadingHTTPServer((self._host, self._port), _Handler)
        except OSError:
            self._srv = None
            return False                      # port taken: caller falls back
        self._srv.persona_override = self._persona    # type: ignore[attr-defined]
        self._srv.daemon_threads = True
        self._thread = threading.Thread(target=self._srv.serve_forever,
                                        kwargs={"poll_interval": 0.2},
                                        daemon=True, name="valkyrie-deception")
        self._thread.start()
        return True

    def stop(self) -> None:
        if self._srv is not None:
            try:
                self._srv.shutdown()
                self._srv.server_close()
            except OSError:
                pass
        self._srv = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._thread = None
