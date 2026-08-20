"""mitmproxy addon — runs inside the mitmproxy worker process.

Intercepts every HTTPS request after TLS termination and applies the same
decision pipeline as the DNS path (blocklist / behavioral / user rules),
plus HTTPS-specific tracker detection: tracking pixels, fingerprinting
scripts, and large-body POSTs to known tracker domains (likely exfil).

Tracking query parameters are stripped from the URL before the request is
forwarded upstream.

The response() hook cleans HTML pages: removes tracking scripts and pixels,
neutralises inline analytics calls, injects fingerprint-protection JS, and
strips tracking query parameters from all href/src attributes.

This module is loaded by mitmproxy via `mitmdump -s tls_addon.py`
(see tls_inspector.py), so it talks to the rest of Valkyrie only through
the Store — it does not import the DNS/behavioral engines directly to
keep mitmproxy's subprocess lightweight and independently restartable.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from .config import (
    BEHAVIORAL_BLOCK_SCORE,
    EXFIL_BODY_SIZE_BYTES,
    FINGERPRINT_PROTECTION,
    FINGERPRINT_URL_PATTERNS,
    MAX_RESPONSE_PROCESS_SIZE,
    RESPONSE_CACHE_TTL,
    STRIP_PARAMS,
    TRACKER_SLDS,
    TRACKER_URL_PATTERNS,
    TRACKING_QUERY_PARAMS,
    TRACKING_SCRIPT_DOMAINS,
)
from . import farble, nyx
from .store import DnsEvent, Store

# 1x1 transparent PNG — returned for suppressed tracking pixels
_TRANSPARENT_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
    b"\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01"
    b"\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)

# Fingerprint protection now comes from farble.py, which generates a DIFFERENT
# script per origin per session. The constant-valued snippet that used to live
# here was actively counterproductive: every user returned the same fake canvas
# hash, the same empty plugin list, the same colour depth — values no real
# browser reports, identical across every site and session, which is precisely
# the durable cross-site identifier the feature exists to prevent. See the
# module docstring in farble.py for the full reasoning.

# Inline analytics keywords that trigger neutralisation
_INLINE_TRACKERS = [
    "fbq(", "gtag(", "_gaq", "ga(",
    "analytics.track", "mixpanel.track",
    "amplitude.getInstance", "heap.track",
    "hj(", "_satellite",
]

# Replacement that neutralises inline tracker calls while keeping the tag
_INLINE_REPLACEMENT = (
    b"window.fbq=function(){};"
    b"window.gtag=function(){};"
    b"window.ga=function(){};"
    b"window._gaq={push:function(){}};"
)

# Regex patterns (compiled once at import time)
_RE_SCRIPT_SRC     = re.compile(
    rb'<script\b[^>]*\bsrc=["\']([^"\']*)["\'][^>]*>.*?</script>',
    re.IGNORECASE | re.DOTALL,
)
_RE_SCRIPT_INLINE  = re.compile(
    rb'<script\b[^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)
_RE_IMG_PIXEL      = re.compile(
    rb'<img\b[^>]*/?>',
    re.IGNORECASE,
)
_RE_HEAD_OPEN      = re.compile(rb'<head\b[^>]*>', re.IGNORECASE)
_RE_BODY_CLOSE     = re.compile(rb'</body\s*>', re.IGNORECASE)
_RE_ATTR_URL       = re.compile(
    rb'((?:href|src|action)=["\'])([^"\']+)(["\'])',
    re.IGNORECASE,
)


def _strip_url_params(url: str, params_to_strip: list[str]) -> str:
    """Remove specific query parameters from any URL string."""
    parts = urlsplit(url)
    if not parts.query:
        return url
    kept = [
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower() not in params_to_strip
    ]
    new_query = urlencode(kept)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _strip_tracking_params(url: str) -> str:
    """Remove known tracking query parameters from a URL."""
    parts = urlsplit(url)
    if not parts.query:
        return url
    kept = [
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not any(k.lower() == p or k.lower().startswith(p) for p in TRACKING_QUERY_PARAMS)
    ]
    new_query = urlencode(kept)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _is_tracker_path(path: str) -> bool:
    lower = path.lower()
    return any(p in lower for p in TRACKER_URL_PATTERNS)


def _is_fingerprint_path(path: str) -> bool:
    lower = path.lower()
    return any(p in lower for p in FINGERPRINT_URL_PATTERNS)


class ValkyrieAddon:
    """mitmproxy addon class — methods are mitmproxy event hooks."""

    def __init__(self, store: Store, blocklist=None, behavioral=None, rules=None,
                 threat_intel=None) -> None:
        self.store           = store
        self.blocklist       = blocklist
        self.behavioral      = behavioral
        self.rules           = rules
        self.threat_intel    = threat_intel
        self.intercept_count = 0
        # response cache: url → (expiry_time, cleaned_bytes | None)
        self._resp_cache: dict[str, tuple[float, bytes | None]] = {}

    # ------------------------------------------------------------------
    # mitmproxy hooks
    # ------------------------------------------------------------------

    def request(self, flow) -> None:
        try:
            self._handle_request(flow)
        except Exception:
            pass    # never let an addon bug break the user's browsing

    def response(self, flow) -> None:
        """Clean tracking elements from HTTP responses (HTML/JS/images)."""
        try:
            self._handle_response(flow)
        except Exception:
            pass

    def _handle_response(self, flow) -> None:
        resp = flow.response
        if resp is None:
            return
        size = len(resp.content)
        if size > MAX_RESPONSE_PROCESS_SIZE:
            return

        url = flow.request.pretty_url
        ct  = resp.headers.get("content-type", "").lower()

        # Cache check
        cached = self._resp_cache.get(url)
        if cached is not None:
            expiry, body = cached
            if time.monotonic() < expiry:
                if body is not None:
                    resp.content = body
                return
        # Evict stale entries lazily (keep cache small)
        if len(self._resp_cache) > 2000:
            now = time.monotonic()
            self._resp_cache = {k: v for k, v in self._resp_cache.items() if v[0] > now}

        t0 = time.monotonic()
        result: bytes | None = None

        if "text/html" in ct:
            result = self._clean_html(flow)
        elif "javascript" in ct:
            result = self._check_script(flow)
        elif "image" in ct:
            result = self._check_pixel(flow)

        elapsed_ms = (time.monotonic() - t0) * 1000
        if elapsed_ms > 50:
            # Processing took too long — cache a None (passthrough) for this URL
            self._resp_cache[url] = (time.monotonic() + RESPONSE_CACHE_TTL, None)
            return

        if result is not None:
            resp.content = result
            self._resp_cache[url] = (time.monotonic() + RESPONSE_CACHE_TTL, result)
        else:
            self._resp_cache[url] = (time.monotonic() + RESPONSE_CACHE_TTL, None)

    def _handle_request(self, flow) -> None:
        req    = flow.request
        domain = req.pretty_host
        path   = req.path or "/"
        url    = req.pretty_url
        proc   = self._process_name(flow)

        self.intercept_count += 1

        # 1. User rules — always_allow wins outright
        if self.rules is not None and self.rules.get().is_always_allowed(domain, proc):
            self._strip_params(flow)
            return

        # 2. User rules — always_block
        if self.rules is not None and self.rules.get().is_always_blocked(domain, proc):
            self._block(flow, domain, url, proc, "user rule: always_block", category="rule_block")
            return

        # 3. Threat-intel FULL-URL match (path-level). Checked before the
        # domain blocklist because it is the more specific verdict and the
        # only one that can act on malware hosted at one path of an otherwise
        # legitimate, compromised site — where blocking the whole domain
        # would be the false positive. This seam exists only here: DNS never
        # sees a path, so a URL indicator is unreachable without TLS
        # inspection.
        if self.threat_intel is not None:
            hit = self.threat_intel.match_url(url)
            if hit is not None:
                self._block(flow, domain, url, proc,
                            f"malware URL ({hit.feed}: {hit.category})",
                            category="threat_intel_url")
                return

        # 4. Blocklist
        if self.blocklist is not None and self.blocklist.is_blocked(domain):
            self._block(flow, domain, url, proc, "domain on blocklist", category="blocked")
            return

        # 5. Behavioral score
        if self.behavioral is not None:
            should_block, score, reason = self.behavioral.should_block(domain, proc)
            if should_block and score >= BEHAVIORAL_BLOCK_SCORE:
                self._block(flow, domain, url, proc, reason or "behavioral score", category="behavioral")
                return

        # 6. Tracking pixel / beacon paths
        if _is_tracker_path(path):
            self._block(flow, domain, url, proc, f"tracking pixel/beacon path: {path}", category="tracker_pixel")
            return

        # 7. Fingerprinting scripts
        if _is_fingerprint_path(path):
            self._block(flow, domain, url, proc, f"fingerprinting script: {path}", category="fingerprint")
            return

        # 8. Data exfiltration heuristic — large POST body to a flagged domain
        if req.method == "POST":
            body_len = len(req.raw_content or b"")
            if body_len > EXFIL_BODY_SIZE_BYTES and (
                (self.blocklist is not None and self.blocklist.is_blocked(domain))
                or _is_tracker_path(path)
            ):
                self._block(flow, domain, url, proc,
                             f"large POST ({body_len}B) to tracker — possible exfil",
                             category="exfil")
                return

        # 8.5 Nyx — SEE & REPORT (observe-only). Read the raw request and note
        # any personal data (device ID, location, contact, fingerprint bundle)
        # crossing to a third party. This never touches the flow and never
        # blocks — it only records what left, so the user can be told. Blocking
        # or lying on outbound theft is a deliberate later slice.
        self._nyx_observe(flow, domain, url, proc)

        # 9. Allowed — strip tracking params and log
        self._strip_params(flow)
        self._log(domain, url, proc, "allowed", "", category="https")

    def _nyx_observe(self, flow, domain: str, url: str, proc: str) -> None:
        """Log Nyx's outbound-data observations. Fully guarded: a parser bug
        here must never break browsing nor derail the request pipeline."""
        try:
            req = flow.request
            observations = nyx.inspect_outbound(
                method=req.method,
                url=url,
                headers=dict(req.headers),
                body=req.raw_content or b"",
            )
            for ob in observations:
                self._log(domain, url, proc, "flagged", ob.sentence,
                          category="nyx_leak")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Response processors
    # ------------------------------------------------------------------

    def _clean_html(self, flow) -> bytes | None:
        """Remove tracking scripts/pixels from an HTML response body."""
        domain  = flow.request.pretty_host
        content = flow.response.content
        removed = 0
        # The farbling script is derived per-ORIGIN, so the page's own origin
        # has to reach the injectors. Two different sites must receive two
        # different scripts — that difference is the entire mechanism that
        # stops them correlating the same user (see farble.py).
        origin = farble.origin_of(flow.request.pretty_url)

        try:
            cleaned = self._clean_html_lxml(content, origin)
            if cleaned is not None:
                removed_count = cleaned[1]
                body = cleaned[0]
            else:
                body, removed_count = self._clean_html_regex(content, domain, origin)
        except Exception:
            body, removed_count = self._clean_html_regex(content, domain, origin)

        removed = removed_count

        if removed > 0:
            self._log(domain, flow.request.pretty_url,
                      self._process_name(flow), "cleaned",
                      f"tracking content removed ({removed} elements)",
                      "page_clean")
        return body

    def _clean_html_lxml(self, content: bytes, origin: str = "") -> tuple[bytes, int] | None:
        """Parse with lxml for precise element removal. Returns (body, count) or None."""
        try:
            from lxml import html as lhtml
            from lxml import etree
        except ImportError:
            return None

        try:
            tree = lhtml.fromstring(content)
        except Exception:
            return None

        removed = 0

        # Remove external tracking scripts
        for script in tree.xpath('//script[@src]'):
            src = script.get('src', '')
            if any(d in src for d in TRACKING_SCRIPT_DOMAINS):
                parent = script.getparent()
                if parent is not None:
                    parent.remove(script)
                    removed += 1

        # Neutralise inline scripts containing tracker calls
        for script in tree.xpath('//script[not(@src)]'):
            text = script.text or ''
            if any(kw in text for kw in _INLINE_TRACKERS):
                script.text = _INLINE_REPLACEMENT.decode()
                removed += 1

        # Remove 1x1 tracking pixels
        for img in tree.xpath('//img'):
            w = img.get('width', '').strip()
            h = img.get('height', '').strip()
            src = img.get('src', '').lower()
            if (w == '1' and h == '1') or any(
                kw in src for kw in ('pixel', 'beacon', 'track', 'collect', '1x1')
            ):
                parent = img.getparent()
                if parent is not None:
                    parent.remove(img)
                    removed += 1

        # Strip tracking params from href/src attributes
        for el in tree.xpath('//*[@href or @src or @action]'):
            for attr in ('href', 'src', 'action'):
                val = el.get(attr)
                if val:
                    cleaned_url = _strip_url_params(val, STRIP_PARAMS)
                    if cleaned_url != val:
                        el.set(attr, cleaned_url)

        # Inject fingerprint protection at start of <head>. Must be FIRST so
        # it patches the surfaces before any page script can read them.
        if FINGERPRINT_PROTECTION:
            heads = tree.xpath('//head')
            if heads:
                try:
                    fp_el = lhtml.fragment_fromstring(
                        farble.script_for(origin).decode())
                    heads[0].insert(0, fp_el)
                except Exception:
                    pass

        # Add removal comment before </body>
        bodies = tree.xpath('//body')
        if bodies and removed > 0:
            comment = etree.Comment(f" Valkyrie: {removed} elements removed ")
            bodies[0].append(comment)

        try:
            result = lhtml.tostring(tree, encoding='unicode').encode('utf-8')
        except Exception:
            result = lhtml.tostring(tree)

        return result, removed

    def _clean_html_regex(self, content: bytes, domain: str,
                          origin: str = "") -> tuple[bytes, int]:
        """Regex fallback when lxml is unavailable."""
        body   = content
        removed = 0

        # Remove external tracking scripts
        def _rm_script_src(m: re.Match) -> bytes:
            nonlocal removed
            src = m.group(1).decode(errors='replace')
            if any(d in src for d in TRACKING_SCRIPT_DOMAINS):
                removed += 1
                return b''
            return m.group(0)
        body = _RE_SCRIPT_SRC.sub(_rm_script_src, body)

        # Neutralise inline scripts
        def _neutralise_inline(m: re.Match) -> bytes:
            nonlocal removed
            inner = m.group(1).decode(errors='replace')
            if any(kw in inner for kw in _INLINE_TRACKERS):
                removed += 1
                return b'<script>' + _INLINE_REPLACEMENT + b'</script>'
            return m.group(0)
        body = _RE_SCRIPT_INLINE.sub(_neutralise_inline, body)

        # Remove 1x1 pixels
        def _rm_pixel(m: re.Match) -> bytes:
            nonlocal removed
            tag = m.group(0).decode(errors='replace')
            src = ''
            wm = re.search(r'width=["\'](\d+)["\']', tag, re.IGNORECASE)
            hm = re.search(r'height=["\'](\d+)["\']', tag, re.IGNORECASE)
            sm = re.search(r'src=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if sm:
                src = sm.group(1).lower()
            is_pixel = (
                (wm and wm.group(1) == '1' and hm and hm.group(1) == '1')
                or any(kw in src for kw in ('pixel', 'beacon', 'track', 'collect', '1x1'))
            )
            if is_pixel:
                removed += 1
                return b''
            return m.group(0)
        body = _RE_IMG_PIXEL.sub(_rm_pixel, body)

        # Strip tracking params from attribute URLs
        def _strip_attr(m: re.Match) -> bytes:
            prefix = m.group(1)
            url    = m.group(2).decode(errors='replace')
            suffix = m.group(3)
            cleaned_url = _strip_url_params(url, STRIP_PARAMS)
            return prefix + cleaned_url.encode() + suffix
        body = _RE_ATTR_URL.sub(_strip_attr, body)

        # Inject fingerprint protection after <head>
        if FINGERPRINT_PROTECTION:
            fp = farble.script_for(origin)
            body = _RE_HEAD_OPEN.sub(lambda m: m.group(0) + fp, body, count=1)

        # Add removal comment before </body>
        if removed > 0:
            comment = f'<!-- Valkyrie: {removed} elements removed -->'.encode()
            body = _RE_BODY_CLOSE.sub(lambda m: comment + m.group(0), body, count=1)

        return body, removed

    def _check_script(self, flow) -> bytes | None:
        """Replace tracker JS files with empty stub."""
        domain = flow.request.pretty_host
        sld    = domain.split('.')[-2] if '.' in domain else domain
        if sld in TRACKER_SLDS:
            self._log(domain, flow.request.pretty_url,
                      self._process_name(flow), "blocked",
                      f"tracker JS blocked: {domain}", "tracker_js")
            return b"/* Blocked by Valkyrie */"
        return None

    def _check_pixel(self, flow) -> bytes | None:
        """Replace tiny tracking images with transparent PNG stub."""
        domain  = flow.request.pretty_host
        url     = flow.request.pretty_url.lower()
        sld     = domain.split('.')[-2] if '.' in domain else domain
        content = flow.response.content
        is_pixel_domain = sld in TRACKER_SLDS
        is_pixel_url    = any(kw in url for kw in ('pixel', 'beacon'))
        if len(content) < 200 and (is_pixel_domain or is_pixel_url):
            self._log(domain, flow.request.pretty_url,
                      self._process_name(flow), "blocked",
                      f"tracking pixel suppressed: {domain}", "tracker_pixel")
            return _TRANSPARENT_PNG
        return None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _strip_params(self, flow) -> None:
        cleaned = _strip_url_params(flow.request.pretty_url, TRACKING_QUERY_PARAMS)
        if cleaned != flow.request.pretty_url:
            parts = urlsplit(cleaned)
            flow.request.path = urlunsplit(("", "", parts.path, parts.query, parts.fragment)) or "/"

    def _block(self, flow, domain: str, url: str, proc: str, reason: str, category: str) -> None:
        from mitmproxy import http
        flow.response = http.Response.make(
            403, b"Blocked by Valkyrie", {"Content-Type": "text/plain"}
        )
        self._log(domain, url, proc, "blocked", reason, category=category)

    def _log(self, domain: str, url: str, proc: str, decision: str, reason: str, category: str) -> None:
        event = DnsEvent.now(
            domain       = domain,
            decision     = decision,
            process_name = proc or "unknown",
            process_pid  = 0,
            process_path = "",
            reason       = reason,
            suspicion    = 0.9 if decision == "blocked" else 0.0,
            raw_category = category,
            url          = url,
        )
        self.store.log(event)

    @staticmethod
    def _process_name(flow) -> str:
        # mitmproxy doesn't expose the originating OS process by default
        # (would require a transparent-mode + psutil socket lookup); we
        # fall back to the client's address as a coarse identifier.
        try:
            return flow.client_conn.peername[0]
        except Exception:
            return "unknown"


def load(loader) -> None:  # pragma: no cover — mitmproxy entrypoint convention
    pass
