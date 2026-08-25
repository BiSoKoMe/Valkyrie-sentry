"""Site content analyzer - Valkyrie genuinely *reads the page*, not a list.

The DNS layer judges a domain by its NAME and behaviour (tracker SLDs, DGA
structure, query-stream shape). Powerful, but it never looks at what the site
actually *contains*. This module is the missing half: fetch the page and score
the real content - the same way a human analyst decides "this site is sketchy"
by looking at what it loads and runs, not by checking a blocklist.

It scores genuine, list-free content signals:

  * **Cryptomining** - in-browser miner signatures (CoinHive/CryptoNight/WASM
    hashers).
  * **Browser fingerprinting** - canvas/WebGL/AudioContext/font-enumeration/
    hardware-probe techniques. One is normal; several *together* is the
    signature of a fingerprinting library.
  * **Obfuscated / packed JavaScript** - eval-packers, `eval(atob(...))`,
    `String.fromCharCode` chains, `document.write(unescape(...))` - the shapes
    malware uses to hide payloads.
  * **Credential harvesting / phishing** - a password field whose form posts to
    a DIFFERENT origin, or a brand impersonated by an unrelated domain.
  * **Tracker density** - how many distinct third-party hosts the page pulls
    from (behavioural ad-tech signature, no name list needed).
  * **Hidden cross-origin iframes** - 0-size/invisible frames to another origin.

The SCORER (`analyze_content`) is pure and unit-tested against real page shapes.
The FETCH (`SiteAnalyzer.analyze_url`) is a thin, isolated, opt-in layer over
httpx with tight timeouts, a size cap, and a cache - because fetching is slow
and makes Valkyrie's own requests, it never runs on the DNS hot path.

Honest boundaries (see ADR 0034):
  * **Static, not dynamic.** It reads the delivered HTML + inline JS; it does
    not execute JavaScript, so payloads assembled at runtime or pulled lazily
    can be missed.
  * **Cloaking beats it.** A site can serve benign content to Valkyrie's fetcher
    and malware to real browsers (bot detection). Static fetch can't defeat that.
  * **It complements, never replaces** the name/behaviour layers - it is one
    more genuine signal, precision-tuned so a normal site scores clean.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


@dataclass
class ContentVerdict:
    decision: str                       # "allow" | "flag" | "block"
    score: float                        # 0.0 - 1.0
    category: str = "clean"             # miner|phishing|malware|fingerprinting|tracker|clean
    reasons: list = field(default_factory=list)
    signals: dict = field(default_factory=dict)
    fetched: bool = True


# Decision thresholds (mirror the DNS scanner's precision-first posture).
BLOCK = 0.70
FLAG = 0.40


# --- helpers ---

def _registrable(host: str) -> str:
    parts = (host or "").lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")


def _host_of(url: str) -> str:
    try:
        return (urlparse(url if "//" in url else "//" + url).hostname or "").lower()
    except Exception:
        return ""


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_ATTR_URL = re.compile(r'(?:src|href|action|data-src)\s*=\s*["\']([^"\']+)["\']', re.I)
_SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)
_PASSWORD = re.compile(r'<input\b[^>]*type\s*=\s*["\']?password', re.I)
_FORM_ACTION = re.compile(r'<form\b[^>]*action\s*=\s*["\']([^"\']+)["\']', re.I)
_IFRAME = re.compile(r"<iframe\b[^>]*>", re.I)
_META_REFRESH = re.compile(r'<meta\b[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*'
                           r'content\s*=\s*["\'][^"\']*url=([^"\';]+)', re.I)


def third_party_hosts(html: str, page_host: str) -> set:
    """Distinct third-party registrable domains the page references. Pure."""
    base = _registrable(page_host)
    out: set = set()
    for u in _ATTR_URL.findall(html):
        h = _host_of(u)
        if h and _registrable(h) != base:
            out.add(_registrable(h))
    return out


# --- content signal detectors (each returns (score, reason) ) ---

_MINER_SIGNS = ("coinhive", "coin-hive", "cryptonight", "crypto-loot", "cryptoloot",
                "jsecoin", "minero", "webminepool", "deepminer", "coinimp",
                "authedmine", "hashvault", "stratum+tcp", "cryptonoter",
                "hashespersecond", "throttlemine")


def _sig_cryptominer(low: str) -> tuple:
    hits = [s for s in _MINER_SIGNS if s in low]
    if hits:
        return 0.9, f"in-browser cryptominer signature ({hits[0]})"
    # WASM miner heuristic: wasm + a hashing loop hint together.
    if "webassembly" in low and ("hashrate" in low or "0x" in low and "cryptonight" in low):
        return 0.7, "WASM cryptomining pattern"
    return 0.0, ""


def _fingerprint_techniques(low: str) -> list:
    tech = []
    if "todataurl" in low and ("filltext" in low or "getimagedata" in low):
        tech.append("canvas")
    if "unmasked_renderer" in low or "webgl_debug_renderer_info" in low:
        tech.append("webgl")
    if "createdynamicscompressor" in low or ("createoscillator" in low and "createanalyser" in low):
        tech.append("audio")
    if "measuretext" in low and low.count("measuretext") >= 3:
        tech.append("font-enum")
    if "hardwareconcurrency" in low and "devicememory" in low:
        tech.append("hardware-probe")
    if "navigator.plugins" in low and "navigator.mimetypes" in low:
        tech.append("plugin-enum")
    return tech


def _sig_fingerprinting(low: str) -> tuple:
    tech = _fingerprint_techniques(low)
    n = len(tech)
    if n >= 3:
        return 0.7, f"browser fingerprinting ({n} techniques: {', '.join(tech)})"
    if n == 2:
        return 0.45, f"browser fingerprinting ({', '.join(tech)})"
    return 0.0, ""


def _sig_obfuscation(text: str, low: str) -> tuple:
    reasons = []
    score = 0.0
    if "eval(function(p,a,c,k,e,d)" in low.replace(" ", ""):
        # A packer alone is only flag-worthy - legit sites minify/pack too.
        score = max(score, 0.55); reasons.append("packed/obfuscated JS (Dean-Edwards packer)")
    if "eval(atob(" in low.replace(" ", "") or "eval(window.atob(" in low.replace(" ", ""):
        # Decode-and-execute a base64 blob: a strong malware tell, rarely benign.
        score = max(score, 0.7); reasons.append("base64-decoded eval payload (eval(atob()))")
    if low.count("string.fromcharcode") >= 4:
        score = max(score, 0.45); reasons.append("String.fromCharCode obfuscation")
    if "document.write(unescape(" in low.replace(" ", ""):
        score = max(score, 0.45); reasons.append("document.write(unescape()) obfuscation")
    # NOTE: a standalone large high-entropy base64 token is deliberately NOT a
    # signal - legit minified/bundled JS and inlined data-URI assets look
    # identical, and it mislabelled real sites (e.g. cnn.com) as malware. The
    # dangerous case (decode AND execute) is already caught by eval(atob()).
    return score, "; ".join(reasons)


_BRANDS = ("paypal", "microsoft", "apple", "amazon", "netflix", "google",
           "facebook", "instagram", "coinbase", "binance", "metamask", "wallet",
           "bankofamerica", "wellsfargo", "chase", "outlook", "office365")


def _sig_phishing(text: str, low: str, page_host: str) -> tuple:
    base = _registrable(page_host)
    # A password field whose form posts to a DIFFERENT origin = credential theft.
    if _PASSWORD.search(text):
        for action in _FORM_ACTION.findall(text):
            ah = _host_of(action)
            if ah and _registrable(ah) != base:
                return 0.8, f"password form posts cross-origin to {ah}"
        # Brand impersonation: page sells itself as a big brand from an unrelated
        # domain, and asks for a password.
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        if m:
            title = m.group(1).lower()
        brand = next((b for b in _BRANDS if b in title or b in low[:4000]), "")
        if brand and brand not in base:
            return 0.6, f"brand impersonation: '{brand}' on unrelated domain + login form"
    return 0.0, ""


def _sig_hidden_iframe(text: str, page_host: str) -> tuple:
    base = _registrable(page_host)
    for tag in _IFRAME.findall(text):
        tl = tag.lower()
        hidden = ("display:none" in tl.replace(" ", "") or "visibility:hidden" in tl.replace(" ", "")
                  or 'width="0"' in tl or "width:0" in tl.replace(" ", "")
                  or 'height="0"' in tl or "height:0" in tl.replace(" ", ""))
        m = re.search(r'src\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        src_host = _host_of(m.group(1)) if m else ""
        if hidden and src_host and _registrable(src_host) != base:
            return 0.2, f"hidden cross-origin iframe to {src_host}"
    return 0.0, ""


def _sig_meta_redirect(text: str, page_host: str) -> tuple:
    base = _registrable(page_host)
    m = _META_REFRESH.search(text)
    if m:
        dst = _host_of(m.group(1))
        if dst and _registrable(dst) != base:
            return 0.2, f"immediate meta-refresh redirect to {dst}"
    return 0.0, ""


def analyze_content(html: str, url: str) -> ContentVerdict:
    """Score a page's ACTUAL CONTENT. Pure - no network. This is the analyst's
    eye: what does the page load and run, regardless of its name."""
    text = html or ""
    low = text.lower()
    page_host = _host_of(url)

    reasons: list = []
    signals: dict = {}
    # Strong, near-verdict signals take the max; weaker ones accumulate.
    strong = 0.0
    weak = 0.0
    category = "clean"

    def _strong(s, r, cat):
        nonlocal strong, category
        if s > strong:
            strong = s
            category = cat
        if r:
            reasons.append(r)

    s, r = _sig_cryptominer(low); signals["cryptominer"] = s
    if s:
        _strong(s, r, "miner")
    s, r = _sig_phishing(text, low, page_host); signals["phishing"] = s
    if s:
        _strong(s, r, "phishing")
    s, r = _sig_fingerprinting(low); signals["fingerprinting"] = s
    if s:
        _strong(s, r, "fingerprinting")
    s, r = _sig_obfuscation(text, low); signals["obfuscation"] = s
    if s:
        _strong(s, r, "malware")

    # Tracker density - behavioural ad-tech signature. Graduated so ordinary
    # ad-supported sites (a handful of third parties) stay allow-with-a-note and
    # only genuinely tracker-heavy pages (15+) reach a flag on density alone.
    # Density is INFORMATIONAL - it annotates the category and contributes a
    # capped weak score, but never flags a page on its own (a site's own CDN
    # domains count as "third party" here, so density alone is too noisy to
    # block/flag). The strong content signals do the flagging.
    tp = third_party_hosts(text, page_host)
    signals["third_parties"] = len(tp)
    if len(tp) >= 25:
        weak += 0.3; reasons.append(f"{len(tp)} distinct third-party hosts (very tracker-heavy)")
    elif len(tp) >= 15:
        weak += 0.2; reasons.append(f"{len(tp)} distinct third-party hosts (tracker-heavy)")
    elif len(tp) >= 8:
        weak += 0.1; reasons.append(f"{len(tp)} distinct third-party hosts")

    for det in (_sig_hidden_iframe, _sig_meta_redirect):
        s, r = det(text, page_host)
        if s:
            weak += s
            reasons.append(r)

    # Combine: a strong content verdict dominates; weak signals add at full
    # weight on their own but only half-weight on top of a strong verdict (so
    # they can tip a clean page to flag, but don't inflate an already-strong one).
    score = min(1.0, strong + weak * (0.5 if strong else 1.0))

    if score >= BLOCK:
        decision = "block"
    elif score >= FLAG:
        decision = "flag"
    else:
        decision = "allow"
    # Category must reflect the verdict: a page pushed to flag/block by the weak
    # privacy signals (no strong content verdict) is "tracker" when third-party
    # density drove it, else a generic "suspicious" - never "clean".
    if category == "clean":
        if len(tp) >= 8:
            category = "tracker"
        elif decision != "allow":
            category = "suspicious"

    return ContentVerdict(decision=decision, score=round(score, 3),
                          category=category, reasons=reasons, signals=signals)


# --- fetch + cache layer (isolated; opt-in; never on the DNS hot path) ---

class SiteAnalyzer:
    """Fetches a URL and analyzes its content. Results cached by host."""

    def __init__(self, store=None, timeout: float = 6.0, max_bytes: int = 1_500_000) -> None:
        self._store = store
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._cache: dict[str, ContentVerdict] = {}

    def analyze_url(self, url: str) -> ContentVerdict:
        """Fetch and analyze. Returns a not-fetched clean verdict on any network
        failure - analysis can only ever ADD signal, never break browsing."""
        if "//" not in url:
            url = "http://" + url
        host = _host_of(url)
        if host in self._cache:
            return self._cache[host]
        html = self._fetch(url)
        if html is None:
            v = ContentVerdict(decision="allow", score=0.0, category="clean",
                               reasons=["fetch failed / unreachable"], fetched=False)
        else:
            v = analyze_content(html, url)
        self._cache[host] = v
        return v

    def _fetch(self, url: str) -> Optional[str]:
        try:
            import httpx
        except Exception:
            return None
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Valkyrie SiteAnalyzer)"}
            with httpx.Client(timeout=self._timeout, follow_redirects=True,
                              headers=headers, verify=True) as c:
                with c.stream("GET", url) as resp:
                    chunks, total = [], 0
                    for chunk in resp.iter_bytes():
                        chunks.append(chunk)
                        total += len(chunk)
                        if total >= self._max_bytes:
                            break
                    return b"".join(chunks).decode("utf-8", errors="replace")
        except Exception:
            return None
