"""Nyx — the data-guard brain (first slice: SEE & REPORT, observe-only).

Valkyrie is a digital-privacy protector, not an antivirus. Nyx is the core
component that watches your *data*: it reads each outbound request in the raw
and decides, from the SHAPE of what's inside, whether a piece of *you* — a
device/advertising ID, your location, an email or phone number, a browser
fingerprint — is being handed to a third party you did not mean to talk to.

This module is the SEEING half. It is a pure function: request in, a list of
plain-language observations out. It never touches the flow, never blocks, never
lies — that is a deliberate later slice. Observe-first means Nyx cannot break a
page or an app, so it can be trusted on before it is ever allowed to act.

Design choices that keep this honest and low-false-positive:

  * THIRD-PARTY GATE FIRST. Your own data going to the site you are actually on
    (a login, a form you filled in) is NOT a leak and is never flagged. Nyx only
    reports personal data crossing to a DIFFERENT registrable domain than the
    page's first party. Without a first party to compare against (no Referer /
    Origin header) Nyx stays silent rather than guess.

  * DECIDE BY DATA-SHAPE, NOT A DOMAIN LIST. There is no allow/deny list of
    trackers here. Nyx recognises the data itself — a UUID under an ad-id key, a
    lat/lon pair, an email, a bundle of fingerprint surfaces in one request — so
    it catches a tracker it has never seen, which a blocklist cannot.

  * NEVER STORE THE RAW VALUE. Observations carry a MASKED sample only. Nyx must
    not become a second copy of the very data it is protecting.

Honest boundary: these are heuristics over cleartext. An exfil path that
encrypts or obfuscates its body will not be seen here. This is a floor, not a
guarantee.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlsplit

from .dns_tunnel import registrable_base

# ── categories ──────────────────────────────────────────────────────────────
CAT_IDENTIFIER  = "identifier"     # advertising / device ID
CAT_LOCATION    = "location"       # GPS / coarse geo coordinates
CAT_CONTACT     = "contact"        # email / phone number
CAT_FINGERPRINT = "fingerprint"    # a bundle of device-fingerprint surfaces

# Human label per category — used to build the sentence the user reads.
_LABEL = {
    CAT_IDENTIFIER:  "device ID",
    CAT_LOCATION:    "location",
    CAT_CONTACT:     "contact details",
    CAT_FINGERPRINT: "browser fingerprint",
}

# ── data-shape signals (generalising, not a domain list) ────────────────────
_ID_KEY = re.compile(
    r"(adid|idfa|gaid|aaid|advertis|device[_-]?id|deviceid|"
    r"client[_-]?id|clientid|visitor|fingerprint|installation|"
    r"\buid\b|\buuid\b|\bfid\b|\bcid\b)",
    re.I,
)
_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
# A long, unbroken high-entropy token is what a persistent ID looks like once
# the vendor drops the dashes. Kept deliberately strict (>=24, single run of
# id-safe chars) so ordinary words and short codes do not trip it.
_LONG_TOKEN = re.compile(r"^[A-Za-z0-9_\-]{24,}$")

_LAT_KEY = re.compile(r"(^|[_\-.])(lat|latitude)([_\-.]|$)", re.I)
_LON_KEY = re.compile(r"(^|[_\-.])(lon|lng|longitude)([_\-.]|$)", re.I)
_LATLON_PAIR = re.compile(
    r"(?<![\d.])[-+]?\d{1,2}\.\d{3,}\s*[,;]\s*[-+]?\d{1,3}\.\d{3,}(?![\d.])"
)

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?<!\d)\+\d{9,15}(?!\d)")   # E.164 only (leading + required)

# Fingerprint-bundle surfaces — each contributes ONE signal; >=3 together in a
# single third-party request is the tell.
_FP_SCREEN = re.compile(r"(screen|resolution|avail(width|height)|\bsw\b|\bsh\b)", re.I)
_FP_WXH    = re.compile(r"\b\d{3,4}\s*[x×]\s*\d{3,4}\b")
_FP_TZ     = re.compile(r"(timezone|\btz\b|utc[_-]?offset)", re.I)
_FP_TZVAL  = re.compile(r"[A-Za-z]+/[A-Za-z_]+")   # America/New_York shape
_FP_LANG   = re.compile(r"(language|\blang\b|\blocale\b)", re.I)
_FP_CORES  = re.compile(r"(hardwareconcurrency|\bcores\b|\bcpu\b|devicememory)", re.I)
_FP_GPU    = re.compile(r"(canvas|webgl|\brenderer\b|\bgpu\b)", re.I)
_FP_UA     = re.compile(r"mozilla/5\.0", re.I)


@dataclass(frozen=True)
class Observation:
    """One piece of personal data seen leaving to a third party. Observe-only:
    describing this never changes the request."""
    category:           str
    destination_host:   str
    first_party_origin: str
    masked_sample:      str
    sentence:           str


# ── helpers ─────────────────────────────────────────────────────────────────
def _host_of(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def first_party_of(headers) -> str:
    """Registrable domain of the page that issued the request, from Referer or
    Origin. Empty string when neither is present — the caller then stays silent
    (nothing can be judged "third party" without a first party)."""
    h = _lower_headers(headers)
    ref = h.get("referer") or h.get("origin") or ""
    host = _host_of(ref)
    return registrable_base(host) if host else ""


def _lower_headers(headers) -> dict:
    if not headers:
        return {}
    try:
        return {str(k).lower(): str(v) for k, v in dict(headers).items()}
    except (TypeError, ValueError):
        return {}


def _mask(value: str) -> str:
    """Never echo the raw value back. Keep just enough for the user to recognise
    it without Nyx storing a usable copy."""
    v = value.strip()
    if "@" in v and _EMAIL.match(v):          # email → first char + domain
        local, _, dom = v.partition("@")
        return (local[:1] or "?") + "***@" + dom
    if len(v) <= 6:
        return "***"
    return v[:2] + "…" + v[-2:]


def _decode_body(body, content_type: str) -> tuple[list[tuple[str, str]], str]:
    """Return (key/value pairs, flat text blob) from a request body. Handles
    form-urlencoded and JSON; falls back to raw text. Pure and defensive — a
    malformed body yields empty pairs, never an exception."""
    if not body:
        return [], ""
    if isinstance(body, bytes):
        try:
            text = body.decode("utf-8", "replace")
        except Exception:
            return [], ""
    else:
        text = str(body)

    ct = (content_type or "").lower()
    pairs: list[tuple[str, str]] = []
    if "json" in ct or text.lstrip()[:1] in ("{", "["):
        try:
            pairs = _flatten_json(json.loads(text))
        except (ValueError, TypeError):
            pairs = []
    if not pairs and "form-urlencoded" in ct:
        try:
            pairs = parse_qsl(text, keep_blank_values=True)
        except ValueError:
            pairs = []
    if not pairs and "&" in text and "=" in text and "{" not in text:
        # Body looks form-shaped even without a declared content-type.
        try:
            pairs = parse_qsl(text, keep_blank_values=True)
        except ValueError:
            pairs = []
    return pairs, text


def _flatten_json(obj, prefix: str = "") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_flatten_json(v, str(k)))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_flatten_json(v, prefix))
    else:
        out.append((prefix, "" if obj is None else str(obj)))
    return out


# ── the brain ───────────────────────────────────────────────────────────────
def inspect_outbound(method: str, url: str, headers=None, body=None,
                     first_party_origin: str | None = None) -> list[Observation]:
    """Read one outbound request and report any personal data crossing to a
    third party. Pure: same input → same output, no side effects, never blocks.
    """
    dest_host = _host_of(url)
    if not dest_host:
        return []
    dest_base = registrable_base(dest_host)

    h = _lower_headers(headers)
    first_party = (first_party_origin or "").strip() or first_party_of(headers)
    # THIRD-PARTY GATE: no first party to compare, or same registrable domain →
    # this is the user talking to their own site. Not a leak. Stay silent.
    if not first_party or first_party == dest_base:
        return []

    # Gather everything readable: query params + parsed body + a flat text blob.
    try:
        query_pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        query_pairs = []
    body_pairs, body_text = _decode_body(body, h.get("content-type", ""))
    pairs = query_pairs + body_pairs
    # Scan the DECODED values too — a percent-encoded email (alice%40x.com) is
    # invisible in the raw body text but present once parse_qsl decodes it.
    blob = url + " " + body_text + " " + " ".join(v for _, v in pairs)

    seen: set[str] = set()          # one observation per category per request
    out: list[Observation] = []

    def add(cat: str, sample: str) -> None:
        if cat in seen:
            return
        seen.add(cat)
        out.append(Observation(
            category=cat,
            destination_host=dest_host,
            first_party_origin=first_party,
            masked_sample=_mask(sample),
            sentence=(f"{first_party} sent your {_LABEL[cat]} to an unrelated "
                      f"server ({dest_host})"),
        ))

    # 1) Advertising / device identifier — keyed id with an id-shaped value,
    #    or a bare UUID anywhere in the payload.
    for k, v in pairs:
        if _ID_KEY.search(k) and (_UUID.search(v) or _LONG_TOKEN.match(v.strip())):
            add(CAT_IDENTIFIER, v)
            break
    if CAT_IDENTIFIER not in seen:
        m = _UUID.search(blob)
        if m:
            add(CAT_IDENTIFIER, m.group(0))

    # 2) Location — a latitude AND a longitude value, or a lat,lon pair.
    lat = lon = False
    for k, v in pairs:
        vs = v.strip()
        if _LAT_KEY.search(k) and _is_float(vs, -90, 90):
            lat = True
        if _LON_KEY.search(k) and _is_float(vs, -180, 180):
            lon = True
    if lat and lon:
        add(CAT_LOCATION, "lat/lon")
    elif _LATLON_PAIR.search(blob):
        add(CAT_LOCATION, _LATLON_PAIR.search(blob).group(0))

    # 3) Contact — email or E.164 phone.
    em = _EMAIL.search(blob)
    if em:
        add(CAT_CONTACT, em.group(0))
    elif _PHONE.search(blob):
        add(CAT_CONTACT, _PHONE.search(blob).group(0))

    # 4) Fingerprint bundle — >=3 distinct device surfaces in one request.
    signals = 0
    if _FP_SCREEN.search(blob) or _FP_WXH.search(blob):
        signals += 1
    if _FP_TZ.search(blob) or _FP_TZVAL.search(body_text):
        signals += 1
    if _FP_LANG.search(blob):
        signals += 1
    if _FP_CORES.search(blob):
        signals += 1
    if _FP_GPU.search(blob):
        signals += 1
    if _FP_UA.search(body_text):
        signals += 1
    if signals >= 3:
        add(CAT_FINGERPRINT, f"{signals} surfaces")

    return out


def _is_float(s: str, lo: float, hi: float) -> bool:
    try:
        f = float(s)
    except (TypeError, ValueError):
        return False
    return lo <= f <= hi and "." in s   # require a decimal → not a plain count


# ── ACT: feed the tracker fake data instead of blocking ─────────────────────
# The observe path (above) only watches. This path ACTS: it rewrites the
# personal data crossing to a third party into ONE consistent fake identity
# (the persona — "John"), so the tracker/app receives a well-formed request
# carrying believable-but-false data and the request STILL COMPLETES. That is
# the deliberate design: deception, not blocking. Blocking breaks apps; a
# coherent lie protects the user AND keeps the page working. Consistency is the
# whole game — every fake value comes from the SAME persona, so a machine that
# lies never contradicts itself (the tell that would give a spoof away).
#
# Fingerprint BUNDLES are intentionally not rewritten outbound here: they span
# many fields and are already handled on the browser READ side by farble. This
# path handles the clearly-rewritable identifiers, locations, and contacts.

def _personal_values(url, headers, body, first_party_origin=None):
    """The raw third-party personal values to overwrite. Same gate + signals as
    inspect_outbound; returns (category, kind, raw_value) tuples. Used only to
    rewrite them away — the raw value is never logged."""
    dest_host = _host_of(url)
    if not dest_host:
        return []
    dest_base = registrable_base(dest_host)
    h = _lower_headers(headers)
    fp = (first_party_origin or "").strip() or first_party_of(headers)
    if not fp or fp == dest_base:
        return []
    try:
        query_pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        query_pairs = []
    body_pairs, body_text = _decode_body(body, h.get("content-type", ""))
    pairs = query_pairs + body_pairs
    blob = url + " " + body_text + " " + " ".join(v for _, v in pairs)

    found: list[tuple[str, str, str]] = []
    # identifier
    idv = None
    for k, v in pairs:
        vs = v.strip()
        if _ID_KEY.search(k) and (_UUID.search(v) or _LONG_TOKEN.match(vs)):
            m = _UUID.search(v)
            idv = m.group(0) if m else vs
            break
    if idv is None:
        m = _UUID.search(blob)
        if m:
            idv = m.group(0)
    if idv:
        found.append((CAT_IDENTIFIER, "", idv))
    # location — the actual lat and lon value strings
    latv = lonv = None
    for k, v in pairs:
        vs = v.strip()
        if latv is None and _LAT_KEY.search(k) and _is_float(vs, -90, 90):
            latv = vs
        if lonv is None and _LON_KEY.search(k) and _is_float(vs, -180, 180):
            lonv = vs
    if latv and lonv:
        found.append((CAT_LOCATION, "lat", latv))
        found.append((CAT_LOCATION, "lon", lonv))
    # contact
    em = _EMAIL.search(blob)
    if em:
        found.append((CAT_CONTACT, "email", em.group(0)))
    else:
        ph = _PHONE.search(blob)
        if ph:
            found.append((CAT_CONTACT, "phone", ph.group(0)))
    return found


def _fake_email(persona) -> str:
    """A stable, believable fake email derived from the ONE persona, so two
    requests never disagree about who the user is."""
    tag = (getattr(persona, "advertising_id", "") or "user").replace("-", "")[:8]
    city = (getattr(persona, "city", "") or "").lower().replace(" ", "")
    local = f"{city}.{tag}" if city else f"user{tag}"
    return f"{local}@gmail.com"


def _fake_for(category: str, raw: str, kind: str, persona):
    if category == CAT_IDENTIFIER:
        return getattr(persona, "advertising_id", None)
    if category == CAT_LOCATION:
        if kind == "lat":
            return getattr(persona, "lat", None)
        if kind == "lon":
            return getattr(persona, "lon", None)
    if category == CAT_CONTACT:
        return _fake_email(persona) if "@" in raw else "+10000000000"
    return None


def _apply_repl(text: str, repl: dict) -> str:
    """Replace each raw value with its fake, in plain, URL-encoded, and
    JSON-safe forms — so the substitution lands whether the value sits in a
    query string, a form body, or a JSON blob."""
    for raw, fake in repl.items():
        if raw and raw in text:
            text = text.replace(raw, fake)
        q = quote(raw, safe="")
        if q != raw and q in text:
            text = text.replace(q, quote(fake, safe=""))
    return text


def fake_outbound(method, url, headers=None, body=None, persona=None,
                  first_party_origin=None):
    """ACT on one outbound request: overwrite third-party personal data with
    consistent persona fakes. Returns (new_url, new_body, faked_categories).
    Pure aside from reading the current persona; the request is left byte-for-
    byte unchanged when there is nothing to fake, so it can never break a page.
    """
    vals = _personal_values(url, headers, body, first_party_origin)
    if not vals:
        return url, body, []
    if persona is None:
        from .persona import current_persona
        persona = current_persona()

    repl: dict = {}
    faked: list[str] = []
    for cat, kind, raw in vals:
        fake = _fake_for(cat, raw, kind, persona)
        if fake is not None and str(fake) != raw:
            repl[raw] = str(fake)
            if cat not in faked:
                faked.append(cat)
    if not repl:
        return url, body, []

    new_url = _apply_repl(url, repl)
    new_body = body
    if body is not None:
        if isinstance(body, bytes):
            try:
                new_body = _apply_repl(body.decode("utf-8", "replace"),
                                       repl).encode("utf-8")
            except Exception:
                new_body = body
        else:
            new_body = _apply_repl(str(body), repl)
    return new_url, new_body, faked
