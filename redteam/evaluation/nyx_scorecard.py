"""Synthetic benchmark for Nyx's disclosure-authority mechanism.

This exercises the real ``inspect_outbound``/``fake_outbound`` pipeline
(``valkyrie/nyx.py``) against realistic workflow shapes -- login, signup,
checkout, upload, messaging, sync, background telemetry, a cross-site embed
-- instead of one leak category at a time. The question this harness answers
is the one a homemade privacy tool usually cannot: does protecting the
unauthorized case ever break the authorized or benign ones, and is the raw
value actually gone from what would have left the machine?

Evidence class: synthetic mechanism evaluation, not independent real-world
efficacy. There is no live browser, no live network capture, and no real
tracker involved -- every request here is fabricated. Nyx's own docstring
already states the honest boundary: these are heuristics over cleartext, and
an exfil path that encrypts or obfuscates its body is invisible here. This
harness cannot and does not claim otherwise.
"""

from __future__ import annotations

import hashlib
import json
import statistics
import time
from dataclasses import asdict, dataclass
from typing import Iterable

from valkyrie import nyx
from valkyrie.persona import build_persona

# A fixed, deterministic persona so faked values are stable and inspectable
# across every scenario in this module.
_PERSONA = build_persona(b"nyx-scorecard-fixed-seed")

FIRST_PARTY = "https://app.example"
THIRD_PARTY = "https://collector.tracker.example/collect"
SIBLING_EMBED = "https://widget.example"  # a different site than FIRST_PARTY

# Sentinel raw values. If any of these strings survive into a faked request,
# an observation's masked sample, or the scorecard report, Nyx retained the
# very data it exists to protect -- that is a hard failure, not a tuning knob.
_RAW_ADID = "550e8400-e29b-41d4-a716-446655440000"
_RAW_EMAIL = "real.person@example.test"
_RAW_PHONE = "+15551234567"
_RAW_CARD = "4242424242424242"  # Luhn-valid; distinct from nyx's fake-card constant
_RAW_LAT, _RAW_LON = "40.7128", "-74.0060"

_JSON_HDR = {"Content-Type": "application/json"}
_FORM_HDR = {"Content-Type": "application/x-www-form-urlencoded"}


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    workflow: str
    expect: str  # "authorized" | "unauthorized" | "benign"
    method: str
    url: str
    headers: dict
    body: bytes
    first_party_origin: str

    def manifest_record(self) -> dict:
        return {**asdict(self), "body": self.body.decode("utf-8", "replace")}


@dataclass(frozen=True)
class ScenarioResult:
    scenario_id: str
    workflow: str
    expect: str
    observed_categories: tuple[str, ...]
    faked_categories: tuple[str, ...]
    request_unchanged: bool
    raw_value_leaked: bool
    latency_ms: float


def _hdr(first_party: str, **extra) -> dict:
    return {"Referer": first_party, **_FORM_HDR, **extra}


def build_scenarios() -> tuple[Scenario, ...]:
    """~30 synthetic workflow shapes: authorized, unauthorized, and benign."""
    scenarios: list[Scenario] = []

    def add(scenario_id, workflow, expect, method, url, headers, body):
        scenarios.append(Scenario(scenario_id, workflow, expect, method, url,
                                  headers, body, FIRST_PARTY))

    # --- AUTHORIZED: the user's own data, to the site they are actually on.
    # Nyx must never touch these -- the third-party gate is the whole design.
    add("auth-login", "login", "authorized", "POST", f"{FIRST_PARTY}/login",
        _hdr(FIRST_PARTY), f"user={_RAW_EMAIL}&pass=hunter2".encode())
    add("auth-signup", "signup", "authorized", "POST", f"{FIRST_PARTY}/signup",
        _hdr(FIRST_PARTY), f"email={_RAW_EMAIL}&phone={_RAW_PHONE}".encode())
    add("auth-checkout", "checkout", "authorized", "POST",
        f"{FIRST_PARTY}/checkout", _hdr(FIRST_PARTY, **_JSON_HDR),
        json.dumps({"card": _RAW_CARD, "email": _RAW_EMAIL}).encode())
    add("auth-upload", "upload", "authorized", "POST", f"{FIRST_PARTY}/upload",
        _hdr(FIRST_PARTY), b"x" * 2048)
    add("auth-messaging", "messaging", "authorized", "POST",
        f"{FIRST_PARTY}/messages/send", _hdr(FIRST_PARTY),
        f"to={_RAW_EMAIL}&body=hey".encode())
    add("auth-sync", "sync", "authorized", "POST", f"{FIRST_PARTY}/sync",
        _hdr(FIRST_PARTY, **_JSON_HDR),
        json.dumps({"lat": _RAW_LAT, "lon": _RAW_LON}).encode())
    add("auth-geolocation-share", "checkout", "authorized", "POST",
        f"{FIRST_PARTY}/delivery-address",
        _hdr(FIRST_PARTY, **_JSON_HDR),
        json.dumps({"latitude": _RAW_LAT, "longitude": _RAW_LON}).encode())

    # --- UNAUTHORIZED: the same personal-data shapes, to an unrelated third
    # party. This is the disclosure Nyx exists to catch.
    add("unauth-adid", "background", "unauthorized", "POST", THIRD_PARTY,
        _hdr(FIRST_PARTY), f"adid={_RAW_ADID}&e=1".encode())
    add("unauth-email-checkout-leak", "checkout", "unauthorized", "POST",
        THIRD_PARTY, _hdr(FIRST_PARTY), f"e={_RAW_EMAIL}".encode())
    add("unauth-phone", "signup", "unauthorized", "POST", THIRD_PARTY,
        _hdr(FIRST_PARTY), f"phone={_RAW_PHONE}".encode())
    add("unauth-location", "background", "unauthorized", "POST", THIRD_PARTY,
        _hdr(FIRST_PARTY), f"latitude={_RAW_LAT}&longitude={_RAW_LON}".encode())
    add("unauth-card", "checkout", "unauthorized", "POST", THIRD_PARTY,
        _hdr(FIRST_PARTY), f"cc={_RAW_CARD}".encode())
    add("unauth-fingerprint", "sync", "unauthorized", "POST", THIRD_PARTY,
        _hdr(FIRST_PARTY),
        b"screen=1920x1080&timezone=America/New_York&lang=en-US&cores=16")
    add("unauth-messaging-embed", "messaging", "unauthorized", "POST",
        THIRD_PARTY, _hdr(SIBLING_EMBED), f"contact={_RAW_EMAIL}".encode())
    add("unauth-json-nested-id", "sync", "unauthorized", "POST", THIRD_PARTY,
        _hdr(FIRST_PARTY, **_JSON_HDR),
        json.dumps({"device": {"uuid": _RAW_ADID}}).encode())
    # A device id sent via a request HEADER rather than the body/query --
    # inspect_outbound()'s header scan catches it, and fake_outbound_headers()
    # (added alongside this scorecard) now deceives it too.
    add("unauth-header-device-id", "background", "unauthorized", "GET",
        THIRD_PARTY, {"Referer": FIRST_PARTY, "X-Device-Id": _RAW_ADID}, b"")
    add("unauth-tracking-cookie", "background", "unauthorized", "GET",
        THIRD_PARTY,
        {"Referer": FIRST_PARTY, "Cookie": "tid=a1b2c3d4e5f6a1b2c3d4e5f6"}, b"")
    add("unauth-query-idfa", "background", "unauthorized", "GET",
        f"{THIRD_PARTY}?idfa={_RAW_ADID}", {"Referer": FIRST_PARTY}, b"")
    add("unauth-multi-tab", "sync", "unauthorized", "POST", THIRD_PARTY,
        _hdr(SIBLING_EMBED), f"adid={_RAW_ADID}".encode())

    # --- BENIGN: cross-site, but carrying nothing personal. Must stay silent
    # and untouched -- flagging these is the false-positive failure mode.
    add("benign-pagination", "sync", "benign", "POST", THIRD_PARTY,
        _hdr(FIRST_PARTY), b"page=3&sort=asc&q=shoes")
    add("benign-search-embed", "messaging", "benign", "GET",
        f"{THIRD_PARTY}?q=weather", {"Referer": FIRST_PARTY}, b"")
    add("benign-upload-large", "upload", "benign", "POST", THIRD_PARTY,
        _hdr(FIRST_PARTY), b"y" * 4096)
    # This one is NOT benign: a real device id, to a real third party. It is
    # filed as "unauthorized" and expected to survive as a named structural
    # gap (see structural_gaps in the report) rather than folded into
    # "benign" traffic, where an unbroken request would misleadingly read as
    # a pass. Without a Referer/Origin, Nyx has no first party to compare
    # against and stays silent by design (see nyx.first_party_of) -- honest,
    # but it means this exact disclosure is invisible to the mechanism.
    add("gap-no-referer-context", "background", "unauthorized", "POST",
        THIRD_PARTY, _FORM_HDR, f"adid={_RAW_ADID}".encode())
    add("benign-first-party-idlike", "login", "benign", "POST",
        f"{FIRST_PARTY}/session", _hdr(FIRST_PARTY),
        f"csrf_token={'a' * 32}".encode())

    return tuple(scenarios)


def manifest_hash(scenarios: Iterable[Scenario]) -> str:
    payload = [s.manifest_record() for s in scenarios]
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def run_scenario(scenario: Scenario) -> ScenarioResult:
    started = time.perf_counter_ns()
    # No explicit first_party_origin: every scenario carries its own Referer
    # header, exactly like the real tls_addon.py call site, so the gate is
    # exercised the same way it is in production.
    observations = nyx.inspect_outbound(
        scenario.method, scenario.url, scenario.headers, scenario.body)
    new_url, new_body, faked = nyx.fake_outbound(
        scenario.method, scenario.url, scenario.headers, scenario.body,
        persona=_PERSONA)
    # Mirrors the real tls_addon.py wiring: fake_outbound() alone never
    # reaches an identifier carried in a request HEADER, so the header-rewrite
    # companion runs alongside it, same as production.
    new_headers, header_faked = nyx.fake_outbound_headers(
        scenario.method, scenario.url, scenario.headers, scenario.body,
        persona=_PERSONA)
    faked = list(dict.fromkeys(faked + header_faked))
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0

    request_unchanged = (new_url == scenario.url and new_body == scenario.body
                         and not new_headers and not faked)
    # Retaining a raw value is only a leak where Nyx claims to have acted:
    # an untouched authorized/benign request legitimately still carries the
    # user's own data, and an unauthorized-but-cookie-only observation is the
    # documented exception (see cookie_never_entered_act_path). So this only
    # checks requests Nyx actually faked: did every raw sentinel it detected
    # in the ORIGINAL request actually disappear from what would be sent.
    serialized = repr((new_url, new_body, new_headers))
    raw_value_leaked = bool(faked) and any(
        raw in scenario.body.decode("utf-8", "replace") + " " + scenario.url
        and raw in serialized
        for raw in (_RAW_ADID, _RAW_EMAIL, _RAW_PHONE, _RAW_CARD, _RAW_LAT, _RAW_LON)
    )
    return ScenarioResult(
        scenario_id=scenario.scenario_id, workflow=scenario.workflow,
        expect=scenario.expect,
        observed_categories=tuple(sorted({o.category for o in observations})),
        faked_categories=tuple(sorted(faked)),
        request_unchanged=request_unchanged,
        raw_value_leaked=raw_value_leaked,
        latency_ms=elapsed_ms,
    )


def score(scenarios: Iterable[Scenario]) -> dict:
    scenario_list = tuple(scenarios)
    results = [run_scenario(s) for s in scenario_list]

    authorized = [r for r in results if r.expect == "authorized"]
    unauthorized_all = [r for r in results if r.expect == "unauthorized"]
    benign = [r for r in results if r.expect == "benign"]

    # Scenarios filed as a NAMED gap are reported on their own rather than
    # folded into the pass rate, where a known blind spot would either
    # misleadingly read as a failure or get averaged away and hidden inside a
    # passing aggregate.
    _GAP_REASONS = {
        "gap-no-referer-context": "no Referer/Origin means no first party to "
            "compare against; Nyx stays silent by design rather than guess",
    }
    structural_gaps = [r for r in unauthorized_all if r.scenario_id in _GAP_REASONS]
    unauthorized = [r for r in unauthorized_all if r not in structural_gaps]

    # Authorized flows must be untouched: identical bytes out, nothing faked.
    authorized_unbroken = sum(r.request_unchanged for r in authorized)
    # Benign cross-site traffic with no personal data must also stay silent.
    benign_unbroken = sum(r.request_unchanged and not r.observed_categories
                          for r in benign)
    # Unauthorized disclosures of a fakeable category must be deceived, i.e.
    # the request leaving the machine no longer carries the raw value.
    unauthorized_deceived = sum(bool(r.faked_categories) for r in unauthorized)
    # Cookie is deliberately excluded from the act path (blanking a
    # third-party cookie can break a logged-in embed) -- it must be observed
    # but never appear in faked_categories. Verify that invariant, not a bug.
    cookie_never_faked = all("cookie" not in r.faked_categories for r in results)
    raw_value_retained_anywhere = any(r.raw_value_leaked for r in results)

    latencies = sorted(r.latency_ms for r in results)

    def percentile(p: float) -> float:
        if not latencies:
            return 0.0
        index = min(len(latencies) - 1, int((len(latencies) - 1) * p))
        return latencies[index]

    return {
        "evidence_class": "synthetic mechanism evaluation",
        "independent": False,
        "manifest_sha256": manifest_hash(scenario_list),
        "totals": {"authorized": len(authorized), "unauthorized": len(unauthorized),
                  "benign": len(benign)},
        "authorized_flow_unbroken_rate": (authorized_unbroken / len(authorized)
                                          if authorized else None),
        "benign_flow_unbroken_rate": (benign_unbroken / len(benign)
                                      if benign else None),
        "unauthorized_disclosure_deceived_rate": (unauthorized_deceived / len(unauthorized)
                                                   if unauthorized else None),
        "cookie_never_entered_act_path": cookie_never_faked,
        "raw_value_retained_anywhere": raw_value_retained_anywhere,
        "structural_gaps": [
            {"scenario_id": r.scenario_id, "reason": _GAP_REASONS[r.scenario_id],
             "observed": bool(r.observed_categories), "deceived": bool(r.faked_categories)}
            for r in structural_gaps
        ],
        "latency_ms": {
            "p50": statistics.median(latencies) if latencies else 0.0,
            "p99": percentile(0.99),
        },
        "results": [asdict(r) for r in results],
        "limitations": [
            "Scenarios are synthetic and committed with the detector, not captured "
            "from a live browser or a real tracker.",
            "Nyx reasons over cleartext request shape; an exfil path that encrypts "
            "or obfuscates its body is invisible to this mechanism and this harness.",
            "The tracking-cookie category is intentionally never rewritten; a "
            "blanked third-party cookie can break a legitimately logged-in embed.",
            "This does not measure live network egress -- it does not prove the "
            "faked bytes are what actually left a real machine's NIC.",
            "structural_gaps lists disclosures Nyx cannot fully act on today "
            "(see each entry's reason) -- named, tracked blind spots, not "
            "something this harness papers over as a pass.",
        ],
    }
