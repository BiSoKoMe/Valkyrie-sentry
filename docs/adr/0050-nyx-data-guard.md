# ADR 0050 - Nyx: the data-guard core (observe -> act -> correlate)

Date: 2026-08-20 . Status: accepted . Follows: ADR 0049 (causality graph), and the fingerprint-farbling / deception-endpoint / persona work

## Context

Valkyrie is a **digital-privacy protector**, not an antivirus - the EDR only
earns its place because malware is the most violent form of data theft. But the
*everyday* privacy leak - a tracker, a wifi network, or an ordinary app quietly
handing a piece of *you* to a third party - had no single component watching it.
The privacy machinery existed but was **scattered and unnamed**: `farble.py`
lies to fingerprinters on the browser read side, `deception.py` answers tracker
beacons with fabricated persona data, DNS/CNAME blocking stops known trackers.
Three good tools, one axis each, no brain over the top, and - crucially -
*nothing that reads what is actually leaving the machine and tells the user*.

The commercial EDRs are famous for a correlation substrate (ADR 0049 gives
Valkyrie one for malware). The privacy side deserved the same idea, pointed at
*data* instead of *processes*, and - the whole point of Valkyrie - done entirely
on-device, since a cloud-fed graph is the thing this product refuses to be.

## Decision

Introduce **Nyx**, a generalizing on-device data-guard core, in three layers.
The through-line of all three is **generalize, don't enumerate**: decide by the
*shape* of the data, never a blocklist, so a tracker never seen before is still
caught.

**1. SEE - `nyx.inspect_outbound` (observe).** Reads each outbound request's raw
URL, headers, and body and reports any personal data crossing to a **third
party** (registrable-domain compare against the page's first party; no first
party => silent, never guess). Categories, all by data-shape: advertising/device
ID, location (lat+lon), contact (email/E.164), fingerprint bundle (>=3 device
surfaces), Luhn-validated payment card, and persistent third-party tracking
cookie. Two hard rules: the raw value is **never stored** (observations carry a
masked sample only), and **first-party data is never flagged** - your own login
to the site you are on is yours.

**2. ACT - `nyx.fake_outbound` (deceive), gated by `config.NYX_ACT`.** Rewrites
the leaking values into **one consistent persona** ("John", from `persona.py`)
so the tracker/app receives believable-but-false data and *the request still
completes*. This is deliberate: **deception, not blocking** - a coherent lie
protects the user without breaking the page, and every fake comes from the same
persona so the machine never contradicts itself across requests (the tell a
sloppy spoof fails). Default **off**: Nyx never alters traffic until armed.
Cookies are observe-only (blanking a third-party cookie can break a logged-in
embed); fingerprint bundles are handled on the read side by farble.

**3. CORRELATE - `nyx_graph.TrackerGraph` (remember).** A local graph that links
a tracker's identity by registrable domain across every surface it touches: the
first-party sites it rode in on (its *reach*), the channels it used, the
different hostnames it wore (its *masks*), the categories it reached for, and
the time span it has been observed. "This one request leaked your ID" becomes
"adnet has followed you across 12 of your sites for 6 days wearing 4 masks." It
is the Threat-Graph idea of ADR 0049, pointed at privacy and built from the
event store, which already persists across sessions - so the memory is durable
without new schema.

All three surface through `/api/nyx` and a mode-aware Nyx panel in the Electron
renderer: what leaked, what was faked, and who is following you - the assistant
half, so protection can be *felt*, not just happen silently.

## Consequences

* The privacy pillar - the actual differentiator, the lane the cloud EDRs
  structurally cannot enter - now has a **named brain and a scoreboard**: a
  privacy battery drives real tracker/exfil/fingerprint traffic through the real
  code and holds at ~96% defended with **zero false positives** (breaking a site
  is the unforgivable failure for a tool in front of all your traffic).
* Nyx unifies rather than replaces: farble (read-side fingerprint lies),
  deception (beacon replies), persona (the one identity), and DNS/CNAME blocking
  all become surfaces the graph correlates and the panel reports.
* Parallel safety model to the EDR responders (ADR 0025/response.py): both
  *can* act, both are **safe-by-default** - the EDR responders are dry-run until
  armed, Nyx is observe until `NYX_ACT` is set.

## Honest boundaries

* Detection is heuristics over **cleartext**. An exfil path that encrypts or
  obfuscates its body is not seen here - this is a floor, not a guarantee.
* The third-party gate needs a first party (Referer/Origin); without one, Nyx
  stays silent rather than risk a false positive.
* Act rewrites identifier/location/contact/card; it does **not** touch cookies
  or spoof a service you are logged into (that would be your-account-your-risk,
  not free game). Trackers you never consented to are free game.
* Correlation reach depends on the first party being parseable from the event;
  where it is not, a tracker still shows by hits/masks/channels, just with lower
  reach.
