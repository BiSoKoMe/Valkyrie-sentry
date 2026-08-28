# Valkyrie -> Platform Roadmap

**What it takes to turn Valkyrie from a personal tool into something a company
could use to protect clients - and, just as important, what that costs in
privacy.**

This doc is deliberately split into *buildable* (engineering we can do) and
*not-buildable* (the parts that make it a company, which no amount of code
produces). It is written in the same no-overclaiming spirit as the audit
reports: it says plainly what exists, what is scaffolding, and what is still
just a plan.

---

## The core trade-off - read this first

Valkyrie's strongest privacy property today is **"nothing leaves your machine,
there is no third party."** The moment it manages many clients from a central
server, **Valkyrie itself becomes the third party** - a server that could see
client data, that is a breach target, that can be subpoenaed. "Being like a
privacy company" partly means *giving up the thing that made Valkyrie's privacy
story special.*

The design decision that keeps the story intact: the fleet agent reports
**status metadata only** - component health, block/allow counts, category
tallies - and **never domains, queries, IPs, or per-request records** (enforced
in `valkyrie/fleet/protocol.py`; proven by the privacy-invariant test in
`tests/test_fleet.py`). The server can tell you a device is protected and how
much it blocked, but it never becomes a browsing-history honeypot. Any future
"detailed telemetry" must be **opt-in per device**, off by default, and clearly
disclosed.

---

## Buildable - status of the engineering

| Capability | Status | Where |
|---|---|---|
| Agent / control-plane split | **Foundation built + tested** | `valkyrie/fleet/` |
| Privacy-preserving enrollment + heartbeat | **Built + tested** | `fleet/protocol.py`, `fleet/agent.py` |
| Token-hash auth (server stores only sha256) | **Built + tested** | `fleet/controller.py`, `fleet/store.py` |
| Fleet console (read-only multi-device view) | **Built** | `fleet/dashboard.html`, `fleet/server.py` |
| Signed-update *verification* (Ed25519) | **Built + tested (verify-only)** | `valkyrie/updater.py` |
| CLI: `--fleet-server`, `--fleet-agent` | **Wired** | `valkyrie/__main__.py` |
| Central policy push (signed block/allow to fleet) | **Built + tested** | `valkyrie/fleet/policy.py` |
| Per-client isolation / multi-tenancy | **Built + tested** | `fleet/controller.py`, `fleet/store.py` |
| Plaintext-bind safety guard | **Built** | `fleet/server.py` |
| Signed-update *apply* (download + install) | Intentionally not built | see below |
| Packaged installers (MSI / pkg) | Not started | see below |
| TLS/HTTPS reverse proxy in front of the server | Deployment step (guard enforces it) | see below |

### What's genuinely done now
You can run `python -m valkyrie --fleet-server --fleet-enroll-token SECRET` on
one machine and `python -m valkyrie --web --fleet-agent http://server:8091
--fleet-enroll-token SECRET` on others; devices enroll once, then report health
+ counts every 30s, and the console at `:8091` shows them online/offline with
block totals. No domains cross the wire.

### The deliberately-unbuilt dangerous parts
- **Auto-*apply* of updates.** `updater.py` verifies a release is authentically
  signed and intact, then stops. Actually running an installer is the single
  highest-risk action in the product and must stay a gated, human-initiated
  step until there's a hardened, tested apply path (staged rollout, rollback,
  signature re-check at apply time). Verify-first is done; apply is not.
- **Exposing the server without TLS.** The control plane speaks plain HTTP
  today and MUST run behind a TLS-terminating reverse proxy (Caddy/nginx) before
  it touches a real network. Enrollment tokens and device tokens are bearer
  credentials - they cannot cross the wire in cleartext.

### Next buildable milestones (in order)
1. **Wire applied policy into the live pipeline** - the agent verifies + applies
   a policy today via a `policy_applier` callback; connect that callback to the
   real blocklist/rules so pushed `block_domains` take effect on the device.
2. **TLS deployment guide** - Caddy/nginx in front; the plaintext-bind guard
   already refuses insecure prod binds, so this is docs + a sample config.
3. **Packaged installers** - MSI (WiX/Advanced Installer) + a hardened Windows
   service definition; signed with an EV code-signing cert.
4. **Update *apply* path** - staged, rollback-capable, re-verifies at apply.
5. **Alerting** - webhook/email when a device goes offline or a threat spikes.
6. **Per-tenant scoped operator logins** - today org scoping is by query/enroll
   token; add real operator accounts scoped to their org(s).

**Done since first draft:** central signed policy push (#2 old), multi-tenant
isolation (#3 old), and the plaintext-bind guard (part of #1 old) are built and
tested - see the status table above.

---

## Not buildable in code - the actual "company"

These are what separate "impressive tool" from "service people trust with their
protection." None of them ship as a commit.

- **External security audit + penetration test.** A third party has to try to
  break the control plane. Our own audit reports are honest but not independent.
- **Certifications** - SOC 2 Type II, ISO 27001. Months of process + auditor
  fees; table stakes for selling to businesses.
- **Legal foundation** - a legal entity, Terms of Service, a Data Processing
  Agreement (you become a data processor the moment you hold client metadata),
  liability + cyber-insurance, and a defined data-retention/deletion policy.
- **24/7 operations** - someone actually watching the fleet, an on-call rotation,
  an incident-response runbook, status page, and SLAs.
- **Threat intelligence** - today Valkyrie uses free public feeds. A real
  offering needs curated/commercial intel and a process to vet and age it.
- **Support + trust** - documentation, onboarding, a support channel, and the
  one thing you cannot ship: a track record earned over time.

---

## Honest bottom line

The **technology** of a privacy-protection company is now genuinely underway in
this repo: a tested, privacy-preserving agent/control-plane foundation, a fleet
console, and the cryptographic core of a safe update channel. That is real and
it works today.

But "make Valkyrie *like them*" is only ~30% an engineering problem. The
majority - audits, certifications, legal liability, 24/7 staffing, funded threat
intel, and earned trust - is organisational and cannot be coded. And the very
act of centralising clients weakens the local-first privacy guarantee that made
Valkyrie distinctive, which is why the whole design above is built to leak as
little as possible to the server.

Recommended framing: pursue this as **"self-hostable fleet management for
Valkyrie"** first (an operator protecting their own machines/household/small
org, no third-party trust required), which is fully achievable with the
engineering roadmap above - and treat "managed service company" as a separate,
mostly-non-engineering decision to make deliberately, with eyes open to the
trade-off.
