# DNS-over-TLS on Unbound Upstream - Verification Report

**Task 2.**
**Goal:** Unbound's own upstream queries leave the machine **encrypted on 853**,
not plaintext 53. Config + on-the-wire verification (no code change; `resolver.py`
and `dns_interceptor.py` untouched).

---

## Status summary

| Phase | Result |
|---|---|
| 1.1 TLS/OpenSSL precondition | ✅ **PASS** - Unbound 1.25.1, OpenSSL 3.2.1 |
| 1.2 Identify the live Unbound instance | ⚠️ **NO Unbound is currently forwarding** (proven below) |
| 2 Apply DoT to the correct `unbound.conf` | ⛔ **Prepared, not applied** - target is admin-only and not currently live |
| 3 Verify on the wire (0 x :53 outbound) | ⛔ **Could NOT run this session** - needs Administrator + capture tool; and Unbound must first be made live |

**Bottom line:** the TLS precondition is met, the exact config is prepared and
machine-corrected (`unbound-service-dot.conf.example`), but the change cannot be
made *live* or verified *on the wire* from this non-elevated session - and,
more fundamentally, **no Unbound instance is in the resolution path right now**,
so applying the config blindly would be the exact "looks like it worked, does
nothing" silent failure this task warns against. Details and the precise
apply+verify procedure are below.

---

## Phase 1.1 - TLS support (PASS)

`unbound -V` (binary `C:\Program Files\Unbound\unbound.exe`):

```
Version 1.25.1
Linked libs: event winsock ... OpenSSL 3.2.1 30 Jan 2024
Linked modules: dns64 respip validator iterator
```

OpenSSL is linked -> `forward-tls-upstream` / port 853 are supported. Precondition met.

## Phase 1.2 - Which Unbound is forwarding right now? (NONE - measured)

`resolver.py` has two modes: **adopt** a native Unbound on `127.0.0.1:53`, or
**spawn** a subprocess on `5301`. Measured live state:

| Signal | Observed | Meaning |
|---|---|---|
| `sc query Unbound` | `STATE: STOPPED` | native service not running |
| `Get-Process unbound` | (none) | no Unbound process at all |
| listener on `:53` (UDP) | PID **33428** | = Valkyrie itself (`data/valkyrie_pid.txt` -> 33428) |
| listener on `:5301` | (none) | no subprocess instance |
| `shutil.which('unbound')` | `None` | binary not on PATH -> `resolver.py` subprocess mode **cannot launch** it |
| `data/unbound.conf` | absent | subprocess mode never generated a config -> never ran |
| `data/valkyrie_unbound_stopped.txt` | present | `start_all.ps1` **stopped the native service** to take port 53 |

**Conclusion:** neither `resolver.py` mode is live. Trace of *why*:
1. `start_all.ps1` stops the native `Unbound` service (to bind `:53` itself) -
   so **adopt mode** has nothing to adopt.
2. `unbound.exe` is installed under `C:\Program Files\Unbound` but is **not on
   PATH**, so `resolver.py`'s `_which("unbound")` returns `None` and **spawn
   mode** bails (`resolver.py:217-224`). Hence no `data/unbound.conf`, nothing on 5301.
3. `__main__.py:481` still calls `UnboundManager.start()`, but with (1)+(2) it
   returns `False`; Valkyrie therefore forwards via its own `dns_interceptor`
   upstream - `config.DNS_UPSTREAM = 40.54.1.13:53` (plaintext) - which this task
   explicitly scopes **out** ("do not touch that file").

So the honest answer to "which unbound.conf is live" is: **none is** - there is
no active Unbound whose config would take effect today.

### The correct config target (for when the native service IS the forwarder)

The native Windows service reads `C:\Program Files\Unbound\service.conf`. It is
currently **stock**: no `forward-zone` at all, i.e. pure recursion (it would
contact root/authoritative servers directly on :53 - legitimate recursion, not a
leak, but also not encrypted forwarding). That file is the right place for the
DoT block. It is **not writable without Administrator** (verified:
`OpenWrite` -> "Access to the path ... is denied").

## Phase 2 - DoT config (prepared, machine-corrected; not applied)

Ready-to-apply artifact: **`unbound-service-dot.conf.example`** (this repo).

Key correction vs. the task template - **do not use `tls-cert-bundle` on this
machine**: every candidate PEM bundle is absent (`icannbundle.pem`,
`ca-bundle.crt`, `Common Files\SSL\cert.pem`), so a `tls-cert-bundle:"<path>"`
would point at nothing and make Unbound fail every upstream TLS handshake and
SERVFAIL - a silent breakage. Use `tls-win-cert: yes` (Windows cert store),
which is present and is what this Unbound build's own `service.conf` documents.

```
server:
    tls-win-cert: yes

forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 8.8.8.8@853#dns.google
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 9.9.9.9@853#dns.quad9.net
```

**Not applied because:** (a) `service.conf` is admin-only (proven), and (b) even
applied, nothing would use it until the native service is both running *and* the
live forwarder - which it is not (Phase 1.2). Applying now would be a no-op
dressed up as success.

## Phase 3 - On-the-wire verification (NOT completed this session)

The task's proof - "capture on the WAN interface filtered to port 53 outbound;
should be ZERO; all resolver traffic on 853" - **could not be executed here**:
packet capture needs Administrator (pktmon, or npcap/tshark), which this
non-elevated, non-interactive session does not have; and there is currently no
live Unbound to capture. I will not substitute "no errors in the log" for a wire
capture. This step is **PENDING an elevated run**, using the exact procedure below.

### Exact apply + verify procedure (run in an elevated shell)

Prerequisite - make the native Unbound service the live forwarder first (see
"Required follow-ups"). Then:

```powershell
# 1. Apply DoT config (as admin): merge unbound-service-dot.conf.example into
#    C:\Program Files\Unbound\service.conf, then:
net stop Unbound; net start Unbound

# 2a. BEFORE/AFTER wire capture with pktmon (built into Windows, admin):
pktmon filter reset
pktmon filter add -p 53      # watch DNS plaintext
pktmon filter add -p 853     # watch DoT
pktmon start --capture --pkt-size 0 -f C:\Temp\dns.etl
#     drive real queries through the resolver:
foreach ($d in 'example.com','wikipedia.org','cloudflare.com') { Resolve-DnsName $d -Server 127.0.0.1 }
pktmon stop
pktmon etl2txt C:\Temp\dns.etl -o C:\Temp\dns.txt
#     PASS = zero OUTBOUND packets to a non-loopback IP on port 53;
#            upstream packets appear to 8.8.8.8/1.1.1.1/9.9.9.9 on port 853.

# 2b. Alternative with tshark (npcap + admin), capture on the WAN adapter:
tshark -i "Wi-Fi" -f "port 53 or port 853" -a duration:20
#     (drive the same queries in another window)
#     PASS = 0 packets on port 53 to the upstreams; all upstream on 853.
```

Note (honest scope): if Unbound is left in **pure-recursion** mode (no
forward-zone), outbound :53 to root/authoritative servers is expected and is
*legitimate recursion, not a leak*. The specific test here - zero outbound :53 -
is only meaningful **with** the forward-zone above, which routes Unbound's chosen
upstream path over TLS.

---

## Required follow-ups (blockers to a real, verifiable DoT)

1. **Make Unbound actually live** (today it is bypassed). This needs a decision
   and touches PROTECTED files, so it is NOT done here - proposing for approval:
   - Option A: add `C:\Program Files\Unbound` to PATH so `resolver.py` can spawn
     its subprocess - but then the DoT directives must live in `resolver.py`'s
     generated template (`_UNBOUND_CONF_TEMPLATE`, currently plaintext
     `9.9.9.9@53`), which is a code change to a protected file.
   - Option B: keep the native service running and point Valkyrie at it instead
     of having `start_all.ps1` stop it - a change to `start_all.ps1` (protected)
     and the `:53` bind strategy.
   Either path changes protected files and needs your approval.
2. **An Administrator session** to write `service.conf`, restart the service, and
   run the wire capture.

## Conclusion

TLS precondition confirmed; exact, machine-correct DoT config prepared; but the
live application and the on-the-wire proof are blocked by (a) no Unbound being in
the current resolution path and (b) Administrator-only operations. Reported
honestly rather than claiming an unverified success.
