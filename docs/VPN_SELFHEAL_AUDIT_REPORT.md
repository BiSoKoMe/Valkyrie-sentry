# WireGuard Multi-Hop + SelfHealing Watchdog — Audit Report

**Date:** 2026-07-08
**Branch:** `claude/valkyrie-repo-cleanup-wkijf9`
**Scope:** `valkyrie/multihop.py`, `valkyrie/wireguard.py`, `valkyrie/intelligence/self_heal.py`
(`class SelfHealing`), `tests/test_multihop.py`, the dashboard's VPN panel
(`valkyrie/web/dashboard.html`) and `/api/vpn/status` (`valkyrie/web/server.py`).
**Method:** static reading of every code path, targeted safe Python repros
(no live `wg` process, no real network interface touched, `start_all.ps1` /
`stop_all.ps1` untouched). Same rigor as `docs/MAC_DIAGNOSIS_REPORT.md` and
`docs/DOT_VERIFICATION_REPORT.md`.

---

## TL;DR

| Component | Verdict |
|---|---|
| Key generation (`wireguard.py`, single-hop) | ✅ **Real** — requires the actual `wg genkey`/`wg pubkey` binary; refuses to run without it. No weak fallback. |
| Key generation (`multihop.py`, two-hop) | ✅ **Real** — pure-Python X25519 via the `cryptography` library (installed: v48.0.1), correct clamping. Fallback path exists but is inert on this machine. |
| Multi-hop config correctness | ⛔ **Was broken — fixed.** Hop-2's `Endpoint` was hardcoded to a WireGuard-internal overlay address (`10.13.14.1:51820`) instead of hop2's real public IP. The tunnel could never establish a handshake. The `hop2_ip` parameter passed by the CLI was silently discarded. |
| Kill switch ("ACTIVE" in dashboard) | ⛔ **Was a hardcoded label — fixed to reflect config-file state.** Real live enforcement (kernel iptables rule actually loaded) still cannot be verified from this tool and is now labeled honestly instead of overclaimed. |
| `tests/test_multihop.py` | ⛔ **Was asserting the bug as correct behavior — fixed.** It literally checked `"10.13.14.1:51820" in hop2_text`, codifying the broken Endpoint. No input-validation tests existed. |
| Input validation on `--hop1`/`--hop2` | ⛔ **Was absent — fixed.** Shell/INI metacharacters flowed straight into the config with no rejection. |
| SelfHealing check/recovery isolation | ✅ Correctly isolates ordinary `Exception`s per component; a failed check does not stop other checks; a failed recovery is logged, not raised. |
| SelfHealing watchdog thread survivability | ⛔ **Was a real gap — fixed.** `except Exception` (not `BaseException`) in `_check_one`/`_loop` meant a `SystemExit`/`KeyboardInterrupt` raised inside any `check_fn`/`recover_fn` would silently kill the watchdog thread forever, with no external signal that self-healing had stopped. Reproduced live; none of today's registered checks currently raise this, so it was latent, not active. |
| SelfHealing test coverage | ⛔ **Confirmed: zero.** No `tests/test_self_heal.py` exists — the exact blind-spot pattern the MAC bug came from. **Not added in this pass** (out of the constrained, minimal-fix scope); flagged as the top follow-up. |

---

## Part 1 — WireGuard key generation

### 1a. Single-hop (`valkyrie/wireguard.py`)

`_wg_genkey()` (`wireguard.py:42-62`) requires the real `wg` binary:

```python
wg = shutil.which("wg")
if not wg:
    raise RuntimeError("`wg` binary not found — WireGuard is not installed")
genkey = subprocess.run([wg, "genkey"], capture_output=True, check=True)
pubkey_proc = subprocess.run([wg, "pubkey"], input=genkey.stdout, ...)
```

There is no fallback here at all — if `wg` isn't on PATH, `generate()` prints
install instructions and returns `{}` (`wireguard.py:210-215`). Keys are the
genuine output of the reference WireGuard tool. **No weak-random path exists
in this file.**

### 1b. Multi-hop (`valkyrie/multihop.py`)

This path does **not** shell out to `wg` at all — it derives keys in pure
Python:

```python
def _generate_private_key() -> bytes:
    key = bytearray(os.urandom(32))
    key[0]  &= 248   # clear bits 0,1,2
    key[31] &= 127   # clear bit 7
    key[31] |= 64    # set bit 6
    return bytes(key)

def _private_to_public(private: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv_obj = X25519PrivateKey.from_private_bytes(private)
        return priv_obj.public_key().public_bytes_raw()
    except ImportError:
        pass
    return os.urandom(32)   # fallback: NOT a real public key
```

- Entropy source is `os.urandom(32)` — a real CSPRNG, correct.
- Curve25519 clamping (`&= 248`, `&= 127`, `|= 64`) matches RFC 7748 §5 exactly.
- Public-key derivation uses the real `cryptography` library's X25519
  implementation when available.

**Verified installed on this machine:**
```
$ python -c "import cryptography; print(cryptography.__version__)"
48.0.1
$ python -c "from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey"
# imports cleanly
```
So today, `_private_to_public` takes the **real** branch. The fallback
(`return os.urandom(32)`) is real code that would silently produce a random
32 bytes that *look* like a valid key but are **not** the actual public key
for the generated private key — this would be a genuine "silent failure":
peers would never complete a handshake, the private key having no
relationship to the advertised public key, and the code gives no warning.
This is currently **dormant risk, not an active bug** (confirmed
`cryptography` is a real dependency here), but it is worth flagging: if this
package is ever missing in a deployment, `multihop.py` degrades to
generating **non-functional keypairs with zero error message**. This is the
same category of risk as the MAC randomizer bug (claims success, does
nothing) but currently inert. Not changed in this pass — see Recommendations.

Key format was independently checked against the test's own validator
(43-char base64 + trailing `=`, decodes to 32 bytes) across 10 generation
rounds — all passed both before and after this session's edits.

---

## Part 2 — Config correctness

### 2a. Hop-2 Endpoint was structurally broken (fixed)

`MultiHopVPN.generate_config(hop1_ip, hop2_ip)` builds two client configs.
Before this session:

```python
def _hop2_conf(self, private_key: str, hop2_ip: str) -> str:
    return (
        ...
        f"Endpoint = 10.13.14.1:51820\n"     # hop2_ip parameter never referenced!
        ...
    )
```

`hop2_ip` (the real public IP/hostname the operator passes via
`--hop2 5.6.7.8`) was accepted as a parameter and then **never used** in the
function body — confirmed by grep (`multihop.py:189` declared it,
`multihop.py:199` [pre-fix] never referenced it). Instead, `Endpoint` was
hardcoded to `10.13.14.1:51820` — the WireGuard **overlay** address that
`server_setup_hop2.sh` assigns to hop2's *own* tunnel interface
(`Address = 10.13.14.1/24`, derived from `MULTIHOP_SUBNET_2`). An `Endpoint`
must be a real, routable address the client can dial to perform the initial
UDP handshake; a WireGuard-internal overlay address is not reachable until
after the very tunnel it's trying to bring up already exists — a
chicken-and-egg failure. Live-reproduced:

```
$ python -c "... mh.generate_config(hop1_ip='1.2.3.4', hop2_ip='5.6.7.8') ..."
=== HOP2 (before fix) ===
[Peer]
Endpoint = 10.13.14.1:51820      # <- 5.6.7.8 (the real hop2 IP) never appears anywhere
```

The setup instructions (`multihop.py:151`, "On hop-1 server, add hop-2 as a
WireGuard peer") confirm this is meant to be a real routed two-tunnel
topology on the client, not a nested single-tunnel design — which makes the
hardcoded overlay address unambiguously wrong under any reading of the
intended design, not just a labeling quibble.

**Fix applied** (`multihop.py`, `_hop2_conf`): `Endpoint` now uses the actual
`hop2_ip` parameter, matching how `_hop1_conf` already used `hop1_ip`
correctly. A comment documents why the overlay address is wrong.

This does **not** fully solve multi-hop WireGuard — see the "what remains a
gap" section below; the manual peer-wiring step 5 in `instructions()` is
still required and still not automated or validated by this tool.

### 2b. `AllowedIPs` / routing chain — otherwise correct

- `hop1_conf`: `AllowedIPs = 10.13.14.0/24` — correctly scopes hop1's peer
  route to *only* hop2's subnet (not `0.0.0.0/0`), which is the standard
  "route the next hop's overlay subnet through this peer" pattern.
- `hop2_conf`: `AllowedIPs = 0.0.0.0/0` + `PersistentKeepalive = 25` — correct
  for the terminal, full-tunnel hop.
- `hop1_conf` sets `DNS = 10.13.13.1` (the hop1 gateway); `hop2_conf` sets no
  `DNS` line. This is consistent with "DNS only needs to be set on the
  interface that's actually forwarding client-originated queries" but is
  worth an explicit code comment — not changed, since it doesn't produce
  incorrect behavior, only an asymmetry that could confuse a maintainer.
- Server-side `server_setup_hop{N}.sh`: correct `wg-quick`, `sysctl`,
  `iptables MASQUERADE`/`FORWARD` boilerplate; a stray `.format(hop_num=...)`
  call at the end of an f-string that already interpolated `{hop_num}` is
  dead code (verified it's a no-op on the fully-substituted string, not a
  bug that produces wrong output) — left as-is; flagged only as minor
  cleanup debt, not fixed (out of scope, purely cosmetic).

### 2c. Input validation — was absent (fixed)

`generate_config()` took `hop1_ip`/`hop2_ip` and wrote them straight into an
INI-style config with **no validation whatsoever**. Reproduced:

```
$ python -c "mh.generate_config(hop1_ip='1.2.3.4; rm -rf /', hop2_ip='5.6.7.8')"
[Peer]
Endpoint = 1.2.3.4; rm -rf /:51820     # written to disk, "success" reported
```

This is not directly shell-exec'd by this tool (it's written into a `.conf`
file that WireGuard itself would later refuse to parse), so it is not an RCE
here — but it is exactly the "looks like it worked, silently produces
garbage" pattern this audit is checking for: `generate_config()` returned
normally, the CLI printed `✓ Configs written`, and the resulting config is
non-functional with no diagnostic.

**Fix applied:** `generate_config()` now validates both IPs against a
conservative allow-list regex (`^[A-Za-z0-9._\-]+$`) before generating any
keys, raising `ValueError` with a clear message on rejection. The
pre-existing `HOP1_IP`/`HOP2_IP` literal placeholders that `__main__.py`
substitutes when `--hop1`/`--hop2` are omitted (`__main__.py:387-388`) still
pass validation intentionally, so the "generate a skeleton to edit later" CLI
flow is preserved unchanged.

---

## Part 3 — The kill switch: label vs. reality

### 3a. `MultiHopVPN().status()` (before fix)

```python
def status(self) -> dict:
    return {
        "hop1_conf_exists": WIREGUARD_HOP1_CONF.exists(),
        "hop2_conf_exists": WIREGUARD_HOP2_CONF.exists(),
        ...
        "kill_switch": _KILL_SWITCH_UP,   # always the iptables command STRING
    }
```

`kill_switch` was **always** the literal iptables command text — present
whether or not any config file existed, whether or not WireGuard was even
installed, and regardless of whether a tunnel was ever brought up. It is not
a status signal at all; it's a constant.

### 3b. Dashboard (before fix) — confirmed hardcoded, not even reading the API field

`valkyrie/web/dashboard.html`, `loadVpnStatus()`:

```js
const res  = await fetch('/api/vpn/status');
const data = await res.json();
...
if (ks) ks.textContent = 'ACTIVE';   // <- ignores `data` entirely
```

This line does not read `data.kill_switch` or anything else from the
response — **"Kill switch: ACTIVE" renders unconditionally**, even when
`/api/vpn/status` reports `hop1_conf_exists: false, hop2_conf_exists: false`
(the actual live state on this machine before any config was generated,
verified directly):

```
$ python -c "from valkyrie.multihop import MultiHopVPN; print(MultiHopVPN().status())"
{'hop1_conf_exists': False, 'hop2_conf_exists': False, ...}
```

At that moment the dashboard would still show "Kill switch: ACTIVE" to the
user — no configs generated, no tunnel possible, and yet the strongest
possible security claim is displayed. This is a direct parallel to the DoT
report's finding: a privacy guarantee ("kill switch blocks leaks") displayed
as active when nothing backing it exists.

**Fix applied:**
- `MultiHopVPN.status()` now computes `kill_switch_configured: bool` — true
  only when **both** hop config files exist on disk **and** both actually
  contain the `PostUp`/`PreDown` iptables directive text. This is the
  strongest claim verifiable without a live tunnel: "the rule is present in
  the generated config," not "the rule is loaded in the kernel."
- The dashboard now renders `configured (not verified live)` /
  `not configured` from this real field instead of a hardcoded string.
- Both new docstrings/comments explicitly state what this field does **not**
  prove: it is not proof the rule was ever applied to a live interface, and
  this tool never runs `wg-quick`, `iptables -S`, or inspects the routing
  table to check.

### 3c. What still cannot be verified (honest limits)

Per the task constraints, no live WireGuard tunnel was established and no
real `wg`/`iptables` commands were run against a real interface in this
session. Therefore the following remain **open, unverified, and cannot be
verified without live network testing**:
- Whether the `PostUp`/`PreDown` iptables rule, once a tunnel is actually
  brought up with `wg-quick`, is syntactically accepted by the target
  Linux server's iptables (the rule itself was only checked for containing
  `iptables`/`OUTPUT`/`-D OUTPUT`, i.e. shape, not that it executes).
- Whether the kill switch actually blocks traffic on tunnel drop in
  practice (would require tearing down `wg0` mid-transfer on a live Linux
  box and observing packet loss/REJECT — explicitly out of scope here).
- Whether, after the Part 2a fix, a hop1→hop2 handshake actually completes
  end-to-end (requires two real VPS servers, the manual peer-wiring step,
  and a live client — explicitly out of scope here).

---

## Part 4 — `tests/test_multihop.py`: gap and fix

### 4a. Before this session

The test suite passed **25/25** while codifying the hop2 Endpoint bug:

```python
check("hop2 conf Endpoint is 10.13.14.1:51820",
      "10.13.14.1:51820" in hop2_text, hop2_text[:300])
```

This assertion is *checking that the bug is present*. A test suite that
"passes" while asserting broken behavior gives zero warning signal — same
failure mode as the MAC bug, where `randomize()` returned `True` and nothing
caught it. The suite verified key format (good), that files get written
(good), and kill-switch **string shape** (good) — but never checked whether
the generated config could plausibly work end-to-end, and had **no**
input-validation tests at all.

### 4b. Fix applied

- Replaced the bug-codifying assertion with one that checks `hop2_ip`
  (`5.6.7.8` in the test's fixture call) appears in `hop2_conf`'s `Endpoint`
  line and that the old broken value does **not**.
- Added two new input-validation tests: a shell-metacharacter `hop1_ip` and
  an empty `hop1_ip` must both raise `ValueError`.
- Added a `status()` assertion that `kill_switch_configured` is `True` only
  because the rule text is actually present in both written files (not a
  hardcoded truthy label).

**Test run after all fixes** (`python tests/test_multihop.py` from repo
root):

```
==================================================
  28 passed  /  0 failed
  RESULT: ALL TESTS PASSED
```

(25 pre-existing + 3 new; no regressions.)

---

## Part 5 — SelfHealing watchdog (`valkyrie/intelligence/self_heal.py`)

### 5a. Registration and recovery wiring — reviewed, correctly isolated

`__main__.py:735-785` registers four components:

| Component | `check_fn` | `recover_fn` |
|---|---|---|
| `dns_interceptor` | `dns_server.is_listening` | stop+restart the DNS thread |
| `store_writer` | `store.is_writing` (checks writer thread `.is_alive()`) | none |
| `web_dashboard` | HTTP GET `/api/stats`, expects 200 within 3s | none |
| `unbound` | raw DNS probe over UDP to the configured upstream, 2s timeout | `unbound.start()` |

`dns_interceptor.is_listening()` (`dns_interceptor.py:166-174`) is a real
liveness check — `self._running and self._sock is not None and
self._thread.is_alive()` — not just a flag that could go stale, and
`start()` (`dns_interceptor.py:135-152`) explicitly handles the
"Thread objects are single-use" `RuntimeError` by rebuilding the `Thread`
object before starting it again, specifically commented as being for the
self-healing restart path. This is solid, deliberate engineering — unlike
the MAC randomizer's silent-failure pattern, this component's health check
and recovery were built with the restart case in mind from the start.

`_check_one()` (`self_heal.py:99-126`, pre-fix) wraps both `check_fn()` and
`recover_fn()` in `try/except Exception`, so:
- A check that raises does **not** stop other components' checks
  (`check_now()` iterates a list snapshot and calls `_check_one` per
  component independently).
- A recovery that raises is caught, logged as `"{name} recovery failed:
  {exc}"`, and does not propagate.
- Verified by reasoning through `dns_server.start()`'s realistic failure
  mode (e.g. `OSError: address already in use` if the OS hasn't released the
  UDP port yet right after `.close()`) — this would be caught correctly by
  the existing `except Exception` and logged, not silently swallowed.

**This part of the design is sound and was not changed.**

### 5b. The watchdog dying silently — confirmed real, now fixed

`_check_one` and `_loop` both caught `Exception`, not `BaseException`. Python
requires `BaseException` to catch `SystemExit`/`KeyboardInterrupt` (and
`GeneratorExit`). Reproduced live, before the fix:

```
$ python -c "
healer.register('bad', lambda: (_ for _ in ()).throw(SystemExit))
healer.start(); time.sleep(0.3)
print(healer._thread.is_alive())
"
False
```

and separately for a `recover_fn`:

```
$ python -c "
healer.register('c', lambda: False, lambda: (_ for _ in ()).throw(KeyboardInterrupt()))
healer.start(); time.sleep(0.3)
print(healer._thread.is_alive())
"
Exception in thread self-heal:
Traceback (most recent call last):
  ...
  File ".../self_heal.py", line 134, in _loop
    self.check_now()
  ...
KeyboardInterrupt
False
```

Once the daemon thread dies this way, `SelfHealing.status()` freezes at its
last values forever — `last_check` stops advancing, but **nothing surfaces
this as an alarm**. `/api/intelligence`'s `self_heal` key
(`web/server.py:353-354`) would keep echoing stale per-component data with
no "watchdog is dead" signal, and the dashboard has no code path that calls
`healer._thread.is_alive()` at all (confirmed via grep — zero references
outside `self_heal.py` itself). This is the same shape of bug as the MAC
randomizer: a component can stop doing its job while everything downstream
keeps reporting the last-known-good state as if it were current.

**Currently latent, not active:** none of the four registered `check_fn`/
`recover_fn` callables in `__main__.py` today raise `SystemExit` or
`KeyboardInterrupt` — `is_listening()`, `is_writing()`, the `urllib`/`socket`
probes, and `dns_server.start()`/`unbound.start()` all only raise ordinary
`Exception` subclasses in their realistic failure modes. So this was not
observed to be causing harm today, but it is exactly the kind of
"the guarantee isn't actually active despite looking designed for it" gap
called out for `resolver.py`/DoT — the code comments explicitly promise "the
watchdog itself must never die" and "one check raising... never affects the
others," and `except Exception` alone does not deliver that promise.

**Fix applied:** both catch clauses widened to `except BaseException`, with
comments explaining why (a stray `SystemExit`/`KeyboardInterrupt` from any
registered callback must not kill the loop thread). Re-verified after the
fix — the thread now survives both repro cases:

```
$ python -c "... KeyboardInterrupt in recover_fn ..."
thread alive after KeyboardInterrupt in recover_fn (patched): True
{'c': {'ok': False, 'failures': 5, 'recoveries': 0, 'last_error': 'recovery raised: ', 'last_check': ...}}
```

### 5c. Test coverage — confirmed zero, not added in this pass

`tests/` has no `test_self_heal.py`, and no other test file imports
`SelfHealing` or `self_heal`. This is the exact blind spot pattern that let
the MAC randomizer bug ship — a component with real failure modes and no
dedicated regression test. **Not fixed in this session** (writing a full
test suite for a threading-based watchdog was judged to be beyond a
"safe, clearly-scoped, non-destructive fix" and risks flakiness on CI without
careful design); flagged below as the top recommended follow-up.

---

## What was fixed (summary)

1. `valkyrie/multihop.py`:
   - `_hop2_conf` now uses the real `hop2_ip` parameter for `Endpoint`
     instead of a hardcoded, unreachable overlay address.
   - `generate_config()` now validates `hop1_ip`/`hop2_ip` and raises
     `ValueError` on empty or metacharacter-containing input, while still
     accepting the CLI's `HOP1_IP`/`HOP2_IP` placeholder sentinels.
   - `status()` now returns `kill_switch_configured: bool`, computed from
     actual file contents, in addition to the existing raw `kill_switch`
     string field (kept for backward compatibility).
2. `valkyrie/web/dashboard.html`: `loadVpnStatus()` now renders
   `kill_switch_configured` from the API response instead of an
   unconditional hardcoded `'ACTIVE'` string.
3. `valkyrie/intelligence/self_heal.py`: `_check_one()` and `_loop()` now
   catch `BaseException` instead of `Exception`, so a `SystemExit`/
   `KeyboardInterrupt` raised inside any registered check/recovery callback
   can no longer silently kill the watchdog thread.
4. `tests/test_multihop.py`: replaced the assertion that codified the hop2
   Endpoint bug with one that catches it; added input-validation tests and
   a `kill_switch_configured` correctness test. **28/28 passing** after all
   fixes (`python tests/test_multihop.py`).

## What remains an open gap (not fixed, needs live testing or further work)

1. **No `tests/test_self_heal.py` exists.** Recommend at minimum: (a) a test
   that a `check_fn` raising `SystemExit`/`BaseException` doesn't kill the
   loop thread (regression test for the 5b fix), (b) a test that
   `recover_fn` is actually invoked on failure and `recoveries` increments,
   (c) a test that `all_ok()` reflects a failed component correctly.
2. **`_private_to_public`'s `ImportError` fallback** (`multihop.py`) returns
   `os.urandom(32)` as a "public key" with zero relationship to the real
   private key if the `cryptography` package is ever missing — dormant on
   this machine (package is installed) but would be a silent,
   undiagnosable handshake failure if it ever activated. Not touched this
   session since `cryptography` is a confirmed hard dependency here;
   recommend either making the import a hard `raise RuntimeError` (fail
   loud) or adding it to `setup.py`/`requirements.txt` as non-optional if it
   isn't already.
3. **Real kill-switch enforcement is still unverified on the wire.** This
   audit only confirmed the iptables rule's *text* is present in generated
   configs. Whether it actually blocks traffic when a live tunnel drops was
   explicitly out of scope (would require a real Linux box + real
   `wg-quick` + a real interface drop) and was not tested.
4. **Full end-to-end multi-hop handshake is still unverified.** The Part 2a
   fix corrects a bug that would have made this structurally impossible, but
   confirming it now *works* requires two real VPS servers, the still-manual
   "add hop-2 as a peer on hop-1" step, and a live client — out of scope
   here.
5. **`server_setup_hop{N}.sh`'s trailing `.format(hop_num=...)` call is dead
   code** (the f-string already substituted `{hop_num}` before `.format()`
   runs) — harmless today (no-op on a string with no remaining placeholders)
   but confusing; minor cleanup, not fixed.

---

## Follow-up pass (same day) — gaps #1 and #2 now closed

- **#1 resolved: `tests/test_self_heal.py` added (17 checks, all passing).**
  Covers exactly the recommended cases and more: (a) a `check_fn` raising
  `SystemExit` and a `recover_fn` raising `KeyboardInterrupt` both leave the
  watchdog thread alive (regression test for the 5b `BaseException` fix),
  (b) `recover_fn` is invoked on failure and `recoveries` increments, then
  the component reports `ok` after a successful recovery, (c) `all_ok()`
  flips correctly, and (d) fault isolation — a raising component does not
  stop its neighbours from being checked. Run: `python tests/test_self_heal.py`.
- **#2 resolved: `_private_to_public` now fails loud.** The `os.urandom(32)`
  fallback is gone; a missing `cryptography` package now raises
  `RuntimeError` with an explicit message instead of returning a fake public
  key. `cryptography` is already listed in `requirements.txt`, so the real
  branch is unchanged — this only removes the silent-failure landmine.
- #3, #4, #5 remain open as documented (they need live network hardware or
  are cosmetic).
