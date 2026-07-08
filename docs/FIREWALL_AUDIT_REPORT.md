# Firewall (`valkyrie/firewall.py`) — Audit Report

**Date:** 2026-07-08
**Branch:** `claude/valkyrie-repo-cleanup-wkijf9`
**Machine:** `LAPTOP-56ETIOCV`, Windows 11 (real hardware, same machine as the MAC
and DoT reports).
**Method:** full read of `valkyrie/firewall.py`, `valkyrie/config.py`,
`valkyrie/dns_interceptor.py`, `valkyrie/__main__.py`, `valkyrie/doh_detector.py`,
`valkyrie/ui.py`, `valkyrie/web/server.py`; cross-repo grep for every call site
of `is_blocked_ip` / `FirewallManager`; a mocked, isolated reproduction of the
Windows netsh path (no live netsh/iptables execution — `subprocess.run` was
monkeypatched, same technique as the MAC diagnosis); and execution of the two
existing test suites before and after the fix.

Applies the same standard as `docs/MAC_DIAGNOSIS_REPORT.md` and
`docs/DOT_VERIFICATION_REPORT.md`: no claim is accepted because "no exception
was raised" or "the test suite is green." Each claim below is backed by a
file:line citation or a reproduced empirical result.

---

## TL;DR

Two distinct problems, one fixed, one **left as a documented gap** (not a code
bug, but a real enforcement gap that the code comments understate):

1. **FIXED — silent failure bug, same class as the MAC randomizer.**
   `_WindowsFirewall.add_doh_rules()` called `netsh advfirewall firewall add
   rule …`, **discarded the `CompletedProcess`**, and unconditionally did
   `ok += 1` regardless of whether netsh actually succeeded. A non-admin
   session, a UAC prompt denial, a locked-down firewall policy, or a malformed
   rule name would all report full success. Reproduced empirically with a
   mocked `subprocess.run` returning `rc=1` ("requires elevation") for all 10
   calls: **before the fix, `add_doh_rules()` returned `10` (claiming all 10
   installed); after the fix, it correctly returns `0`.** Same gap existed in
   `teardown()` (delete-rule return code ignored). Fixed; both now check
   `returncode` and set `last_error`.

2. **NOT FIXED (architectural, not a bug) — `is_blocked_ip()` / the in-process
   `_IPSet` is never consulted by anything that makes a real traffic decision.**
   `FirewallManager.is_blocked_ip()` exists, is unit-correct, and is called
   *only* from `tests/test_firewall.py` and `tests/test_ip_leak.py`. It is
   **never** called from `dns_interceptor.py`, `doh_detector.py`, `__main__.py`,
   `ui.py`, or `web/server.py` — those last two only call `.count()` for
   display. On Windows, this means the 12k+ threat-intel CIDR ranges loaded
   into `_IPSet` are counted in the dashboard ("12,348 IP ranges") and never
   otherwise used — no code path blocks, flags, or even logs a connection
   because it matched a CIDR range. This is not a bug I introduced or can
   safely "fix" by wiring in a new enforcement path (that would be a real
   feature, not a scoped defect fix) — it is flagged here as the primary
   finding, exactly analogous to the DoT report's "the guarantee isn't active"
   conclusion.

---

## Evidence

### 1. Return-code checking — mixed by platform (task question #1)

| Method | Platform | Return code checked before claiming success? |
|---|---|---|
| `_LinuxFirewall.setup_chain()` (`firewall.py:253-260`) | Linux | Yes — `-I OUTPUT` result gated (the chain-create `-N` result is deliberately ignored, which is correct: `-N` fails benignly if the chain already exists from a prior run, and the function's own return value comes from the `-I` check). |
| `_LinuxFirewall.add_doh_rules()` (`firewall.py:262-273`) | Linux | Yes — `if r.returncode == 0: ok += 1`. |
| `_LinuxFirewall.add_cidr_rules_batch()` (`firewall.py:275-303`) | Linux | Yes — both the `iptables-restore` batch path and the one-by-one fallback gate on `returncode`. |
| `_WindowsFirewall.setup()` (`firewall.py:332-338`, pre-fix) | Windows | Yes — already correct before this audit. |
| `_WindowsFirewall.add_doh_rules()` (`firewall.py:340-357`, **pre-fix**) | Windows | **No.** `_run([...])` result was discarded; `ok += 1` ran unconditionally inside the `try` block. Only a raised `TimeoutExpired`/`OSError` (binary missing, hang) was treated as failure — a clean non-zero exit from netsh (elevation denied, duplicate rule, malformed syntax, Windows Firewall service disabled) was indistinguishable from success. |
| `_WindowsFirewall.teardown()` (`firewall.py:363-370`, **pre-fix**) | Windows | **No.** Same pattern — delete-rule result discarded. |

**Empirical reproduction (mocked `subprocess.run`, no live netsh call):**

```
netsh calls made: 10
add_doh_rules() returned: 10  (claims 10 rules added)
Expected if return codes were checked: 0

CONFIRMED BUG: every netsh call failed (rc=1, 'requires elevation') but
add_doh_rules() reports ALL rules successfully installed.
```

This is the same silent-failure shape as `mac_randomizer.py`'s adapter cycle:
a subprocess call whose result is thrown away, followed by an optimistic
success signal. The Windows path is the one that matters most for this
project — this is a Windows 11 machine, and `_WindowsFirewall` is the class
active by default (`firewall.py:395-398` selects `_LinuxFirewall` only when
`platform.system() == "Linux"`).

**Fix applied** (`firewall.py`, `_WindowsFirewall` class): `add_doh_rules()`
now only increments `ok` when `r.returncode == 0`; on any failure it records
`self.last_error` with the netsh diagnostic text. `teardown()` now does the
same. `setup()` was already correct but now also records `last_error` for a
consistent diagnostic surface. `FirewallManager.start()` was updated to print
a `[yellow]` warning naming how many of the expected DoH rules actually
installed (and why) whenever the count comes up short, instead of only ever
printing the `[green]✓[/green]` success line regardless of outcome
(`firewall.py:480-491`).

Re-running the same mocked scenario against the fixed code:

```
add_doh_rules() returned: 0
last_error = netsh add rule failed for 94.140.15.15 (rc=1): The requested
operation requires elevation (Run as administrator).
```

The failure is no longer swallowed.

### 2. Is `_IPSet` / `is_blocked_ip()` actually consulted by the DNS decision path? (task question #2)

No. Full-repo grep for `is_blocked_ip`:

```
tests\test_firewall.py:116,127,128,129,130
tests\test_ip_leak.py:160,162,164
valkyrie\firewall.py:384 (docstring example), 506 (definition)
```

Every call site outside `firewall.py` itself is a test. `dns_interceptor.py`'s
decision pipeline (documented at `dns_interceptor.py:8-13`: user rules →
intelligence memory → blocklist/scanner → threat classifier → baseline
anomaly) has **no reference to `firewall`, `FirewallManager`, or
`is_blocked_ip`** anywhere in the file — confirmed by grep returning zero
matches. `DNSInterceptor.__init__` (`dns_interceptor.py:91-107`) does not
accept a firewall parameter at all, and `__main__.py:624-639` — the only
place `DNSInterceptor(...)` is constructed for real use — does not pass one
either.

`firewall` is only wired into two other places, both display-only:
- `ui.py:70,149` — `self._firewall.count()` for the dashboard row.
- `web/server.py:12,54,137` — same, `state.firewall.count()`.

`doh_detector.py` is a separate, independent mechanism: it scans
`psutil.net_connections()` every 5s for established TCP/443 connections to
the 10 hardcoded `DOH_PROVIDER_IPS` and **logs/alerts** — it does not call
into `firewall.py` at all and is not blocking anything itself; the actual
blocking of those same 10 IPs comes from the kernel DoH rules that
`FirewallManager.start()` installs independently. That part is consistent and
fine on its own.

**What this means concretely:** the module docstring says the firewall
"Catches apps that hardcode IP addresses and skip DNS resolution entirely"
(`firewall.py:3-5`) via "IP ranges — CIDRs from threat-intel feeds" (line 9).
On Linux this is true — CIDRs are installed as real iptables DROP rules in
the kernel, independent of any in-process check. **On Windows it is not
true for the CIDR ranges**: `_WindowsFirewall.add_cidr_rules_batch()` is a
documented no-op (`firewall.py:359-361`, "_IPSet handles it") and the class
docstring explicitly states "_IPSet covers all 12k ranges for Valkyrie's own
connection logging and alerting" (`firewall.py:326-327`) — but there is no
logging or alerting consumer either. A Windows process that hardcodes a
tracker IP found only in the CIDR feeds (not the 10 DoH IPs) is not blocked,
not flagged, and not logged by this component. Only the 10 hardcoded DoH IPs
get real Windows kernel enforcement (via the netsh rules just fixed above).

This is not a "bug that can be fixed with a return-code check" — it is a
missing integration (wiring `is_blocked_ip()` or the raw `_ipset` into the
DNS interceptor's per-connection path, or into a new outbound-connection
watcher, would be a feature addition, not a safe scoped fix) and is reported
here as the audit's primary finding, per the task's read-only-first
constraint.

### 3. `FIREWALL_NEVER_BLOCK` / `FIREWALL_DOH_IPS` consistency (task question #3)

`FIREWALL_NEVER_BLOCK` (`config.py:147-154`): loopback, RFC1918 ranges,
link-local, and `DNS_UPSTREAM` (the configured upstream resolver IP — so the
firewall can never accidentally block DNS forwarding itself).

- `_in_never_block()` (`firewall.py:82-95`) is applied at **feed-parse time**
  only, inside `_parse_feed()` (`firewall.py:107-118`): every CIDR from a
  downloaded feed is checked against `FIREWALL_NEVER_BLOCK` before being added
  to the merged set, so a hostile/broken feed entry for `10.0.0.0/8` etc.
  cannot make it into `blocked_ips.txt`. Verified in `test_firewall.py`
  section 8 ("no RFC1918 in blocklist" — PASS) and section 3/7 ("Private range
  exclusion via FirewallManager" — PASS, all 4 checks).
- **No inverted-logic risk found.** `_in_never_block` is a pure "return True
  if it overlaps a protected range" predicate consumed with the correct
  polarity (`if cidr and not _in_never_block(cidr): result.add(cidr)` —
  `firewall.py:116`) — protected ranges are excluded, not included.
- One gap: `_in_never_block` is applied when parsing **downloaded feeds**
  and is exercised again in the CIDR test bench, but it is **not
  re-applied** to `FIREWALL_DOH_IPS` merges in `start()`/`update()`
  (`firewall.py:465,502`: `all_cidrs = cidrs | set(FIREWALL_DOH_IPS)`).
  This is not currently dangerous — `FIREWALL_DOH_IPS` is a small hardcoded
  literal list of public resolver IPs (`config.py:136-142`), none of which
  overlap `FIREWALL_NEVER_BLOCK` — but it means a future edit that added a
  private/loopback address to `FIREWALL_DOH_IPS` by mistake would not be
  caught by any code path, only by (accidental) code review. Low severity,
  noted but not changed, since `FIREWALL_DOH_IPS` isn't user- or
  feed-controlled input.
- `FIREWALL_DOH_IPS` is applied consistently: merged into `_ipset` on every
  `start()`/`update()` call (`firewall.py:465,502`) and passed to
  `add_doh_rules()` for real kernel enforcement on both platforms
  (`firewall.py:472-473`). No path skips it.

### 4. Test coverage — same class of gap as the MAC bug? (task question #4)

**Partially — real coverage exists, but not on the exact path that was
broken, and it required admin privileges this session happened to have.**

`tests/test_firewall.py` section 9 ("Kernel rule installation") *does* call
`fw3.start()` for real and checks `count > 0` — and in this session (running
elevated, evidenced by "12,348 rules installed and removed cleanly" and
`test_ip_leak.py`'s Windows DoH checks passing against live kernel state)
this test would have caught total netsh failure via `count == 0`. However:

- It does **not** check that the reported `doh_ok` count matches the
  expected `len(FIREWALL_DOH_IPS)` — a **partial** failure (e.g. 6 of 10 DoH
  rules installed due to a duplicate-name collision or throttling) would
  still show `count > 0` and pass, silently under-reporting real coverage.
  This is exactly the shape of gap the return-code fix now surfaces via
  `last_error`, but no test asserts on it yet.
- `tests/test_ip_leak.py`'s kernel-drop test (`test_kernel_drop()`,
  `test_ip_leak.py:100-146`) is explicitly **Linux-only**
  (`if platform.system() != "Linux": skip(...)`) — on this Windows machine it
  unconditionally skips, so **there is no test on this platform that proves
  a netsh-installed rule actually drops a packet**, unlike the Linux
  kernel-drop test which does a real reachability check before/after. This
  mirrors the MAC report's finding #6 almost exactly: "green tests say
  nothing about live behavior" — except here the live-behavior test exists,
  it's just platform-gated to the one platform (Linux) that is not this
  machine.
- No test calls `is_blocked_ip()` through `dns_interceptor.py` or any
  production pipeline — all `is_blocked_ip()` tests instantiate
  `FirewallManager` directly and call it themselves (`test_firewall.py:113-116`,
  `test_ip_leak.py:155-164`), so the tests **cannot** detect that nothing in
  production ever calls this method. Green tests here validate the method's
  internal correctness, not its use.

### 5. Bare `except Exception: pass` audit (task question #5)

Grep of all exception handlers in `firewall.py`:

| Location | Handler | Assessment |
|---|---|---|
| `firewall.py:147-148` `fetch_ip_blocklist` | `except Exception as exc: _print(f"Warning: {label}: {exc}")` | Fine — logged, non-fatal (one feed failing shouldn't block others). |
| `firewall.py:439-441` `FirewallManager.start` | `except Exception as exc: self._print(...); cidrs = set()` | Fine — logged, degrades to DoH-only. |
| `firewall.py:478-480` `FirewallManager.stop` (pre- and post-fix) | `except Exception as exc: self._print(f"...warning: {exc}")` | Fine — logged, not swallowed silently. |
| `firewall.py:492-495` `FirewallManager.update` | `except Exception as exc: self._print(...); return self._rule_count` | Fine — logged. |
| `_LinuxFirewall.teardown()` (`firewall.py:311-314`, pre-fix) | `except (subprocess.TimeoutExpired, OSError): pass` | **Silent**, but scoped to cleanup-on-shutdown of a best-effort chain teardown — genuinely low stakes (worst case: a leftover iptables rule, not a false sense of security about active protection). Left as-is; not the security-critical direction of failure (fails toward "rule stays", not "rule silently isn't applied"). |
| `_LinuxFirewall.add_doh_rules` / `add_cidr_rules_batch` (pre- and post-fix) | `except (subprocess.TimeoutExpired, OSError): pass` inside a per-item loop | Return-code already gates the `ok` counter correctly (see §1); the bare `pass` here only prevents one bad IP from crashing the whole batch — the caller still sees an accurate `ok` count that's short of the input length. Acceptable. |
| `_WindowsFirewall.add_doh_rules` / `teardown` (**pre-fix**) | `except (subprocess.TimeoutExpired, OSError): pass`, combined with discarded return code | **This was the security-relevant one** — the only handler in the file where "silently pass" was paired with an unconditional success signal (`ok += 1` outside any success check). Fixed in this audit (§1). |

No bare `except:` (no exception class) exists anywhere in the file — all
handlers at least name `Exception` or specific classes.

---

## What was fixed

`valkyrie/firewall.py`, `_WindowsFirewall` class only:

1. Added `self.last_error: str | None` to `__init__`.
2. `setup()`: now records `last_error` on non-zero return code or exception
   (previously already returned `False` correctly, so behavior is unchanged
   except for the new diagnostic).
3. `add_doh_rules()`: now only counts a rule as installed when
   `r.returncode == 0`; records `last_error` with the netsh diagnostic
   otherwise. **This is the actual fix for the silent-failure bug.**
4. `teardown()`: now checks the delete-rule return code and records
   `last_error` on failure (previously discarded entirely).
5. `FirewallManager.start()`: prints a `[yellow]` warning with the shortfall
   count and `last_error` whenever fewer DoH rules installed than expected,
   instead of only ever printing the unconditional `[green]✓[/green]` line.

Not touched: `start_all.ps1`, `stop_all.ps1` (protected files, per
instructions), `_LinuxFirewall` (already correct), the CIDR-loading/parsing
logic, `FIREWALL_NEVER_BLOCK`/`FIREWALL_DOH_IPS` definitions in `config.py`,
and no live netsh/iptables command was executed against this machine's real
firewall at any point — verification was via code reading plus a mocked
`subprocess.run` in an isolated script, per the task constraints.

## Test results after the fix

```
python tests/test_firewall.py --quick   → All checks PASSED (39/39)
python tests/test_ip_leak.py            → 7 passed, 1 failed, 1 skipped
```

The one `test_ip_leak.py` failure ("ordinary site IP not blocked") is
**pre-existing and unrelated to this fix**: `data/blocked_ips.txt` (this
machine's real, previously-downloaded threat-intel cache — confirmed present
at 12,332–12,348 ranges across runs) contains `198.51.100.0/24` at line 5377,
almost certainly ingested from one of the live feeds in
`FIREWALL_IP_SOURCES` (Spamhaus DROP/eDROP, Firehol level1, or Feodo Tracker
— feeds are known to occasionally list RFC5737 documentation ranges).
`test_ip_leak.py`'s `SAFE_IP = "198.51.100.7"` collides with that real cached
entry. This is a test-fixture/data collision, not a firewall.py defect: the
diff applied here touches only `_WindowsFirewall` netsh return-code handling
and never touches CIDR parsing, loading, or the never-block logic. Confirmed
by inspecting the diff scope directly (`git diff valkyrie/firewall.py`) and
the cache file contents. The `[2] Kernel-level DROP` test is skipped on this
machine because it is explicitly gated `Linux-only` in the test file itself.

---

## Bottom line

- **The Windows netsh silent-failure bug is real, reproduced, and now
  fixed** in the same narrow, low-risk way as the MAC report's proposed fix
  (check the return code; record — don't swallow — the failure). It was not
  previously caught by `test_firewall.py`'s admin-gated integration test
  because that test only asserts `count > 0`, not that the count matches
  what was expected.
- **The bigger finding is architectural, not a bug fix candidate under this
  task's scope**: `is_blocked_ip()` / the in-process CIDR set is fully
  correct in isolation but is dead code from the perspective of the live
  traffic-decision pipeline — nothing in `dns_interceptor.py`, `__main__.py`,
  or any runtime path ever calls it. On Windows specifically, this means the
  12k+ threat-intel CIDR ranges provide **zero actual protection** beyond
  populating a dashboard counter; only the 10 hardcoded DoH resolver IPs get
  real kernel-level enforcement. This claim is verifiable by grep (zero
  non-test call sites) and is not a matter of missing admin privileges or
  live-machine conditions — it would be true on any Windows machine running
  this code as shipped.
- `FIREWALL_NEVER_BLOCK` protection logic itself has no inverted-logic bug
  and is correctly, consistently applied to all feed-derived CIDRs.

---

## Follow-up pass (same day) — the primary finding is now addressed

The audit's headline finding was that `is_blocked_ip()` / the in-process CIDR
set was **dead code from the live traffic-decision path**: on Windows the 12k+
threat-intel ranges only populated a dashboard counter and blocked nothing.
That is no longer true.

**What changed:** the DNS interceptor now screens **resolved answer IPs**, not
just domains. After an allowed query is forwarded and the upstream answer comes
back, `DNSInterceptor._answer_blocked_ip()`
(`valkyrie/dns_interceptor.py`) parses the reply's A/AAAA records and checks
each against `firewall.is_blocked_ip()`. If any answer falls inside a blocked
range, the reply is rewritten to the sinkhole and the event is relabelled
`blocked` with reason `answer IP <ip> in threat-intel range` (category
`firewall_ip`), and the block is fed to the intelligence layer. `__main__.py`
now passes the `FirewallManager` into the interceptor for this purpose.

**Why this is the right integration point:** it catches a case pure domain
matching cannot — a clean/unknown domain that resolves to a known-bad IP
(fast-flux, parked C2, a flagged CDN edge) — and it works identically on
Windows and Linux, closing the platform gap where Windows had no kernel CIDR
enforcement at all. It fails **open** on any parse error (a malformed reply is
passed through unchanged), so the screening can only ever add blocks, never
break resolution.

**Coverage:** `tests/test_firewall.py` section `[8c]` now exercises this path
(blocked answer detected, clean answer passes, garbage wire fails open, no-op
when no firewall is wired in). Section `[8b]` additionally locks in the netsh
return-code fix with a mocked `subprocess.run` — asserting the DoH count is
*exactly* `len(FIREWALL_DOH_IPS)` on full success and `0` when every call
fails, closing the "partial install passes because count > 0" gap called out in
§4 above.

**Still open (unchanged):** kernel-level packet drops for arbitrary CIDRs
remain Linux-only; on Windows the enforcement is at the DNS-answer layer
(above), which does not stop an app that hardcodes a bad IP and skips DNS
entirely. That residual — apps bypassing DNS on Windows — is the one class the
in-process set still cannot reach without a separate outbound-connection
watcher, and is left as documented future work.
