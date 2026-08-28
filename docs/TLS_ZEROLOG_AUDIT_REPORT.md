# TLS Inspector + Zero-Log Mode - Audit Report

**Date:** 2026-07-08.
**Scope:** `valkyrie/tls_inspector.py` (optional HTTPS interception via
mitmproxy) and `valkyrie/zero_log.py` (RAM-only "no disk writes" mode).
**Method:** empirical, on this machine - mitmproxy 12.2.3 is installed here,
so the TLS claims were verified with *real* mitmproxy starts, real socket
probes, and one real proxied HTTPS request, not just code reading. Zero-log
claims were verified with isolated `sqlite3` experiments reproducing the
exact URI/connection patterns the code uses. Same standard as
`docs/MAC_DIAGNOSIS_REPORT.md` and `docs/DOT_VERIFICATION_REPORT.md`: no
exception != it worked, docstring != reality.

---

## TL;DR

| Component | Claim | Verdict |
|---|---|---|
| TLS inspector - CA generation | CA cert is generated and usable | ✅ **HOLDS** - verified live |
| TLS inspector - `start()` return value | `True` means mitmproxy is listening | ❌ **WAS FALSE** - reproduced two ways; **fixed** |
| TLS inspector - real interception | Traffic actually gets intercepted | ✅ **HOLDS** - real HTTPS request round-tripped, `intercept_count` incremented |
| `tests/test_tls.py` coverage | Exercises real interception | ✅ **Yes** - but did not cover the bind-race/failure path (documented, not newly tested) |
| Zero-log - RAM-only Store | No disk file backs the DB | ✅ **HOLDS** - verified empirically (`PRAGMA database_list` shows no file; 5000+ large inserts and a 200k-row sort produced zero temp files on this system) |
| Zero-log - scope ("no disk writes") | *Only* the event Store is RAM-only; other components are untouched by design | ⚠️ **Confirmed gap, as suspected** - `unbound.log`, `data/service_stdout.log`/`service_stderr.log` (NSSM redirect), and blocklist cache all write to disk regardless of zero-log state; `--debug` also prints every domain to stdout independent of `--zero-log` |
| Zero-log - secure wipe | DELETE + `secure_delete` pragma actually scrubs session data | ❌ **WAS FALSE in the real shutdown path** - reproduced the exact ordering bug (`store.stop()` before `zero_log.disable()` destroys the shared-cache DB *before* the wipe runs); **fixed** |
| `tests/test_zero_log.py` coverage | Exercises secure wipe | ⚠️ Passes, but never reproduces the real `__main__.py` shutdown order, so it did not (and still does not) catch the ordering bug directly - it is now prevented at the `__main__.py` call-site instead |

**Bottom line:** both components have the *same* silent-success pattern the
MAC and DoT reports found. TLS inspection's `start()` could report success
before (or despite) an actual bind failure - reproduced twice below. Zero-log's
"secure wipe" could run against a database that no longer existed, because of
shutdown-order sensitivity in `file::memory:?cache=shared` semantics that
nothing in the code accounted for. Both are now fixed with small, scoped
changes. The "RAM-only Store" and "CA generation" claims, by contrast, hold up
under direct empirical testing - not everything here was broken.

---

## Part 1 - `valkyrie/tls_inspector.py`

### 1.1 Does `start()` verify mitmproxy is actually listening? (NO, as designed - reproduced)

Before this fix, `TLSInspector.start()` (`tls_inspector.py:88-138`, prior
version) ran mitmproxy's `DumpMaster` on a background thread and set a
`threading.Event` (`ready`) **immediately after constructing `DumpMaster` and
adding the addon** - i.e. *before* `loop.run_until_complete(master.run())`
even started. Reading mitmproxy's own source confirms the actual socket bind
happens deep inside `Master.run()`:

```python
# mitmproxy/master.py — Master.run()
if ps := self.addons.get("proxyserver"):
    await asyncio.wait([create_task(ps.setup_servers()), ...])
    ...
await self.running()   # Proxyserver.running() sets self.is_running = True
```

So `ready.set()` fired well before `setup_servers()` ran. `start()`'s return
value and `is_running()` were therefore **construction-success signals**, not
**bind-success signals** - exactly the gap the task asked about.

**Reproduced empirically (before the fix), two ways:**

1. **Race window** - probed the raw socket the instant `start()` returned:
   ```
   start() returned True after 0.801 s
   is_running() = True
   IMMEDIATE probe: port NOT open yet -> timed out
   AFTER 1.5s: port OPEN
   ```
   `start()` reported success while the port was demonstrably still closed.

2. **Bind failure (port already in use)** - occupied the target port first,
   then called `start()`:
   ```
   start() returned True
   is_running() right after start(): True
   is_running() after 2s (bind should have failed by now): False
   thread alive: False
   ```
   `start()` returned `True` and the process printed
   `[green]✓[/green] TLS inspector on port {port}` in `__main__.py:796`
   (gated only on `if tls_inspector.start():`) - while mitmproxy's own
   `ErrorCheck` addon had already called `sys.exit(1)` and the background
   thread was dead within ~1-2 seconds. Nothing in `__main__.py` re-checks
   `is_running()` after startup (confirmed by grep - the only call sites are
   the initial `if tls_inspector.start():` and the final `.stop()`), so the
   status box would keep showing `("TLS Inspect", True, "port 8443")` and
   `Protection: ACTIVE` for the rest of the session while **zero interception
   is happening**. This is the same "claims success, actually silently
   failed" pattern as the MAC randomizer bug.

**Fix applied** (`tls_inspector.py`): `ready.set()` is no longer called at
construction time. Instead, a coroutine scheduled on the same event loop
polls mitmproxy's own `proxyserver.is_running` flag (`Proxyserver.running()`
in `mitmproxy/addons/proxyserver.py:114`, which is set only after
`setup_servers()` succeeds) at 0.1s intervals for up to 5s, and separately
checks `master.should_exit`. `ready.set()` now fires only once the *real*
outcome (bound / failed-to-bind) is known. Additionally, the outer exception
handler in the background thread was widened from `except Exception` to
`except BaseException`, because mitmproxy's `ErrorCheck.shutdown_if_errored()`
reports startup failures (e.g. port-in-use) via `sys.exit(1)` - which raises
`SystemExit`, a `BaseException` subclass that `except Exception` does **not**
catch. Without this widening, the failure path would have silently fallen
through to the full `ready.wait()` timeout instead of failing fast.

**Re-verified after the fix**, same two scenarios:

```
SUCCESS CASE: start() -> True after 1.007 s
  port OPEN immediately: correct

FAILURE CASE (port pre-occupied): start() -> False after 0.805 s  (was: True, immediately)
```

`start()`'s return value is now trustworthy in both directions.

### 1.2 CA certificate generation/trust (HOLDS - verified live)

`setup_ca()` (`tls_inspector.py:65-82`) copies mitmproxy's auto-generated CA
(`{confdir}/mitmproxy-ca-cert.pem`) to the stable path `TLS_CA_CERT_PATH`
(`data/valkyrie-ca.pem`). Verified empirically on a real `start()` run:

```
mitmproxy generated cert in confdir exists: True
setup_ca returned: C:\...\data\valkyrie-ca.pem
exists immediately after setup_ca(): True
```

This part is not a silent failure - the file genuinely exists with real
content by the time `setup_ca()` returns, and the install instructions
printed alongside it are accurate for each platform. (Whether a user actually
*installs* the CA into their OS/browser trust store is out of Valkyrie's
control and is correctly flagged in `CA_INSTALL_INSTRUCTIONS` as a manual
step - no false claim is made there.)

### 1.3 `tests/test_tls.py` - real coverage or smoke test? (Real coverage, with one gap)

`tests/test_tls.py` does **not** stop at "mitmproxy binary exists" - it:
- starts a real `TLSInspector` on `TLS_PROXY_PORT`,
- checks the CA file materializes,
- sends an actual HTTP request through the proxy via
  `urllib.request.ProxyHandler` (`test_tls.py:74-88`),
- reads back `inspector.get_intercept_count()`.

Ran it for real on this machine (mitmproxy is installed here):

```
Starting mitmproxy on 127.0.0.1:8443 ...
  PASS — proxy started
  PASS — CA cert file exists
  PASS — inspector reports running
Sending a test HTTPS request through the proxy ...
  PASS — request round-tripped through mitmproxy
  Intercept count: 1

ALL TESTS PASSED
```

`intercept_count` genuinely incremented from 0 to 1 - this is real evidence
of interception, not a rubber-stamp pass. Re-ran after applying the `start()`
fix above: still `ALL TESTS PASSED`, `Intercept count: 1`, confirming the fix
did not regress the happy path.

**Coverage gap (unchanged by this audit):** the test's `time.sleep(1)` before
checking `is_running()` happens to be enough margin to avoid the race in
§1.1 in practice, but it does not exercise the bind-failure path (port
already in use) that this audit reproduced. Given the scope constraint
("don't touch mitmproxy installs / live interception beyond what's already
here"), I did not add a new bind-conflict test case to `test_tls.py` - the
underlying defect is fixed at the source (`tls_inspector.py`) instead, which
is the more direct fix. Flagging the missing negative-path test as a residual
gap for a future pass.

---

## Part 2 - `valkyrie/zero_log.py`

### 2.1 What "RAM-only" actually means (mostly HOLDS, one caveat)

`ZeroLogMode.make_ram_store()` creates a `Store(ram_uri=RAM_DB_URI)` where
`RAM_DB_URI = "file::memory:?cache=shared"` (`config.py:338`). Verified with
an isolated experiment reproducing exactly this URI and connection pattern:

```python
conn = sqlite3.connect('file::memory:?cache=shared', uri=True, check_same_thread=False)
# ... 5000 inserts of 500-byte strings ...
for row in conn.execute('PRAGMA database_list'): print(row)
# -> (0, 'main', '')     <-- empty string = no backing file, genuinely in-RAM
# New tmp files: set()   New cwd files: set()   New data/ files: set()
```

`PRAGMA database_list` reporting an **empty path** for the `main` database is
the authoritative signal that this is a pure in-memory database with no
backing file - not a "trust the URI name" assumption. No files appeared in
the temp dir, cwd, or `data/` even after several thousand inserts.

`journal_mode` for this URI defaults to `memory` (not `WAL`/`DELETE`), so no
`-wal`/`-journal` sidecar files are created either - confirmed via
`PRAGMA journal_mode` returning `('memory',)`.

**Caveat (not a confirmed bug, flagged honestly):** `temp_store` defaults to
`0` ("compile-time default") rather than being explicitly forced to `2`
(always-memory). On this machine, forcing a large `ORDER BY` over 200,000
rows (~400MB) produced **zero** `etilqs_*`/`sqlite_*` temp files in the OS
temp directory - so on this system/SQLite build, large sorts did not spill to
disk. This behavior is not guaranteed by the code itself (no explicit
`PRAGMA temp_store=MEMORY` is set anywhere in `store.py` or `zero_log.py`) and
could differ on other SQLite builds/platforms where the compiled-in default
is disk-backed temp storage. This is a soft gap: the current behavior is
correct here, but it is not a guarantee the code enforces.

`valkyrie_rules.yaml` is documented (module docstring, `zero_log.py:8`) as
still read from disk at startup - this is accurately scoped, not a false
claim, since rules are static configuration, not session/browsing data.

### 2.2 Does zero-log mode cover the *whole* app, or just the Store? (Confirmed gap - matches the DoT report's "claim vs actual scope" pattern)

This was the central question, and the answer is the same shape as the DoT
report: the mechanism that exists does what it says, but other components
that are *not* aware of zero-log mode keep writing to disk regardless.
Verified by reading the actual write call sites, then confirming which files
exist on disk right now on this machine:

| Component | Disk write | Gated by zero-log? |
|---|---|---|
| `Store` events / scan_cache / baselines | RAM only when `ram_uri` set | ✅ Yes - this is the part that works |
| `resolver.py:380` - Unbound log | `DATA_DIR / "unbound.log"`, written unconditionally via `_UNBOUND_CONF_TEMPLATE`'s `logfile` directive | ❌ **No** - resolver has no knowledge of zero-log at all |
| `install_service.bat:261-262` - NSSM service wrapper | `AppStdout` / `AppStderr` set to `data/service_stdout.log` / `data/service_stderr.log` | ❌ **No** - this is an OS-level redirect configured outside Python; zero-log cannot intercept it even in principle, since it happens before any Python code runs |
| `blocklist.py:121` - blocklist download cache | `BLOCKLIST_PATH.write_text(...)` unconditionally when the cached list is stale | ❌ **No** - but this is public tracker-list content, not user browsing history, so the privacy impact is low even though the literal "no disk writes" claim is still violated |
| `dns_interceptor.py:254` - per-query debug print | `print(f"[dns] {qname} decision={decision} proc={proc.name} ...")`, gated on `self._debug` (i.e. `--debug` flag) | ❌ **No** - `args.debug` and `args.zero_log` are fully independent flags in `__main__.py`; nothing disables debug printing when zero-log is active |

**On this machine, `data/service_stdout.log` and `data/service_stderr.log`
genuinely exist** (confirmed via `ls data/`), because `install_service.bat`
configures NSSM to redirect the Windows service's stdout/stderr to those
files unconditionally. Since `console.print(...)` calls throughout
`__main__.py` output plenty of state (CA paths, status boxes, blocklist
update summaries), and `dns_interceptor.py` will print every domain queried
when `--debug` is set, running Valkyrie **as a Windows service with `--debug`
and `--zero-log` together** would write per-domain browsing activity to a
plaintext log file on disk - while the dashboard's `zero_log.status()`
(`zero_log.py:149`) reports `"disk_writes": "none"`. This is a genuine
claim-vs-scope gap, structurally identical to the DoT report's finding that
"DNS is encrypted" didn't hold end-to-end.

**Scope note on the fix:** this class of gap spans `resolver.py`,
`install_service.bat`, `blocklist.py`, and `dns_interceptor.py` - none of
which are `tls_inspector.py` or `zero_log.py`, and `install_service.bat` sits
right next to the explicitly protected `start_all.ps1`/`stop_all.ps1`. Per
the task's read-only-first, narrowly-scoped-fix constraint, I did not modify
these other files. This is reported as an **open gap** for a follow-up task,
not silently fixed or silently ignored.

### 2.3 "Secure wipe" - does it actually overwrite data, or just drop references? (Was broken in the real shutdown path - reproduced and fixed)

`_secure_wipe()` (`zero_log.py:204-233`, prior version) opened a **new**
connection to `RAM_DB_URI`, ran `DELETE FROM {table}` for each table, then set
`PRAGMA secure_delete=ON` - all wrapped in nested bare `except Exception:
pass` blocks. Two independent problems were found and reproduced:

**(a) Pragma ordering was backwards.** `secure_delete` controls whether
*future* deletes zero-fill freed pages; setting it *after* the deletes means
those specific deletes ran under default (non-secure) semantics:

```python
conn.execute('DELETE FROM events')
conn.execute('PRAGMA secure_delete=ON')   # set AFTER delete, as the code did
conn.commit()
# rows are gone from the table, but the DELETE itself did not get the
# secure zero-fill behavior it was supposed to get
```

**(b) The bigger issue - shutdown ordering destroys the DB before the wipe
runs.** `file::memory:?cache=shared` databases are torn down the instant
their *last* open connection closes (documented SQLite shared-cache-in-memory
behavior). `Store`'s writer thread holds the one long-lived connection to
this database; `store.stop()` joins that thread, which closes its connection
as its final act (`store.py:473`). The real shutdown sequence in
`__main__.py`, before this audit, was:

```python
firewall.stop()
store.stop()          # <-- closes the writer thread's connection
if zero_log:
    zero_log.disable()   # <-- _secure_wipe() opens a FRESH connection here
```

Reproduced the exact consequence with an isolated experiment matching this
pattern:

```
data present: [(1, 'supersecret.example.com')]
writer_conn closed (this is what store.stop() does)
secure_wipe conn SELECT failed (table gone): no such table: events
```

By the time `_secure_wipe()` opens its connection, the shared-cache database
has already been destroyed by SQLite itself (because the writer thread's
connection - the last one open - had already closed). `_secure_wipe()`'s
`DELETE FROM events` inside its `try/except Exception: pass` therefore threw
`sqlite3.OperationalError: no such table: events` and was **silently
swallowed** - then the code printed `"Zero log: all session data wiped"` as
if the explicit wipe mechanism had run, when in fact SQLite's own
last-connection teardown had already erased the data, not the code's DELETE
statements. This is functionally harmless from a pure privacy standpoint
(the data is genuinely gone from RAM either way), but it is the **exact same
"success theater" pattern** as the MAC randomizer bug: the code claims a
specific action happened (explicit secure delete) and prints success, but
that action's real code path silently no-ops, and the actual outcome is an
accidental side effect of something else, not the mechanism being tested or
verified.

**Why `tests/test_zero_log.py` didn't catch this:** its "Secure wipe" test
(lines 107-122) calls `zl3.enable()` -> `r3.start()` -> `zl3.disable()`
directly, **without ever calling `r3.stop()`** first. The writer thread's
connection therefore stays open throughout, so `_secure_wipe()`'s fresh
connection always finds a live database in the test - the test cannot
observe the ordering bug because it never reproduces `__main__.py`'s real
shutdown sequence. Ran the existing test before touching anything to
confirm this: **14/14 passed**, including "disable() / secure wipe runs
without error" - a green test that says nothing about the real ordering bug,
same lesson as `test_mac.py`'s 11/11 in the MAC report.

**Fixes applied:**
1. `zero_log.py::_secure_wipe()` - moved `PRAGMA secure_delete=ON` to *before*
   the `DELETE FROM` statements, with a comment explaining why order matters.
2. `zero_log.py::_secure_wipe()` - added a docstring explaining the
   last-connection-closes-the-DB hazard explicitly, so future callers don't
   reintroduce the ordering bug.
3. `__main__.py` - reordered the shutdown block so `zero_log.disable()` runs
   **before** `store.stop()`, guaranteeing `_secure_wipe()`'s connection is
   opened while the Store's writer-thread connection (or any other) is still
   alive, so the explicit DELETE actually executes against live data:
   ```python
   if zero_log:
       zero_log.disable()
   store.stop()
   ```

**Re-verified after the fix**, reproducing the corrected order:

```
data present: [(1, 'supersecret.example.com')]
DELETE run while writer_conn still open
after wipe (writer_conn still open): []
OK: explicit DELETE actually executed against live data before last-connection teardown
```

And end-to-end using the real `ZeroLogMode`/`Store` pair in the corrected
order (`zl.disable()` then `store.stop()`): the wipe now either explicitly
deletes the rows (if other connections remain) or the table is already gone
because the last connection closed - both outcomes are privacy-safe, but now
the *explicit* mechanism the code claims to use is verified to actually run
against real data rather than silently failing against an empty/nonexistent
database.

### 2.4 Test run after fixes

```
python tests/test_zero_log.py
...
  14 passed  /  0 failed
  RESULT: ALL TESTS PASSED
```

No regressions. Note per the task's expectation: this environment has
mitmproxy installed and is not running elevated for MAC/adapter work (not
relevant here), so both test files ran to completion rather than skipping -
that is the expected "real" path, not a SKIP.

```
python tests/test_tls.py
...
  PASS — request round-tripped through mitmproxy
  Intercept count: 1

ALL TESTS PASSED
```

---

## Summary of changes made

| File | Change | Why |
|---|---|---|
| `valkyrie/tls_inspector.py` | `start()` now waits for mitmproxy's own `proxyserver.is_running` flag (polled via a coroutine on the same event loop) before signalling readiness, instead of signalling immediately after construction; widened the background thread's exception handler to `BaseException` to catch `SystemExit` raised by mitmproxy's `ErrorCheck` addon on startup failure | `start()`'s return value was not trustworthy - reproduced both a race (port not yet open when `True` was returned) and a bind-failure case (`True` returned, proxy dead ~1-2s later) |
| `valkyrie/zero_log.py` | `_secure_wipe()`: set `PRAGMA secure_delete=ON` before the deletes, not after; added a docstring on the last-connection-closes-the-DB hazard | Pragma ordering meant the explicit deletes didn't get secure zero-fill; documented the sharp edge so it isn't reintroduced |
| `valkyrie/__main__.py` | Reordered final shutdown: `zero_log.disable()` now runs before `store.stop()` | Reproduced that the previous order let `store.stop()` destroy the shared-cache in-memory DB before `_secure_wipe()` ran, making the explicit wipe a no-op in the one place it matters - the real app shutdown path |

**Not modified** (explicitly out of scope, or the constraint said not to
touch): `start_all.ps1`, `stop_all.ps1`, `install_service.bat`,
`resolver.py`, `blocklist.py`, `dns_interceptor.py`. The disk-writes-outside-
zero-log-scope gap in §2.2 spans exactly these files and is reported as an
**open gap**, not fixed here.

## Open gaps (not fixed, flagged honestly)

1. **Zero-log mode does not cover the whole app.** `unbound.log`,
   `data/service_stdout.log`/`service_stderr.log` (NSSM), the blocklist
   download cache, and `--debug`'s per-domain stdout printing are all
   unaffected by `--zero-log`. The dashboard's `"disk_writes": "none"` claim
   is only true for the event Store, not for the process as a whole under
   every flag combination (particularly `--debug` + `--zero-log` +
   service mode).
2. **`temp_store` is not explicitly forced to memory-only.** Current
   behavior on this machine/SQLite build shows no disk spill for large
   sorts, but nothing in the code guarantees this on other platforms.
3. **`tests/test_tls.py` has no negative-path (bind-conflict) test case**,
   so a future regression of the `start()` fix would not be caught by the
   existing suite - only by re-running the manual reproduction in §1.1.
4. **`tests/test_zero_log.py`'s secure-wipe test never calls `store.stop()`
   before `disable()`**, so it cannot detect the ordering class of bug fixed
   here if it were reintroduced elsewhere. The fix was applied at the
   `__main__.py` call site rather than by hardening the test, per the
   task's preference for a scoped code fix over test additions in files
   outside the two named modules.

---

## Follow-up pass (same day) - the `--debug` stdout leak is closed

Gap #1's most actionable component - `--debug` printing every resolved domain
to stdout while `--zero-log` is active - is now fixed in `__main__.py`. When
zero-log is active, the DNS interceptor is constructed with per-domain debug
output forced off (`debug = args.debug and not zero_log.is_active()`), and a
startup line tells the user the per-domain trace was suppressed. This removes
the terminal-scrollback trace that otherwise defeated RAM-only operation.

The remaining sub-items of gap #1 (`unbound.log`, NSSM `service_*.log`, the
blocklist cache) are still on-disk by design and untouched - they are written
by external processes/service wrappers, not the event Store, and suppressing
them would change the service/launcher setup (out of scope for a code-level
fix). They remain documented, not silently claimed as covered.
