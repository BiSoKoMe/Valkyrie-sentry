# MAC Randomizer — Live-Write Diagnosis Report

**Task 1, Phase 1 (diagnosis only — no edits applied to `mac_randomizer.py`).**
**Branch:** `claude/valkyrie-repo-cleanup-wkijf9`
**Machine:** `LAPTOP-56ETIOCV`, Windows 11, real hardware.
**Method:** read-only registry reads, live replication of the real code paths,
`list2cmdline` inspection of the exact commands issued, and a safe empirical
netsh test. No writes to the registry or any adapter were performed.

---

## TL;DR — where the chain breaks

```
write MAC  ──►  registry NetworkAddress  ──►  adapter cycle  ──►  live read-back
  OK              OK (BA27EB3C8C90)            ✗ NEVER RUNS        ✗ still original
                                               (BROKEN LINK)        A8:41:F4:DD:F1:6C
```

The registry write **succeeds**. The adapter **cycle** (disable/enable that makes
Windows load the new `NetworkAddress`) **does not run successfully**, so the live
MAC never changes. The code then **returns `True` anyway** and logs
"MAC randomised" — a textbook silent failure.

**Root cause is NOT the registry key lookup and NOT the write. It is `_apply_windows`'s
adapter-cycle step, compounded by unconditional `return True`.**

---

## Evidence

### 1. Elevation (diagnosis point #1 — prime suspect)

```
User: LAPTOP-56ETIOCV\badam
Elevated(Admin): False
_is_windows_admin() = False
```

This session is **not** elevated. `randomize()` has a correct guard
(`mac_randomizer.py:102-107`) that refuses and sets `last_error` when not admin —
that part is good and is **not** a silent failure. However, the registry already
contains a written `NetworkAddress` (below) whose value never reached the live
adapter, which proves the failure also exists **downstream of** the admin guard,
in the cycle step. Elevation is necessary but not sufficient; the cycle is
independently broken.

### 2. Adapter-key resolution — fix #2 is intact (verified live)

`_find_windows_adapter_key('Wi-Fi', <class-guid>)` returned:

```
SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0008
```

Cross-checked against the raw registry:

```
0008  NetCfgInstanceId={66479D68-6793-461E-B811-7C77CFF82724}  Realtek 8852BE Wireless LAN WiFi 6 PCI-E NIC
```

and against `getmac /v` (Wi-Fi transport = `\Device\Tcpip_{66479D68-...}`) and
`Get-NetAdapter` (Wi-Fi = Realtek 8852BE). **The two-step lookup
(`Connection\Name` → `NetCfgInstanceId`) resolves to the correct, active adapter
key.** The old DriverDesc-matching bug is not present. **Fix #2 has not regressed.**

### 3. Registry write landed — but live MAC did not change (the smoking gun)

| | Value |
|---|---|
| `...\0008\NetworkAddress` (registry) | `BA27EB3C8C90` → `BA:27:EB:3C:8C:90` |
| Wi-Fi live MAC (`Get-NetAdapter`) | `A8-41-F4-DD-F1-6C` (factory Realtek OUI `A8:41:F4`) |

The written value is well-formed for this path: 12 hex chars, no separators,
uppercase, and locally-administered (`BA` → 2nd nibble `A ∈ {2,6,A,E}`, unicast
bit clear). **So the write format is correct and the write reached the correct
key — yet the live interface still reports its original hardware MAC.** The only
way both can be true is that **the adapter was never cycled**, so Windows never
loaded the new `NetworkAddress`.

### 4. The cycle command is malformed (the mechanism)

`subprocess.list2cmdline` of the exact list the code passes
(`mac_randomizer.py:265-273`):

```
disable -> netsh interface set interface \"Wi-Fi\" disable
enable  -> netsh interface set interface \"Wi-Fi\" enable
```

The interface name is `f'"{iface}"'` — it carries **literal embedded quote
characters**. Under `subprocess` (no shell), netsh receives an interface name of
`"Wi-Fi"` *including the quotes*, which matches **no** interface. netsh matches
alias names literally; the correct form is a bare `name=<alias>` token.

Safe empirical test (target = **disconnected** `Ethernet`, never the Wi-Fi uplink;
non-admin so nothing changes):

```
BUGGY (as code):   rc=1  out='The requested operation requires elevation (Run as administrator).'
CORRECT syntax:    rc=1  out='The requested operation requires elevation (Run as administrator).'
```

At non-admin privilege the elevation check fires first and masks the name-parse
difference at runtime — but `list2cmdline` proves the malformed argument is what
gets sent, and the registry-vs-live mismatch in §3 proves the cycle did not take
effect on a run where the write itself succeeded.

### 5. Silent failure confirmed in code

`_apply_windows` (`mac_randomizer.py:265-274`):
- both netsh calls use `capture_output=True` with **no return-code check**;
- the method ends with an **unconditional `return True`**.

So a failed disable, a failed enable, a wrong name, or an elevation denial all
produce `return True`. `randomize()` then logs `"MAC randomised: Wi-Fi → …"`
(`mac_randomizer.py:116`) and reports success. The application believes the MAC
changed when it did not. This is exactly the "no errors, so it worked" class the
task forbids.

### 6. Why 11/11 unit tests pass while the live write is broken

`test_mac.py` covers only: MAC **generation** format, OUI bytes, LAA bit, backup
JSON round-trip, never-randomise exclusions, and `status()` returning a dict.
**None of the 11 tests call `_apply_windows`, write the registry, or invoke
netsh.** The entire apply/cycle path — the part that is broken — has **zero test
coverage**. Green tests here say nothing about live behavior.

### 7. Secondary finding — fix #1 (hyphen-vs-colon "accept both") is NOT in the regex

Measured:

```
02:0C:29:C7:35:FF  colon_valid=True  hyphen_valid=False
```

`_MAC_RE` (`mac_randomizer.py:38`) accepts **colon format only**. Hyphen-separated
MACs fail `_is_valid_mac`. This is **not** the cause of the live-write failure
(every internal caller normalises hyphen→colon before validating — e.g.
`_read_current_mac` at `mac_randomizer.py:353`), so today it is a latent gap, not
an active break. But if the intended contract is "accept both," the regex does
not honour it. Flagging for the fix proposal; low priority relative to the cycle.

---

## Root cause (ranked)

1. **PRIMARY — `_apply_windows` never cycles the adapter, and hides it.**
   - (a) netsh interface name is passed with embedded quotes (`\"Wi-Fi\"`) → matches
     no interface (proven via `list2cmdline`).
   - (b) return code is never checked and the method `return True`s unconditionally
     → every failure is swallowed.
   - Net measured effect: registry `NetworkAddress=BA27EB3C8C90`, live MAC still
     `A8:41:F4:DD:F1:6C`. The write→registry link is fine; the cycle→apply link is
     where it breaks.

2. **ENVIRONMENTAL — not elevated.** Correctly guarded in `randomize()`, so not a
   silent failure by itself, but a required precondition for any real fix
   verification (the cycle needs admin).

3. **SECONDARY — no `_is_valid_mac` hyphen acceptance** (latent; not the live break).

---

## Proposed fix (NOT applied — `mac_randomizer.py` is protected; awaiting approval)

Scope: `_apply_windows` only, plus an optional one-line regex change for finding #7.
Three changes:
1. Pass the interface name as a bare `name=<iface>` token and use documented
   `admin=disabled` / `admin=enabled` (no embedded quotes).
2. Check each netsh return code; on failure set `last_error` and `return False`.
3. **Verify on the machine**: after the cycle, read the live MAC back and compare
   to what was written; if they differ, `return False` with a diagnostic
   `last_error` — so the code itself refuses to claim success it cannot prove.

Full proposed diff is in the assistant message accompanying this report.

## Re-verification plan (after approval + apply)

Because the cycle needs Administrator and this session is non-elevated, the final
proof must run in an **elevated** shell against a real adapter:
1. Elevated: run `randomize('Wi-Fi')` (or `python -m valkyrie --mac-rand`).
2. Read `...\0008\NetworkAddress` (registry) **and** `Get-NetAdapter -Name Wi-Fi`
   (live) — they must now be **equal**.
3. Confirm `test_mac.py` still reports **11/11**.

Note: cycling Wi-Fi briefly drops connectivity during the disable/enable — expected
for a MAC change. This cannot be executed from the current non-elevated,
non-interactive session; it needs an Administrator run.

---

## STOP

Per the task: diagnosis complete, report written, no edits applied to the
protected file. Proposed fix is presented as a diff for approval below. **Not**
proceeding to Task 2 (DoT) until this Task 1 checkpoint is approved.
