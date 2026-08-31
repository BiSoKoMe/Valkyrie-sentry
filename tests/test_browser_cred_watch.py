#!/usr/bin/env python3
"""Browser credential-store watch (valkyrie/browser_cred_watch.py) - T1555.003.

  [1] credential_store_paths() finds Chromium + Firefox stores, skips system
      pseudo-accounts (Public/Default/...)
  [2] poll_once() emits a HIGH/T1555.003 event for a non-browser handle hit
  [3] Cooldown - the SAME (pid, path) hit is not re-emitted every poll tick
  [4] A hit from a known BROWSER process itself is never reported (real scan)
  [5] A hit from an unrelated process IS reported (real scan)
  [6] A raising emitter never breaks the watch
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_FAILURES: list[str] = []


def _check(label: str, ok: bool) -> None:
    print(f"  [{'+' if ok else '!'}] {label}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        _FAILURES.append(label)


def main() -> int:
    import tempfile
    import time
    from valkyrie.browser_cred_watch import CredentialStoreWatch, credential_store_paths
    from valkyrie import telemetry as T

    print("\n=== browser credential-store watch ===\n")

    print("[1] credential_store_paths() — synthetic user profile tree")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        # A real interactive user with a Chrome profile + a Firefox profile.
        chrome_default = root / "alice" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
        chrome_default.mkdir(parents=True)
        (chrome_default / "Login Data").write_bytes(b"x")
        ff_profile = root / "alice" / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles" / "abcd.default-release"
        ff_profile.mkdir(parents=True)
        (ff_profile / "logins.json").write_bytes(b"{}")
        # System pseudo-accounts that must be skipped.
        (root / "Public" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default").mkdir(parents=True)
        (root / "Default" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default").mkdir(parents=True)

        paths = credential_store_paths(users_root=root)
        names = {p.name for p in paths}
        _check("finds Chrome's Login Data", "Login Data" in names)
        _check("finds Firefox's logins.json", "logins.json" in names)
        _check("only alice's profile contributed paths",
               all("alice" in str(p) for p in paths))
        _check("Public/Default pseudo-accounts skipped",
               not any("Public" in str(p) or str(p).count("Default") > 1 for p in paths))

    print("\n[2] poll_once() — a non-browser handle hit becomes a T1555.003 event")
    emitted: list = []
    watch = CredentialStoreWatch(emit=emitted.append, cooldown=0.0)
    watch._paths_lower = {r"c:\users\alice\appdata\local\google\chrome\user data\default\login data"}
    watch._scan = lambda: [{"pid": 4242, "name": "evil_stealer.exe",
                            "path": r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data"}]
    n = watch.poll_once()
    _check("emits exactly one event", n == 1 and len(emitted) == 1)
    ev = emitted[0]
    _check("category is process", ev.category == T.CAT_PROCESS)
    _check("severity is HIGH (this signal never needs corroboration)", ev.severity == T.SEV_HIGH)
    _check("action is flagged", ev.action == T.ACT_FLAGGED)
    _check("carries the T1555.003 technique",
           "T1555.003" in ev.fields.get("technique", ""))
    _check("carries the browser_cred_access label",
           "browser_cred_access" in ev.labels)
    _check("actor is the suspicious process, not the browser",
           ev.actor_name == "evil_stealer.exe" and ev.actor_pid == 4242)

    print("\n[3] Cooldown — the same (pid, path) is not re-emitted every tick")
    emitted2: list = []
    watch2 = CredentialStoreWatch(emit=emitted2.append, cooldown=10_000.0)
    hit = [{"pid": 99, "name": "x.exe", "path": r"C:\a\Login Data"}]
    watch2._scan = lambda: hit
    n1 = watch2.poll_once()
    n2 = watch2.poll_once()
    _check("first poll emits", n1 == 1)
    _check("second poll (within cooldown) emits nothing new", n2 == 0)
    _check("still only one event total", len(emitted2) == 1)

    print("\n[4]/[5] Real _scan() — browser processes excluded, others included")
    import valkyrie.browser_cred_watch as bcw

    class _FakeFile:
        def __init__(self, path):
            self.path = path

    class _FakeProc:
        def __init__(self, pid, name, files, create_time=1000.0, raise_on_open=False):
            self.pid = pid
            self.info = {"pid": pid, "name": name, "create_time": create_time}
            self._files = files
            self._raise_on_open = raise_on_open
            self.open_files_calls = 0

        def open_files(self):
            self.open_files_calls += 1
            if self._raise_on_open:
                raise PermissionError("access denied (simulated)")
            return [_FakeFile(p) for p in self._files]

    target = r"c:\users\alice\appdata\local\google\chrome\user data\default\login data"
    fake_procs = [
        _FakeProc(100, "chrome.exe", [target.upper()]),      # the OWNING browser
        _FakeProc(200, "mimikatz.exe", [target.upper()]),    # a real hit
        _FakeProc(300, "notepad.exe", [r"C:\Users\alice\notes.txt"]),  # unrelated file
    ]
    if bcw._PSUTIL:
        orig_process_iter = bcw.psutil.process_iter
        bcw.psutil.process_iter = lambda *a, **k: fake_procs
        try:
            watch3 = CredentialStoreWatch(emit=lambda ev: None)
            watch3._paths_lower = {target}
            hits = watch3._scan()
            _check("chrome.exe (the owning browser) is excluded",
                   not any(h["pid"] == 100 for h in hits))
            _check("an unrelated process holding the same file IS flagged",
                   any(h["pid"] == 200 for h in hits))
            _check("a process with no matching open file is not flagged",
                   not any(h["pid"] == 300 for h in hits))
        finally:
            bcw.psutil.process_iter = orig_process_iter
    else:
        print("  SKIP (psutil not installed)")

    print("\n[7]-[11] Identity-cached open_files() (Beta 0.5.9: a live profile "
          "found this call was 70.7% of idle CPU - see "
          "docs/BETA_0_5_TELEMETRY_RELIABILITY.md). Six required checks:")
    if bcw._PSUTIL:
        proc_a = _FakeProc(500, "suspicious.exe", [target.upper()], create_time=2000.0)

        print("  [7] a newly-created non-browser process still gets inspected")
        bcw.psutil.process_iter = lambda *a, **k: [proc_a]
        try:
            watch7 = CredentialStoreWatch(emit=lambda ev: None, backstop_interval=60.0)
            watch7._paths_lower = {target}
            hits7 = watch7._scan()
            _check("first-ever scan inspects the new process",
                   proc_a.open_files_calls == 1)
            _check("and correctly flags it", any(h["pid"] == 500 for h in hits7))

            print("  [8] the SAME (pid, create_time) does not pay open_files() "
                  "again on the very next poll")
            watch7._scan()
            _check("second scan (well within backstop_interval) does NOT "
                   "call open_files() again", proc_a.open_files_calls == 1)

            print("  [9] PID reuse with a DIFFERENT create_time counts as a new process")
            proc_a_reused = _FakeProc(500, "suspicious.exe", [target.upper()], create_time=9999.0)
            bcw.psutil.process_iter = lambda *a, **k: [proc_a_reused]
            watch7._scan()
            _check("a different create_time under the same pid is inspected fresh",
                   proc_a_reused.open_files_calls == 1)
            _check("the OLD (pid, create_time) instance is not what got skipped - "
                   "it simply no longer exists this scan",
                   proc_a.open_files_calls == 1)

            print("  [10] existing (long-lived) processes eventually receive "
                  "the backstop scan")
            bcw.psutil.process_iter = lambda *a, **k: [proc_a_reused]
            # Simulate time passing well beyond the backstop interval,
            # without a real sleep.
            watch7._inspected_at[(500, 9999.0)] = time.time() - 61.0
            watch7._scan()
            _check("backstop interval elapsed -> inspected again",
                   proc_a_reused.open_files_calls == 2)
        finally:
            bcw.psutil.process_iter = orig_process_iter

        print("  [11] a process that fails inspection is not permanently "
              "excluded - just deferred to the same backstop cadence")
        proc_denied = _FakeProc(600, "locked.exe", [], create_time=3000.0,
                                raise_on_open=True)
        bcw.psutil.process_iter = lambda *a, **k: [proc_denied]
        try:
            watch11 = CredentialStoreWatch(emit=lambda ev: None, backstop_interval=60.0)
            watch11._paths_lower = {target}
            hits11 = watch11._scan()
            _check("inspection failure does not raise out of _scan()", hits11 == [])
            _check("open_files() was attempted once", proc_denied.open_files_calls == 1)
            _check("the failed attempt IS recorded (not left None forever)",
                   (600, 3000.0) in watch11._inspected_at)
            watch11._scan()
            _check("immediately after: not retried (deferred like a success would be)",
                   proc_denied.open_files_calls == 1)
            watch11._inspected_at[(600, 3000.0)] = time.time() - 61.0
            watch11._scan()
            _check("after the backstop interval: retried, not permanently poisoned",
                   proc_denied.open_files_calls == 2)
        finally:
            bcw.psutil.process_iter = orig_process_iter
    else:
        print("  SKIP (psutil not installed)")

    print("\n[6] A raising emitter never breaks the watch")
    def _boom(_ev):
        raise RuntimeError("bad sink")
    watch4 = CredentialStoreWatch(emit=_boom, cooldown=0.0)
    watch4._scan = lambda: [{"pid": 1, "name": "x.exe", "path": "p"}]
    try:
        watch4.poll_once()
        _check("poll_once swallows emitter exceptions", True)
    except Exception:
        _check("poll_once swallows emitter exceptions", False)

    print("\n" + "=" * 52)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
