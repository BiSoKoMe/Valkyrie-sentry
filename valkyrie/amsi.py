"""AMSI content scanning - a real malware verdict from the OS antimalware engine.

Valkyrie ships no signature engine and will not fake one: an internet-scale
signature cloud is rank-6 "needs infra" in ``docs/GAP_ANALYSIS.md``. But the
honest local path has always been documented there too - *ask the engine that
already has one*. On Windows that surface is *AMSI*, the Antimalware Scan
Interface: the OS-documented API that the registered antimalware provider
(Microsoft Defender by default, or a third-party AV) answers with a real verdict
on arbitrary content.

**What this adds that Valkyrie did not have.** Until now every endpoint verdict
was a heuristic - a rule matched a command line, a scorer found a shape, an
entropy check crossed a threshold. Valkyrie had *zero* content conviction: it
could say "this script looks obfuscated" but never "this content is
Trojan:PowerShell/Malgent". Two concrete gains:

  * **Content conviction.** A real malware name for script content and files,
    from an engine with a signature corpus Valkyrie will never have.
  * **Correlatable verdicts.** The conviction enters Valkyrie's own pipeline as
    a ``Detection``, so it participates in kill-chain correlation and the
    sequence IOAs. "The AV convicted this script" AND "this same lineage then
    touched LSASS" becomes ONE incident with one timeline. Defender alone does
    not feed Valkyrie's graph; that correlation is the added value.

**Honest boundaries - read these before believing a verdict.**

  * ``not_detected`` is NOT proof of clean. It means no registered provider had
    an opinion. Absence of a signature is not absence of malware.
  * If Defender is the provider, script content Valkyrie scans here was very
    likely *already* scanned by Defender's own AMSI hook when PowerShell ran it.
    Valkyrie is not a second scanner and does not claim to add detection there -
    it adds the file-path scanning Defender never surfaces to us, and the
    correlation above.
  * With **no** provider registered, AMSI initializes fine and every scan
    returns ``not_detected`` forever. ``available()`` reports only that the API
    initialized. The single honest proof that a provider actually answers is
    ``self_test()`` - see its docstring.
  * A conviction is the *provider's* verdict, not Valkyrie's. We report the
    result and the provider; we do not second-guess or re-score it.

Stdlib-only ctypes, matching ``etw/wineventlog.py`` - no new dependency, no
console window, and it imports cleanly on non-Windows (where ``available()`` is
simply False and every entry point degrades to a no-op).
"""

from __future__ import annotations

import hashlib
import logging
import os
import sys
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, replace
from typing import Optional

log = logging.getLogger("valkyrie.amsi")

IS_WINDOWS = sys.platform == "win32"

# ---------------------------------------------------------------------------
# AMSI_RESULT (amsi.h)
# ---------------------------------------------------------------------------
# The documented ``AmsiResultIsMalware`` macro is ``result >= AMSI_RESULT_DETECTED``.
# The 0x4000-0x4FFF band is an *administrative policy* block (WDAC/AppLocker) -
# that is a block, not a malware conviction, and we keep the two distinct.
AMSI_RESULT_CLEAN                  = 0
AMSI_RESULT_NOT_DETECTED           = 1
AMSI_RESULT_BLOCKED_BY_ADMIN_START = 0x4000      # 16384
AMSI_RESULT_BLOCKED_BY_ADMIN_END   = 0x4FFF      # 20479
AMSI_RESULT_DETECTED               = 0x8000      # 32768

# Dispositions - Valkyrie's vocabulary over the raw enum.
DISP_MALWARE      = "malware"           # provider convicted the content
DISP_BLOCKED      = "blocked_by_admin"  # policy block (WDAC/AppLocker), not a conviction
DISP_CLEAN        = "clean"             # provider explicitly vouched for it
DISP_NOT_DETECTED = "not_detected"      # no provider opinion - NOT "safe"
DISP_UNKNOWN      = "unknown"           # a result the spec does not define
DISP_SKIPPED      = "skipped"           # we chose not to scan (empty/oversized)
DISP_ERROR        = "error"             # the scan call itself failed
DISP_UNAVAILABLE  = "unavailable"       # AMSI not initialized on this host

# Dispositions that mean a provider actually rendered a verdict.
_SCANNED = frozenset({DISP_MALWARE, DISP_BLOCKED, DISP_CLEAN,
                      DISP_NOT_DETECTED, DISP_UNKNOWN})


def classify_amsi_result(result: int) -> str:
    """Map a raw ``AMSI_RESULT`` to a Valkyrie disposition. Pure; unit-tested.

    Deliberately conservative at the edges: an undefined result is ``unknown``
    and is never treated as a conviction. Precision over aggression - a false
    "malware" verdict on a user's own script is the cardinal sin.
    """
    try:
        r = int(result)
    except (TypeError, ValueError):
        return DISP_UNKNOWN
    if r >= AMSI_RESULT_DETECTED:
        return DISP_MALWARE
    if AMSI_RESULT_BLOCKED_BY_ADMIN_START <= r <= AMSI_RESULT_BLOCKED_BY_ADMIN_END:
        return DISP_BLOCKED
    if r == AMSI_RESULT_CLEAN:
        return DISP_CLEAN
    if r == AMSI_RESULT_NOT_DETECTED:
        return DISP_NOT_DETECTED
    return DISP_UNKNOWN


# ---------------------------------------------------------------------------
# Microsoft's AMSI test marker
# ---------------------------------------------------------------------------
# Assembled at runtime from parts rather than written as one literal. Defender
# recognises this marker, and a scanner that reads it *in this source file*
# could quarantine Valkyrie's own code - a self-inflicted outage. The value is
# byte-identical at scan time; only the on-disk representation differs.
_TEST_PREFIX = "AMSI Test Sample: "
_TEST_PARTS  = ("7e72c3ce", "861b", "4339", "8740", "0ac1484c1386")


def amsi_test_sample() -> str:
    """Microsoft's documented, harmless AMSI test marker.

    A conviction on this proves the AMSI path works end-to-end. A *non*-conviction
    proves nothing: this marker is a **Defender-specific signature**, and on a host
    where a third-party AV is installed Defender stands down entirely, leaving a
    provider that has never heard of it. Measured on a live host with Avast +
    McAfee registered: both provider DLLs loaded and answered, and both returned
    ``not_detected`` for this marker *and* for EICAR. See ``AmsiScanner.self_test``.

    It is a *marker*, not malware - it does nothing when executed.
    """
    return _TEST_PREFIX + "-".join(_TEST_PARTS)


# ---------------------------------------------------------------------------
# Provider inspection
# ---------------------------------------------------------------------------
# AMSI providers are in-process COM servers: ``AmsiInitialize`` loads each
# registered provider DLL into the *calling* process. That makes "is a provider
# actually here?" a question we can answer factually - check the registry for
# what is registered, then ask the loader what is resident - instead of
# inferring it from a scan result, which cannot tell "no provider" apart from
# "provider with no opinion".

_AMSI_PROVIDER_KEY = r"SOFTWARE\Microsoft\AMSI\Providers"


def _module_is_loaded(basename: str) -> bool:
    """Is ``basename`` resident in this process? (GetModuleHandleW, no deps.)"""
    if not (IS_WINDOWS and basename):
        return False
    try:
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        k32.GetModuleHandleW.restype = wintypes.HMODULE
        return bool(k32.GetModuleHandleW(basename))
    except Exception:
        return False


def registered_providers() -> list[dict]:
    """Enumerate the AMSI providers registered on this host.

    Returns ``[{clsid, path, exists, loaded}]``. ``loaded`` is only meaningful
    after ``AmsiScanner.start()`` has run in this process.
    """
    if not IS_WINDOWS:
        return []
    out: list[dict] = []
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _AMSI_PROVIDER_KEY) as key:
            count = winreg.QueryInfoKey(key)[0]
            for i in range(count):
                try:
                    clsid = winreg.EnumKey(key, i)
                except OSError:
                    continue
                path = ""
                try:
                    sub = rf"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32"
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub) as ck:
                        path = str(winreg.QueryValueEx(ck, "")[0] or "")
                except OSError:
                    pass
                out.append({
                    "clsid":  clsid,
                    "path":   path,
                    "exists": bool(path) and os.path.exists(path),
                    "loaded": _module_is_loaded(os.path.basename(path)) if path else False,
                })
    except OSError as e:
        log.debug("AMSI provider enumeration failed: %s", e)
    return out


# Self-test conclusions - deliberately tri-state.
SELFTEST_CONFIRMED   = "confirmed"      # a provider convicted the marker: path proven
SELFTEST_INCONCLUSIVE = "inconclusive"  # provider loaded but doesn't know this marker
SELFTEST_NO_PROVIDER = "no_provider"    # nothing registered/loaded: AMSI is a no-op here

_SELFTEST_EXPLAIN = {
    SELFTEST_CONFIRMED: (
        "An antimalware provider convicted the AMSI test marker. The scanning "
        "path is proven end to end: content Valkyrie submits gets a real verdict."
    ),
    SELFTEST_INCONCLUSIVE: (
        "An AMSI provider is loaded and answering, but did not recognise the test "
        "marker. That marker is a Microsoft Defender signature, so a third-party "
        "provider (Avast, McAfee, …) is expected to miss it while still scanning "
        "real content normally. This test cannot confirm or deny the path here — "
        "it is inconclusive, not a failure."
    ),
    SELFTEST_NO_PROVIDER: (
        "No AMSI provider is registered or resident. AMSI initializes but every "
        "scan returns 'not detected' regardless of content, so it contributes "
        "nothing until an antimalware provider is installed."
    ),
}


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AmsiVerdict:
    """One provider verdict. Immutable, serializable, self-describing."""

    disposition:   str
    result:        int   = -1
    content_name:  str   = ""
    scanned_bytes: int   = 0
    elapsed_ms:    float = 0.0
    cached:        bool  = False
    error:         str   = ""

    @property
    def is_malware(self) -> bool:
        """True only for a real conviction - an admin-policy block is not one."""
        return self.disposition == DISP_MALWARE

    @property
    def scanned(self) -> bool:
        """True when a provider actually rendered a verdict on this content."""
        return self.disposition in _SCANNED

    def summary(self) -> str:
        if self.disposition == DISP_MALWARE:
            return f"antimalware provider convicted this content (AMSI result {self.result})"
        if self.disposition == DISP_BLOCKED:
            return "content blocked by administrative policy (WDAC/AppLocker)"
        if self.disposition == DISP_NOT_DETECTED:
            return "no provider opinion (not a clean bill of health)"
        if self.disposition == DISP_CLEAN:
            return "provider vouched for this content"
        if self.error:
            return f"{self.disposition}: {self.error}"
        return self.disposition

    def to_dict(self) -> dict:
        return {
            "disposition":   self.disposition,
            "result":        self.result,
            "content_name":  self.content_name,
            "scanned_bytes": self.scanned_bytes,
            "elapsed_ms":    round(self.elapsed_ms, 3),
            "cached":        self.cached,
            "error":         self.error,
            "is_malware":    self.is_malware,
            "summary":       self.summary(),
        }


# ---------------------------------------------------------------------------
# The scanner
# ---------------------------------------------------------------------------

class AmsiScanner:
    """Thin, resilient ctypes client for the AMSI provider on this host.

    Lifecycle mirrors every other Valkyrie subsystem (``start``/``stop``/
    ``available``/``is_healthy``/``stats``) so the component registry adapts it
    with no special-casing. Every failure path degrades to a no-op verdict -
    a scanner that cannot scan must never take the engine down with it.
    """

    name = "amsi"

    def __init__(
        self,
        app_name: str = "Valkyrie",
        *,
        enabled: bool = True,
        cache_size: int = 512,
        max_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        self._app_name   = app_name
        self._enabled    = bool(enabled)
        self._max_bytes  = int(max_bytes)
        self._cache_size = int(cache_size)

        self._dll = None
        self._ctx = None                       # HAMSICONTEXT
        self._lock = threading.Lock()          # guards ctx lifecycle + cache + stats
        self._cache: "OrderedDict[str, AmsiVerdict]" = OrderedDict()
        self._available: Optional[bool] = None
        self._provider_confirmed: Optional[bool] = None
        self._last_selftest: Optional[dict] = None

        self.stats = {
            "scans": 0, "malware": 0, "blocked": 0, "clean": 0,
            "not_detected": 0, "skipped": 0, "errors": 0,
            "cache_hits": 0, "bytes_scanned": 0, "total_ms": 0.0,
        }
        self.last_error: str = ""

    # -- capability ---------------------------------------------------------

    def available(self) -> bool:
        """Can AMSI run on this host at all? (Windows + ``amsi.dll`` loadable.)

        This is capability, not state - it does NOT mean a provider will answer.
        See ``self_test()`` for the only honest proof of that.
        """
        if self._available is not None:
            return self._available
        if not (IS_WINDOWS and self._enabled):
            self._available = False
            return False
        try:
            import ctypes
            ctypes.WinDLL("amsi.dll")
            self._available = True
        except Exception as e:                      # missing on very old builds
            self.last_error = f"amsi.dll unavailable: {e}"
            self._available = False
        return self._available

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> bool:
        """Initialize the AMSI context. Returns True when scanning is live."""
        if not self.available():
            return False
        with self._lock:
            if self._ctx is not None:
                return True
            try:
                self._bind()
            except Exception as e:
                self.last_error = f"AMSI bind failed: {e}"
                log.warning("AMSI unavailable: %s", e)
                self._ctx = None
                return False
        log.info("AMSI scanner initialized (provider verdicts available)")
        return True

    def stop(self) -> None:
        with self._lock:
            ctx, self._ctx = self._ctx, None
            if ctx is not None and self._dll is not None:
                try:
                    self._dll.AmsiUninitialize(ctx)
                except Exception:
                    pass
            self._cache.clear()

    # Alias so the component registry's restart path reads naturally.
    close = stop

    def is_running(self) -> bool:
        return self._ctx is not None

    def is_healthy(self) -> bool:
        """Healthy when initialized and not failing more often than it succeeds."""
        if not self.available():
            return True          # not applicable on this host - not a fault
        if self._ctx is None:
            return False
        errs, scans = self.stats["errors"], self.stats["scans"]
        return errs <= max(3, scans // 4)

    def _bind(self) -> None:
        """Load amsi.dll, declare prototypes, and initialize the context."""
        import ctypes
        from ctypes import POINTER, byref, c_int, c_ulong, c_void_p, c_wchar_p

        dll = ctypes.WinDLL("amsi.dll")

        dll.AmsiInitialize.argtypes = [c_wchar_p, POINTER(c_void_p)]
        dll.AmsiInitialize.restype  = ctypes.HRESULT
        dll.AmsiUninitialize.argtypes = [c_void_p]
        dll.AmsiUninitialize.restype  = None
        dll.AmsiOpenSession.argtypes = [c_void_p, POINTER(c_void_p)]
        dll.AmsiOpenSession.restype  = ctypes.HRESULT
        dll.AmsiCloseSession.argtypes = [c_void_p, c_void_p]
        dll.AmsiCloseSession.restype  = None
        dll.AmsiScanBuffer.argtypes = [c_void_p, c_void_p, c_ulong, c_wchar_p,
                                       c_void_p, POINTER(c_int)]
        dll.AmsiScanBuffer.restype  = ctypes.HRESULT

        ctx = c_void_p()
        # ctypes.HRESULT raises OSError on a failing HRESULT, so a bad init
        # surfaces as an exception rather than a silently-null context.
        dll.AmsiInitialize(self._app_name, byref(ctx))
        if not ctx.value:
            raise OSError("AmsiInitialize returned a null context")

        self._dll = dll
        self._ctx = ctx

    # -- cache --------------------------------------------------------------

    def _cache_get(self, key: str) -> Optional[AmsiVerdict]:
        with self._lock:
            v = self._cache.get(key)
            if v is not None:
                self._cache.move_to_end(key)
                self.stats["cache_hits"] += 1
            return v

    def _cache_put(self, key: str, verdict: AmsiVerdict) -> None:
        with self._lock:
            self._cache[key] = verdict
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)

    # -- scanning -----------------------------------------------------------

    def scan_bytes(self, data: bytes, content_name: str = "",
                   *, use_cache: bool = True) -> AmsiVerdict:
        """Scan a byte buffer. Never raises - failures come back as verdicts."""
        if not self._enabled:
            return AmsiVerdict(DISP_UNAVAILABLE, content_name=content_name,
                               error="AMSI scanning disabled by configuration")
        if self._ctx is None:
            return AmsiVerdict(DISP_UNAVAILABLE, content_name=content_name,
                               error="AMSI not initialized on this host")
        if not data:
            self._bump("skipped")
            return AmsiVerdict(DISP_SKIPPED, content_name=content_name,
                               error="empty content")
        if len(data) > self._max_bytes:
            # Deliberately NOT truncating: a partial scan that comes back
            # "not detected" is a misleading answer, and misleading is worse
            # than absent.
            self._bump("skipped")
            return AmsiVerdict(DISP_SKIPPED, content_name=content_name,
                               scanned_bytes=len(data),
                               error=f"content exceeds {self._max_bytes} byte scan cap")

        key = ""
        if use_cache:
            key = hashlib.sha256(data).hexdigest()
            hit = self._cache_get(key)
            if hit is not None:
                return replace(hit, cached=True, content_name=content_name)

        verdict = self._scan_call(data, content_name)
        if use_cache and key and verdict.scanned:
            self._cache_put(key, verdict)
        return verdict

    def scan_string(self, text: str, content_name: str = "",
                    *, use_cache: bool = True) -> AmsiVerdict:
        """Scan text. Encoded UTF-16LE, the form providers expect for script content."""
        try:
            data = (text or "").encode("utf-16-le", errors="replace")
        except Exception as e:
            self._bump("errors", str(e))
            return AmsiVerdict(DISP_ERROR, content_name=content_name, error=str(e))
        return self.scan_bytes(data, content_name, use_cache=use_cache)

    def scan_file(self, path: str, *, use_cache: bool = True) -> AmsiVerdict:
        """Scan a file's contents, passing its path as the AMSI content name.

        This is the capability Valkyrie previously had none of: a real malware
        verdict for a process image, a dropped payload, or a triage artifact.
        """
        name = str(path or "")
        try:
            size = os.path.getsize(name)
        except OSError as e:
            self._bump("skipped")
            return AmsiVerdict(DISP_SKIPPED, content_name=name, error=str(e))
        if size > self._max_bytes:
            self._bump("skipped")
            return AmsiVerdict(DISP_SKIPPED, content_name=name, scanned_bytes=size,
                               error=f"file exceeds {self._max_bytes} byte scan cap")
        try:
            with open(name, "rb") as fh:
                data = fh.read(self._max_bytes + 1)
        except OSError as e:
            self._bump("skipped")
            return AmsiVerdict(DISP_SKIPPED, content_name=name, error=str(e))
        return self.scan_bytes(data, name, use_cache=use_cache)

    def _scan_call(self, data: bytes, content_name: str) -> AmsiVerdict:
        """The actual AMSI round trip: open session -> scan -> close session."""
        import ctypes
        from ctypes import byref, c_int, c_void_p

        t0 = time.perf_counter()
        session = c_void_p()
        opened = False
        try:
            self._dll.AmsiOpenSession(self._ctx, byref(session))
            opened = bool(session.value)
            res = c_int(0)
            buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
            self._dll.AmsiScanBuffer(
                self._ctx, ctypes.cast(buf, c_void_p), len(data),
                content_name or None,
                session if opened else None,
                byref(res),
            )
            elapsed = (time.perf_counter() - t0) * 1000.0
            disposition = classify_amsi_result(res.value)
            self._record(disposition, len(data), elapsed)
            return AmsiVerdict(
                disposition   = disposition,
                result        = int(res.value),
                content_name  = content_name,
                scanned_bytes = len(data),
                elapsed_ms    = elapsed,
            )
        except Exception as e:                       # a scan failure is never fatal
            self._bump("errors", str(e))
            log.debug("AMSI scan failed for %r: %s", content_name, e)
            return AmsiVerdict(DISP_ERROR, content_name=content_name,
                               scanned_bytes=len(data),
                               elapsed_ms=(time.perf_counter() - t0) * 1000.0,
                               error=str(e))
        finally:
            if opened:
                try:
                    self._dll.AmsiCloseSession(self._ctx, session)
                except Exception:
                    pass

    # -- self test ----------------------------------------------------------

    def self_test(self) -> dict:
        """Probe the AMSI path and report a **tri-state** conclusion.

        Scanning Microsoft's test marker can only ever *prove a positive*. A
        conviction means the whole path works end to end. A non-conviction is
        genuinely ambiguous, so this does not report it as failure - it checks
        what providers are actually resident and reports one of:

          * ``confirmed``    - a provider convicted the marker. Path proven.
          * ``inconclusive`` - a provider DLL is loaded and answering, but did
            not recognise this marker. Expected for non-Defender AV: the marker
            is a Defender signature. Scanning may still work on real content;
            this test simply cannot tell you.
          * ``no_provider``  - nothing registered or resident. Every scan on
            this host will return ``not_detected`` forever, and AMSI adds
            nothing until an antimalware provider is installed.

        **Side effect, by design:** a provider that *does* convict will log a
        detection in its own history. That entry is the evidence the path works.
        It is why this is on demand and never on a timer.
        """
        verdict = self.scan_string(amsi_test_sample(),
                                   content_name="valkyrie-amsi-selftest",
                                   use_cache=False)
        providers = registered_providers()
        resident = [p for p in providers if p["loaded"]]

        if verdict.is_malware:
            conclusion = SELFTEST_CONFIRMED
        elif resident:
            conclusion = SELFTEST_INCONCLUSIVE
        else:
            conclusion = SELFTEST_NO_PROVIDER

        self._provider_confirmed = (conclusion == SELFTEST_CONFIRMED)
        self._last_selftest = {
            "conclusion":         conclusion,
            "verdict":            verdict.to_dict(),
            "providers":          providers,
            "providers_resident": [os.path.basename(p["path"]) for p in resident],
            "explanation":        _SELFTEST_EXPLAIN[conclusion],
            "ts":                 time.time(),
        }
        return dict(self._last_selftest)

    def provider_state(self) -> str:
        """Factual provider presence, independent of any scan result.

        ``resident`` (a provider DLL is loaded in this process and answering),
        ``registered`` (registered but not yet loaded - call ``start()`` first),
        ``none`` (AMSI is a no-op on this host), or ``unsupported``.
        """
        if not self.available():
            return "unsupported"
        providers = registered_providers()
        if any(p["loaded"] for p in providers):
            return "resident"
        if providers:
            return "registered"
        return "none"

    def last_self_test(self) -> Optional[dict]:
        """The most recent ``self_test`` result, or None if never run."""
        return dict(self._last_selftest) if self._last_selftest else None

    # -- observability ------------------------------------------------------

    def _bump(self, key: str, error: str = "") -> None:
        with self._lock:
            self.stats[key] = self.stats.get(key, 0) + 1
        if error:
            self.last_error = error

    def _record(self, disposition: str, nbytes: int, elapsed_ms: float) -> None:
        with self._lock:
            self.stats["scans"] += 1
            self.stats["bytes_scanned"] += nbytes
            self.stats["total_ms"] += elapsed_ms
            if disposition == DISP_MALWARE:
                self.stats["malware"] += 1
            elif disposition == DISP_BLOCKED:
                self.stats["blocked"] += 1
            elif disposition == DISP_CLEAN:
                self.stats["clean"] += 1
            elif disposition == DISP_NOT_DETECTED:
                self.stats["not_detected"] += 1

    def status(self) -> dict:
        scans = self.stats["scans"]
        providers = registered_providers() if self.available() else []
        return {
            "available":  self.available(),
            "running":    self.is_running(),
            "healthy":    self.is_healthy(),
            "enabled":    self._enabled,
            # Factual provider presence, independent of any scan result. The
            # self-test conclusion is separate and may legitimately be
            # "inconclusive" on a host with a non-Defender provider.
            "provider_state": self.provider_state(),
            "providers":  [{"path": p["path"], "loaded": p["loaded"],
                            "exists": p["exists"]} for p in providers],
            "self_test":  self._last_selftest,
            "max_bytes":  self._max_bytes,
            "cache_size": self._cache_size,
            "cached":     len(self._cache),
            "avg_ms":     round(self.stats["total_ms"] / scans, 3) if scans else 0.0,
            "last_error": self.last_error,
            **self.stats,
        }
