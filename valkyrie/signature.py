"""Authenticode signature state — the strongest generic signal available.

WHY
---
Almost every behavioural rule in this project describes WHAT a process did.
Signature state describes something orthogonal and much harder for an attacker
to fake: whether the binary doing it is trusted code at all.

That orthogonality is what makes it valuable. "powershell.exe spawned by
winword.exe" needs a rule per parent/child shape and an attacker can pick a pair
nobody wrote a rule for. "an UNSIGNED binary running out of %TEMP% spawned a
shell" generalises across every payload that has ever done it, including the one
written tomorrow, because the attacker cannot sign their malware with a
certificate chaining to a root the machine trusts. They can steal a certificate
(rare, expensive, revocable) or stay unsigned (cheap, and now visible).

This is also the single biggest unlock for imported vendor content: the largest
category of Elastic rules Valkyrie cannot express is the one keying on
code-signature state.

THE THREE RULES THIS MODULE OBEYS
---------------------------------
1. **NEVER BLOCK.** Verification touches the disk and, left at its defaults,
   the network - Authenticode revocation checking will happily make an outbound
   CRL/OCSP request. On a security agent that sits in front of every process
   start, that turns a signature check into a stall, and this codebase has
   already lost a night to a startup path that blocked the event loop.
   Revocation checking is therefore disabled and URL retrieval is cache-only:
   no verification here ever waits on a network.

2. **UNKNOWN IS NOT UNSIGNED.** A file we could not verify - deleted, locked,
   access denied, verification errored - is ``UNKNOWN``, never ``UNSIGNED``.
   Collapsing the two would let a transient read failure manufacture a
   detection, which is the prime-directive violation this project cannot ship.
   Rules that key on signature state must decline to fire on UNKNOWN.

3. **CACHE, KEYED ON IDENTITY NOT PATH.** Verification costs milliseconds and
   process starts arrive in bursts. The cache key includes size and mtime, so a
   binary that is replaced at the same path is re-verified rather than
   inheriting the previous verdict - which is exactly the swap an attacker
   performs.

Non-Windows and missing-API paths degrade to UNKNOWN rather than raising, so
this module is importable and testable anywhere.
"""

from __future__ import annotations

import os
import sys
import threading
from time import monotonic as _monotonic
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Trust(str, Enum):
    """What we know about a file's signature."""

    TRUSTED = "trusted"        # signed, chain verifies to a trusted root
    UNSIGNED = "unsigned"      # verified as carrying NO signature at all
    UNTRUSTED = "untrusted"    # signed, but the signature is not acceptable
                               # (expired, revoked, untrusted root, tampered)
    UNKNOWN = "unknown"        # we could not tell. NEVER treat as unsigned.


# --- WinVerifyTrust result codes we can interpret -------------------------
# Anything not listed collapses to UNKNOWN rather than being guessed at.
_TRUST_E_NOSIGNATURE      = 0x800B0100
_TRUST_E_BAD_DIGEST       = 0x80096010     # content was modified after signing
_TRUST_E_EXPLICIT_DISTRUST = 0x800B0111    # admin/user explicitly distrusts it
_TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
_CERT_E_UNTRUSTEDROOT     = 0x800B0109
_CERT_E_EXPIRED           = 0x800B0101
_CERT_E_CHAINING          = 0x800B010A
_CERT_E_REVOKED           = 0x800B010C
_CRYPT_E_SECURITY_SETTINGS = 0x80092026
_TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
_TRUST_E_ACTION_UNKNOWN   = 0x800B0002

# A signature exists but is not acceptable. Distinguished from UNSIGNED because
# "signed by a revoked cert" and "not signed" are different stories, and the
# first is a much stronger signal.
_UNTRUSTED_CODES = {
    _TRUST_E_BAD_DIGEST, _TRUST_E_EXPLICIT_DISTRUST, _TRUST_E_SUBJECT_NOT_TRUSTED,
    _CERT_E_UNTRUSTEDROOT, _CERT_E_EXPIRED, _CERT_E_CHAINING, _CERT_E_REVOKED,
    _CRYPT_E_SECURITY_SETTINGS,
}


@dataclass(frozen=True)
class SignatureInfo:
    trust: Trust
    code: int = 0
    detail: str = ""

    @property
    def is_trusted(self) -> bool:
        return self.trust is Trust.TRUSTED

    @property
    def known(self) -> bool:
        """False when we could not determine anything. Rules keying on signature
        state must refuse to fire when this is False."""
        return self.trust is not Trust.UNKNOWN

    def to_dict(self) -> dict:
        return {"trust": self.trust.value, "code": self.code, "detail": self.detail}


_UNKNOWN = SignatureInfo(Trust.UNKNOWN, 0, "not evaluated")

# ---------------------------------------------------------------------------
# Win32 plumbing
# ---------------------------------------------------------------------------
_AVAILABLE = False
_wintrust = None
_ACTION_GUID = None

if sys.platform == "win32":                                  # pragma: no cover
    try:
        import ctypes
        from ctypes import wintypes

        class _GUID(ctypes.Structure):
            _fields_ = [("Data1", ctypes.c_ulong),
                        ("Data2", ctypes.c_ushort),
                        ("Data3", ctypes.c_ushort),
                        ("Data4", ctypes.c_ubyte * 8)]

        class _WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD),
                        ("pcwszFilePath", wintypes.LPCWSTR),
                        ("hFile", wintypes.HANDLE),
                        ("pgKnownSubject", ctypes.c_void_p)]

        class _WINTRUST_DATA(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD),
                        ("pPolicyCallbackData", ctypes.c_void_p),
                        ("pSIPClientData", ctypes.c_void_p),
                        ("dwUIChoice", wintypes.DWORD),
                        ("fdwRevocationChecks", wintypes.DWORD),
                        ("dwUnionChoice", wintypes.DWORD),
                        ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
                        ("dwStateAction", wintypes.DWORD),
                        ("hWVTStateData", wintypes.HANDLE),
                        ("pwszURLReference", wintypes.LPCWSTR),
                        ("dwProvFlags", wintypes.DWORD),
                        ("dwUIContext", wintypes.DWORD),
                        ("pSignatureSettings", ctypes.c_void_p)]

        class _CATALOG_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD),
                        ("wszCatalogFile", ctypes.c_wchar * 260)]

        class _WINTRUST_CATALOG_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD),
                        ("dwCatalogVersion", wintypes.DWORD),
                        ("pcwszCatalogFilePath", wintypes.LPCWSTR),
                        ("pcwszMemberTag", wintypes.LPCWSTR),
                        ("pcwszMemberFilePath", wintypes.LPCWSTR),
                        ("hMemberFile", wintypes.HANDLE),
                        ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
                        ("cbCalculatedFileHash", wintypes.DWORD),
                        ("pcCatalogContext", ctypes.c_void_p),
                        ("hCatAdmin", wintypes.HANDLE)]

        _wintrust = ctypes.WinDLL("wintrust.dll")
        _kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        # argtypes are MANDATORY here, not hygiene. Without them ctypes marshals
        # pointer and HANDLE arguments as C int, which silently truncates every
        # 64-bit handle. The catalog lookup then fails for every file and each
        # one is reported UNSIGNED - a wrong answer that looks exactly like a
        # working implementation.
        _PBYTE = ctypes.POINTER(ctypes.c_ubyte)
        _wintrust.WinVerifyTrust.restype = ctypes.c_long
        _wintrust.WinVerifyTrust.argtypes = [wintypes.HANDLE,
                                             ctypes.POINTER(_GUID),
                                             ctypes.c_void_p]
        _wintrust.CryptCATAdminAcquireContext.restype = wintypes.BOOL
        _wintrust.CryptCATAdminAcquireContext.argtypes = [
            ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.DWORD]
        _wintrust.CryptCATAdminReleaseContext.restype = wintypes.BOOL
        _wintrust.CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE,
                                                          wintypes.DWORD]
        _wintrust.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL
        _wintrust.CryptCATAdminCalcHashFromFileHandle.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), _PBYTE,
            wintypes.DWORD]
        _wintrust.CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE
        _wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [
            wintypes.HANDLE, _PBYTE, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE)]
        _wintrust.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL
        _wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [
            wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
        _wintrust.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL
        _wintrust.CryptCATCatalogInfoFromContext.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(_CATALOG_INFO), wintypes.DWORD]
        _kernel32.CreateFileW.restype = wintypes.HANDLE
        _kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        _kernel32.CloseHandle.restype = wintypes.BOOL
        _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        _ACTION_GUID = _GUID(0x00AAC56B, 0xCD44, 0x11D0,
                             (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0,
                                                  0x4F, 0xC2, 0x95, 0xEE))
        _AVAILABLE = True
    except Exception:   # noqa: BLE001 — no signature support is survivable
        _AVAILABLE = False

_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0                 # rule 1: never wait on a revocation server
_WTD_CHOICE_FILE = 1
_WTD_CHOICE_CATALOG = 2
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000   # rule 1: never fetch over the wire
_WTD_SAFER_FLAG = 0x00000100
_INVALID_HANDLE = -1


def _classify(code: int) -> SignatureInfo:
    if code == 0:
        return SignatureInfo(Trust.TRUSTED, 0, "signature verified")
    ucode = code & 0xFFFFFFFF
    if ucode == _TRUST_E_NOSIGNATURE:
        return SignatureInfo(Trust.UNSIGNED, ucode, "no Authenticode signature")
    if ucode in _UNTRUSTED_CODES:
        return SignatureInfo(Trust.UNTRUSTED, ucode,
                             "signature present but not acceptable")
    # Deliberately NOT guessed at. An unrecognised status is UNKNOWN, because
    # the alternative is inventing a verdict that a rule may act on.
    return SignatureInfo(Trust.UNKNOWN, ucode, "unrecognised verification status")


_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
# ctypes returns INVALID_HANDLE_VALUE as an unsigned integer whose width
# depends on the build, so check every representation rather than assume one.
_INVALID_HANDLES = (-1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)


_CAT_ADMIN = None
_CAT_ADMIN_LOCK = threading.Lock()
_CAT_ADMIN_FAILED = False


def _get_cat_admin():
    """One process-wide catalog admin context, acquired lazily.

    CryptCATAdminAcquireContext opens and indexes the machine's catalog store.
    Doing that per file made catalog verification cost ~56ms per binary, which
    is far too much to put on a process-start path. It is safe to hold one for
    the process lifetime and pass it to every lookup.
    """
    global _CAT_ADMIN, _CAT_ADMIN_FAILED
    if _CAT_ADMIN is not None or _CAT_ADMIN_FAILED:
        return _CAT_ADMIN
    with _CAT_ADMIN_LOCK:
        if _CAT_ADMIN is not None or _CAT_ADMIN_FAILED:
            return _CAT_ADMIN
        try:
            import ctypes
            h = wintypes.HANDLE()
            if _wintrust.CryptCATAdminAcquireContext(ctypes.byref(h), None, 0):
                _CAT_ADMIN = h
            else:
                _CAT_ADMIN_FAILED = True
        except Exception:   # noqa: BLE001
            _CAT_ADMIN_FAILED = True
    return _CAT_ADMIN


def _verify_catalog(path: str) -> Optional[SignatureInfo]:
    """Verify a file that is signed by a CATALOG rather than in-place.

    THIS IS NOT AN EDGE CASE - IT IS MOST OF WINDOWS. Microsoft ships the
    majority of System32 without an embedded Authenticode signature; integrity
    comes from a catalog under %SystemRoot%\\System32\\CatRoot. Plain
    WinVerifyTrust on the file therefore returns TRUST_E_NOSIGNATURE for
    cmd.exe, notepad.exe, ipconfig.exe and hundreds of others.

    Measured before this existed: cmd.exe and notepad.exe both reported
    UNSIGNED. Any rule keying on "unsigned binary" would have fired on half the
    operating system - a false-positive source large enough to make the whole
    signal unusable, and precisely the prime-directive violation this project
    cannot ship.

    Returns None when no catalog membership was found, so the caller can keep
    the original embedded-signature verdict.
    """
    import ctypes
    h_file = None
    h_cat_info = None
    # The catalog admin context is acquired ONCE and reused. Acquiring it per
    # file dominated the cost - it opens and indexes the catalog store every
    # time - and it is the difference between ~56ms and a few ms per binary on
    # the process-start path.
    h_cat_admin = _get_cat_admin()
    if not h_cat_admin:
        return None
    try:
        h_file = _kernel32.CreateFileW(path, _GENERIC_READ, _FILE_SHARE_READ,
                                       None, _OPEN_EXISTING, 0, None)
        if not h_file or h_file in _INVALID_HANDLES:
            return None

        size = wintypes.DWORD(0)
        _wintrust.CryptCATAdminCalcHashFromFileHandle(
            h_file, ctypes.byref(size), None, 0)
        if size.value == 0:
            return None
        buf = (ctypes.c_ubyte * size.value)()
        if not _wintrust.CryptCATAdminCalcHashFromFileHandle(
                h_file, ctypes.byref(size), buf, 0):
            return None

        h_cat_info = _wintrust.CryptCATAdminEnumCatalogFromHash(
            h_cat_admin, buf, size.value, 0, None)
        if not h_cat_info:
            return None            # genuinely not in any catalog

        ci = _CATALOG_INFO()
        ci.cbStruct = ctypes.sizeof(_CATALOG_INFO)
        if not _wintrust.CryptCATCatalogInfoFromContext(h_cat_info,
                                                        ctypes.byref(ci), 0):
            return None

        member_tag = "".join(f"{b:02X}" for b in buf)
        wci = _WINTRUST_CATALOG_INFO()
        ctypes.memset(ctypes.byref(wci), 0, ctypes.sizeof(wci))
        wci.cbStruct = ctypes.sizeof(_WINTRUST_CATALOG_INFO)
        wci.pcwszCatalogFilePath = ci.wszCatalogFile
        wci.pcwszMemberTag = member_tag
        wci.pcwszMemberFilePath = path
        wci.hMemberFile = h_file
        wci.pbCalculatedFileHash = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
        wci.cbCalculatedFileHash = size.value
        wci.hCatAdmin = h_cat_admin

        wd = _WINTRUST_DATA()
        ctypes.memset(ctypes.byref(wd), 0, ctypes.sizeof(wd))
        wd.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
        wd.dwUIChoice = _WTD_UI_NONE
        wd.fdwRevocationChecks = _WTD_REVOKE_NONE
        wd.dwUnionChoice = _WTD_CHOICE_CATALOG
        wd.pFile = ctypes.cast(ctypes.pointer(wci),
                               ctypes.POINTER(_WINTRUST_FILE_INFO))
        wd.dwStateAction = _WTD_STATEACTION_VERIFY
        wd.dwProvFlags = _WTD_CACHE_ONLY_URL_RETRIEVAL | _WTD_SAFER_FLAG

        rc = _wintrust.WinVerifyTrust(ctypes.c_void_p(_INVALID_HANDLE),
                                      ctypes.byref(_ACTION_GUID),
                                      ctypes.byref(wd))
        try:
            wd.dwStateAction = _WTD_STATEACTION_CLOSE
            _wintrust.WinVerifyTrust(ctypes.c_void_p(_INVALID_HANDLE),
                                     ctypes.byref(_ACTION_GUID),
                                     ctypes.byref(wd))
        except Exception:   # noqa: BLE001
            pass
        info = _classify(int(rc))
        if info.trust is Trust.TRUSTED:
            return SignatureInfo(Trust.TRUSTED, 0, "catalog-signed")
        return info
    except Exception:   # noqa: BLE001
        return None
    finally:
        try:
            if h_cat_info:
                _wintrust.CryptCATAdminReleaseCatalogContext(
                    h_cat_admin, h_cat_info, 0)
            # h_cat_admin is intentionally NOT released - it is process-wide and
            # reused (see _get_cat_admin).
            if h_file and h_file not in _INVALID_HANDLES:
                _kernel32.CloseHandle(h_file)
        except Exception:   # noqa: BLE001
            pass


def _verify_uncached(path: str) -> SignatureInfo:
    if not _AVAILABLE:
        return SignatureInfo(Trust.UNKNOWN, 0, "signature API unavailable")
    try:                                                      # pragma: no cover
        import ctypes
        fi = _WINTRUST_FILE_INFO(ctypes.sizeof(_WINTRUST_FILE_INFO), path,
                                 None, None)
        wd = _WINTRUST_DATA()
        ctypes.memset(ctypes.byref(wd), 0, ctypes.sizeof(wd))
        wd.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
        wd.dwUIChoice = _WTD_UI_NONE
        wd.fdwRevocationChecks = _WTD_REVOKE_NONE
        wd.dwUnionChoice = _WTD_CHOICE_FILE
        wd.pFile = ctypes.pointer(fi)
        wd.dwStateAction = _WTD_STATEACTION_VERIFY
        wd.dwProvFlags = _WTD_CACHE_ONLY_URL_RETRIEVAL | _WTD_SAFER_FLAG

        rc = _wintrust.WinVerifyTrust(ctypes.c_void_p(_INVALID_HANDLE),
                                      ctypes.byref(_ACTION_GUID),
                                      ctypes.byref(wd))
        # The state handle must be closed or wintrust leaks per call - on a
        # process-start path that is a leak per process on the machine.
        try:
            wd.dwStateAction = _WTD_STATEACTION_CLOSE
            _wintrust.WinVerifyTrust(ctypes.c_void_p(_INVALID_HANDLE),
                                     ctypes.byref(_ACTION_GUID),
                                     ctypes.byref(wd))
        except Exception:   # noqa: BLE001
            pass
        info = _classify(int(rc))
        # No EMBEDDED signature is not the end of the question - most of Windows
        # is catalog-signed. Only after the catalog lookup also comes back empty
        # is a file genuinely unsigned.
        if info.trust is Trust.UNSIGNED:
            cat = _verify_catalog(path)
            if cat is not None:
                return cat
        return info
    except Exception as exc:   # noqa: BLE001
        return SignatureInfo(Trust.UNKNOWN, 0, f"verification failed: {exc!r}")


# ---------------------------------------------------------------------------
# cache
# ---------------------------------------------------------------------------
_CACHE: dict = {}
_CACHE_LOCK = threading.Lock()
_CACHE_MAX = 4096


def _identity(path: str):
    """Cache key. Includes size and mtime so a binary REPLACED at a known-good
    path is re-verified instead of inheriting the old verdict - which is exactly
    the substitution an attacker performs against a path-keyed cache."""
    try:
        st = os.stat(path)
        return (os.path.normcase(path), st.st_size, int(st.st_mtime))
    except Exception:   # noqa: BLE001
        return None


# --- time budget ----------------------------------------------------------
# Measured on a real machine: 118 distinct binaries cost ~6.5s to verify cold,
# about 56ms each, dominated by the catalog hash-and-enumerate path. Cached
# lookups are microseconds, so steady state is free - but a COLD BURST (a build
# spawning a hundred compilers, a login storm) would otherwise put seconds of
# synchronous work on the process-start path.
#
# This module's docstring promises verification never blocks. A promise in a
# docstring is not an implementation, and this project has already lost a night
# to a startup path that blocked the event loop for 253 seconds. So the promise
# is enforced: verification gets a bounded share of wall-clock time per window,
# and past it every answer is UNKNOWN.
#
# UNKNOWN is the safe direction by construction - rules keying on signature
# state fail closed, so exhausting the budget costs signal, never correctness.
_BUDGET_WINDOW_S = 1.0
_BUDGET_SPEND_S = 0.25          # at most a quarter of any given second
_budget_window_start = 0.0
_budget_spent = 0.0
_BUDGET_LOCK = threading.Lock()
_budget_skipped = 0


def _take_budget() -> bool:
    """May we spend time verifying right now?"""
    global _budget_window_start, _budget_spent, _budget_skipped
    now = _monotonic()
    with _BUDGET_LOCK:
        if now - _budget_window_start >= _BUDGET_WINDOW_S:
            _budget_window_start = now
            _budget_spent = 0.0
        if _budget_spent >= _BUDGET_SPEND_S:
            _budget_skipped += 1
            return False
    return True


def _spend_budget(seconds: float) -> None:
    global _budget_spent
    with _BUDGET_LOCK:
        _budget_spent += seconds


def verify(path: Optional[str]) -> SignatureInfo:
    """Signature state of a file. Never raises, never blocks on the network,
    and never spends more than a bounded slice of wall clock per second.

    Returns UNKNOWN for anything we could not determine - a missing path, a
    locked file, an unavailable API, or an exhausted time budget. UNKNOWN must
    never be read as "unsigned".
    """
    if not path:
        return _UNKNOWN
    key = _identity(path)
    if key is None:
        return SignatureInfo(Trust.UNKNOWN, 0, "file not stat-able")
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
    if hit is not None:
        return hit                     # cached: free, and never budgeted

    if not _take_budget():
        # Deliberately NOT cached: this is a statement about how busy we are,
        # not about the file. Caching it would make one busy second permanently
        # blind us to that binary.
        return SignatureInfo(Trust.UNKNOWN, 0, "verification budget exhausted")

    t0 = _monotonic()
    info = _verify_uncached(path)
    _spend_budget(_monotonic() - t0)

    with _CACHE_LOCK:
        if len(_CACHE) >= _CACHE_MAX:
            _CACHE.clear()          # bounded; simplicity beats an LRU here
        _CACHE[key] = info
    return info


def trust_of(path: Optional[str]) -> str:
    """Convenience: the Trust value as a plain string, for rule matching."""
    return verify(path).trust.value


def cache_stats() -> dict:
    with _CACHE_LOCK:
        entries = len(_CACHE)
    with _BUDGET_LOCK:
        skipped = _budget_skipped
    return {"entries": entries, "available": _AVAILABLE,
            "budget_skipped": skipped}


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()

