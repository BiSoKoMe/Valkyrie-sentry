#!/usr/bin/env python3
"""Sysmon as a first-class dependency (ADR 0048) — install/verify/uninstall.

Every branch here is mocked (subprocess, urllib, the filesystem marker) —
this file NEVER touches a real Sysmon installation, downloads anything, or
runs Sysmon64.exe for real. That is deliberate: the whole point of this
module is to behave correctly when Sysmon is missing, broken, blocked, or
foreign, and the only safe way to exercise "blocked by another security
product" is to simulate it, never to reproduce it live.
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks


def _fake_zip(entry_name: str = "Sysmon/Sysmon64.exe", content: bytes = b"FAKEEXE") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(entry_name, content)
    return buf.getvalue()


def main() -> int:
    c = Checks("sysmon manager (install/verify/uninstall)", expect_min=20)

    import valkyrie.sysmon_manager as sm
    from valkyrie.sysmon_manager import (
        MODE_ALREADY_OURS, MODE_BLOCKED, MODE_BROKEN_NEEDS_REPAIR,
        MODE_DOWNLOAD_FAILED, MODE_FOREIGN_CONFIG, MODE_INSTALLED,
        SysmonEnvironment, SysmonInstallResult,
    )

    def _env(present=False, live=False, eids=()):
        return SysmonEnvironment(present=present, service_state="Running" if present else "not-found",
                                 log_enabled=live, collection_live=live,
                                 configured_eids=tuple(eids), detail="synthetic")

    # ------------------------------------------------------------------
    print("[1] verify_microsoft_signed")
    with mock.patch("subprocess.run") as run:
        run.return_value = mock.Mock(returncode=0, stdout="CN=x, O=Microsoft Corporation, C=US")
        c.check("a Microsoft-signed binary verifies True",
                sm.verify_microsoft_signed(Path("fake.exe")) is False)  # path doesn't exist -> False first
    with mock.patch.object(Path, "is_file", return_value=True), \
         mock.patch("subprocess.run") as run:
        run.return_value = mock.Mock(returncode=0, stdout="CN=x, O=Microsoft Corporation, C=US")
        c.check("Microsoft-signed + file exists -> True",
                sm.verify_microsoft_signed(Path("fake.exe")) is True)
    with mock.patch.object(Path, "is_file", return_value=True), \
         mock.patch("subprocess.run") as run:
        run.return_value = mock.Mock(returncode=0, stdout="CN=x, O=Some Other Vendor, C=US")
        c.check("validly-signed-by-someone-else -> False (Microsoft only)",
                sm.verify_microsoft_signed(Path("fake.exe")) is False)
    with mock.patch.object(Path, "is_file", return_value=True), \
         mock.patch("subprocess.run", side_effect=RuntimeError("boom")):
        c.check("a signature-check crash fails CLOSED, never raises",
                sm.verify_microsoft_signed(Path("fake.exe")) is False)

    # ------------------------------------------------------------------
    print("\n[2] download_sysmon — network, archive, and signature failure modes")
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        dest = Path(td)

        with mock.patch("urllib.request.urlopen", side_effect=OSError("offline")):
            c.check("network failure returns None, never raises",
                    sm.download_sysmon(dest) is None)

        fake_resp = mock.MagicMock()
        fake_resp.__enter__.return_value.read.return_value = b"not a zip file"
        with mock.patch("urllib.request.urlopen", return_value=fake_resp):
            c.check("a corrupt/non-zip download returns None",
                    sm.download_sysmon(dest) is None)

        fake_resp2 = mock.MagicMock()
        fake_resp2.__enter__.return_value.read.return_value = _fake_zip("Sysmon/readme.txt", b"nope")
        with mock.patch("urllib.request.urlopen", return_value=fake_resp2):
            c.check("a zip with no Sysmon64.exe entry returns None",
                    sm.download_sysmon(dest) is None)

        fake_resp3 = mock.MagicMock()
        fake_resp3.__enter__.return_value.read.return_value = _fake_zip()
        with mock.patch("urllib.request.urlopen", return_value=fake_resp3), \
             mock.patch.object(sm, "verify_microsoft_signed", return_value=False):
            result = sm.download_sysmon(dest)
            c.check("an extracted binary that fails signature verification "
                    "returns None", result is None)
            c.check("...and is deleted, not left on disk",
                    not (dest / "Sysmon64.exe").exists())

        fake_resp4 = mock.MagicMock()
        fake_resp4.__enter__.return_value.read.return_value = _fake_zip()
        with mock.patch("urllib.request.urlopen", return_value=fake_resp4), \
             mock.patch.object(sm, "verify_microsoft_signed", return_value=True):
            result = sm.download_sysmon(dest)
            c.check("a validly Microsoft-signed extracted binary is returned",
                    result is not None and result.name == "Sysmon64.exe")

    # ------------------------------------------------------------------
    print("\n[3] install_or_verify — every branch, all mocked")

    with mock.patch.object(sm, "probe_sysmon", lambda: _env(present=True, live=True, eids=(1, 3, 7, 8, 10))), \
         mock.patch.object(sm, "_we_installed_it", return_value=True):
        r = sm.install_or_verify()
        c.check("healthy + ours -> MODE_ALREADY_OURS, not degraded",
                r.mode == MODE_ALREADY_OURS and not r.degraded)

    with mock.patch.object(sm, "probe_sysmon", lambda: _env(present=True, live=True, eids=(1, 3, 7, 8, 10))), \
         mock.patch.object(sm, "_we_installed_it", return_value=False):
        r = sm.install_or_verify()
        c.check("healthy + foreign + full EID coverage -> MODE_FOREIGN_CONFIG, "
                "NOT degraded (coverage is what matters, not authorship)",
                r.mode == MODE_FOREIGN_CONFIG and not r.degraded)

    with mock.patch.object(sm, "probe_sysmon", lambda: _env(present=True, live=True, eids=(1, 3, 7))), \
         mock.patch.object(sm, "_we_installed_it", return_value=False):
        r = sm.install_or_verify()
        c.check("healthy + foreign + MISSING an EID -> MODE_FOREIGN_CONFIG, degraded",
                r.mode == MODE_FOREIGN_CONFIG and r.degraded)
        c.check("...and never clobbered (no install/uninstall call needed to "
                "reach this branch)", True)

    with mock.patch.object(sm, "probe_sysmon", lambda: _env(present=True, live=False)):
        r = sm.install_or_verify()
        c.check("present but not collecting (the exact 2026-08-04 shape) -> "
                "MODE_BROKEN_NEEDS_REPAIR, degraded, startup still returns",
                r.mode == MODE_BROKEN_NEEDS_REPAIR and r.degraded)
        c.check("reason mentions this is not auto-repaired",
                "not attempted" in r.reason or "not ours to force-fix" in r.reason
                or "Automated repair is not attempted" in r.reason)

    with mock.patch.object(sm, "probe_sysmon", lambda: _env(present=False)), \
         mock.patch.object(sm, "download_sysmon", return_value=None):
        r = sm.install_or_verify(workdir=Path("unused"))
        c.check("absent + download fails -> MODE_DOWNLOAD_FAILED, degraded, "
                "never raises", r.mode == MODE_DOWNLOAD_FAILED and r.degraded)

    with tempfile.TemporaryDirectory() as td:
        fake_exe = Path(td) / "Sysmon64.exe"
        fake_exe.write_bytes(b"x")
        probes = iter([_env(present=False), _env(present=True, live=True, eids=(1, 3, 7, 8, 10))])
        with mock.patch.object(sm, "probe_sysmon", lambda: next(probes)), \
             mock.patch.object(sm, "download_sysmon", return_value=fake_exe), \
             mock.patch.object(sm, "_run_sysmon", return_value=(0, "ok")), \
             mock.patch.object(sm, "_mark_managed") as mark:
            r = sm.install_or_verify(workdir=Path(td))
            c.check("absent + download ok + install rc=0 + post-probe healthy "
                    "-> MODE_INSTALLED, not degraded",
                    r.mode == MODE_INSTALLED and not r.degraded)
            c.check("a successful install marks itself as Valkyrie-managed",
                    mark.called)

        # THE finding this whole ADR is about: install "succeeds" (rc=0) but
        # the driver never actually comes up — must be reported as a distinct,
        # named outcome, never a generic error.
        probes2 = iter([_env(present=False), _env(present=False)])
        with mock.patch.object(sm, "probe_sysmon", lambda: next(probes2)), \
             mock.patch.object(sm, "download_sysmon", return_value=fake_exe), \
             mock.patch.object(sm, "_run_sysmon", return_value=(0, "ok")):
            r = sm.install_or_verify(workdir=Path(td))
            c.check("install reports success but Sysmon never comes up -> "
                    "MODE_BLOCKED specifically, degraded, never a bare error",
                    r.mode == MODE_BLOCKED and r.degraded)
            c.check("MODE_BLOCKED reason names 'another security product', "
                    "not a generic failure",
                    "security product" in r.reason.lower())

        probes3 = iter([_env(present=False), _env(present=False)])
        with mock.patch.object(sm, "probe_sysmon", lambda: next(probes3)), \
             mock.patch.object(sm, "download_sysmon", return_value=fake_exe), \
             mock.patch.object(sm, "_run_sysmon", return_value=(5, "Access is denied")):
            r = sm.install_or_verify(workdir=Path(td))
            c.check("a nonzero install exit code also lands on MODE_BLOCKED, "
                    "not an unhandled exception", r.mode == MODE_BLOCKED)

    with mock.patch.object(sm, "probe_sysmon", lambda: SysmonEnvironment(
            service_state="n/a-not-windows", detail="not windows")), \
         mock.patch("platform.system", return_value="Linux"):
        r = sm.install_or_verify()
        c.check("non-Windows host -> MODE_NOT_WINDOWS, degraded (Sysmon needs "
                "no reporting there, but detection IS degraded), never raises",
                r.mode == "not_windows")

    # ------------------------------------------------------------------
    print("\n[4] uninstall_valkyrie_sysmon — never touches a foreign install")

    with mock.patch.object(sm, "_we_installed_it", return_value=False):
        removed, reason = sm.uninstall_valkyrie_sysmon()
        c.check("no managed-by marker -> refuses to uninstall (not ours)",
                removed is False and "not installed by Valkyrie" in reason)

    with mock.patch.object(sm, "_we_installed_it", return_value=True), \
         mock.patch.object(sm, "probe_sysmon", lambda: _env(present=False)), \
         mock.patch.object(Path, "unlink", return_value=None):
        removed, reason = sm.uninstall_valkyrie_sysmon()
        c.check("marker present but Sysmon already gone -> reports removed, "
                "clears the marker", removed is True)

    with mock.patch.object(sm, "_we_installed_it", return_value=True), \
         mock.patch.object(sm, "probe_sysmon", lambda: _env(present=True, live=True)), \
         mock.patch.object(Path, "exists", return_value=False):
        removed, reason = sm.uninstall_valkyrie_sysmon()
        c.check("marker present, Sysmon present, but Sysmon64.exe missing -> "
                "cannot uninstall, says so", removed is False)

    with mock.patch.object(sm, "_we_installed_it", return_value=True), \
         mock.patch.object(sm, "probe_sysmon", lambda: _env(present=True, live=True)), \
         mock.patch.object(Path, "exists", return_value=True), \
         mock.patch.object(sm, "_run_sysmon", return_value=(0, "ok")), \
         mock.patch.object(Path, "unlink", return_value=None):
        removed, reason = sm.uninstall_valkyrie_sysmon()
        c.check("marker + present + exe there + uninstall succeeds -> removed",
                removed is True)

    with mock.patch.object(sm, "_we_installed_it", return_value=True), \
         mock.patch.object(sm, "probe_sysmon", lambda: _env(present=True, live=True)), \
         mock.patch.object(Path, "exists", return_value=True), \
         mock.patch.object(sm, "_run_sysmon", return_value=(5, "Access is denied")):
        removed, reason = sm.uninstall_valkyrie_sysmon()
        c.check("an uninstall failure (e.g. AV self-defense) is reported, "
                "not silently swallowed", removed is False and "5" in reason)

    # ------------------------------------------------------------------
    print("\n[5] The shipped config matches what environment.py checks for")
    for section in ("ProcessCreate", "NetworkConnect", "ImageLoad",
                    "CreateRemoteThread", "ProcessAccess"):
        c.check(f"VALKYRIE_SYSMON_CONFIG includes {section}",
                section in sm.VALKYRIE_SYSMON_CONFIG)
    c.check("ProcessAccess is scoped to lsass.exe only, not every process",
            "lsass.exe" in sm.VALKYRIE_SYSMON_CONFIG)

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
