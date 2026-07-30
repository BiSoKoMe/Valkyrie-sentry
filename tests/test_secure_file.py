"""Tests for secure_file.py — protecting the TLS CA private key.

Why this file matters more than its size suggests: whoever can read
`valkyrie-ca.key` can mint a trusted certificate for ANY domain and
impersonate it to this machine with a valid padlock. On Windows the engine's
data directory sits under %ProgramData%, whose default ACL grants
BUILTIN\\Users read — so "we wrote the key to our data dir" means "every
local account can read it" unless something actively prevents it.

The properties tested here:

  * an exposed file is REPORTED exposed (a checker that cannot see the
    problem is worse than no checker, because it manufactures confidence);
  * hardening actually REMOVES the dangerous grant, verified by re-reading
    the ACL rather than trusting the command's exit code — the first draft of
    this module returned success while the file was still readable, because
    an explicit non-inherited ACE survived `/inheritance:r`;
  * the process's OWN account keeps access, or the engine locks itself out of
    the key it just protected;
  * the public CERTIFICATE is deliberately NOT hardened — the user has to be
    able to open it to install it, and it grants nothing on its own. Getting
    this backwards would break the install flow for no security gain.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie import secure_file as sf

_IS_WINDOWS = platform.system() == "Windows"


def _grant_users_read(path: Path) -> bool:
    """Recreate the dangerous %ProgramData% grant. True if it took."""
    if not _IS_WINDOWS:
        os.chmod(path, 0o644)
        return True
    icacls = str(Path(os.environ.get("SystemRoot", r"C:\Windows"))
                 / "System32" / "icacls.exe")
    r = subprocess.run([icacls, str(path), "/grant", f"*{sf.SID_USERS}:(R)"],
                       capture_output=True, text=True, timeout=20)
    return r.returncode == 0


def main() -> int:
    c = Checks("secure file", expect_min=12)

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)

        # ── Detection: an exposed secret must be reported as exposed ─────
        print("\n[1] an exposed key is REPORTED exposed")
        key = tdp / "ca.key"
        key.write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n", encoding="utf-8")
        granted = _grant_users_read(key)
        if not granted:
            c.skip("exposure detection", "could not set the test ACL")
        else:
            ok, detail = sf.verify(key)
            c.check(f"verify() flags a Users-readable key as exposed ({detail[:60]})",
                    ok is False)
            if _IS_WINDOWS:
                sids, _ = sf.access_sids(key)
                c.check("the Users SID is genuinely present before hardening",
                        sf.SID_USERS in sids)

        # ── Hardening actually removes the grant ─────────────────────────
        print("\n[2] hardening REMOVES the dangerous grant")
        ok, detail = sf.harden(key)
        c.check(f"harden() reports success ({detail[:60]})", ok is True)
        ok2, detail2 = sf.verify(key)
        c.check("verify() now reports the key protected", ok2 is True)
        if _IS_WINDOWS:
            sids, _ = sf.access_sids(key)
            c.check("the Users SID is GONE after hardening",
                    sf.SID_USERS not in sids)
            c.check("Everyone is not present either",
                    sf.SID_EVERYONE not in sids)
            c.check("the running account KEEPS access (engine must read its key)",
                    sf.current_user_sid() in sids or not sf.current_user_sid())
            c.check("Administrators retains access (recovery/inspection)",
                    sf.SID_ADMINISTRATORS in sids)
        else:
            mode = key.stat().st_mode & 0o777
            c.check(f"POSIX mode is 0600 (got {oct(mode)})", mode == 0o600)

        # ── Idempotence ──────────────────────────────────────────────────
        print("\n[3] hardening twice is safe")
        ok3, _ = sf.harden(key)
        c.check("harden() is idempotent", ok3 is True)

        # ── Directories, so a key created LATER is already protected ─────
        print("\n[4] a directory can be hardened before the key exists")
        d = tdp / "confdir"
        d.mkdir()
        okd, detaild = sf.harden(d, is_dir=True)
        c.check(f"harden() works on a directory ({detaild[:50]})", okd is True)
        # A file created inside should inherit the restriction.
        child = d / "generated-ca.pem"
        child.write_text("key", encoding="utf-8")
        okc, _ = sf.verify(child)
        c.check("a key created INSIDE a hardened dir is already protected",
                okc is True)

        # ── The public certificate must stay readable ────────────────────
        print("\n[5] the PUBLIC cert is deliberately left readable")
        cert = tdp / "ca.pem"
        cert.write_text("-----BEGIN CERTIFICATE-----\nfake\n", encoding="utf-8")
        _grant_users_read(cert)
        okcert, _ = sf.verify(cert)
        c.check("an un-hardened public cert reads as 'not restricted' "
                "(correct — users must open it to install it)", okcert is False)

        # ── Robustness ───────────────────────────────────────────────────
        print("\n[6] robustness")
        missing = tdp / "nope.key"
        okm, dm = sf.verify(missing)
        c.check("verify() on a missing file is False, not a crash", okm is False)
        okh, dh = sf.harden(missing)
        c.check("harden() on a missing file is False, not a crash", okh is False)
        c.check("describe() returns a one-line summary",
                isinstance(sf.describe(key), str) and "\n" not in sf.describe(key))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
