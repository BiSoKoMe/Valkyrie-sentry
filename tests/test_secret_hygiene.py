"""Every secret Valkyrie writes must be unreadable by other local accounts.

This is the systemic guard for a bug class found FOUR times in one audit:

  * `valkyrie-ca.key`      - TLS CA private key. Read it and you can mint a
    trusted certificate for any domain and impersonate it to this machine.
  * `mac_key.bin`          - MAC install key. Every per-network address is
    HMAC(key, network), so reading it predicts and links every address the
    machine will ever use.
  * `control_token.txt`    - the credential for every state-changing API
    route: isolate the host, kill a process, disable telemetry protection.
  * `fleet_agent.json`     - the device's fleet enrolment token.

All four had the same root cause: `DATA_DIR` sits under `%ProgramData%`,
which inherits a `BUILTIN\\Users: read` ACE, so anything written there is
world-readable unless something actively prevents it. Two of them shipped
code that protected the file on POSIX and *explicitly skipped Windows* -
one with the comment "POSIX only; no-op on Windows" - meaning the secret was
knowingly left readable on the platform the product actually ships on.

Fixing the four write sites is necessary but not sufficient: the next secret
added inherits the same default. So this file tests the INVARIANT rather
than the four instances - if someone adds a secret to the registry without
protecting it, or a future build regresses one, this fails.
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


def main() -> int:
    # Sections [2]-[4] below read or write Windows ACLs through PowerShell's
    # Get-Acl/Set-Acl. Some Windows hosts - GitHub's windows-latest runner among
    # them - cannot auto-load Microsoft.PowerShell.Security, so those checks fail
    # for a reason unrelated to secret hygiene. Probe once and skip only the
    # ACL-dependent checks: section [1] (the registry itself) is pure data and
    # stays covered either way, so this is a narrower skip than skipping the file.
    # The product already fails safe here - _verdict_from_sids() treats an ACL
    # read error as NOT protected - so the skip conceals no risk.
    acl_err = ""
    if platform.system() == "Windows":
        with tempfile.TemporaryDirectory() as probe_dir:
            probe = Path(probe_dir) / "probe.bin"
            probe.write_bytes(b"probe")
            _sids, acl_err = sf.access_sids(probe)

    # expect_min guards against a check silently disappearing, so it has to be
    # told when three of them are legitimately skipped - otherwise the very
    # guard that protects coverage reports a failure for honest absence. The
    # floor stays 10 wherever ACLs work, and only drops where they provably
    # do not.
    c = Checks("secret hygiene", expect_min=8 if acl_err else 10)

    # --- The registry itself ---
    print("\n[1] the secret registry covers what it should")
    reg = sf.known_secrets()
    names = {label for label, _ in reg}
    c.check(f"registry is populated ({len(reg)} entries)", len(reg) >= 8)
    for must in ("TLS CA private key", "MAC install key", "API control token",
                 "fleet enrolment token"):
        c.check(f"registry includes the {must}", must in names)
    c.check("registry includes the WireGuard configs (they carry PrivateKey)",
            any("WireGuard" in n for n in names))

    # --- The invariant, on this machine ---
    print("\n[2] every secret PRESENT on this machine is protected")
    audit = sf.audit_secrets()
    if acl_err:
        c.skip("live secret audit", f"PowerShell ACL access unavailable ({acl_err[:60]})")
    elif not audit:
        c.skip("live secret audit", "no secrets exist on this host yet")
    else:
        exposed = [(label, p, detail) for label, p, ok, detail in audit if not ok]
        for label, p, ok, detail in audit:
            print(f"  {'OK  ' if ok else 'EXPOSED'} {label} ({p.name})")
        c.check(f"no known secret is world-readable ({len(exposed)} exposed)",
                not exposed)
        if exposed:
            for label, p, detail in exposed:
                print(f"    !! {label}: {p} — {detail}")

    # --- The backstop actually fixes an exposed secret ---
    print("\n[3] harden_known_secrets() heals an exposed secret")
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "secret.bin"
        f.write_bytes(b"\x00" * 32)
        # Simulate the %ProgramData% default by granting Users read.
        if platform.system() == "Windows":
            icacls = str(Path(os.environ.get("SystemRoot", r"C:\Windows"))
                         / "System32" / "icacls.exe")
            subprocess.run([icacls, str(f), "/grant", f"*{sf.SID_USERS}:(R)"],
                           capture_output=True, timeout=20)
        else:
            os.chmod(f, 0o644)
        if acl_err:
            c.skip("harden() heals an exposed secret",
                   f"PowerShell ACL access unavailable ({acl_err[:60]})")
        else:
            before_ok, _ = sf.verify(f)
            c.check("precondition: the file starts exposed", before_ok is False)
            sf.harden(f)
            after_ok, detail = sf.verify(f)
            c.check(f"harden() fixes it ({detail[:45]})", after_ok is True)

    # --- Idempotence, because this runs on every launch ---
    print("\n[4] the startup sweep is safe to run repeatedly")
    first = sf.harden_known_secrets()
    second = sf.harden_known_secrets()
    if acl_err:
        c.skip("startup sweep idempotence",
               f"PowerShell ACL access unavailable ({acl_err[:60]})")
    else:
        c.check("a second sweep finds nothing left to fix (idempotent)",
                len(second) == 0)
    c.check("the sweep reports what it changed, not a bare boolean",
            isinstance(first, list))
    c.check("audit_secrets() never raises on a missing file",
            isinstance(sf.audit_secrets(), list))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
