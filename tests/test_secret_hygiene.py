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

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie import secure_file as sf


def main() -> int:
    c = Checks("secret hygiene", expect_min=10)

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
    if not audit:
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
        import os
        import platform
        import subprocess
        if platform.system() == "Windows":
            icacls = str(Path(os.environ.get("SystemRoot", r"C:\Windows"))
                         / "System32" / "icacls.exe")
            subprocess.run([icacls, str(f), "/grant", f"*{sf.SID_USERS}:(R)"],
                           capture_output=True, timeout=20)
        else:
            os.chmod(f, 0o644)
        before_ok, _ = sf.verify(f)
        c.check("precondition: the file starts exposed", before_ok is False)
        sf.harden(f)
        after_ok, detail = sf.verify(f)
        c.check(f"harden() fixes it ({detail[:45]})", after_ok is True)

    # --- Idempotence, because this runs on every launch ---
    print("\n[4] the startup sweep is safe to run repeatedly")
    first = sf.harden_known_secrets()
    second = sf.harden_known_secrets()
    c.check("a second sweep finds nothing left to fix (idempotent)",
            len(second) == 0)
    c.check("the sweep reports what it changed, not a bare boolean",
            isinstance(first, list))
    c.check("audit_secrets() never raises on a missing file",
            isinstance(sf.audit_secrets(), list))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
