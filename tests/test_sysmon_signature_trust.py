#!/usr/bin/env python3
"""Sysmon SignatureStatus must reach the code-signature rules, and fail closed.

Sysmon's EID 1 already carries the OS's own Authenticode verdict for the binary
it is reporting (``SignatureStatus``). Until this was wired up, ``sysmon.py``
called ``classify_behavior(name, parent, cmdline, image)`` with no signature
argument at all, so every ``Rule.signed`` rule in ``behavioral_rules.py``
(masquerade-unsigned-system-binary, tampered-or-revoked-signature,
unsigned-binary-from-drop-zone) was structurally unreachable from the real-time
Sysmon path -- they could only ever fire through the ~2s disk-verify poller in
``signature.py``. A fake ``svchost.exe`` observed by Sysmon produced no
signature-based detection.

This test pins both halves of the fix:

  1. the vocabulary map is correct (Sysmon's words -> Valkyrie's words), and
  2. it FAILS CLOSED -- an unrecognised status maps to "unknown", which
     satisfies no rule. An unknown OS verdict must never be read as "unsigned"
     and manufacture a critical detection. That direction is the one that
     matters: a missed detection is a gap, but a fabricated one is a lie.

Everything runs through the REAL production functions -- the XML is parsed by
``parse_event_xml`` exactly as the live sensor parses it, then handed to
``classify_sysmon``. No mocks, no hand-built data dicts, so a regression in
either the parser, the mapping, or the call wiring fails this test.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks                                        # noqa: E402
from valkyrie.etw.sysmon import (                                 # noqa: E402
    _sysmon_signature_trust,
    classify_sysmon,
)
from valkyrie.etw.wineventlog import parse_event_xml              # noqa: E402

_EID1 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System>
<Provider Name='Microsoft-Windows-Sysmon' Guid='{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}'/>
<EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task>
<TimeCreated SystemTime='2026-08-11T07:10:00.000000000Z'/>
<EventRecordID>{rid}</EventRecordID>
<Execution ProcessID='4' ThreadID='8'/>
<Channel>Microsoft-Windows-Sysmon/Operational</Channel>
<Computer>TESTHOST</Computer><Security UserID='S-1-5-18'/>
</System>
<EventData>
<Data Name='UtcTime'>2026-08-11 07:10:00.000</Data>
<Data Name='ProcessId'>5000</Data>
<Data Name='Image'>{image}</Data>
<Data Name='OriginalFileName'>svchost.exe</Data>
<Data Name='CommandLine'>{cmdline}</Data>
<Data Name='CurrentDirectory'>C:\\Windows\\system32\\</Data>
<Data Name='User'>TESTHOST\\Administrator</Data>
<Data Name='IntegrityLevel'>High</Data>
<Data Name='Hashes'>SHA256=ABC123</Data>
<Data Name='Signature'>{signature}</Data>
<Data Name='SignatureStatus'>{status}</Data>
<Data Name='Signed'>{signed}</Data>
<Data Name='ParentProcessId'>4000</Data>
<Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>
<Data Name='ParentCommandLine'>cmd.exe /c x</Data>
</EventData>
</Event>"""

# A payload wearing a core system binary's name, run from a user-writable
# directory -- the exact shape masquerade-unsigned-system-binary exists for.
_FAKE_SVCHOST = r"C:\Users\Public\Downloads\svchost.exe"


def _classify(status: str, image: str = _FAKE_SVCHOST, rid: int = 9000):
    xml = _EID1.format(image=image, cmdline="svchost.exe -k netsvcs",
                       signature="Microsoft Windows", status=status,
                       signed="true", rid=rid)
    ev = parse_event_xml(xml)
    return ev, classify_sysmon(1, ev.get("data", {}))


def _labels(res) -> str:
    if not res:
        return ""
    return " ".join(res.get("labels", []) or []) + " " + str(res.get("technique", ""))


def main() -> int:
    c = Checks("Sysmon SignatureStatus reaches the signature rules, fails closed",
               expect_min=12)

    # [1] The vocabulary map: Sysmon's words -> Valkyrie's event-side words.
    #     "not_trusted" is deliberately absent here: it is a RULE-side value
    #     meaning "unsigned or untrusted", never something an event carries.
    for status, expect in (("Valid", "trusted"), ("valid", "trusted"),
                           ("NotSigned", "unsigned"), ("Unsigned", "unsigned"),
                           ("Expired", "untrusted"), ("Invalid", "untrusted"),
                           ("Bad Digest", "untrusted")):
        got = _sysmon_signature_trust(status)
        c.check(f"SignatureStatus '{status}' -> '{expect}' (got '{got}')",
                got == expect)

    # [2] FAIL CLOSED. Anything unrecognised is "unknown", which satisfies no
    #     Rule.signed requirement. These are the values a real host actually
    #     produces when verification could not complete.
    for status in ("Unknown", "Timeout", "", "   ", "SomeFutureWindowsValue"):
        got = _sysmon_signature_trust(status)
        c.check(f"unrecognised status '{status}' fails closed to 'unknown' "
                f"(got '{got}')", got == "unknown")
    c.check("None fails closed to 'unknown'",
            _sysmon_signature_trust(None) == "unknown")

    # [3-5] End-to-end, as a controlled experiment: the SAME fake svchost.exe
    # from the same user-writable directory, three times, with SignatureStatus
    # as the only variable.
    #
    # Assert on the signature-gated LABELS, not on the ATT&CK id. T1036.005 is
    # shared with the path-based rules (masquerade_syspath - "core Windows
    # system binary running from a user-writable directory"), which fire on
    # path alone and are correct to fire in all three cases. Keying this test
    # on the technique id would pass no matter what the signature layer did,
    # which is precisely the blindness being tested for.
    SIG_LABELS = {"masquerade_system_binary", "unsigned_drop_zone"}

    def _sig_labels(res) -> set:
        return SIG_LABELS & set((res or {}).get("labels", []) or [])

    # Unsigned: the signature rules must now fire through the real Sysmon path.
    # This is the check that fails outright on the pre-fix code, where no
    # signature argument was passed and these rules were unreachable here.
    _, unsigned_res = _classify("NotSigned", rid=9000)
    c.check("unsigned fake svchost.exe -> signature rules fire from Sysmon "
            f"(got {sorted(_sig_labels(unsigned_res)) or 'none'})",
            "masquerade_system_binary" in _sig_labels(unsigned_res))

    # Validly signed: the same binary, same path, must NOT trip a signature
    # rule -- the false-positive floor.
    _, valid_res = _classify("Valid", rid=9001)
    c.check("validly signed binary trips no signature rule "
            f"(got {sorted(_sig_labels(valid_res)) or 'none'})",
            not _sig_labels(valid_res))

    # The one that protects honesty: an UNKNOWN verdict must NOT manufacture a
    # signature-based detection. If this ever flips, Valkyrie is inventing
    # evidence out of missing data.
    _, unknown_res = _classify("Timeout", rid=9002)
    c.check("unknown signature verdict manufactures no signature detection "
            f"(got {sorted(_sig_labels(unknown_res)) or 'none'})",
            not _sig_labels(unknown_res))

    # And the path layer stays independent of all this - it should still call
    # the fake svchost out on location alone, whatever the signature says.
    c.check("path-based masquerade still fires independently of signature",
            all("masquerade_syspath" in ((r or {}).get("labels", []) or [])
                for r in (unsigned_res, valid_res, unknown_res)))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
