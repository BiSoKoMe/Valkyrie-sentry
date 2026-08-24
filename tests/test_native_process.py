"""The Sysmon-free process sensor: command-line detection with no download.

Valkyrie's best detection needs to see a process's command line in real time.
The only real-time source for that used to be Sysmon EID 1 — a separate
install that no ordinary user will ever perform, which meant the good path was
dark for real customers and the engine fell back to a racy 2s poller.

Windows emits the same information for free in **Security event 4688** once
process-creation auditing (with command line) is enabled — a built-in config
change, not a download. This sensor reads 4688 and feeds the SAME classifier
stack the Sysmon sensor uses.

These tests drive real 4688-shaped event XML through the whole
parse -> map -> classify path, with no changes to the host's audit policy
(exactly like the Sysmon tests use synthetic Sysmon XML). The property that
matters most is PARITY: a given process must classify identically whether the
evidence arrived via Sysmon or via native 4688 — otherwise "Sysmon-free" would
quietly mean "worse".
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Checks
from valkyrie import native_audit
from valkyrie.etw.native_process import map_4688
from valkyrie.etw.sysmon import classify_sysmon
from valkyrie.etw.wineventlog import parse_event_xml


def _event_4688(image, cmdline, parent, pid_hex="0x1f4", user="lawyer"):
    """A realistic Security/4688 rendered-event XML."""
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/>
        <EventID>4688</EventID>
        <TimeCreated SystemTime="2026-07-31T04:00:00.000Z"/>
        <Computer>TEST</Computer>
      </System>
      <EventData>
        <Data Name="SubjectUserName">{user}</Data>
        <Data Name="NewProcessId">{pid_hex}</Data>
        <Data Name="NewProcessName">{image}</Data>
        <Data Name="CommandLine">{cmdline}</Data>
        <Data Name="ParentProcessName">{parent}</Data>
        <Data Name="SubjectLogonId">0x3e7</Data>
      </EventData>
    </Event>"""


def main() -> int:
    c = Checks("native process sensor", expect_min=16)

    # ── PID hex conversion (4688's format) ──────────────────────────────
    print("\n[1] 4688 hex PID is converted to a usable decimal")
    from valkyrie.etw.native_process import _hex_to_dec
    c.check("0x1f4 -> 500", _hex_to_dec("0x1f4") == "500")
    c.check("plain decimal passes through", _hex_to_dec("4242") == "4242")
    c.check("garbage PID -> '0', not a crash", _hex_to_dec("nonsense") == "0")
    c.check("empty PID -> '0'", _hex_to_dec("") == "0")

    # ── Mapping is total (old/truncated 4688 must not raise) ────────────
    print("\n[2] mapping tolerates missing 4688 fields")
    m = map_4688({"NewProcessName": r"C:\x.exe"})   # no cmdline, no parent
    c.check("missing command line -> empty string", m["CommandLine"] == "")
    c.check("missing parent -> empty string", m["ParentImage"] == "")
    c.check("map_4688({}) does not raise", isinstance(map_4688({}), dict))

    # ── End to end: a real 4688 XML detects encoded PowerShell ──────────
    print("\n[3] end-to-end: Security/4688 XML -> detection")
    xml = _event_4688(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwA",
        r"C:\Windows\explorer.exe")
    ev = parse_event_xml(xml)
    c.check("the 4688 XML parses to event_id 4688", ev.get("event_id") == 4688)
    c.check("the command line survived parsing",
            "enc" in ev.get("data", {}).get("CommandLine", ""))
    verdict = classify_sysmon(1, map_4688(ev.get("data", {})))
    c.check("encoded PowerShell IS detected via native 4688", verdict is not None)
    c.check("it is at least medium severity",
            verdict and verdict["severity"] in ("medium", "high", "critical"))
    c.check("encoded-command label is present",
            verdict and any("encoded" in l for l in verdict["labels"]))

    # ── PARITY: native path == sysmon path for the same process ─────────
    print("\n[4] PARITY — native 4688 classifies identically to Sysmon EID 1")
    cases = [
        # (image, cmdline, parent)
        (r"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami", r"C:\Program Files\Microsoft Office\winword.exe"),
        (r"C:\Windows\System32\rundll32.exe", "rundll32.exe C:\\Users\\Public\\evil.dll,Go", r"C:\Windows\System32\cmd.exe"),
        (r"C:\Windows\notepad.exe", "notepad.exe report.txt", r"C:\Windows\explorer.exe"),
    ]
    parity = True
    for image, cmd, parent in cases:
        sysmon_d = {"Image": image, "CommandLine": cmd, "ParentImage": parent, "ProcessId": "500"}
        native_d = map_4688({"NewProcessName": image, "CommandLine": cmd,
                             "ParentProcessName": parent, "NewProcessId": "0x1f4"})
        a = classify_sysmon(1, sysmon_d)
        b = classify_sysmon(1, native_d)
        same = ((a is None) == (b is None)) and (
            a is None or (a["severity"] == b["severity"] and a["labels"] == b["labels"]))
        if not same:
            parity = False
            print(f"    MISMATCH: {cmd!r}  sysmon={a}  native={b}")
    c.check("every case classifies the same via both sources", parity)

    # ── The emit path produces a real TelemetryEvent ────────────────────
    print("\n[5] the sensor emits a well-formed event")
    from valkyrie.etw.native_process import NativeProcessSensor
    captured = []
    s = NativeProcessSensor()
    s.submit = lambda ev: captured.append(ev)      # intercept the sink
    v = classify_sysmon(1, map_4688(ev.get("data", {})))
    s._emit(ev, v)
    c.check("an event was emitted", len(captured) == 1)
    te = captured[0]
    c.check("source is tagged etw.native", te.source == "etw.native")
    c.check("the emitted event carries the actor name",
            "powershell" in (te.actor_name or "").lower())

    # ── native_audit command construction (no execution) ────────────────
    print("\n[6] audit-enable uses the locale-independent subcategory GUID")
    cmd = native_audit._enable_audit_cmd()
    c.check("auditpol targets the Process Creation GUID, not a localised name",
            "{0CCE922B-69AE-11D9-BED3-505054503030}" in " ".join(cmd))
    c.check("enable_process_auditing never raises off-Windows/without admin",
            isinstance(native_audit.enable_process_auditing(), tuple))

    return c.finish()


if __name__ == "__main__":
    raise SystemExit(main())
