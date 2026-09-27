# ADR 0063 - Detector precision pass: stop alerting on tools, alert on use

Date: 2026-09-25 . Status: accepted . Amends: ADR 0027, ADR 0028

## Context

The owner's target for the detector is a high per-execution detection rate at
a low false-positive rate on benign activity. Until now the FP side had never
been measured on the path that matters most: Sysmon EID 1 process creation,
through `classify_sysmon`, into the engine's incident gate (`severity >=
medium`, `edr/engine.py`). Measured on 2026-09-25:

| Benign set | Raised an incident |
|---|---:|
| Elastic benign corpus (731 real launches that once tripped an Elastic rule) | 598 (81.8%) |
| Everyday workstation launches (47, hand-written) | 34 (72.3%) |

At that rate a user sees an incident every time they open a terminal, a
script shells out, or an installer runs. That also makes the 3% FP target
unreachable.

The causes, in order of size:

1. `process_telemetry.classify_process` scored any start of a LOLBin (cmd,
   powershell, rundll32, curl, schtasks, sc, wscript...) MEDIUM on the
   binary name alone. The engine then labelled it T1059 via the label map.
2. `-NoProfile` / `-NonInteractive` / `//nologo` / `//b` (how all automation
   starts a script host) scored MEDIUM as "hidden".
3. The "download cradle" check fired HIGH on either half of a cradle. That
   included a bare `Invoke-Expression` (Claude Code's own shell launcher and
   Chocolatey) and a bare `Invoke-WebRequest` (a developer fetching a zip).
4. PowerShell's encoded-command switches were matched on every process, so
   `node -e`, `perl -e` and `sqlcmd -e` scored HIGH as "encoded PowerShell".
5. node.exe and java.exe counted as internet-facing servers, so `npm run`
   and Gradle builds read as web shells.
6. Any `\\` anywhere counted as a UNC path. A doubled separator in a local
   path (`C:\Temp\\f.txt`) read as "references a network path".
7. Installers creating their updater task, or running InstallUtil on their
   own service, raised incidents.

Separately, two real detection gaps showed up:

- A copied-and-renamed system utility (cmd.exe run as `lsass.exe`,
  powershell.exe as `updater.exe`) was only caught by location heuristics,
  under the wrong technique. Sysmon's `OriginalFileName` was never read.
- The EID 7 image-load handler dropped every signed DLL. So the DLL
  search-order hijack that plants Microsoft's own signed copy was invisible.
  Meanwhile every unsigned DLL load (Python extensions, Node addons, game
  mods) was an incident.

## Decision

Alert on how a tool is used, never on the tool existing.

- Bare LOLBin start is LOW. The `lolbin` label stays, because causality, the
  kill-chain, decisions and the anomaly nose read it. Escalation comes from
  the command-line heuristics, IOA rules, the anomaly scorer, an Office
  parent, or a temp/download image path, each of which already escalates.
- Non-interactive flags are LOW (`noninteractive_flags`). A real hidden
  window (`-w hidden`) stays MEDIUM.
- Cradle = fetch AND (execute OR decode) is HIGH. certutil `-urlcache`/`-decode`
  stays HIGH alone. Fetch alone is LOW (`lolbin_network_fetch`), and the
  engine routes it to the sequence engine ahead of the severity gate, like
  `discovery_command`, so "document shell fetched a payload" and "fetched
  then persisted" still complete. Execute alone is LOW (`dynamic_exec`).
- Encoded-command switches are judged only when PowerShell is the process or
  is what the command line launches.
- node.exe/java.exe spawning a shell is a 0.3 compounding signal
  (`runtime_spawned_shell`). Dedicated servers (w3wp, nginx, Tomcat, SQL
  Server...) keep the 0.6 signal that fires alone. `java -> cmd /c curl
  http://...` still fires.
- A UNC path must be a token that starts at a boundary (or a `/switch:`) with
  `\\host\`. `\\?\` and `\\.\` are excluded.
- `schtasks /create` and InstallUtil launched by msiexec are LOW context
  rules. These are keyed on the parent, not on a `\program files\`
  command-line exclusion. That exclusion was tried and rejected, because
  `cmd_not` matches anywhere in the line and is forgeable for free
  (`/logfile="C:\Program Files\x" /u C:\temp\evil.dll`). A NETLOGON/SYSVOL
  UNC exemption was also tried and reverted, for the reason `Rule.cmd_not`'s
  own docstring gives: an attacker can name a share "sysvol".
- New: `OriginalFileName` rename detection in EID 1 for a watched set of
  system utilities and attacker staples: HIGH,
  `T1036.003 Rename System Utilities`. 32/64-bit vendor builds
  (procdump64, PsExec64) are not renames.
- New: EID 7, a Windows system-library name loaded from a user-writable
  folder, signed or not: HIGH, T1574.001 (+ T1574.002). The list excludes
  DLLs apps legitimately bundle (dbghelp, d3d*, dxgi, msvcp*). Any other
  unsigned load is LOW, except a Windows system binary loading one from a
  user folder, which is MEDIUM.

## Evidence

Offline, through the real `classify_sysmon` path:

| Benign set | Before | After |
|---|---:|---:|
| Elastic benign corpus (independent) | 81.8% | 2.9% |
| Everyday launches (hand-written; regression guard only) | 72.3% | 0% |
| This machine's own running processes, full path known (91) | 3.3% | 0% |

Detection did not move: Tier A replay 70/90 before and after; the live-shape
replay (each catalog command as `cmd.exe /c <cmd>` plus its child, through
`classify_sysmon`, the incident gate and the harness's technique match) 42
before and after. The evasion ratchet HELD with no per-technique regression.
New detections: `evasion-masquerade-lsass` flips to credited as T1036.003 on
the Sysmon events a runner already produces.

`tests/test_benign_launch_fp.py` (37 checks) pins it: the Elastic corpus under
a 4% ceiling, the everyday list at zero, and nine attack shapes that must
still alert. Against the unmodified HEAD it fails 28 of 37.

## Honest boundaries

- All of this is offline, through the real classifier functions. Live
  detection is only proven by the Tier B workflow (`docs/LIVE_FIRE_EVALUATION.md`),
  which has not been run on this change.
- The amsi.dll hijack is only visible live if Sysmon delivers signed image
  loads. The shipped config (`sysmon_manager.py`) includes unsigned loads
  only. Widening it needs a live run to validate, because a malformed config
  blinds Sysmon entirely.
- Discovery commands still never alert alone, by design. A per-execution
  score that counts them needs a telemetry tier (technique-tagged, sub-alert,
  queryable) that the engine does not persist today. That is the next piece
  of work, not something to paper over by raising their severity.
- The remaining Elastic hits are mostly management tooling sending
  `-EncodedCommand` (Ansible over WinRM) and IIS worker processes spawning
  cmd. Those are the real tradeoff between those tools and actual attacks,
  not bugs.
