# Provenance Architecture Limitations

## LIVE VALIDATION BLOCKED

This developer workstation is not a disposable isolated Windows VM. Atomic Red
Team must not run here. A valid run requires a snapshot-capable VM, restore
procedure, isolated network policy, Sysmon event coverage, the Atomic Red Team
dependency, and a live Valkyrie agent.

Read-only host check, 2026-08-28: `ASUSTeK COMPUTER INC. ASUS TUF Gaming A15
FA506NF_FA506NF`, Windows 11 Home build 26200; it is physical hardware, not a
VM. `Sysmon64` is installed but stopped, and the `Invoke-AtomicRedTeam`
PowerShell module is absent. This is insufficient and unsafe for Tier-B.

## Other limits

- User-mode process and network collectors are lossy and can be delayed.
- Nyx port attribution is best-effort, not browser semantic attribution.
- The consequence rule cannot prevent the already-observed request.
- The current unified response remains dry-run pending measured false-positive,
  latency, and live-enforcement evidence.
- Signed-driver and WFP capabilities are not deployed, so they must not be
  represented as active prevention.
