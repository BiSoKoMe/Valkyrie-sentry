# Valkyrie red-team test kit — real Atomic Red Team, honest scoring

This kit runs **real Atomic Red Team** atomics against a **running Valkyrie**
and produces a real DETECTED / MISSED / BLOCKED scorecard — the measurement that
replaces the in-repo corpus number with ground truth.

> **Run this in a throwaway VM with a snapshot. Never on a machine you care
> about.** Atomic Red Team executes genuinely destructive actions (deletes
> volume shadow copies, disables Defender, dumps LSASS, writes persistence). The
> VM is the whole point. See "Set up the VM" below.

## Why a VM (and why this isn't already run for you)

The dev machine this was built on is **Windows 11 Home** with no hypervisor
installed, so a Windows guest can't be provisioned headlessly here (enabling
virtualization on Home needs elevation + a reboot; a guest OS is a multi-GB
install). So this kit is **turnkey but VM-targeted**: stand up a VM once, then
the run is one command. The scripts are careful but were **authored, not
executed** here — treat them like the kernel driver: real, reviewable, unrun.

## The honest test plan (10 atomics)

Deliberately a **fair spread** — Valkyrie is strong on some of these and
genuinely weak on others. A rigged list of only-wins would be worthless. `Predict`
is the honest expectation *on a machine with Sysmon + PowerShell Script Block
Logging enabled* (see provisioning); without those, the "conditional" rows drop.

| # | ATT&CK | Atomic | Valkyrie detector | Predict | Why |
|---|--------|--------|-------------------|---------|-----|
| 1 | **T1071.004** | DNS query to a flagged/tracker domain | DNS sinkhole + scanner | **DETECT (strong)** | Always-on DNS is Valkyrie's best layer |
| 2 | **T1547.001** | Registry Run-key persistence | ASEP poller + `reg-add-runkey` rule | **DETECT** | The artifact persists — the poller catches it even if it missed the process |
| 3 | **T1053.005** | Scheduled task create | ASEP poller + `schtasks-create` rule | **DETECT** | Persistent artifact |
| 4 | **T1218.010** | Regsvr32 Squiblydoo (remote scriptlet) | `regsvr32-scriptlet` rule | **CONDITIONAL** | Needs the process (cmdline) captured — poller may miss a fast exit; Sysmon closes it |
| 5 | **T1003.001** | LSASS dump via `comsvcs` MiniDump | `comsvcs-minidump` rule (+ Sysmon EID 10) | **CONDITIONAL** | cmdline rule needs process capture; Sysmon adds the handle-access detection |
| 6 | **T1562.001** | Disable Defender real-time monitoring | `defender-disable` rule + PS 4104 | **CONDITIONAL** | Needs PS Script Block Logging or process capture |
| 7 | **T1490** | `vssadmin delete shadows` (DESTRUCTIVE) | `vssadmin-delete` rule (critical) | **CONDITIONAL** | Very short-lived process — poller likely misses; Sysmon/kernel catches |
| 8 | **T1055** | CreateRemoteThread process injection | Sysmon EID 8 → ESP `inject-then-creds` | **CONDITIONAL / MISS** | **No visibility without Sysmon or the kernel driver** — demonstrates the sensor dependency of the new ESP layer |
| 9 | **T1033** | `whoami /priv` (discovery) | `whoami-priv` rule (low) | **LIKELY MISS** | Classic poller gap — the process starts and exits between 2s polls |
| 10 | **T1490/T1486** | shadow-delete → mass encrypt (sequence) | ESP `ransomware-detonation` | **CONDITIONAL** | Fires only if both underlying detections land (see #7 caveat) |

**What to expect honestly:** strong on DNS + persistence artifacts; partial on
the LOLBin/credential/defense-evasion rows (config-dependent); real misses on
short-lived process tests and on injection without Sysmon. And almost nothing is
**BLOCKED** — Valkyrie is detection, not prevention, until the kernel driver is
built. A perfect score is not the honest expectation; a *fair* score is.

## Set up the VM (fastest legit routes)

1. **Microsoft's free Windows 11 dev VM** (no license, pre-activated, expires):
   <https://developer.microsoft.com/windows/downloads/virtual-machines/> —
   ships VirtualBox / VMware / Hyper-V / Parallels images. Import, snapshot.
2. **Or VirtualBox + a Windows 11 eval ISO.** (Note: a running Windows hypervisor
   — WSL2/VBS — can force VirtualBox into slow Hyper-V-compat mode; disable
   "Windows Hypervisor Platform" in the VM if it's sluggish.)

Give the VM **no bridged access to your real network** if you can avoid it —
NAT is fine and safer.

## Run it (inside the VM)

```powershell
# 1. Provision the guest: Sysmon + config, PS Script Block Logging, Atomic module.
#    (Run elevated. Reboot not required.)
.\redteam\provision.ps1

# 2. Install + start Valkyrie in the VM (ValkyrieSetup.exe), confirm the API:
#    Invoke-RestMethod http://127.0.0.1:8090/api/health   # should respond

# 3. Take a VM snapshot now (so the destructive atomics are one-click revert).

# 4. Run the scored red-team pass (auto-cleans each atomic):
.\redteam\run-redteam.ps1 -ApiBase http://127.0.0.1:8090

# → prints a per-atomic DETECTED/MISSED table + the honest total.

# 5. Revert the snapshot.
```

## How scoring works (no faking)

`run-redteam.ps1` snapshots Valkyrie's incident list before each atomic, runs the
atomic via `Invoke-AtomicTest`, waits for the pipeline to settle, then pulls the
new incidents from `GET /api/edr/incidents` and checks whether any new detection
carries the expected ATT&CK technique. DETECTED means Valkyrie raised a matching
incident; **BLOCKED** is tracked separately (only true if the action was actually
prevented — expected to be rare). Every atomic is cleaned up (`-Cleanup`) after.
The scorecard is whatever actually happened — it is not massaged.
