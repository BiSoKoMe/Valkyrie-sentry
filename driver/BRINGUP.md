# Valkyrie driver bring-up runbook

Execute this **only inside a disposable, snapshotted VM**. A kernel bug is a
bugcheck (BSOD), and a bad block list is an unbootable machine. Nothing in this
document should ever be run on a machine you care about.

Static review completed 2026-08-04 — six defects found and fixed before first
build (see `docs/adr/0043-driver-hardening.md`). This runbook assumes those
fixes are present.

---

## 0. VM setup (do not skip)

| Setting | Value | Why |
|---|---|---|
| Snapshot | Take one named `clean` **before anything else** | Your rollback for every failed step |
| Networking | **Host-only or NAT**, never bridged | Later stages run attack tooling |
| RAM / CPU | ≥4 GB, ≥2 vCPU | Driver Verifier is memory-hungry |
| Guest | Windows 10/11 x64, same build family as your host | Callback behaviour varies by build |
| Kernel debugger | Optional but strongly recommended | Without it a BSOD tells you almost nothing |

```powershell
# In the VM, as Administrator:
bcdedit /set testsigning on
bcdedit /set nointegritychecks off      # keep integrity checks ON; we sign properly
# Optional but recommended — lets you read a crash instead of guessing:
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
shutdown /r /t 0
```
After reboot you will see a "Test Mode" desktop watermark. That is expected.
**Take a second snapshot here, named `testsigning`.**

---

## 1. Build

Requires **Visual Studio 2022** + **WDK** (matching SDK), or the self-contained
**EWDK**. From a Developer/EWDK prompt:

```powershell
cd driver\valkyrie_km
msbuild valkyrie_km.vcxproj /p:Configuration=Release /p:Platform=x64
# -> x64\Release\valkyrie_km.sys
```

**If `PsSetCreateProcessNotifyRoutineEx` fails at load with STATUS_ACCESS_DENIED,
the `/INTEGRITYCHECK` linker flag is missing.** It is now set in the vcxproj;
verify it survived any project edits:

```powershell
dumpbin /headers x64\Release\valkyrie_km.sys | findstr /i "Integrity"
# expect: "Image has Integrity checks enforced"
```

This is the single most common first-driver failure and it presents as a
generic `sc start` error with no explanation.

---

## 2. Static analysis — before you ever load it

Run both. They find in minutes what a bugcheck takes hours to diagnose.

```powershell
# Code Analysis (driver-specific ruleset)
msbuild valkyrie_km.vcxproj /p:Configuration=Release /p:Platform=x64 `
        /p:RunCodeAnalysis=true /p:EnablePREfast=true

# Static Driver Verifier — symbolic execution of the callback contracts
msbuild valkyrie_km.vcxproj /t:sdv /p:Inputs="/check:default" `
        /p:Configuration=Release /p:Platform=x64
```
**Gate: zero PREfast warnings, SDV result "Pass", before proceeding.**

---

## 3. Test-sign

```powershell
# One-time: create a test certificate
makecert -r -pe -ss PrivateCertStore -n "CN=ValkyrieTest" ValkyrieTest.cer
certmgr /add ValkyrieTest.cer /s /r localMachine root
certmgr /add ValkyrieTest.cer /s /r localMachine trustedpublisher

signtool sign /v /s PrivateCertStore /n ValkyrieTest /fd sha256 `
              x64\Release\valkyrie_km.sys
signtool verify /v /pa x64\Release\valkyrie_km.sys
```

---

## 4. Load — telemetry only

The driver ships detection-only: prevention and self-protection stay off until
user mode explicitly enables them. **Do not change that for the first load.**

```powershell
copy x64\Release\valkyrie_km.sys C:\Windows\System32\drivers\
sc create ValkyrieKm type= kernel binPath= C:\Windows\System32\drivers\valkyrie_km.sys
sc start ValkyrieKm
sc query ValkyrieKm          # expect STATE : 4  RUNNING
```

Verify from Python (unprivileged run should now FAIL — that is the ACL fix
working; run elevated to succeed):

```powershell
python -c "from valkyrie.kernel_bridge import KernelSensor; s=KernelSensor(); print(s.available(), s.stats())"
```

**Stage gate — all must hold before you continue:**
- [ ] `available()` is True when elevated, **False when not** (device ACL)
- [ ] Process create/exit events arrive with correct pid/ppid/image
- [ ] `events_dropped` stays 0 while browsing/compiling normally
- [ ] **Zero thread-injection events during ordinary use** — if you see one per
      process start, the first-thread suppression regressed
- [ ] No bugcheck after 30 minutes of normal work

---

## 5. Driver Verifier — the stress gate

```powershell
verifier /standard /driver valkyrie_km.sys
shutdown /r /t 0
```
Then run **72 hours** of load: process churn, browsing, compiles, VM suspend/
resume. Any bugcheck here is a real bug that would have hit a user.

```powershell
verifier /querysettings     # confirm it is active
verifier /reset             # turn off when done
```

---

## 6. Enable LSASS protection — the first real capability

Push a policy with `VLK_POLICY_ENABLE_SELFPROTECT` and agent pid, leaving
prevention off.

**Validation — this is the money shot:**
1. Download Mimikatz **inside the VM only**.
2. Run `sekurlsa::logonpasswords`.
3. **Expected: it fails to read LSASS memory, and the process does NOT die.**
   You should see `VLK_EVT_LSASS_ACCESS_BLOCKED` with `granted_access` showing
   the stripped mask.
4. Confirm Windows still logs in, locks/unlocks, and RDP works — stripping
   LSASS rights too broadly breaks authentication.

If `ObRegisterCallbacks` returned failure at load, this silently does nothing.
That is expected without an ELAM-entitled certificate; the driver degrades to
telemetry rather than crashing. Check `sc query` + your stats output to tell
"protection off" from "protection on and working".

---

## 7. Enable prevention — last, and carefully

```
Only after 1-6 are green. Start with a block list of exactly ONE test binary
you created yourself. Never a system binary. Never a wildcard.
```

Safety rails already in the driver: images under `\Windows\` are never denied,
and the policy is clamped to 256 entries. **Test the rail explicitly** — put
`notepad.exe` on the block list and confirm it still launches.

**Known limitation, do not skip reading:** blocking matches the **FNV-1a hash of
the lowercased basename**. Renaming `evil.exe` to `notevil.exe` bypasses it
entirely. This is adequate for a self-test and **inadequate against real
malware** — image-hash (SHA256) blocking is the real answer and is not built.
Do not describe this as malware prevention.

---

## 8. Recovery — when, not if

| Symptom | Recovery |
|---|---|
| Boot loop / BSOD on start | Boot Safe Mode → `sc config ValkyrieKm start= disabled` → reboot |
| Safe Mode also fails | Restore the `testsigning` snapshot |
| Machine boots but is unusable | `sc stop ValkyrieKm` then `sc delete ValkyrieKm` |
| A process can't start | Policy block list — push an empty policy, or stop the driver |

Always keep a Windows recovery ISO attached to the VM.

---

## 9. What this does NOT give you

State these honestly wherever the driver is described:

- **No file system visibility.** There is no minifilter. No pre-write ransomware
  blocking, no quarantine, no file-based self-protection.
- **No kernel network visibility.** There is no WFP callout.
- **No memory-operation visibility.** `VirtualAllocEx`/`WriteProcessMemory` need
  ETW-TI, which needs PPL, which needs an ELAM certificate Microsoft grants only
  to vetted AV vendors.
- **No PPL self-protection.** The Ob callback strips handle rights, which raises
  the cost of tampering but does not stop a determined admin-level attacker.
- **Prevention is basename-hash only** — see §7.
- **Not production-signed.** Test-signing works only on a machine in test mode.
  Production needs an EV certificate + Microsoft attestation signing, which
  requires a legal entity.
