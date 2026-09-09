; electron-builder NSIS customization for Valkyrie.
;
; The assisted (perMachine) installer runs elevated, so these hooks can install
; the Windows service, register the no-prompt arm/disarm tasks, and run the VC++
; runtime. The engine + scripts + nssm.exe ship under $INSTDIR\resources\engine
; (staged by build_app.ps1 -> electron-builder extraResources).

; customInit runs in .onInit, before the "install" Section that copies files —
; the ONLY hook electron-builder offers that early. Stops a pre-existing
; ValkyrieShield service before resources\engine\valkyrie.exe is touched.
;
; Without this, an in-place upgrade left the OLD service running through the
; entire file-copy step below, and NSSM (still supervising the old process,
; AppExit=Restart) raced its own restart-on-exit against the file being
; overwritten -- caught live on 2026-08-05: NSSM logged a real
; "CreateProcess() failed: The system cannot find the file specified" the
; instant valkyrie.exe was between delete and recreate, then several rapid
; kill/restart cycles (exit code 1 -> AppExit Restart) until the copy
; finished and customInstall's service-install.ps1 (below) finally got to
; stop + cleanly reinstall the service. That script was already correct; it
; just always ran too late to prevent the race, only to clean up after it.
!macro customInit
  DetailPrint "Stopping any existing Valkyrie service before upgrade..."
  nsExec::ExecToLog 'sc.exe stop ValkyrieShield'
  ; sc.exe stop returns once the stop is ACCEPTED, not once the process has
  ; actually exited. A fixed wait is simpler and more robust across NSIS/sc.exe
  ; versions than parsing `sc query` output for a STOPPED state; on a first
  ; install (no existing service) the stop fails instantly and this is the
  ; only cost paid. NSSM's AppStopMethodConsole + subsequent escalation
  ; normally completes in well under a second once genuinely SCM-driven.
  Sleep 3000
!macroend

!macro customInstall
  ; --- The engine binary must actually be on disk before anything else here
  ; touches it. Found on a real machine (2026-09-07): three separate installs
  ; (2026-08-20, 2026-08-23, 2026-09-05) each finished "successfully" with
  ; resources\engine\ containing nssm.exe but NOT valkyrie.exe -- the extract
  ; step silently dropped the one file the whole service depends on (most
  ; likely AV real-time scanning holding a lock on a freshly-written unsigned
  ; SYSTEM-service binary during the upgrade race customInit guards above; the
  ; exact mechanism was never pinned down, which is precisely why this must be
  ; a hard, visible check rather than trusted to not recur). Every subsequent
  ; boot then failed with SCM error 7000/7024 "the system cannot find the file
  ; specified", with nothing in the installer UI ever saying so. An install
  ; that cannot run Valkyrie's actual engine is not a successful install.
  IfFileExists "$INSTDIR\resources\engine\valkyrie.exe" engine_present engine_missing
  engine_missing:
    DetailPrint "[ERROR] resources\engine\valkyrie.exe was not written by this installer."
    MessageBox MB_OK|MB_ICONSTOP "Valkyrie's engine file did not install correctly $\r$\n$\r$\n(resources\engine\valkyrie.exe is missing). Protection cannot run without it.$\r$\n$\r$\nThis can happen if antivirus real-time scanning locked the file during setup. Please close other security software temporarily and run this installer again, or download a fresh copy."
    Abort
  engine_present:

  ; --- Visual C++ runtime (bundled only if build_app.ps1 fetched it) ---------
  IfFileExists "$INSTDIR\resources\engine\vc_redist.x64.exe" vc_yes vc_no
  vc_yes:
    DetailPrint "Installing Visual C++ runtime..."
    nsExec::ExecToLog '"$INSTDIR\resources\engine\vc_redist.x64.exe" /quiet /norestart'
  vc_no:

  ; --- No-prompt arm/disarm scheduled tasks ---------------------------------
  ; register-tasks.ps1 is Register-ScheduledTask -Force, so re-running this on
  ; every upgrade is already idempotent - it replaces, never duplicates. What
  ; was missing was noticing when this step itself fails: nsExec::ExecToLog's
  ; exit code was never checked, so a machine could finish "installed
  ; successfully" with ValkyrieArm/ValkyrieDisarm silently never registered -
  ; found on a real machine during a DNS-lifecycle audit. Not fatal to the
  ; whole install (the engine/dashboard still work without these tasks; only
  ; arm/disarm-from-the-app degrades), but it must not be silent.
  DetailPrint "Registering Valkyrie protection tasks..."
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\engine\register-tasks.ps1" -Root "$INSTDIR\resources\engine"'
  Pop $0
  ${If} $0 != 0
    DetailPrint "[WARNING] Registering protection tasks failed (exit $0) - Start/Stop Protection may not work until this is repaired."
  ${EndIf}

  ; --- Always-on engine as a Windows service --------------------------------
  DetailPrint "Installing Valkyrie engine service..."
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\engine\service-install.ps1" -Root "$INSTDIR\resources\engine"'
  Pop $0
  ${If} $0 != 0
    ; This is the actual product, not an optional extra like the tasks above -
    ; a DetailPrint alone scrolls out of view and the installer still reports
    ; "Completed" while protection silently never runs. Surface it.
    DetailPrint "[ERROR] Installing the Valkyrie service failed (exit $0)."
    MessageBox MB_OK|MB_ICONEXCLAMATION "The Valkyrie protection service could not be installed (exit code $0).$\r$\n$\r$\nThe app will still open, but protection will not be running. Check $\r$\n%ProgramData%\Valkyrie\service_stderr.log, or reinstall as Administrator."
  ${EndIf}
!macroend

!macro customUnInstall
  DetailPrint "Removing Valkyrie engine service..."
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\engine\service-uninstall.ps1" -Root "$INSTDIR\resources\engine"'

  DetailPrint "Removing Valkyrie protection tasks..."
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\engine\unregister-tasks.ps1"'
!macroend
