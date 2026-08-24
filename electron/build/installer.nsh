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
  ; --- Visual C++ runtime (bundled only if build_app.ps1 fetched it) ---------
  IfFileExists "$INSTDIR\resources\engine\vc_redist.x64.exe" vc_yes vc_no
  vc_yes:
    DetailPrint "Installing Visual C++ runtime..."
    nsExec::ExecToLog '"$INSTDIR\resources\engine\vc_redist.x64.exe" /quiet /norestart'
  vc_no:

  ; --- No-prompt arm/disarm scheduled tasks ---------------------------------
  DetailPrint "Registering Valkyrie protection tasks..."
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\engine\register-tasks.ps1" -Root "$INSTDIR\resources\engine"'

  ; --- Always-on engine as a Windows service --------------------------------
  DetailPrint "Installing Valkyrie engine service..."
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\engine\service-install.ps1" -Root "$INSTDIR\resources\engine"'
!macroend

!macro customUnInstall
  DetailPrint "Removing Valkyrie engine service..."
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\engine\service-uninstall.ps1" -Root "$INSTDIR\resources\engine"'

  DetailPrint "Removing Valkyrie protection tasks..."
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\engine\unregister-tasks.ps1"'
!macroend
