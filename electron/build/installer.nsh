; electron-builder NSIS customization for Valkyrie.
;
; The assisted (perMachine) installer runs elevated, so these hooks can install
; the Windows service, register the no-prompt arm/disarm tasks, and run the VC++
; runtime. The engine + scripts + nssm.exe ship under $INSTDIR\resources\engine
; (staged by build_app.ps1 -> electron-builder extraResources).

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
