@echo off
:: start_all.bat - thin wrapper around start_all.ps1.
:: All logic (elevation, Unbound handoff, launch, DNS, dashboard) lives in
:: the PowerShell script - this just invokes it. The .ps1 handles its own
:: UAC self-elevation, so this wrapper does not need to run elevated itself.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_all.ps1"
