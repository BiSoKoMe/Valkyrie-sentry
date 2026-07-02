@echo off
:: stop_all.bat - thin wrapper around stop_all.ps1.
:: All logic (DNS reset, process stop, Unbound restore) lives in the
:: PowerShell script - this just invokes it. The .ps1 handles its own UAC
:: self-elevation, so this wrapper does not need to run elevated itself.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0stop_all.ps1"
