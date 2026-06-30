@echo off
setlocal

:: ---------------------------------------------------------------------
:: uninstall_service.bat — remove the Valkyrie Windows service
:: ---------------------------------------------------------------------

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    exit /b 1
)

set "PROJECT_ROOT=%~dp0"
set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"
set "NSSM_EXE=%PROJECT_ROOT%\tools\nssm.exe"
set "SERVICE_NAME=ValkyrieShield"

echo [*] Stopping service...
if exist "%NSSM_EXE%" (
    "%NSSM_EXE%" stop %SERVICE_NAME%
) else (
    sc stop %SERVICE_NAME% >nul 2>&1
)

echo [*] Removing service...
if exist "%NSSM_EXE%" (
    "%NSSM_EXE%" remove %SERVICE_NAME% confirm
) else (
    sc delete %SERVICE_NAME%
)

echo [*] Removing Windows Firewall rule...
netsh advfirewall firewall delete rule name="Valkyrie DNS UDP 5300" >nul 2>&1

echo [OK] Valkyrie service uninstalled.
endlocal
