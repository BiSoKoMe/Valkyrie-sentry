@echo off
setlocal enabledelayedexpansion

:: ---------------------------------------------------------------------
:: install_service.bat — register Valkyrie as a Windows service via NSSM
:: ---------------------------------------------------------------------

:: 1. Require Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    echo Right-click install_service.bat and choose "Run as administrator".
    exit /b 1
)

set "PROJECT_ROOT=%~dp0"
set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"
set "NSSM_DIR=%PROJECT_ROOT%\tools"
set "NSSM_EXE=%NSSM_DIR%\nssm.exe"
set "SERVICE_NAME=ValkyrieShield"

:: 2. Ensure NSSM is present
if not exist "%NSSM_EXE%" (
    echo [*] NSSM not found — downloading...
    if not exist "%NSSM_DIR%" mkdir "%NSSM_DIR%"
    set "NSSM_ZIP=%TEMP%\nssm-2.24.zip"
    powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://nssm.cc/release/nssm-2.24.zip' -OutFile '%NSSM_ZIP%'"
    if not exist "%NSSM_ZIP%" (
        echo [ERROR] Failed to download NSSM. Check your internet connection.
        exit /b 1
    )
    powershell -NoProfile -Command "Expand-Archive -Path '%NSSM_ZIP%' -DestinationPath '%TEMP%\nssm_extract' -Force"
    copy /Y "%TEMP%\nssm_extract\nssm-2.24\win64\nssm.exe" "%NSSM_EXE%" >nul
    if not exist "%NSSM_EXE%" (
        copy /Y "%TEMP%\nssm_extract\nssm-2.24\win32\nssm.exe" "%NSSM_EXE%" >nul
    )
    if not exist "%NSSM_EXE%" (
        echo [ERROR] Could not extract nssm.exe
        exit /b 1
    )
    echo [OK] NSSM ready at %NSSM_EXE%
)

:: 3. Resolve python.exe full path
for /f "delims=" %%P in ('where python') do (
    set "PYTHON_EXE=%%P"
    goto :found_python
)
:found_python
if not defined PYTHON_EXE (
    echo [ERROR] python.exe not found on PATH.
    exit /b 1
)

:: 4. Install the service
echo [*] Installing service "%SERVICE_NAME%"...
"%NSSM_EXE%" install %SERVICE_NAME% "%PYTHON_EXE%"
"%NSSM_EXE%" set %SERVICE_NAME% AppParameters "-m valkyrie --web --no-ui"
"%NSSM_EXE%" set %SERVICE_NAME% AppDirectory "%PROJECT_ROOT%"
"%NSSM_EXE%" set %SERVICE_NAME% DisplayName "Valkyrie Privacy Shield"
"%NSSM_EXE%" set %SERVICE_NAME% Description "Local privacy gateway — DNS sinkhole + firewall"
"%NSSM_EXE%" set %SERVICE_NAME% Start SERVICE_AUTO_START

:: 5. Restart on failure (3 retries)
"%NSSM_EXE%" set %SERVICE_NAME% AppExit Default Restart
"%NSSM_EXE%" set %SERVICE_NAME% AppRestartDelay 5000
"%NSSM_EXE%" set %SERVICE_NAME% AppThrottle 5000

:: 6. Start it
echo [*] Starting service...
"%NSSM_EXE%" start %SERVICE_NAME%

echo.
sc query %SERVICE_NAME% | find "STATE"
echo [OK] Valkyrie installed and running as a Windows service.
echo      Dashboard: http://localhost:8080
endlocal
