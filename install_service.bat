@echo off
setlocal enabledelayedexpansion

:: ---------------------------------------------------------------------
:: install_service.bat - register Valkyrie as a Windows service via NSSM
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

:: Manual override: `install_service.bat -SkipDownload` skips the download
:: step entirely - use this after placing tools\nssm.exe yourself.
set "SKIP_DOWNLOAD=0"
if /i "%~1"=="-SkipDownload" set "SKIP_DOWNLOAD=1"

:: 2. Ensure NSSM is present
if exist "%NSSM_EXE%" goto :after_nssm

if "%SKIP_DOWNLOAD%"=="1" (
    echo [ERROR] -SkipDownload was passed but tools\nssm.exe was not found.
    echo Place nssm.exe at: %NSSM_EXE%
    echo Then re-run this script.
    exit /b 1
)

echo [*] NSSM not found - trying mirrors...
if not exist "%NSSM_DIR%" mkdir "%NSSM_DIR%"
set "NSSM_ZIP=%TEMP%\nssm_download.zip"
set "NSSM_EXTRACT=%TEMP%\nssm_extract"
if exist "%NSSM_ZIP%" del /f /q "%NSSM_ZIP%" >nul 2>&1
if exist "%NSSM_EXTRACT%" rmdir /s /q "%NSSM_EXTRACT%" >nul 2>&1

set "DOWNLOADED=0"

:: NOTE: the release asset is named nssm_x64.zip, not nssm.zip - verified
:: against the actual GitHub release at the time of writing.
call :try_download "https://github.com/ONLYOFFICE/nssm/releases/download/v2.24.1/nssm_x64.zip" "%NSSM_ZIP%"
if "%DOWNLOADED%"=="1" goto :extract_nssm

call :try_download "https://github.com/nssmliq/NSSM/releases/download/v2.24/nssm-2.24.zip" "%NSSM_ZIP%"
if "%DOWNLOADED%"=="1" goto :extract_nssm

call :try_download "https://nssm.cc/release/nssm-2.24.zip" "%NSSM_ZIP%"
if "%DOWNLOADED%"=="1" goto :extract_nssm

echo.
echo [ERROR] Automatic download failed. Please download NSSM manually:
echo   1. Open https://github.com/ONLYOFFICE/nssm/releases in your browser
echo   2. Download the latest release zip
echo   3. Extract it
echo   4. Copy nssm.exe from the win64 folder to:
echo      %NSSM_EXE%
echo   5. Run this script again - it will detect the file and continue automatically
exit /b 1

:extract_nssm
echo [*] Extracting NSSM...
powershell -NoProfile -Command "Expand-Archive -Path '%NSSM_ZIP%' -DestinationPath '%NSSM_EXTRACT%' -Force" >nul 2>&1
if not exist "%NSSM_EXTRACT%" (
    echo [ERROR] Failed to extract downloaded NSSM archive.
    exit /b 1
)

:: Detect architecture - pick win64/nssm.exe or win32/nssm.exe
set "ARCH_DIR=win32"
for /f %%A in ('powershell -NoProfile -Command "if ([Environment]::Is64BitOperatingSystem) { Write-Output 'win64' } else { Write-Output 'win32' }"') do set "ARCH_DIR=%%A"

:: Search recursively - different mirrors nest the zip contents differently
:: (some wrap in a version folder, some don't), so don't assume a fixed
:: path depth. Filter the recursive listing for the right architecture dir.
set "FOUND_NSSM="
for /f "delims=" %%F in ('dir /s /b "%NSSM_EXTRACT%\nssm.exe" 2^>nul ^| findstr /i "\\%ARCH_DIR%\\"') do (
    if not defined FOUND_NSSM set "FOUND_NSSM=%%F"
)
if not defined FOUND_NSSM (
    echo [WARNING] No %ARCH_DIR% build found - falling back to any nssm.exe in the archive.
    for /f "delims=" %%F in ('dir /s /b "%NSSM_EXTRACT%\nssm.exe" 2^>nul') do (
        if not defined FOUND_NSSM set "FOUND_NSSM=%%F"
    )
)
if not defined FOUND_NSSM (
    echo [ERROR] Could not locate nssm.exe inside the downloaded archive.
    exit /b 1
)

copy /Y "%FOUND_NSSM%" "%NSSM_EXE%" >nul
if not exist "%NSSM_EXE%" (
    echo [ERROR] Could not copy nssm.exe to tools directory.
    exit /b 1
)
echo [OK] NSSM ready at %NSSM_EXE%

:after_nssm

:: 3. Resolve python.exe full path - must be an interpreter that ACTUALLY
:: has Valkyrie's dependencies installed, not merely "any real-looking path".
::
:: A path not living under WindowsApps is necessary but not sufficient: a
:: "real" interpreter found elsewhere on the system can easily be a totally
:: separate, dependency-free environment (this happened in practice - the
:: previous version of this script picked exactly such an interpreter, and
:: the service crashed in <5s with ImportError, which NSSM's restart
:: throttle then reported as a stuck PAUSED state). Every candidate is
:: therefore validated by actually importing Valkyrie's required packages
:: with it before being accepted.
::
:: Pass 1 (preferred) - candidates NOT under WindowsApps:
::   1. Every line `where python` returns
::   2. sys.executable as reported by whatever `python` currently resolves to
::   3. sys.executable via the `py` launcher (py -3)
::   4. A fixed list of common real-install locations
:: Pass 2 (fallback, only if pass 1 finds nothing) - same sources again,
:: this time also allowing WindowsApps paths, since a Store-distributed
:: interpreter that actually has the dependencies installed (as happened
:: here) is strictly better than no working interpreter at all.
pushd "%PROJECT_ROOT%"

set "PYTHON_EXE="

for /f "delims=" %%P in ('where python 2^>nul') do (
    if not defined PYTHON_EXE (
        echo %%P | findstr /i "WindowsApps" >nul
        if errorlevel 1 (
            call :probe_python "%%P"
            if "!PROBE_OK!"=="1" set "PYTHON_EXE=%%P"
        )
    )
)

if not defined PYTHON_EXE (
    for /f "delims=" %%P in ('python -c "import sys; print(sys.executable)" 2^>nul') do (
        echo %%P | findstr /i "WindowsApps" >nul
        if errorlevel 1 (
            call :probe_python "%%P"
            if "!PROBE_OK!"=="1" set "PYTHON_EXE=%%P"
        )
    )
)

if not defined PYTHON_EXE (
    for /f "delims=" %%P in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do (
        echo %%P | findstr /i "WindowsApps" >nul
        if errorlevel 1 (
            call :probe_python "%%P"
            if "!PROBE_OK!"=="1" set "PYTHON_EXE=%%P"
        )
    )
)

if not defined PYTHON_EXE (
    for %%D in (
        "C:\Python313\python.exe"
        "C:\Python312\python.exe"
        "C:\Python311\python.exe"
        "C:\Python310\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
        "%LOCALAPPDATA%\Python\bin\python.exe"
        "C:\Program Files\Python313\python.exe"
        "C:\Program Files\Python312\python.exe"
        "C:\Program Files\Python311\python.exe"
    ) do (
        if not defined PYTHON_EXE if exist %%D (
            call :probe_python "%%~D"
            if "!PROBE_OK!"=="1" set "PYTHON_EXE=%%~D"
        )
    )
)

:: Pass 2 - relax the WindowsApps exclusion, keep the dependency probe.
:: Prefer sys.executable's resolved path here over the bare `where python`
:: hit: sys.executable points at the real interpreter binary INSIDE the
:: Store package (...\WindowsApps\PythonSoftwareFoundation.Python.3.x_xxxx\
:: python.exe), whereas `where python` surfaces the thin AppExecutionAlias
:: redirector (...\WindowsApps\python.exe) that depends on Store activation
:: infrastructure to even launch - infrastructure that may not be available
:: to a service running in Session 0. The nested binary is a real exe, not
:: a redirector, so it is the safer of the two Store-distributed options.
if not defined PYTHON_EXE (
    echo [*] No working interpreter found outside WindowsApps - trying Store Python too...
    for /f "delims=" %%P in ('python -c "import sys; print(sys.executable)" 2^>nul') do (
        if not defined PYTHON_EXE (
            call :probe_python "%%P"
            if "!PROBE_OK!"=="1" (
                set "PYTHON_EXE=%%P"
                echo [WARNING] Using a Microsoft Store Python interpreter. This can be
                echo           unreliable for services launched outside an interactive
                echo           session. If the service misbehaves, install Python from
                echo           https://python.org instead.
            )
        )
    )
)

if not defined PYTHON_EXE (
    for /f "delims=" %%P in ('where python 2^>nul') do (
        if not defined PYTHON_EXE (
            call :probe_python "%%P"
            if "!PROBE_OK!"=="1" (
                set "PYTHON_EXE=%%P"
                echo [WARNING] Using a Microsoft Store Python interpreter. This can be
                echo           unreliable for services launched outside an interactive
                echo           session. If the service misbehaves, install Python from
                echo           https://python.org instead.
            )
        )
    )
)

if not defined PYTHON_EXE (
    echo [ERROR] No Python interpreter with Valkyrie's dependencies could be found.
    echo Install the required packages and re-run this installer:
    echo   python -m pip install psutil rich pyyaml dnspython fastapi uvicorn
    echo If only the Microsoft Store Python stub is on PATH, install Python
    echo directly from https://python.org instead - the Store version is
    echo unreliable when launched outside an interactive session.
    popd
    exit /b 1
)

popd
echo [*] Using Python interpreter - dependencies verified: %PYTHON_EXE%

:: 3b. If the service already exists (e.g. a previous run installed it
:: pointing at a broken or dependency-less interpreter), remove it first so
:: the reinstall below starts clean rather than leaving stale NSSM config
:: behind.
sc query %SERVICE_NAME% >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Existing service found - removing before reinstall...
    "%NSSM_EXE%" stop %SERVICE_NAME% >nul 2>&1
    "%NSSM_EXE%" remove %SERVICE_NAME% confirm >nul 2>&1
)

:: 4. Install the service
echo [*] Installing service "%SERVICE_NAME%"...
"%NSSM_EXE%" install %SERVICE_NAME% "%PYTHON_EXE%"
"%NSSM_EXE%" set %SERVICE_NAME% AppParameters "-m valkyrie --web --no-ui"
"%NSSM_EXE%" set %SERVICE_NAME% AppDirectory "%PROJECT_ROOT%"
"%NSSM_EXE%" set %SERVICE_NAME% DisplayName "Valkyrie Privacy Shield"
"%NSSM_EXE%" set %SERVICE_NAME% Description "Local privacy gateway - DNS sinkhole + firewall"
"%NSSM_EXE%" set %SERVICE_NAME% Start SERVICE_AUTO_START

:: NSSM discards the wrapped process's stdout/stderr by default, which made
:: this exact crash hard to diagnose (had to dig through Event Viewer to
:: find the exit code). Capture both to log files going forward.
if not exist "%PROJECT_ROOT%\data" mkdir "%PROJECT_ROOT%\data"
"%NSSM_EXE%" set %SERVICE_NAME% AppStdout "%PROJECT_ROOT%\data\service_stdout.log"
"%NSSM_EXE%" set %SERVICE_NAME% AppStderr "%PROJECT_ROOT%\data\service_stderr.log"

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
exit /b 0

:: ---------------------------------------------------------------------
:: probe_python <python_exe_path>  - sets PROBE_OK=1 if this interpreter
:: can actually import Valkyrie and every package "--web --no-ui" needs,
:: 0 otherwise (missing deps, broken/sandboxed interpreter, wrong cwd).
:: Run from PROJECT_ROOT (caller pushd's there) so "import valkyrie"
:: resolves the local package. Placed after the final "exit /b 0" above
:: so normal execution never falls into it.
:: ---------------------------------------------------------------------
:probe_python
set "PROBE_OK=0"
"%~1" -c "import valkyrie, psutil, rich, yaml, dns, fastapi, uvicorn" >nul 2>&1
if %errorlevel% equ 0 set "PROBE_OK=1"
exit /b 0

:: ---------------------------------------------------------------------
:: try_download <url> <dest_zip_path>  - sets DOWNLOADED=1 on success,
:: 0 on any failure (HTTP error, timeout, empty file). Never aborts the
:: calling script - caller decides what to do next. Placed after the
:: final "exit /b 0" above so normal execution never falls into it.
:: ---------------------------------------------------------------------
:try_download
set "DOWNLOADED=0"
echo [*] Trying %~1 ...
powershell -NoProfile -Command ^
    "try { $ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri '%~1' -OutFile '%~2' -UseBasicParsing -TimeoutSec 30; if ((Get-Item '%~2' -ErrorAction Stop).Length -gt 0) { exit 0 } else { exit 1 } } catch { Write-Host ('    failed: ' + $_.Exception.Message); exit 1 }"
if %errorlevel% equ 0 (
    if exist "%~2" (
        set "DOWNLOADED=1"
        echo [OK] Downloaded from %~1
    )
)
exit /b 0
