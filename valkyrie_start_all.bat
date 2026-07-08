@echo off
setlocal enableextensions
set "LOG=%~dp0launcher_debug.log"

REM ============================================================
REM  Valkyrie one-click full-stack launcher (ADDITIVE - new file)
REM
REM  Step 1: MAC randomizer as its own visible step (checked exit
REM          code, pauses loudly on failure - does not hide it).
REM  Step 2: existing start_all.ps1, unchanged (Unbound handoff,
REM          engine launch, DNS takeover, dashboard).
REM
REM  ASCII only. No em-dashes, no smart quotes.
REM  No parenthesized if-blocks: goto labels are used instead so a
REM  stray "(" or ")" inside an echo can never break cmd parsing.
REM  These are documented recurring traps in this repo's .bat files.
REM ============================================================

REM ------------------------------------------------------------
REM  Self-elevate: if not admin, relaunch via UAC then exit this
REM  non-elevated instance. Triggers UAC once; start_all.ps1 sees
REM  it is already admin and does NOT prompt a second time.
REM ------------------------------------------------------------
net session >nul 2>&1
if %errorlevel% EQU 0 goto ELEVATED

echo [%date% %time%] non-admin start; requesting elevation > "%LOG%"
echo.
echo Not running as Administrator.
echo Approve the UAC prompt to continue...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
if errorlevel 1 goto UAC_FAILED
echo [%date% %time%] elevated instance launched >> "%LOG%"
exit /b

:UAC_FAILED
echo [%date% %time%] elevation FAILED or was cancelled >> "%LOG%"
echo.
echo ERROR: Could not start the elevated launcher.
echo You may have cancelled the UAC prompt, or a policy blocks
echo elevation. Nothing was changed. Right-click this file and
echo choose "Run as administrator" to try directly.
echo.
pause
exit /b

:ELEVATED
cd /d "%~dp0"
echo [%date% %time%] elevated instance running in "%cd%" >> "%LOG%"

echo.
echo ============================================================
echo  VALKYRIE LAUNCHER  [running as Administrator]
echo ============================================================

REM ============================================================
REM  STEP 1 of 2 : MAC randomizer
REM
REM  Run once and exit with a real return code. We call the same
REM  MacRandomizer the engine uses directly, because
REM  "python -m valkyrie --mac-rand" does NOT return - it starts
REM  the full blocking engine. On registry!=live the apply path
REM  fails loudly, so a nonzero exit here is a genuine failure.
REM ============================================================
echo.
echo [STEP 1/2] Randomizing MAC address...
echo.
python -c "import sys; from valkyrie.mac_randomizer import MacRandomizer; m=MacRandomizer(); r=m.randomize(); print('MAC randomised: '+r) if r else print('MAC randomisation FAILED: '+(m.last_error or 'unknown error')); sys.exit(0 if r else 1)"
set MAC_RC=%errorlevel%
echo [%date% %time%] MAC step exit code = %MAC_RC% >> "%LOG%"
if %MAC_RC% EQU 0 goto MAC_OK

echo.
echo ============================================================
echo  WARNING: MAC randomizer returned exit code %MAC_RC%.
echo  The MAC address was NOT changed. This failure is shown,
echo  not hidden. See the message just above for the reason.
echo  A common cause is the registry write not applying to the
echo  live adapter. The full stack will still start next.
echo ============================================================
echo.
pause
goto STEP2

:MAC_OK
echo.
echo [STEP 1/2] MAC randomizer OK.

:STEP2
echo.
echo [STEP 2/2] Starting the Valkyrie full stack...
echo.
powershell -ExecutionPolicy Bypass -File "%~dp0start_all.ps1"
echo [%date% %time%] start_all.ps1 returned exit code %errorlevel% >> "%LOG%"

echo.
echo ============================================================
echo  Launcher finished. Valkyrie runs in its own window.
echo  Dashboard: http://localhost:8090
echo  Press any key to close THIS launcher window.
echo ============================================================
pause >nul
endlocal
