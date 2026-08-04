@echo off
REM ============================================================================
REM  build_km.bat — compile + PREfast + link valkyrie_km WITHOUT the WDK's
REM  Visual Studio integration.
REM
REM  WHY THIS EXISTS
REM  ---------------
REM  valkyrie_km.vcxproj sets PlatformToolset=WindowsKernelModeDriver10.0. That
REM  toolset is registered by the WDK's Visual Studio extension (WDK.vsix), NOT
REM  by the WDK itself. A machine can have the complete WDK — headers, libs,
REM  build\*.props/targets — and still be unable to `msbuild valkyrie_km.vcxproj`
REM  because the toolset is missing from
REM      VC\v170\Platforms\x64\PlatformToolsets\.
REM  msbuild's error in that state does not say "install the vsix"; it says the
REM  platform toolset cannot be found, which reads like a broken project file.
REM
REM  This script drives cl.exe / link.exe directly with the same flags the WDK
REM  driver targets would use, so the driver is buildable and analysable on any
REM  box with VS Build Tools + the WDK, vsix or not.
REM
REM  WHAT IT DOES NOT DO
REM  -------------------
REM  It does not sign, install, or load anything. The output .sys is unsigned and
REM  MUST NOT be loaded on a machine you care about — see driver/BRINGUP.md.
REM  Static Driver Verifier is NOT run here: SDV is a separate WDK feature
REM  (staticdv.exe + its rule set) driven through msbuild, and it is absent when
REM  the vsix is absent. See docs/adr/0043-driver-hardening.md.
REM
REM  Usage:  driver\build_km.bat
REM ============================================================================
setlocal enabledelayedexpansion

set "VS=C:\Program Files\Microsoft Visual Studio\2022\Community"
set "WK=C:\Program Files (x86)\Windows Kits\10"
set "SDKV=10.0.26100.0"

REM --- locate the MSVC toolchain version rather than hardcoding it ------------
set "MSVC="
for /d %%D in ("%VS%\VC\Tools\MSVC\*") do set "MSVC=%%D"
if not defined MSVC (
    echo [FATAL] No MSVC toolchain under "%VS%\VC\Tools\MSVC".
    exit /b 1
)
if not exist "%WK%\Include\%SDKV%\km\ntifs.h" (
    echo [FATAL] WDK kernel headers not found for SDK %SDKV%.
    echo         Looked for "%WK%\Include\%SDKV%\km\ntifs.h".
    exit /b 1
)

set "PATH=%MSVC%\bin\Hostx64\x64;%WK%\bin\%SDKV%\x64;%PATH%"

REM km\crt MUST precede the MSVC include dir: otherwise crtdefs.h is picked up
REM from user-mode CRT headers and pulls in corecrt.h, which does not exist in a
REM kernel build (fatal C1083).
set INC=/I"%WK%\Include\%SDKV%\km\crt" /I"%WK%\Include\%SDKV%\km" /I"%WK%\Include\%SDKV%\shared" /I"%MSVC%\include"

REM Do NOT define _KERNEL_MODE by hand — /kernel defines it, and redefining a
REM reserved macro is C4117, which /WX makes fatal.
set DEFS=/D_WIN64 /D_AMD64_ /DAMD64 /DNDEBUG /DNTDDI_VERSION=0x0A000010 /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00

set CFLAGS=/c /nologo /W4 /WX /O2 /Oy- /GF /Gm- /Zp8 /GS /Gy /fp:precise /Zc:wchar_t- /Zc:forScope /Zc:inline /GR- /kernel

cd /d "%~dp0valkyrie_km"
if not exist objs mkdir objs

echo.
echo === [1/3] COMPILE (/W4 /WX) ===
cl %CFLAGS% %DEFS% %INC% /Foobjs\ valkyrie_km.c
if errorlevel 1 ( echo [FAIL] compile & exit /b 1 )

echo.
echo === [2/3] PREfast static analysis (driver plugin) ===
REM /WX is dropped here on purpose: the WDK's own ntddk.h ships two broken SAL
REM annotations on WheaErrorRecordBuilderAddPacket (C28230/C28285) that we
REM cannot fix and must not fail the build on. Warnings citing valkyrie_km.c are
REM the ones that matter; the check below enforces that there are none.
cl %CFLAGS:/WX=% %DEFS% %INC% /analyze /analyze:plugin"%WK%\bin\%SDKV%\x64\WindowsPrefast.dll" /Foobjs\ valkyrie_km.c 2>&1 | findstr /C:"valkyrie_km.c(" > objs\prefast_ours.txt
REM Test emptiness by FILE SIZE, not by piping to `find /c`. On a dev box with
REM Git for Windows on PATH, `find` resolves to GNU find, which ignores /c /v ""
REM and blocks forever waiting on stdin — the build hangs with no output and no
REM error. %%~zA is a cmd builtin and cannot be shadowed.
set "OURWARN=0"
for %%A in (objs\prefast_ours.txt) do if not "%%~zA"=="0" set "OURWARN=1"
if "!OURWARN!"=="1" (
    echo [FAIL] PREfast reported warning^(s^) in valkyrie_km.c:
    type objs\prefast_ours.txt
    exit /b 1
)
echo   PREfast: 0 warnings in valkyrie_km.c

echo.
echo === [3/3] LINK ===
REM /INTEGRITYCHECK is mandatory: PsSetCreateProcessNotifyRoutineEx and
REM ObRegisterCallbacks both refuse to register without it. See the vcxproj.
link /nologo /OUT:objs\valkyrie_km.sys /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry ^
     /INTEGRITYCHECK /NODEFAULTLIB /RELEASE /OPT:REF /OPT:ICF ^
     /LIBPATH:"%WK%\Lib\%SDKV%\km\x64" /LIBPATH:"%MSVC%\lib\x64" ^
     objs\valkyrie_km.obj ntoskrnl.lib hal.lib wdmsec.lib BufferOverflowFastFailK.lib
if errorlevel 1 ( echo [FAIL] link & exit /b 1 )

echo.
echo === VERIFY (do not trust the exit codes above) ===
if not exist objs\valkyrie_km.sys ( echo [FAIL] no .sys produced & exit /b 1 )
dumpbin /nologo /headers objs\valkyrie_km.sys | findstr /C:"Check integrity" >nul
if errorlevel 1 ( echo [FAIL] .sys is NOT marked /INTEGRITYCHECK & exit /b 1 )
echo   .sys present and marked "Check integrity".
echo.
echo BUILD OK: driver\valkyrie_km\objs\valkyrie_km.sys
echo NOTE: unsigned. Do NOT load it on a machine you care about.
endlocal
