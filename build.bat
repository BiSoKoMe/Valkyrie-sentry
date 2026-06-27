@echo off
title Valkyrie — Build Standalone .exe
echo.
echo  ==========================================
echo   VALKYRIE — Building standalone .exe
echo  ==========================================
echo.

set SCRIPT_DIR=%~dp0

:: ── Step 1: Build React frontend ──────────────────────────────────────────────
echo [1/4] Building React frontend...
cd /d "%SCRIPT_DIR%ui"
call npm install
if %errorLevel% neq 0 ( echo ERROR: npm install failed & pause & exit /b 1 )
call npm run build
if %errorLevel% neq 0 ( echo ERROR: npm build failed & pause & exit /b 1 )
cd /d "%SCRIPT_DIR%"

:: ── Step 2: Install Python build dependencies ──────────────────────────────────
echo.
echo [2/4] Installing Python build dependencies...
pip install pyinstaller pywebview uvicorn fastapi dnslib psutil h11 anyio sniffio
if %errorLevel% neq 0 ( echo ERROR: pip install failed & pause & exit /b 1 )

:: ── Step 3: Bundle with PyInstaller ───────────────────────────────────────────
echo.
echo [3/4] Bundling with PyInstaller (this takes 1-3 minutes)...
pyinstaller valkyrie.spec --clean --noconfirm
if %errorLevel% neq 0 ( echo ERROR: PyInstaller failed & pause & exit /b 1 )

:: ── Step 4: Done ──────────────────────────────────────────────────────────────
echo.
echo  ==========================================
echo   BUILD COMPLETE
echo  ==========================================
echo.
echo   Output: %SCRIPT_DIR%dist\Valkyrie.exe
echo.
echo   Double-click Valkyrie.exe to launch.
echo   It will request admin rights automatically.
echo.
pause
