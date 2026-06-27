@echo off
title Valkyrie Launcher

:: Request admin rights (needed for DNS sinkhole on port 53)
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

set SCRIPT_DIR=%~dp0

echo.
echo  ==========================================
echo   VALKYRIE - Privacy Engine
echo  ==========================================
echo.
echo  Starting backend...
start "Valkyrie - Backend" cmd /k "cd /d "%SCRIPT_DIR%" && python -m uvicorn valkyrie_api:app --host 0.0.0.0 --port 8000"

timeout /t 3 /nobreak >nul

echo  Starting UI...
start "Valkyrie - UI" cmd /k "cd /d "%SCRIPT_DIR%ui" && npm run dev"

timeout /t 5 /nobreak >nul

echo  Opening browser...
start http://localhost:5173

echo.
echo  Valkyrie is running.
echo  Close the two terminal windows to stop.
echo.
pause
