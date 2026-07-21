@echo off
REM ===================================================================
REM  Build valkyrie.exe  -  a single self-contained Windows executable
REM  bundling the whole app, including the EDR / security-operations
REM  layer and the web console.
REM
REM  Run this ON WINDOWS (PyInstaller does not cross-compile). You need
REM  Python 3.10+ on PATH. The result is dist\valkyrie.exe.
REM ===================================================================
setlocal

echo.
echo  [1/3] Installing build + runtime dependencies...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements_modular.txt pyinstaller
if errorlevel 1 goto :fail

REM Optional extras baked into the .exe:
REM   cryptography  -> enables signed remote-response over the fleet
REM   httpx         -> vendor-neutral AI investigation providers + fleet client
REM The offline analyst and local response work without either. Both are small,
REM so bundle them by default. No AI-vendor SDK is needed.
python -m pip install cryptography httpx

echo.
echo  [2/3] Building valkyrie.exe with PyInstaller...
python -m PyInstaller --clean --noconfirm valkyrie.spec
if errorlevel 1 goto :fail

echo.
echo  [3/3] Done.
echo.
if exist dist\valkyrie.exe (
    echo  Built:  dist\valkyrie.exe
    echo.
    echo  Quick check:
    echo      dist\valkyrie.exe --hunt list
    echo      dist\valkyrie.exe --web
    echo.
    echo  The exe keeps its data\ folder, valkyrie_rules.yaml and logs
    echo  next to itself - copy the whole dist\ folder to deploy.
) else (
    echo  WARNING: dist\valkyrie.exe was not produced - check the log above.
)
goto :eof

:fail
echo.
echo  BUILD FAILED - see the error above.
exit /b 1
