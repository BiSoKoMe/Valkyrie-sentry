@echo off
:: ===================================================================
:: Valkyrie launcher — opens the control page in your default browser.
::
:: The page shows live Running/Stopped status and gives you Start,
:: Stop and Open-Dashboard buttons.
::
:: - To START from a cold stop, the page will point you at start_all.bat
::   (starting the DNS sinkhole needs Administrator, which a browser
::   cannot request on its own — start_all.bat self-elevates via UAC).
:: - Stop / Restart work once Valkyrie is running. This script passes the
::   server's control token (written to data\control_token.txt on startup)
::   into the page so those buttons can authenticate to the loopback-only
::   control API.
:: ===================================================================
setlocal EnableExtensions

set "TOKEN="
if exist "%~dp0data\control_token.txt" set /p TOKEN=<"%~dp0data\control_token.txt"

:: Build a file:// URL with forward slashes so the browser accepts the
:: #token fragment cleanly.
set "DIR=%~dp0"
set "DIR=%DIR:\=/%"

start "" "file:///%DIR%valkyrie/web/launcher.html#%TOKEN%@8090"

endlocal
