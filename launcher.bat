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
:: - Stop / Restart require an authorized local session (the Valkyrie app, or
::   the served dashboard) and are not available from this page — the control
::   API now only accepts its credential as a request header, which a file://
::   page cannot attach to a no-cors request.
:: ===================================================================
setlocal EnableExtensions

:: Build a file:// URL with forward slashes so the browser accepts it cleanly.
set "DIR=%~dp0"
set "DIR=%DIR:\=/%"

start "" "file:///%DIR%valkyrie/web/launcher.html#8090"

endlocal
