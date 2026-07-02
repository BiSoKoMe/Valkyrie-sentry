@echo off
:: ===================================================================
:: Stop Valkyrie - triggers the elevated on-demand "ValkyrieStop"
:: scheduled task, which runs stop_all.ps1 as Administrator with NO
:: UAC prompt (resets DNS, stops Valkyrie, restores Unbound).
::
:: One-time setup: run setup_task.ps1 as Administrator first.
:: ===================================================================
schtasks /run /tn "ValkyrieStop"
if errorlevel 1 (
    echo.
    echo [!] Could not start the task "ValkyrieStop".
    echo     Run setup_task.ps1 as Administrator once to register it.
    echo.
    pause
)
