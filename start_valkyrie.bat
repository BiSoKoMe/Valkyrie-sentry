@echo off
:: ===================================================================
:: Start Valkyrie - triggers the elevated on-demand "ValkyrieStart"
:: scheduled task. Because the task is pre-registered with highest
:: privileges, this runs start_all.ps1 as Administrator with NO UAC
:: prompt.
::
:: One-time setup: run setup_task.ps1 as Administrator first.
:: ===================================================================
schtasks /run /tn "ValkyrieStart"
if errorlevel 1 (
    echo.
    echo [!] Could not start the task "ValkyrieStart".
    echo     Run setup_task.ps1 as Administrator once to register it.
    echo.
    pause
)
