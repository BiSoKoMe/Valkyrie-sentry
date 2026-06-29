@echo off
title Valkyrie Emergency Recovery
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Run this as Administrator. Right-click recover.bat and "Run as administrator".
    pause
    exit /b 1
)

echo.
echo ============================================
echo  VALKYRIE EMERGENCY RECOVERY
echo ============================================
echo  Undoing all Shield mode changes...
echo.

echo [1/4] Restoring DNS to DHCP on all interfaces...
powershell -NonInteractive -Command "Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }"
echo     Done.

echo.
echo [2/4] Removing all Valkyrie firewall rules...
powershell -NonInteractive -Command "Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'Valkyrie*' } | Remove-NetFirewallRule -ErrorAction SilentlyContinue"
echo     Done.

echo.
echo [3/4] Cleaning Valkyrie entries from hosts file...
powershell -NonInteractive -Command "$h='C:\Windows\System32\drivers\etc\hosts'; $t=[IO.File]::ReadAllText($h,'UTF8'); if($t -match '# Valkyrie-start') { $t=[regex]::Replace($t,'# Valkyrie-start[\s\S]*?# Valkyrie-end\r?\n?',''); [IO.File]::WriteAllText($h,$t,'UTF8'); Write-Host '    Entries removed.' } else { Write-Host '    Already clean.' }"

echo.
echo [4/4] Flushing DNS cache...
ipconfig /flushdns >nul
echo     Done.

echo.
echo ============================================
echo  RECOVERY COMPLETE
echo ============================================
echo.
echo  DNS restored to automatic (DHCP).
echo  All Valkyrie firewall rules removed.
echo  Hosts file cleaned.
echo.
echo  If WiFi still seems slow, run:
echo    netsh winsock reset
echo    netsh int ip reset
echo  ...then restart your PC.
echo.
pause
