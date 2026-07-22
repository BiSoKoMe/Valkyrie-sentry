' run-hidden.vbs
' Launches a PowerShell script with a *guaranteed* no console window, ever.
'
' Why this exists: `powershell.exe -WindowStyle Hidden` does NOT reliably
' prevent a console flash. Windows allocates and shows the console as part
' of normal process creation; PowerShell only hides it *after* it starts
' running and parses its own -WindowStyle argument. On a loaded system (or
' just some machines) that gap is visible as a brief flash — this is a
' well-documented Windows behavior, not a Valkyrie-specific bug, and it is
' exactly what a security product must never show.
'
' WScript.Shell.Run's window-style parameter is different: it is written
' into the child process's STARTUPINFO *before* CreateProcess is called, so
' the window is never created in the first place. That is the only fully
' deterministic way to do this on Windows without a compiled helper.
'
' Usage: wscript.exe //B //NoLogo run-hidden.vbs <script.ps1> [extra args...]

Dim shell, target, cmd, i

If WScript.Arguments.Count < 1 Then
    WScript.Quit 1
End If

Set shell = CreateObject("WScript.Shell")
target = WScript.Arguments(0)
cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File """ & target & """"

For i = 1 To WScript.Arguments.Count - 1
    cmd = cmd & " " & WScript.Arguments(i)
Next

' 0 = SW_HIDE (no window). True = wait for it to finish, so the scheduled
' task's own "last run result" reflects the script's real exit code.
WScript.Quit shell.Run(cmd, 0, True)
