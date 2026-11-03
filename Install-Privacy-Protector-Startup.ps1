# For a source checkout: starts the engine hidden at sign-in, for your user only (no admin rights).
# The installer does this itself for the installed app. -Remove takes it away.
param([switch]$Remove)

$ErrorActionPreference = "Stop"
$AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$Name = "PrivacyProtector.OpenSource"

if ($Remove) {
    Remove-ItemProperty -Path $RunKey -Name $Name -ErrorAction SilentlyContinue
    Write-Host "Privacy Protector no longer starts at sign-in."
    exit 0
}

$Python = (Get-Command python -ErrorAction Stop).Source
$PythonW = Join-Path (Split-Path -Parent $Python) "pythonw.exe"
if (-not (Test-Path -LiteralPath $PythonW)) { $PythonW = $Python }
$Launcher = Join-Path $AppRoot "privacy_protector.py"
Set-ItemProperty -Path $RunKey -Name $Name -Value "`"$PythonW`" `"$Launcher`" --background"
Write-Host "Privacy Protector starts at sign-in."
