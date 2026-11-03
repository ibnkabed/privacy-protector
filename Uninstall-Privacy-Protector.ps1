# Removes everything Privacy Protector changed in Windows, for a source checkout
# (the installed app's uninstaller does the same by itself):
#   - stops the engine
#   - restores the PC's DNS servers and removes the watchdog task (PC protection)
#   - removes the phone's firewall rules, including version 1's
#   - removes the capability-history copy task
#   - removes the sign-in entry
# Your rules and history stay in %LOCALAPPDATA%\PrivacyProtector\data unless you add -RemoveData.
#Requires -RunAsAdministrator
param([switch]$RemoveData)

$ErrorActionPreference = "Continue"
$AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DataDir = if ($env:PRIVACY_PROTECTOR_DATA_DIR) { $env:PRIVACY_PROTECTOR_DATA_DIR } else { Join-Path $env:LOCALAPPDATA "PrivacyProtector\data" }

Get-CimInstance Win32_Process -Filter "Name like 'python%' or Name = 'PrivacyProtector.exe'" |
    Where-Object { $_.CommandLine -and ($_.CommandLine -match 'app\.py|privacy_protector\.py|--engine') -and $_.CommandLine.Contains($AppRoot) } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

& (Join-Path $AppRoot "scripts\Disable-PC-Protection.ps1") -DataDir $DataDir
& (Join-Path $AppRoot "scripts\Disable-Phone-Protection.ps1") -DataDir $DataDir -IncludeVersion1
& (Join-Path $AppRoot "scripts\Disable-Capability-History.ps1") -DataDir $DataDir
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "PrivacyProtector.OpenSource" -ErrorAction SilentlyContinue
$OldLink = Join-Path ([Environment]::GetFolderPath("Startup")) "Privacy Protector Background.lnk"
Remove-Item -LiteralPath $OldLink -Force -ErrorAction SilentlyContinue

if ($RemoveData -and (Test-Path -LiteralPath $DataDir)) {
    Remove-Item -LiteralPath $DataDir -Recurse -Force
    Write-Host "Data removed: $DataDir"
}
Write-Host "Privacy Protector's changes to Windows are removed."
