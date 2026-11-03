# Setup-Defender.ps1 — optional Windows Defender hardening.
# Run once, if you want it, in an elevated PowerShell window. It only turns protections on;
# it never turns one off and adds no exclusions. Attack-surface rules and controlled folder
# access start in audit mode, so nothing is blocked until you read the audit and decide.
# The settings after it are written to <data dir>\pc\defender-after.json.

#Requires -RunAsAdministrator
param([string]$DataDir = "")
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

if (-not $DataDir) {
    $DataDir = if ($env:PRIVACY_PROTECTOR_DATA_DIR) { $env:PRIVACY_PROTECTOR_DATA_DIR } else { Join-Path $env:LOCALAPPDATA "PrivacyProtector" }
}
$results = [ordered]@{}

function Step([string]$name, [scriptblock]$action) {
    try { & $action; $results[$name] = 'OK' }
    catch { $results[$name] = "ERROR: $($_.Exception.Message)" }
}

Step 'core' {
    Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -CloudBlockLevel High `
        -PUAProtection Enabled -SignatureUpdateInterval 4 -ScanAvgCPULoadFactor 30 -EnableLowCpuPriority $true
}

Step 'network-protection' { Set-MpPreference -EnableNetworkProtection Enabled }

Step 'controlled-folder-access-audit' { Set-MpPreference -EnableControlledFolderAccess AuditMode }

Step 'asr-office-email-audit' {
    $ids = 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550',  # executable content from email
           'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',  # Office creating child processes
           '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84',  # Office injecting into processes
           '3B576869-A4EC-4529-8536-B80A7769E899',  # Office creating executable content
           'D3E037E1-3EB8-44C8-A917-57927947596D'   # JS/VBS launching downloaded content
    Add-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions ($ids | ForEach-Object { 'AuditMode' })
}

Step 'signatures' { Update-MpSignature }

$pcDir = Join-Path $DataDir 'pc'
New-Item -ItemType Directory -Force -Path $pcDir | Out-Null
@{ pref = Get-MpPreference; status = Get-MpComputerStatus; savedAt = (Get-Date).ToString('o') } |
    ConvertTo-Json -Depth 6 | Set-Content (Join-Path $pcDir 'defender-after.json') -Encoding UTF8

$results.GetEnumerator() | ForEach-Object { '{0,-32} {1}' -f $_.Key, $_.Value }
