# Cancels the Windows permission-log copy task and deletes the copy. What the app saved in data\pc stays.
#Requires -RunAsAdministrator
param([string]$DataDir = "")
if (-not $DataDir) {
    $DataDir = if ($env:PRIVACY_PROTECTOR_DATA_DIR) { $env:PRIVACY_PROTECTOR_DATA_DIR } else { Join-Path $env:LOCALAPPDATA "PrivacyProtector\data" }
}
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir 'pc') | Out-Null
$Log = Join-Path $DataDir 'pc\capability-history-setup.log'
function Write-Log([string]$Text) { "$(Get-Date -Format o) $Text" | Out-File -FilePath $Log -Append -Encoding utf8 }

try {
    $TaskName = 'PrivacyProtector.OpenSource-CapabilityHistory'
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    foreach ($dir in 'capability-history', 'bin') {
        $path = Join-Path $env:ProgramData "PrivacyProtector.OpenSource\$dir"
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
    Write-Log "REMOVED task=$TaskName"
} catch {
    Write-Log "ERROR $($_.Exception.Message)"
    exit 1
}
