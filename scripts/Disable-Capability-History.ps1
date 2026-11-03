# Cancels the Windows permission-log copy task and deletes the copy. What the app saved in data\pc stays.
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$Log = Join-Path $PSScriptRoot '..\data\pc\capability-history-setup.log'
function Write-Log([string]$Text) { "$(Get-Date -Format o) $Text" | Out-File -FilePath $Log -Append -Encoding utf8 }

try {
    $TaskName = 'PrivacyProtector-CapabilityHistory'
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    foreach ($dir in 'capability-history', 'bin') {
        $path = Join-Path $env:ProgramData "PrivacyProtector\$dir"
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
    Write-Log "REMOVED task=$TaskName"
} catch {
    Write-Log "ERROR $($_.Exception.Message)"
    exit 1
}
