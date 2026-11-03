# Installs a scheduled task running as SYSTEM that copies the Windows capability access log to a folder the user can read every 5 minutes.
#
# Since the 2026-09-23 update, Windows writes camera, microphone, and location usage times only to
# C:\ProgramData\Microsoft\Windows\CapabilityAccessManager\CapabilityAccessManager.db, which only
# SYSTEM can read. This task copies it read-only to C:\ProgramData\PrivacyProtector\capability-history.
#
# The copy script is a visible file in C:\ProgramData\PrivacyProtector\bin, writable only by SYSTEM and administrators,
# so the task never runs a file a standard user could modify. It does not embed an encoded command (EncodedCommand):
# A protection program silently deleted the task when it was in this form.
# To revert: scripts\Disable-Capability-History.ps1
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$Log = Join-Path $PSScriptRoot '..\data\pc\capability-history-setup.log'
function Write-Log([string]$Text) { "$(Get-Date -Format o) $Text" | Out-File -FilePath $Log -Append -Encoding utf8 }

function New-OwnerAcl([Security.Principal.SecurityIdentifier]$Owner) {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [System.Security.AccessControl.PropagationFlags]::None
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $who = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($who, 'FullControl', $inherit, $none, 'Allow')))
    }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Owner, 'ReadAndExecute', $inherit, $none, 'Allow')))
    return $acl
}

try {
    $TaskName = 'PrivacyProtector-CapabilityHistory'
    $Base = Join-Path $env:ProgramData 'PrivacyProtector'
    $Dest = Join-Path $Base 'capability-history'
    $Bin = Join-Path $Base 'bin'
    $Script = Join-Path $Bin 'Copy-CapabilityHistory.ps1'
    $OwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User

    foreach ($dir in @($Base, $Dest, $Bin)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Set-Acl -Path $dir -AclObject (New-OwnerAcl $OwnerSid)
    }

    $copy = @'
# Privacy Protector: copies the Windows capability-usage history (read-only) for the owner's monitoring.
$ErrorActionPreference = 'Stop'
$src = Join-Path $env:ProgramData 'Microsoft\Windows\CapabilityAccessManager'
$dst = Join-Path $env:ProgramData 'PrivacyProtector\capability-history'
try {
  foreach ($name in 'CapabilityAccessManager.db-wal', 'CapabilityAccessManager.db-shm', 'CapabilityAccessManager.db') {
    $from = Join-Path $src $name
    $to = Join-Path $dst $name
    if (-not (Test-Path -LiteralPath $from)) { Remove-Item -LiteralPath $to -Force -ErrorAction SilentlyContinue; continue }
    $reader = [IO.File]::Open($from, 'Open', 'Read', 'ReadWrite, Delete')
    try { $writer = [IO.File]::Create("$to.tmp"); try { $reader.CopyTo($writer) } finally { $writer.Close() } } finally { $reader.Close() }
    Move-Item -LiteralPath "$to.tmp" -Destination $to -Force
  }
  Remove-Item -LiteralPath (Join-Path $dst 'copy-error.txt') -Force -ErrorAction SilentlyContinue
} catch {
  "$(Get-Date -Format o) $($_.Exception.Message)" | Out-File -FilePath (Join-Path $dst 'copy-error.txt') -Encoding utf8
  exit 1
}
'@
    Set-Content -LiteralPath $Script -Value $copy -Encoding UTF8

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Script`""
    $every = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
    $boot = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew `
        -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $TaskName -Description 'Privacy Protector: copies the Windows capability-usage history for read-only monitoring by the device owner.' `
        -Action $action -Trigger @($every, $boot) -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    $deadline = (Get-Date).AddSeconds(45)
    do { Start-Sleep -Seconds 3; $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue }
    while ($info -and $info.LastTaskResult -eq 267011 -and (Get-Date) -lt $deadline)  # 267011 = has not run yet
    Start-Sleep -Seconds 2
    $exists = [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    $copied = Test-Path -LiteralPath (Join-Path $Dest 'CapabilityAccessManager.db')
    $result = if ($info) { $info.LastTaskResult } else { 'none' }
    $err = Get-Content -LiteralPath (Join-Path $Dest 'copy-error.txt') -ErrorAction SilentlyContinue
    Write-Log "OK task=$TaskName exists=$exists lastResult=$result firstCopy=$copied script=$Script $err"
    if (-not ($exists -and $copied)) { exit 2 }
} catch {
    Write-Log "ERROR $($_.Exception.Message)"
    exit 1
}
