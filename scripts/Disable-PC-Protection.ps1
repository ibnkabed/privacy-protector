#Requires -RunAsAdministrator
# Undoes Enable-PC-Protection.ps1 exactly: removes the watchdog, restores the
# saved DNS servers and browser policies, and the DNS client log state.
param([string]$DataDir = "")
$ErrorActionPreference = "Stop"

if (-not $DataDir) {
    $DataDir = if ($env:PRIVACY_PROTECTOR_DATA_DIR) { $env:PRIVACY_PROTECTOR_DATA_DIR } else { Join-Path (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)) "data" }
}
$PcData = Join-Path $DataDir "pc"
$BackupPath = Join-Path $PcData "dns-backup.json"
$TaskName = "PrivacyProtector-PC-DNS-Watchdog"
$InstallDir = Join-Path $env:ProgramFiles "PrivacyProtector"

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue

if (-not (Test-Path -LiteralPath $BackupPath)) {
    foreach ($Adapter in Get-NetAdapter | Where-Object { $_.Status -eq "Up" -or $_.HardwareInterface }) {
        Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ResetServerAddresses
    }
    Clear-DnsClientCache
    Write-Host "No backup found; adapters reset to automatic DNS"
    exit 0
}

$Backup = Get-Content -LiteralPath $BackupPath -Raw | ConvertFrom-Json
foreach ($Saved in $Backup.adapters) {
    $Adapter = Get-NetAdapter | Where-Object { [string]$_.InterfaceGuid -eq $Saved.guid }
    if (-not $Adapter) { continue }
    $Servers = @()
    foreach ($List in @($Saved.ipv4, $Saved.ipv6)) {
        if ($List) { $Servers += ($List -split "[,\s]+" | Where-Object { $_ }) }
    }
    if ($Servers.Count -gt 0) {
        Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ServerAddresses $Servers
    } else {
        Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ResetServerAddresses
    }
}
foreach ($Browser in $Backup.browsers) {
    if ($Browser.previous) {
        Set-ItemProperty -Path $Browser.key -Name DnsOverHttpsMode -Value $Browser.previous -Type String
    } else {
        Remove-ItemProperty -Path $Browser.key -Name DnsOverHttpsMode -ErrorAction SilentlyContinue
    }
}
if (-not $Backup.dnsClientLogWasEnabled) {
    wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:false | Out-Null
}
Clear-DnsClientCache
Remove-Item -LiteralPath $BackupPath -Force
Write-Host "PC protection removed; previous DNS settings restored"
