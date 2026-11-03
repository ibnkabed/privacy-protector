#Requires -RunAsAdministrator
# Routes this PC's own DNS through the local Privacy Protector engine.
# Safe by construction:
#   - refuses to switch unless the engine already answers on 127.0.0.1
#   - saves the previous DNS settings once, for Disable-PC-Protection.ps1
#   - installs a SYSTEM watchdog that falls back to Cloudflare within a
#     minute if the engine stops, and returns to the engine when it is back
param([string]$DataDir = "")
$ErrorActionPreference = "Stop"

if (-not $DataDir) {
    $DataDir = if ($env:PRIVACY_PROTECTOR_DATA_DIR) { $env:PRIVACY_PROTECTOR_DATA_DIR } else { Join-Path $env:LOCALAPPDATA "PrivacyProtector\data" }
}
$PcData = Join-Path $DataDir "pc"
$AppRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
New-Item -ItemType Directory -Force -Path $PcData | Out-Null
$BackupPath = Join-Path $PcData "dns-backup.json"
$LogPath = Join-Path $PcData "setup.log"
$TaskName = "PrivacyProtector.OpenSource-PC-DNS-Watchdog"
$InstallDir = Join-Path $env:ProgramFiles "PrivacyProtector.OpenSource"
$WatchdogSource = Join-Path $AppRoot "scripts\PC-DNS-Watchdog.ps1"
$WatchdogTarget = Join-Path $InstallDir "PC-DNS-Watchdog.ps1"
$DnsLog = "Microsoft-Windows-DNS-Client/Operational"
$Browsers = @(
    @{ Name = "Chrome"; Key = "HKLM:\SOFTWARE\Policies\Google\Chrome" },
    @{ Name = "Edge"; Key = "HKLM:\SOFTWARE\Policies\Microsoft\Edge" },
    @{ Name = "Brave"; Key = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" }
)

function Write-SetupLog([string]$Message) {
    $Stamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
    Add-Content -LiteralPath $LogPath -Encoding UTF8 -Value "$Stamp $Message"
    Write-Host $Message
}

function Test-Engine {
    foreach ($Attempt in 1..3) {
        try {
            Resolve-DnsName -Name "www.msftconnecttest.com" -Server 127.0.0.1 -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null
            return $true
        } catch {
            Start-Sleep -Seconds 2
        }
    }
    return $false
}

function Get-TargetAdapters {
    Get-NetAdapter | Where-Object {
        $_.Status -eq "Up" -or $_.HardwareInterface
    } | Where-Object { $_.InterfaceDescription -notmatch "Loopback" }
}

function Get-StaticServers([string]$Guid, [string]$Stack) {
    $Key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Stack\Parameters\Interfaces\$Guid"
    try { return [string](Get-ItemPropertyValue -Path $Key -Name NameServer -ErrorAction Stop) } catch { return "" }
}

if (-not (Test-Engine)) {
    # The app turns this on from Settings while its engine answers on 127.0.0.1:53; nothing changes otherwise.
    Write-SetupLog "ERROR engine does not answer on 127.0.0.1:53; DNS left unchanged"
    exit 1
}

# 1. Back up the original settings once. A second run must not overwrite them
#    with 127.0.0.1, or restoring would restore nothing.
if (-not (Test-Path -LiteralPath $BackupPath)) {
    $Adapters = @(foreach ($Adapter in Get-TargetAdapters) {
        [pscustomobject]@{
            name = $Adapter.Name
            guid = [string]$Adapter.InterfaceGuid
            ipv4 = Get-StaticServers $Adapter.InterfaceGuid "Tcpip"
            ipv6 = Get-StaticServers $Adapter.InterfaceGuid "Tcpip6"
        }
    })
    $BrowserPolicies = @(foreach ($Browser in $Browsers) {
        $Existing = ""
        try { $Existing = [string](Get-ItemPropertyValue -Path $Browser.Key -Name DnsOverHttpsMode -ErrorAction Stop) } catch {}
        [pscustomobject]@{ name = $Browser.Name; key = $Browser.Key; previous = $Existing }
    })
    $LogWasEnabled = [bool]((wevtutil gl $DnsLog) -match "enabled:\s*true")
    [pscustomobject]@{
        savedAt = (Get-Date).ToString("o")
        adapters = $Adapters
        browsers = $BrowserPolicies
        dnsClientLogWasEnabled = $LogWasEnabled
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $BackupPath -Encoding UTF8
    Write-SetupLog "Saved previous DNS settings"
}

# 2. The DNS client log records which process asked for each name. It is the
#    per-program attribution the phone never had.
wevtutil sl $DnsLog /e:true /ms:52428800 /rt:false | Out-Null
Write-SetupLog "Enabled DNS client operational log"

# 3. Browsers in "secure" DNS mode bypass the system resolver entirely.
#    "automatic" keeps encryption whenever the system resolver supports it,
#    and the local engine already forwards every query over DoH.
foreach ($Browser in $Browsers) {
    New-Item -Path $Browser.Key -Force | Out-Null
    Set-ItemProperty -Path $Browser.Key -Name DnsOverHttpsMode -Value "automatic" -Type String
}
Write-SetupLog "Browsers now use the system resolver"

# 4. Point every active adapter at the engine (IPv4 and IPv6 loopback).
foreach ($Adapter in Get-TargetAdapters) {
    Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ServerAddresses @("127.0.0.1", "::1")
    Write-SetupLog "DNS of '$($Adapter.Name)' -> engine"
}
Clear-DnsClientCache

# 5. Watchdog: installed under Program Files so only administrators can edit
#    the script that runs as SYSTEM.
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -LiteralPath $WatchdogSource -Destination $WatchdogTarget -Force
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument (
    "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$WatchdogTarget`" -StateDir `"$PcData`""
)
$Every = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$Boot = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew -StartWhenAvailable
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger @($Every, $Boot) `
    -Settings $Settings -Principal $Principal -Force | Out-Null
Write-SetupLog "Installed watchdog task $TaskName"

if (Test-Engine) {
    Write-SetupLog "OK PC protection active"
} else {
    Write-SetupLog "WARNING engine stopped answering; the watchdog will fall back within a minute"
}
