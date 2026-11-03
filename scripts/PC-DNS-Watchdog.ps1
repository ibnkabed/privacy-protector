# Runs every minute as SYSTEM. Keeps the PC on the local engine while it
# answers, and on Cloudflare while it does not, so a stopped engine never
# leaves the PC without internet for more than a minute.
param([string]$StateDir = "")
$ErrorActionPreference = "SilentlyContinue"

$Engine = @("127.0.0.1", "::1")
$Fallback = @("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001")

function Test-Engine {
    foreach ($Attempt in 1..2) {
        try {
            Resolve-DnsName -Name "www.msftconnecttest.com" -Server 127.0.0.1 -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null
            return $true
        } catch {
            Start-Sleep -Seconds 2
        }
    }
    return $false
}

$Healthy = Test-Engine
$Wanted = if ($Healthy) { $Engine } else { $Fallback }
$Changed = @()
$Adapters = Get-NetAdapter | Where-Object {
    ($_.Status -eq "Up" -or $_.HardwareInterface) -and $_.InterfaceDescription -notmatch "Loopback"
}
foreach ($Adapter in $Adapters) {
    $Current = @((Get-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv4).ServerAddresses)
    $OnEngine = $Current.Count -gt 0 -and $Current[0] -eq "127.0.0.1"
    if ($Healthy -ne $OnEngine) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ServerAddresses $Wanted -ErrorAction Stop
            $Changed += $Adapter.Name
        } catch {}
    }
}
if ($Changed.Count -gt 0) {
    Clear-DnsClientCache
}

if ($StateDir -and (Test-Path -LiteralPath $StateDir)) {
    $StatePath = Join-Path $StateDir "watchdog.json"
    $Previous = $null
    try { $Previous = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json } catch {}
    $LastSwitch = if ($Changed.Count -gt 0) { (Get-Date).ToString("o") } elseif ($Previous) { $Previous.lastSwitchAt } else { "" }
    [pscustomobject]@{
        mode = if ($Healthy) { "engine" } else { "fallback" }
        checkedAt = (Get-Date).ToString("o")
        lastSwitchAt = $LastSwitch
        switched = $Changed
    } | ConvertTo-Json -Compress | Set-Content -LiteralPath $StatePath -Encoding UTF8
}
