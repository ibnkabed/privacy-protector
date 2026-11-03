# Runs Privacy Protector from source in this window, for developers.
# The installed app needs none of this: it starts from the Start menu and at sign-in.
#   -TestPort   answers DNS on 53053 instead of 53, so it can run beside another DNS service
#   -NoBrowser  does not open the dashboard
param(
    [switch]$TestPort,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DnsPort = if ($TestPort) { 53053 } else { 53 }
$DashboardUrl = "http://127.0.0.1:8733"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python 3.12 or newer was not found on PATH."
}

if (-not $NoBrowser) {
    Start-Job -ScriptBlock {
        param($Url)
        for ($Attempt = 0; $Attempt -lt 60; $Attempt++) {
            try {
                $Response = Invoke-WebRequest -Uri "$Url/api/health" -UseBasicParsing -TimeoutSec 1
                if ($Response.StatusCode -eq 200) { Start-Process $Url; return }
            } catch {}
            Start-Sleep -Milliseconds 500
        }
    } -ArgumentList $DashboardUrl | Out-Null
}

Write-Host "Privacy Protector — dashboard $DashboardUrl, DNS port $DnsPort. Stop with Ctrl+C."
Push-Location $AppRoot
try {
    python (Join-Path $AppRoot "app.py") --dns-port $DnsPort --attached
} finally {
    Pop-Location
}
