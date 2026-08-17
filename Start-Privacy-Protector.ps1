param(
    [switch]$IPhoneMode,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonFile = Join-Path $AppRoot "app.py"
$DnsPort = if ($IPhoneMode) { 53 } else { 53053 }
$DashboardUrl = "http://127.0.0.1:8733"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python was not found on PATH."
}

if (-not $NoBrowser) {
    Start-Job -ScriptBlock {
        param($Url)
        for ($Attempt = 0; $Attempt -lt 30; $Attempt++) {
            try {
                $Response = Invoke-WebRequest -Uri "$Url/api/health" -UseBasicParsing -TimeoutSec 1
                if ($Response.StatusCode -eq 200) {
                    Start-Process $Url
                    return
                }
            } catch {
            }
            Start-Sleep -Milliseconds 300
        }
    } -ArgumentList $DashboardUrl | Out-Null
}

Write-Host ""
Write-Host "Privacy Protector" -ForegroundColor Cyan
Write-Host "Dashboard: $DashboardUrl"
Write-Host "DNS port: $DnsPort"
Write-Host "Stop with Ctrl+C"
Write-Host ""

Push-Location $AppRoot
try {
    python $PythonFile --dns-port $DnsPort
} finally {
    Pop-Location
}
