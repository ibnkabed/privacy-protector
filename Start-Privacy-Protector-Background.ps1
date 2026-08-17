$ErrorActionPreference = "Stop"

$AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ServerEntry = Join-Path $AppRoot "app.py"
$HealthUrl = "http://127.0.0.1:8733/api/health"
$RuntimeData = Join-Path $env:LOCALAPPDATA "PrivacyProtector\data"
$LogPath = Join-Path $RuntimeData "background-startup.log"

function Test-PrivacyProtectorReady {
    try {
        $Response = Invoke-WebRequest -UseBasicParsing -Uri $HealthUrl -TimeoutSec 1
        return $Response.StatusCode -eq 200
    } catch {
        return $false
    }
}

function Write-StartupLog([string]$Message) {
    New-Item -ItemType Directory -Force -Path $RuntimeData | Out-Null
    $Stamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
    Add-Content -LiteralPath $LogPath -Encoding UTF8 -Value "$Stamp $Message"
}

if (Test-PrivacyProtectorReady) {
    exit 0
}

if (-not (Test-Path -LiteralPath $ServerEntry)) {
    Write-StartupLog "ERROR app.py was not found"
    exit 1
}

$Python = (Get-Command python -ErrorAction Stop).Source
$Pythonw = Join-Path (Split-Path -Parent $Python) "pythonw.exe"
if (-not (Test-Path -LiteralPath $Pythonw)) {
    Write-StartupLog "ERROR pythonw.exe was not found"
    exit 1
}

# DNS and classification stay active after the dashboard window closes.
# DNS monitors every domain continuously. Extra iPhone function and packet
# observers stay disabled because they duplicate coverage or consume more CPU.
Start-Process `
    -FilePath $Pythonw `
    -ArgumentList @(
        "`"$ServerEntry`"",
        "--dns-port", "53",
        "--web-port", "8733"
    ) `
    -WorkingDirectory $AppRoot `
    -WindowStyle Hidden | Out-Null

for ($Attempt = 0; $Attempt -lt 40; $Attempt++) {
    if (Test-PrivacyProtectorReady) {
        Write-StartupLog "OK background service ready; all-domain DNS monitoring active"
        exit 0
    }
    Start-Sleep -Milliseconds 250
}

Write-StartupLog "ERROR background service did not become ready"
exit 1
