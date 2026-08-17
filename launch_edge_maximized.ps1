$ErrorActionPreference = "Stop"

$Url = "http://127.0.0.1:8733/"
$HealthUrl = "${Url}api/health"
$AppRoot = $PSScriptRoot
$ServerEntry = Join-Path $AppRoot "app.py"
$PreparationScript = Join-Path $AppRoot "Prepare-iPhone-Connection.ps1"
$DataRoot = Join-Path $env:LOCALAPPDATA "PrivacyProtector"
$EdgeProfile = Join-Path $DataRoot "edge-profile"
$PageTitle = "Privacy Protector"

Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class PrivacyProtectorWindow {
    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
}
'@

function Test-PrivacyProtectorReady {
    try {
        $Response = Invoke-WebRequest -UseBasicParsing -Uri $HealthUrl -TimeoutSec 1
        return $Response.StatusCode -eq 200
    } catch {
        return $false
    }
}

function Find-PythonWindowless {
    $Python = (Get-Command python -ErrorAction Stop).Source
    $Pythonw = Join-Path (Split-Path -Parent $Python) "pythonw.exe"
    if (-not (Test-Path -LiteralPath $Pythonw)) {
        throw "pythonw.exe was not found next to python.exe."
    }
    return $Pythonw
}

function Test-IPhoneDnsPrepared {
    $RuleNames = @(
        "Privacy Protector DNS UDP",
        "Privacy Protector DNS TCP"
    )
    foreach ($RuleName in $RuleNames) {
        $Rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue |
            Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" } |
            Select-Object -First 1
        if (-not $Rule) {
            return $false
        }
    }
    return $true
}

function Test-DnsPortAvailable {
    $UdpOwner = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue |
        Select-Object -First 1
    $TcpOwner = Get-NetTCPConnection -State Listen -LocalPort 53 -ErrorAction SilentlyContinue |
        Select-Object -First 1
    return -not ($UdpOwner -or $TcpOwner)
}

function Prepare-IPhoneDns {
    if (-not (Test-Path -LiteralPath $PreparationScript)) {
        throw "Prepare-iPhone-Connection.ps1 was not found."
    }
    $Arguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"{0}"' -f $PreparationScript),
        "-StartBackend"
    )
    $PowerShellHost = (Get-Command pwsh -ErrorAction Stop).Source
    $Preparation = Start-Process `
        -FilePath $PowerShellHost `
        -Verb RunAs `
        -ArgumentList $Arguments `
        -WorkingDirectory $AppRoot `
        -WindowStyle Hidden `
        -PassThru

    for ($Attempt = 0; $Attempt -lt 120; $Attempt++) {
        if (Test-PrivacyProtectorReady) {
            return
        }
        if ($Preparation.HasExited) {
            $StatusPath = Join-Path $DataRoot "data\connection-status.json"
            if (Test-Path -LiteralPath $StatusPath) {
                try {
                    $Status = Get-Content -LiteralPath $StatusPath -Raw | ConvertFrom-Json
                    if (-not $Status.ok) {
                        throw [InvalidOperationException]::new([string]$Status.error)
                    }
                } catch [InvalidOperationException] {
                    throw
                } catch {
                }
            }
        }
        Start-Sleep -Milliseconds 250
    }
    throw "Privacy Protector did not become ready after DNS preparation."
}

function Get-PrivacyProtectorWindow {
    return Get-Process msedge -ErrorAction SilentlyContinue |
        Where-Object {
            $_.MainWindowHandle -ne 0 -and
            ($_.MainWindowTitle -eq $PageTitle -or $_.MainWindowTitle -like "$PageTitle -*")
        } |
        Sort-Object StartTime -Descending |
        Select-Object -First 1
}

if (-not (Test-Path -LiteralPath $ServerEntry)) {
    throw "app.py was not found."
}

$Edge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
if (-not (Test-Path -LiteralPath $Edge)) {
    $Edge = "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
}
if (-not (Test-Path -LiteralPath $Edge)) {
    throw "Microsoft Edge was not found."
}

$ExistingWindow = Get-PrivacyProtectorWindow
if ((Test-PrivacyProtectorReady) -and $ExistingWindow) {
    [void][PrivacyProtectorWindow]::ShowWindowAsync($ExistingWindow.MainWindowHandle, 3)
    [void][PrivacyProtectorWindow]::SetForegroundWindow($ExistingWindow.MainWindowHandle)
    exit 0
}

if (-not (Test-PrivacyProtectorReady)) {
    if (-not (Test-DnsPortAvailable) -or -not (Test-IPhoneDnsPrepared)) {
        Prepare-IPhoneDns
    }
    if (-not (Test-PrivacyProtectorReady)) {
        if (-not (Test-DnsPortAvailable)) {
            throw "DNS port 53 is still in use by another process."
        }
        $Pythonw = Find-PythonWindowless
        Start-Process `
            -FilePath $Pythonw `
            -ArgumentList @(
                "`"$ServerEntry`"",
                "--dns-port", "53",
                "--web-port", "8733"
            ) `
            -WorkingDirectory $AppRoot `
            -WindowStyle Hidden | Out-Null
    }

    $Ready = $false
    for ($Attempt = 0; $Attempt -lt 40; $Attempt++) {
        if (Test-PrivacyProtectorReady) {
            $Ready = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $Ready) {
        throw "Privacy Protector service did not start."
    }
}

$ExistingWindow = Get-PrivacyProtectorWindow
if ($ExistingWindow) {
    [void][PrivacyProtectorWindow]::ShowWindowAsync($ExistingWindow.MainWindowHandle, 3)
    [void][PrivacyProtectorWindow]::SetForegroundWindow($ExistingWindow.MainWindowHandle)
    exit 0
}

New-Item -ItemType Directory -Force -Path $EdgeProfile | Out-Null
$ExistingHandles = @(
    Get-Process msedge -ErrorAction SilentlyContinue |
        Where-Object { $_.MainWindowHandle -ne 0 } |
        ForEach-Object { [long]$_.MainWindowHandle }
)

$EdgeArguments = @(
    "--app=$Url",
    "--start-maximized",
    "--disable-background-mode",
    "--no-first-run",
    "--no-default-browser-check",
    "--user-data-dir=`"$EdgeProfile`""
)

Start-Process `
    -FilePath $Edge `
    -ArgumentList $EdgeArguments `
    -WorkingDirectory (Split-Path -Parent $Edge) `
    -WindowStyle Maximized | Out-Null

$Window = $null
for ($Attempt = 0; $Attempt -lt 60; $Attempt++) {
    $Window = Get-PrivacyProtectorWindow
    if ($Window -and $ExistingHandles -notcontains [long]$Window.MainWindowHandle) {
        break
    }
    Start-Sleep -Milliseconds 250
}

if (-not $Window) {
    throw "Privacy Protector window did not open."
}

for ($Attempt = 0; $Attempt -lt 4; $Attempt++) {
    [void][PrivacyProtectorWindow]::ShowWindowAsync($Window.MainWindowHandle, 3)
    Start-Sleep -Milliseconds 250
}
[void][PrivacyProtectorWindow]::SetForegroundWindow($Window.MainWindowHandle)
