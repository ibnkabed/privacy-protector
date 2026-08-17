param(
    [switch]$Remove,
    [switch]$StartBackend
)

$ErrorActionPreference = "Stop"
$AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RuntimeData = Join-Path $env:LOCALAPPDATA "PrivacyProtector\data"
$StatusPath = Join-Path $RuntimeData "connection-status.json"
New-Item -ItemType Directory -Force -Path $RuntimeData | Out-Null
$RuleNames = @(
    "Privacy Protector DNS UDP",
    "Privacy Protector DNS TCP"
)

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
$IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    $PowerShellHost = (Get-Command pwsh -ErrorAction Stop).Source
    $Arguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"{0}"' -f $MyInvocation.MyCommand.Path)
    )
    if ($Remove) {
        $Arguments += "-Remove"
    }
    if ($StartBackend) {
        $Arguments += "-StartBackend"
    }
    Start-Process $PowerShellHost -Verb RunAs -ArgumentList $Arguments -WorkingDirectory $AppRoot
    exit
}

$PortOwners = @()
$SharedAccessOriginalStartMode = ""
$HnsWasRunning = $false
$BackendProcess = $null

function Restore-SharedAccessStartMode {
    param([string]$Mode)
    $ScMode = switch ($Mode) {
        "Automatic" { "auto" }
        "Disabled" { "disabled" }
        default { "demand" }
    }
    & "$env:SystemRoot\System32\sc.exe" config SharedAccess start= $ScMode | Out-Null
}

function Remove-SharedAccessDnsOwner {
    param([int]$AllowedPid = 0)
    $Owners = @(
        Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty OwningProcess -Unique
    )
    foreach ($OwnerPid in $Owners) {
        if ($AllowedPid -gt 0 -and $OwnerPid -eq $AllowedPid) {
            continue
        }
        $OwnerServices = @(
            Get-CimInstance Win32_Service -Filter "ProcessId=$OwnerPid" -ErrorAction SilentlyContinue
        )
        if ($OwnerServices.Count -eq 1 -and $OwnerServices[0].Name -eq "SharedAccess") {
            Stop-Process -Id $OwnerPid -Force
            continue
        }
        $OwnerProcess = Get-Process -Id $OwnerPid -ErrorAction SilentlyContinue
        $OwnerName = if ($OwnerProcess) { $OwnerProcess.ProcessName } else { "PID $OwnerPid" }
        throw "DNS port 53 is owned by an unrelated process: $OwnerName."
    }
}

try {
    if ($StartBackend) {
        $PortOwners = @(
            Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty OwningProcess -Unique
        ) + @(
            Get-NetTCPConnection -State Listen -LocalPort 53 -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty OwningProcess -Unique
        )
        $PortOwners = @($PortOwners | Where-Object { $_ } | Select-Object -Unique)
        foreach ($OwnerPid in $PortOwners) {
            $OwnerServices = @(
                Get-CimInstance Win32_Service -Filter "ProcessId=$OwnerPid" -ErrorAction SilentlyContinue
            )
            $SharedAccess = $OwnerServices | Where-Object { $_.Name -eq "SharedAccess" }
            if ($SharedAccess) {
                $HnsService = Get-Service -Name hns -ErrorAction SilentlyContinue
                if ($HnsService -and $HnsService.Status -eq "Running") {
                    $HnsWasRunning = $true
                    Stop-Service -Name hns -Force
                    $HnsService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(15))
                }
                $CanForceTerminate = (
                    $OwnerServices.Count -eq 1 -and
                    $OwnerServices[0].Name -eq "SharedAccess"
                )
                $SharedAccessOriginalStartMode = [string]$SharedAccess.StartMode
                & "$env:SystemRoot\System32\sc.exe" config SharedAccess start= disabled | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    throw "Unable to complete the operation."
                }
                $StopOutput = @(& "$env:SystemRoot\System32\sc.exe" stop SharedAccess 2>&1)
                $StopExitCode = $LASTEXITCODE
                $PortReleased = $false
                $ServiceProcessTerminated = $false
                $FreeSamples = 0
                for ($Attempt = 0; $Attempt -lt 80; $Attempt++) {
                    $StillBound = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue
                    $OwnerProcessAlive = Get-Process -Id $OwnerPid -ErrorAction SilentlyContinue
                    if (-not $StillBound) {
                        $FreeSamples += 1
                        if ($FreeSamples -ge 10 -and -not $OwnerProcessAlive) {
                            $PortReleased = $true
                            break
                        }
                    } else {
                        $FreeSamples = 0
                    }
                    if ($Attempt -ge 20 -and $OwnerProcessAlive -and -not $ServiceProcessTerminated) {
                        if (
                            $StopExitCode -eq 0 -and
                            $OwnerPid -gt 0 -and
                            $CanForceTerminate
                        ) {
                            Stop-Process -Id $OwnerPid -Force
                            $ServiceProcessTerminated = $true
                        }
                    }
                    Start-Sleep -Milliseconds 150
                }
                if (-not $PortReleased) {
                    $StopDetail = ($StopOutput | ForEach-Object { [string]$_ }) -join " | "
                    throw "SharedAccess did not release DNS port 53. sc=$StopExitCode $StopDetail"
                }
                continue
            }
            $OwnerProcess = Get-Process -Id $OwnerPid -ErrorAction SilentlyContinue
            $OwnerName = if ($OwnerProcess) { $OwnerProcess.ProcessName } else { "PID $OwnerPid" }
            throw "DNS port 53 is owned by an unrelated process: $OwnerName."
        }
    }

    foreach ($RuleName in $RuleNames) {
        Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule
    }

    if ($Remove) {
        @{
            ok = $true
            action = "removed"
            timestamp = (Get-Date).ToString("o")
        } | ConvertTo-Json | Set-Content -LiteralPath $StatusPath -Encoding UTF8
        Write-Host "Privacy Protector firewall rules were removed from Windows." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        exit
    }

    $PythonPath = (Get-Command python).Source

    New-NetFirewallRule `
        -DisplayName $RuleNames[0] `
        -Direction Inbound `
        -Action Allow `
        -Protocol UDP `
        -LocalPort 53 `
        -Profile Private `
        -RemoteAddress LocalSubnet `
        -Program $PythonPath | Out-Null

    New-NetFirewallRule `
        -DisplayName $RuleNames[1] `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 53 `
        -Profile Private `
        -RemoteAddress LocalSubnet `
        -Program $PythonPath | Out-Null

    $Connection = Get-NetIPConfiguration |
        Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up" } |
        Select-Object -First 1

    if (-not $Connection) {
        throw "Unable to complete the operation."
    }

    $Address = $Connection.IPv4Address.IPAddress

    if ($StartBackend) {
        $PythonFile = Join-Path $AppRoot "app.py"
        $BackendStdOut = Join-Path $RuntimeData "backend-startup-output.log"
        $BackendStdErr = Join-Path $RuntimeData "backend-startup-error.log"
        if ($SharedAccessOriginalStartMode) {
            & "$env:SystemRoot\System32\sc.exe" config SharedAccess start= disabled | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "SharedAccess could not be disabled for DNS preparation."
            }
            Remove-SharedAccessDnsOwner
            Start-Sleep -Milliseconds 150
        }
        $Ready = $false
        for ($StartAttempt = 0; $StartAttempt -lt 5 -and -not $Ready; $StartAttempt++) {
            Remove-SharedAccessDnsOwner
            $BackendProcess = Start-Process `
                -FilePath $PythonPath `
                -ArgumentList @(
                    ('"{0}"' -f $PythonFile),
                    "--dns-port", "53",
                    "--web-port", "8733"
                ) `
                -WorkingDirectory $AppRoot `
                -WindowStyle Hidden `
                -RedirectStandardOutput $BackendStdOut `
                -RedirectStandardError $BackendStdErr `
                -PassThru

            for ($Attempt = 0; $Attempt -lt 80; $Attempt++) {
                if ($BackendProcess.HasExited) {
                    break
                }
                Remove-SharedAccessDnsOwner -AllowedPid $BackendProcess.Id
                try {
                    $Response = Invoke-WebRequest -Uri "http://127.0.0.1:8733/api/health" -UseBasicParsing -TimeoutSec 1
                    if ($Response.StatusCode -eq 200) {
                        $Ready = $true
                        break
                    }
                } catch {
                }
                Start-Sleep -Milliseconds 250
            }
            if (-not $Ready -and -not $BackendProcess.HasExited) {
                Stop-Process -Id $BackendProcess.Id -Force -ErrorAction SilentlyContinue
            }
            if (-not $Ready) {
                Start-Sleep -Milliseconds 250
            }
        }
        if (-not $Ready) {
            $BackendError = if (Test-Path -LiteralPath $BackendStdErr) {
                (Get-Content -LiteralPath $BackendStdErr -Tail 8 -ErrorAction SilentlyContinue) -join " | "
            } else {
                ""
            }
            $Conflicts = @(
                Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        $ConflictProcess = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                        "udp:$($_.OwningProcess):$($ConflictProcess.ProcessName)"
                    }
            ) + @(
                Get-NetTCPConnection -State Listen -LocalPort 53 -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        $ConflictProcess = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                        "tcp:$($_.OwningProcess):$($ConflictProcess.ProcessName)"
                    }
            )
            $SharedAccessStartValue = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess").Start
            throw "The backend could not bind DNS port 53. start=$SharedAccessStartValue conflict=$($Conflicts -join ',') $BackendError"
        }
    }

    if ($SharedAccessOriginalStartMode) {
        Restore-SharedAccessStartMode $SharedAccessOriginalStartMode
        $SharedAccessOriginalStartMode = ""
    }
    if ($HnsWasRunning) {
        Start-Service -Name hns
        $HnsWasRunning = $false
    }

    @{
        ok = $true
        action = "prepared"
        address = $Address
        python = $PythonPath
        sharedAccessStopped = [bool]($PortOwners.Count)
        backendStarted = [bool]$StartBackend
        backendPid = if ($BackendProcess) { $BackendProcess.Id } else { 0 }
        timestamp = (Get-Date).ToString("o")
    } | ConvertTo-Json | Set-Content -LiteralPath $StatusPath -Encoding UTF8

    Write-Host ""
    Write-Host "Privacy Protector is ready." -ForegroundColor Green
    Write-Host "Computer address: $Address" -ForegroundColor Cyan
    Write-Host "Configure the iPhone DNS setting manually only when needed."
    Start-Sleep -Seconds 4
} catch {
    if ($BackendProcess -and -not $BackendProcess.HasExited) {
        Stop-Process -Id $BackendProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($SharedAccessOriginalStartMode) {
        Restore-SharedAccessStartMode $SharedAccessOriginalStartMode
    }
    if ($HnsWasRunning) {
        Start-Service -Name hns -ErrorAction SilentlyContinue
    }
    @{
        ok = $false
        action = "error"
        error = $_.Exception.Message
        timestamp = (Get-Date).ToString("o")
    } | ConvertTo-Json | Set-Content -LiteralPath $StatusPath -Encoding UTF8
    Write-Host ""
    Write-Host "Unable to complete the operation:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    if (-not $StartBackend) {
        Read-Host "Press Enter to close"
    }
    exit 1
}
