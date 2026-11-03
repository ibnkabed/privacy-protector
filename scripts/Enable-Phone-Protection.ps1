#Requires -RunAsAdministrator
# Lets a phone on your home network use this computer as its DNS server:
# opens DNS (port 53, UDP and TCP) to the local subnet on private networks only,
# for the Privacy Protector program alone. Disable-Phone-Protection.ps1 removes it.
param([string]$Program = "", [string]$DataDir = "")
$ErrorActionPreference = "Stop"

$RuleNames = @("Privacy Protector (open source) DNS UDP", "Privacy Protector (open source) DNS TCP")
foreach ($RuleName in $RuleNames) {
    Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}
$Common = @{ Direction = "Inbound"; Action = "Allow"; LocalPort = 53; Profile = "Private"; RemoteAddress = "LocalSubnet" }
if ($Program) { $Common.Program = $Program }
New-NetFirewallRule -DisplayName $RuleNames[0] -Protocol UDP @Common | Out-Null
New-NetFirewallRule -DisplayName $RuleNames[1] -Protocol TCP @Common | Out-Null

if ($DataDir) {
    $State = Join-Path $DataDir "phone-firewall.json"
    @{ ok = $true; action = "added"; program = $Program; at = (Get-Date).ToString("o") } |
        ConvertTo-Json | Set-Content -LiteralPath $State -Encoding UTF8
}
Write-Host "Phone DNS is open to your local network."
