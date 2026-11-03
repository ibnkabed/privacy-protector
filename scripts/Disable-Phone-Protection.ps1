#Requires -RunAsAdministrator
# Undoes Enable-Phone-Protection.ps1: removes the two firewall rules.
param([string]$DataDir = "")
$ErrorActionPreference = "Stop"

foreach ($RuleName in @("Privacy Protector DNS (UDP)", "Privacy Protector DNS (TCP)")) {
    Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}
if ($DataDir) {
    Remove-Item -LiteralPath (Join-Path $DataDir "phone-firewall.json") -Force -ErrorAction SilentlyContinue
}
Write-Host "Phone DNS is closed to your local network."
