#Requires -RunAsAdministrator
# Undoes Enable-Phone-Protection.ps1: removes the two firewall rules.
# -IncludeVersion1 also removes the rules that version 1 of this app created.
param([string]$DataDir = "", [switch]$IncludeVersion1)
$ErrorActionPreference = "Stop"

$RuleNames = @("Privacy Protector (open source) DNS UDP", "Privacy Protector (open source) DNS TCP")
if ($IncludeVersion1) { $RuleNames += @("Privacy Protector DNS UDP", "Privacy Protector DNS TCP") }
foreach ($RuleName in $RuleNames) {
    Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}
if ($DataDir) {
    Remove-Item -LiteralPath (Join-Path $DataDir "phone-firewall.json") -Force -ErrorAction SilentlyContinue
}
Write-Host "Phone DNS is closed to your local network."
