param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$DnsAddress,

    [ValidateSet("connected", "disconnected", "reconnect", "address-changed")]
    [string]$State = "disconnected"
)

# A toast under the app's own name and icon, through the AppUserModelID registered below.
# Without it Windows attributes the toast to PowerShell.
# Runs in Windows PowerShell 5.1, the only edition that reaches the Windows toast API directly.
$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSEdition -eq "Core") {
    & powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $MyInvocation.MyCommand.Path -DnsAddress $DnsAddress -State $State
    exit $LASTEXITCODE
}
$AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppId = "PrivacyProtector.OpenSource"
$Identifier = "privacy-protector-dns-$State"
$AddressText = if ([string]::IsNullOrWhiteSpace($DnsAddress)) {
    "DNS: not available"
} else {
    "DNS: $DnsAddress"
}

if ($State -eq "connected") {
    $LogoPath = Join-Path $AppRoot "web\assets\Privacy Protector notification green.png"
    $Text = @("Your phone is connected")
} elseif ($State -eq "address-changed") {
    $LogoPath = Join-Path $AppRoot "web\assets\Privacy Protector notification orange.png"
    $Text = @("This PC's address changed", "New address: $DnsAddress • Set it as the DNS on your phone's networks")
} elseif ($State -eq "reconnect") {
    $LogoPath = Join-Path $AppRoot "web\assets\Privacy Protector notification orange.png"
    $Text = @("Your phone left protection half an hour ago", "Reconnect it to the router • $AddressText")
} else {
    $LogoPath = Join-Path $AppRoot "web\assets\Privacy Protector notification red.png"
    $Text = @("Your phone is not connected", $AddressText)
}

# The identity (name and icon) is registered every time, so it stays right if the folder moves.
$Key = "HKCU:\Software\Classes\AppUserModelId\$AppId"
New-Item -Path $Key -Force | Out-Null
Set-ItemProperty -Path $Key -Name DisplayName -Value "Privacy Protector"
Set-ItemProperty -Path $Key -Name IconUri -Value (Join-Path $AppRoot "web\assets\Privacy Protector.png")
Set-ItemProperty -Path $Key -Name ShowInSettings -Value 1 -Type DWord

[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]

function X([string]$s) { [Security.SecurityElement]::Escape($s) }
$TextXml = ($Text | ForEach-Object { "<text>$(X $_)</text>" }) -join ""
$Image = ""
if (Test-Path -LiteralPath $LogoPath) {
    $Image = "<image placement=`"appLogoOverride`" src=`"$(X $LogoPath)`"/>"
}
$Xml = @"
<toast>
  <visual><binding template="ToastGeneric">$TextXml$Image</binding></visual>
  <audio src="ms-winsoundevent:Notification.Default"/>
</toast>
"@
$Doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$Doc.LoadXml($Xml)
$Toast = [Windows.UI.Notifications.ToastNotification]::new($Doc)
# The same tag replaces the previous toast of the same state instead of piling up.
$Toast.Tag = $Identifier
$Toast.Group = "privacy-protector"
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Show($Toast)
