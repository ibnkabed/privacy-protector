; Inno Setup script for the Privacy Protector installer.
;   iscc /DAppVersion=2.1.1 packaging\PrivacyProtector.iss
; Expects the PyInstaller output in dist\PrivacyProtector.
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6D3B0E9A-4C7F-4E43-9B2A-7C1E5F2D8A41}
AppName=Privacy Protector
AppVersion={#AppVersion}
AppVerName=Privacy Protector {#AppVersion}
AppPublisher=IbnKabed
AppPublisherURL=https://github.com/ibnkabed/privacy-protector
AppSupportURL=https://github.com/ibnkabed/privacy-protector/issues
AppCopyright=Copyright (c) 2026 IbnKabed
VersionInfoVersion={#AppVersion}
VersionInfoProductName=Privacy Protector
VersionInfoProductVersion={#AppVersion}
DefaultDirName={autopf}\Privacy Protector Open Source
DefaultGroupName=Privacy Protector
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=PrivacyProtector-Setup-{#AppVersion}
SetupIconFile=..\web\assets\privacy-protector.ico
UninstallDisplayIcon={app}\PrivacyProtector.exe
UninstallDisplayName=Privacy Protector
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
CloseApplications=force

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "arabic"; MessagesFile: "compiler:Languages\Arabic.isl"

[Tasks]
Name: "startup"; Description: "Start Privacy Protector when I sign in"; GroupDescription: "Startup:"
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\dist\PrivacyProtector\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Privacy Protector"; Filename: "{app}\PrivacyProtector.exe"
Name: "{autodesktop}\Privacy Protector"; Filename: "{app}\PrivacyProtector.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "PrivacyProtector.OpenSource"; ValueData: """{app}\PrivacyProtector.exe"" --background"; Tasks: startup; Flags: uninsdeletevalue

[Run]
Filename: "{app}\PrivacyProtector.exe"; Description: "Open Privacy Protector"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
; Stop the engine, then undo every Windows change it made (DNS servers, firewall rules, scheduled tasks).
Filename: "{sys}\taskkill.exe"; Parameters: "/im PrivacyProtector.exe /f"; Flags: runhidden; RunOnceId: "StopEngine"
Filename: "{app}\PrivacyProtector.exe"; Parameters: "--cleanup-system"; Flags: runhidden waituntilterminated; RunOnceId: "CleanupSystem"

[InstallDelete]
Type: filesandordirs; Name: "{app}\_internal"
