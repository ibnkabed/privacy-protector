$ErrorActionPreference = "Stop"

$Launcher = Join-Path $PSScriptRoot "Privacy Protector.cmd"
if (-not (Test-Path -LiteralPath $Launcher)) {
    throw "Privacy Protector.cmd was not found."
}

$Desktop = [Environment]::GetFolderPath("Desktop")
$DisplayName = "Privacy Protector"
$LinkPath = Join-Path $Desktop ($DisplayName + ".lnk")
$Edge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
if (-not (Test-Path -LiteralPath $Edge)) {
    $Edge = "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
}

$ProjectIcon = Join-Path $PSScriptRoot "web\assets\Privacy Protector.ico"
$IconPath = if (Test-Path -LiteralPath $ProjectIcon) {
    $ProjectIcon
} elseif (Test-Path -LiteralPath $Edge) {
    $Edge
} else {
    ""
}
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

[ComImport]
[Guid("00021401-0000-0000-C000-000000000046")]
internal class ShellLinkObject {
}

[ComImport]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
[Guid("000214F9-0000-0000-C000-000000000046")]
internal interface IShellLinkW {
    void GetPath(
        [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder file,
        int maxPath,
        IntPtr findData,
        uint flags);
    void GetIDList(out IntPtr itemIdList);
    void SetIDList(IntPtr itemIdList);
    void GetDescription(
        [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder description,
        int maxName);
    void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string description);
    void GetWorkingDirectory(
        [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder directory,
        int maxPath);
    void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string directory);
    void GetArguments(
        [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder arguments,
        int maxPath);
    void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string arguments);
    void GetHotkey(out short hotkey);
    void SetHotkey(short hotkey);
    void GetShowCmd(out int showCommand);
    void SetShowCmd(int showCommand);
    void GetIconLocation(
        [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder iconPath,
        int iconPathLength,
        out int iconIndex);
    void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string iconPath, int iconIndex);
    void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string path, uint reserved);
    void Resolve(IntPtr windowHandle, uint flags);
    void SetPath([MarshalAs(UnmanagedType.LPWStr)] string file);
}

public static class UnicodeShortcut {
    public static void Create(
        string linkPath,
        string targetPath,
        string workingDirectory,
        string description,
        string iconPath) {
        IShellLinkW link = (IShellLinkW)new ShellLinkObject();
        link.SetPath(targetPath);
        link.SetWorkingDirectory(workingDirectory);
        link.SetDescription(description);
        link.SetShowCmd(1);
        if (!String.IsNullOrEmpty(iconPath)) {
            link.SetIconLocation(iconPath, 0);
        }
        ((IPersistFile)link).Save(linkPath, false);
    }
}
'@

[UnicodeShortcut]::Create(
    $LinkPath,
    $Launcher,
    $PSScriptRoot,
    "Privacy Protector - iPhone network protection",
    $IconPath
)

Write-Host "OK: desktop shortcut created."
