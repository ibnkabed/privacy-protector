param([switch]$Remove)

$ErrorActionPreference = "Stop"
$AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackgroundScript = Join-Path $AppRoot "Start-Privacy-Protector-Background.ps1"
$Startup = [Environment]::GetFolderPath("Startup")
$LinkPath = Join-Path $Startup "Privacy Protector Background.lnk"

if ($Remove) {
    if (Test-Path -LiteralPath $LinkPath) {
        Remove-Item -LiteralPath $LinkPath -Force
    }
    exit 0
}

$PowerShellHost = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
if (-not $PowerShellHost) {
    $PowerShellHost = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
}
if (-not (Test-Path -LiteralPath $PowerShellHost)) {
    throw "PowerShell was not found."
}
if (-not (Test-Path -LiteralPath $BackgroundScript)) {
    throw "Start-Privacy-Protector-Background.ps1 was not found."
}

Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

[ComImport]
[Guid("00021401-0000-0000-C000-000000000046")]
internal class ShellLinkObject { }

[ComImport]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
[Guid("000214F9-0000-0000-C000-000000000046")]
internal interface IShellLinkW {
    void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder file, int maxPath, IntPtr findData, uint flags);
    void GetIDList(out IntPtr itemIdList);
    void SetIDList(IntPtr itemIdList);
    void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder description, int maxName);
    void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string description);
    void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder directory, int maxPath);
    void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string directory);
    void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder arguments, int maxPath);
    void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string arguments);
    void GetHotkey(out short hotkey);
    void SetHotkey(short hotkey);
    void GetShowCmd(out int showCommand);
    void SetShowCmd(int showCommand);
    void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder iconPath, int iconPathLength, out int iconIndex);
    void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string iconPath, int iconIndex);
    void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string path, uint reserved);
    void Resolve(IntPtr windowHandle, uint flags);
    void SetPath([MarshalAs(UnmanagedType.LPWStr)] string file);
}

public static class PrivacyProtectorStartupLink {
    public static void Create(string linkPath, string targetPath, string arguments, string workingDirectory, string iconPath) {
        IShellLinkW link = (IShellLinkW)new ShellLinkObject();
        link.SetPath(targetPath);
        link.SetArguments(arguments);
        link.SetWorkingDirectory(workingDirectory);
        link.SetDescription("Privacy Protector lightweight background DNS service");
        link.SetShowCmd(7);
        if (!String.IsNullOrEmpty(iconPath)) link.SetIconLocation(iconPath, 0);
        ((IPersistFile)link).Save(linkPath, false);
    }

    public static string[] Read(string linkPath) {
        IShellLinkW link = (IShellLinkW)new ShellLinkObject();
        ((IPersistFile)link).Load(linkPath, 0);
        StringBuilder path = new StringBuilder(32768);
        StringBuilder args = new StringBuilder(32768);
        StringBuilder cwd = new StringBuilder(32768);
        link.GetPath(path, path.Capacity, IntPtr.Zero, 0);
        link.GetArguments(args, args.Capacity);
        link.GetWorkingDirectory(cwd, cwd.Capacity);
        return new[] { path.ToString(), args.ToString(), cwd.ToString() };
    }
}
'@

$Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$BackgroundScript`""
$Icon = Join-Path $AppRoot "web\assets\Privacy Protector.ico"
[PrivacyProtectorStartupLink]::Create(
    $LinkPath,
    $PowerShellHost,
    $Arguments,
    $AppRoot,
    $(if (Test-Path -LiteralPath $Icon) { $Icon } else { "" })
)

$Saved = [PrivacyProtectorStartupLink]::Read($LinkPath)
[pscustomobject]@{
    LinkPath = $LinkPath
    TargetPath = $Saved[0]
    Arguments = $Saved[1]
    WorkingDirectory = $Saved[2]
}
