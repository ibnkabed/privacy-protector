# PyInstaller build of PrivacyProtector.exe (one folder, no console window).
#   pyinstaller packaging/PrivacyProtector.spec --noconfirm
# The version comes from the VERSION file at the repository root.
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

ROOT = Path(SPECPATH).parent
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

datas = [
    (str(ROOT / "web"), "web"),
    (str(ROOT / "scripts"), "scripts"),
    (str(ROOT / "tools"), "tools"),
    (str(ROOT / "Show-Privacy-Protector-Notification.ps1"), "."),
    (str(ROOT / "LICENSE"), "."),
    (str(ROOT / "NOTICE"), "."),
]
binaries = []
hiddenimports = ["app", "program_inventory", "win32com.client", "pythoncom", "win32event", "pystray._win32"]
for package in ("pymobiledevice3",):
    try:
        found = collect_all(package)
    except Exception:  # noqa: BLE001 - the iPhone USB tools are optional
        continue
    datas += found[0]
    binaries += found[1]
    hiddenimports += found[2]

numbers = tuple(int(part) for part in (VERSION.split("-")[0].split(".") + ["0", "0", "0"])[:4])
version_file = ROOT / "build" / "version-info.txt"
version_file.parent.mkdir(parents=True, exist_ok=True)
version_file.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={numbers}, prodvers={numbers}),
  kids=[StringFileInfo([StringTable('040904B0', [
    StringStruct('CompanyName', 'IbnKabed'),
    StringStruct('FileDescription', 'Privacy Protector'),
    StringStruct('FileVersion', '{VERSION}'),
    StringStruct('InternalName', 'PrivacyProtector'),
    StringStruct('LegalCopyright', 'Copyright (c) 2026 IbnKabed. AGPL-3.0'),
    StringStruct('OriginalFilename', 'PrivacyProtector.exe'),
    StringStruct('ProductName', 'Privacy Protector'),
    StringStruct('ProductVersion', '{VERSION}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])])
""", encoding="utf-8")

a = Analysis([str(ROOT / "privacy_protector.py")], pathex=[str(ROOT)], binaries=binaries, datas=datas,
             hiddenimports=hiddenimports, excludes=["tkinter", "pytest"])
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="PrivacyProtector", console=False,
          icon=str(ROOT / "web" / "assets" / "privacy-protector.ico"), version=str(version_file))
coll = COLLECT(exe, a.binaries, a.datas, name="PrivacyProtector")
