"""Runs one of the app's own PowerShell scripts with administrator rights.

Windows asks you once through its UAC prompt; nothing runs if you decline.
Only scripts inside the app's own ``scripts`` folder can be started.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from pathlib import Path

import paths

SCRIPTS = paths.APP_ROOT / "scripts"


def powershell() -> str:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return str(Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")


def _quote(value: str) -> str:
    return subprocess.list2cmdline([str(value)])


def run_script(name: str, *args: str, wait: bool = True, timeout_ms: int = 120000) -> bool:
    """Runs scripts/<name> elevated and hidden. True when it ran and exited 0."""
    script = (SCRIPTS / name).resolve()
    if script.parent != SCRIPTS.resolve() or not script.is_file() or sys.platform != "win32":
        return False
    params = " ".join(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
                       "-File", _quote(str(script)), *(_quote(a) for a in args)])

    class ShellExecuteInfo(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_ulong), ("fMask", ctypes.c_ulong), ("hwnd", ctypes.c_void_p),
                    ("lpVerb", ctypes.c_wchar_p), ("lpFile", ctypes.c_wchar_p), ("lpParameters", ctypes.c_wchar_p),
                    ("lpDirectory", ctypes.c_wchar_p), ("nShow", ctypes.c_int), ("hInstApp", ctypes.c_void_p),
                    ("lpIDList", ctypes.c_void_p), ("lpClass", ctypes.c_wchar_p), ("hkeyClass", ctypes.c_void_p),
                    ("dwHotKey", ctypes.c_ulong), ("hIcon", ctypes.c_void_p), ("hProcess", ctypes.c_void_p)]

    info = ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x40  # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = powershell()
    info.lpParameters = params
    info.nShow = 0  # SW_HIDE
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
        return False  # declined at the UAC prompt, or Windows refused
    kernel = ctypes.windll.kernel32
    try:
        if not wait:
            return True
        kernel.WaitForSingleObject(ctypes.c_void_p(info.hProcess), timeout_ms)
        code = ctypes.c_ulong(1)
        kernel.GetExitCodeProcess(ctypes.c_void_p(info.hProcess), ctypes.byref(code))
        return code.value == 0
    finally:
        kernel.CloseHandle(ctypes.c_void_p(info.hProcess))
