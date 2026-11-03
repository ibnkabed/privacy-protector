"""The engine does not live as a child of an agent session.

When a terminal or another tool starts the engine, it becomes a descendant of the agent program.
If that program is closed, all its descendants are closed with it, so blocking and mobile DNS drop
without any error in the engine. This happened more than once.

So on startup the engine checks its chain of parents. If it finds an agent program in that chain, it
relaunches itself with the same arguments via WMI (``Win32_Process.Create``), so it becomes a child of
``WmiPrvSE.exe`` in the user's own session, and then exits before opening any port. ``--attached``
keeps it tied to whoever deliberately wants to run it in the foreground.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

import hidden_window

# Agent programs whose descendants are closed when they are closed.
AGENT_PROGRAMS = {"claude.exe", "codex.exe"}
TH32CS_SNAPPROCESS = 0x2


class _Entry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260),
    ]


def _processes() -> dict[int, tuple[int, str]]:
    """Each process ID ← (its parent's ID, its name), from a single snapshot without a subprocess."""
    kernel = ctypes.windll.kernel32
    snapshot = kernel.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    table: dict[int, tuple[int, str]] = {}
    entry = _Entry()
    entry.dwSize = ctypes.sizeof(_Entry)
    try:
        ok = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            table[entry.th32ProcessID] = (entry.th32ParentProcessID, entry.szExeFile)
            ok = kernel.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    return table


def agent_ancestor(pid: int | None = None) -> str:
    """Name of the first agent program in the process's parent chain, or an empty string."""
    if os.name != "nt":
        return ""
    table = _processes()
    current, seen = pid or os.getpid(), set()
    while current in table and current not in seen:
        seen.add(current)
        parent, _ = table[current]
        if parent not in table:
            return ""
        name = table[parent][1]
        if name.lower() in AGENT_PROGRAMS:
            return name
        current = parent
    return ""


def _quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def relaunch_detached(argv: list[str]) -> bool:
    """Starts a copy of the engine with the same arguments via WMI, so it does not inherit the agent's tree. Returns whether it succeeded."""
    python = Path(sys.executable)
    pythonw = python.with_name("pythonw.exe")
    exe = pythonw if pythonw.exists() else python
    command_line = subprocess.list2cmdline([str(exe), str(Path(argv[0]).resolve()), *argv[1:]])
    script = (
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        "$s = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{ShowWindow=[uint16]0}; "
        "$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{"
        f"CommandLine={_quote(command_line)}; CurrentDirectory={_quote(str(Path(argv[0]).resolve().parent))}; "
        "ProcessStartupInformation=$s}; exit $r.ReturnValue"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), startupinfo=hidden_window.startupinfo(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0
