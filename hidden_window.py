"""The subprocess window is explicitly hidden.

CREATE_NO_WINDOW alone is not enough: a console window kept flashing from wevtutil, and all its calls carried the flag. So every background subprocess
gets a STARTUPINFO with SW_HIDE.
"""
from __future__ import annotations

import subprocess


def startupinfo():
    """Hidden STARTUPINFO on Windows, and None on other platforms."""
    if not hasattr(subprocess, "STARTUPINFO"):
        return None
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = 0   # SW_HIDE
    return info
