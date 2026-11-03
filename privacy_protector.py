"""Privacy Protector's entry point: the installed PrivacyProtector.exe runs this.

    PrivacyProtector.exe                  open the dashboard, starting the engine first if needed
    PrivacyProtector.exe --background     start the engine if needed, without opening anything (sign-in)
    PrivacyProtector.exe --engine [...]   run the engine itself (app.py options may follow)
    PrivacyProtector.exe --cleanup-system undo every Windows change the app made (the uninstaller runs this)

From source the same commands work with ``python privacy_protector.py``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
import webbrowser

import paths

WEB_PORT = 8733
DASHBOARD = f"http://127.0.0.1:{WEB_PORT}/"
CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008


def engine_running(timeout: float = 1.5) -> bool:
    try:
        with urllib.request.urlopen(DASHBOARD + "api/health", timeout=timeout) as reply:
            return bool(json.loads(reply.read().decode("utf-8")).get("ok"))
    except (OSError, ValueError):
        return False


def start_engine() -> bool:
    """Starts the engine detached and hidden, then waits until it answers."""
    if engine_running():
        return True
    if paths.FROZEN:
        command = [sys.executable, "--engine"]
    else:
        pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        command = [pythonw if os.path.exists(pythonw) else sys.executable, os.path.abspath(__file__), "--engine"]
    import hidden_window

    subprocess.Popen(command, cwd=str(paths.APP_ROOT), close_fds=True,
                     creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW, startupinfo=hidden_window.startupinfo())
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if engine_running():
            return True
        time.sleep(0.5)
    return False


def cleanup_system() -> int:
    """Undoes the phone firewall rules, the PC's DNS change and watchdog, and the capability history copy.
    Runs with the rights it was given (the uninstaller is already elevated)."""
    scripts = paths.APP_ROOT / "scripts"
    powershell = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    failed = 0
    for name, extra in (("Disable-PC-Protection.ps1", []), ("Disable-Phone-Protection.ps1", ["-IncludeVersion1"]),
                        ("Disable-Capability-History.ps1", [])):
        result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                                 str(scripts / name), "-DataDir", str(paths.DATA_ROOT), *extra],
                                creationflags=CREATE_NO_WINDOW, capture_output=True, timeout=180)
        failed += result.returncode != 0
    return 1 if failed else 0


def run_helper(argv: list[str]) -> int:
    """The engine runs its helpers as ``<interpreter> <script.py> ...``; inside the exe the interpreter is this
    program, so the script runs here: from its file when it is shipped as one, else as a bundled module."""
    import runpy
    from pathlib import Path

    script = Path(argv[0])
    sys.argv = [str(script), *argv[1:]]
    try:
        if script.is_file():
            runpy.run_path(str(script), run_name="__main__")
        else:
            runpy.run_module(script.stem, run_name="__main__", alter_sys=True)
    except SystemExit as stop:
        return int(stop.code or 0) if isinstance(stop.code, int) or stop.code is None else 1
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] and argv[0].endswith(".py"):
        return run_helper(argv)
    if argv[:1] == ["--engine"]:
        import app

        sys.argv = [sys.argv[0], *argv[1:]]
        app.main()
        return 0
    if argv[:1] == ["--cleanup-system"]:
        return cleanup_system()
    ok = start_engine()
    if argv[:1] != ["--background"] and ok:
        webbrowser.open(DASHBOARD)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
