"""Inventory what is actually still installed, so that apps removed from the device are dropped from the constellations.

Computer: the whole disk is scanned, along with Appx packages (their folders and data) and live processes, in a hidden subprocess at low priority every day, because a scan takes minutes and would not burden the DNS engine with them. Any program whose name has disappeared from all of this is removed from the computer's domains and permissions, provided its last appearance was before the scan: a new program that appeared after the scan is not deleted until a later scan covers it.

iPhone: the device's app list is read over the network every six hours (pairing stays valid after the cable is connected once), so new apps are added and removed ones are deleted. The list from the device is the reference; nothing is deleted if it cannot be read.
"""

from __future__ import annotations

import json
import logging
import os
import re
import string
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import hidden_window

SCAN_MAX_AGE = 24 * 3600
# iOS refuses to read the app list over the network (tested 2026-10-28), so it is tried every hour to catch any cable connection.
PHONE_SCAN_INTERVAL = 3600
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
BELOW_NORMAL = getattr(subprocess, "BELOW_NORMAL_PRIORITY_CLASS", 0)
# System backup copies whose programs are never run; scanning them doubles the time.
SKIP_DIRS = {"winsxs", "$recycle.bin", "system volume information", "installer"}
# Folders that hold many programs: if one is the deepest remaining part of a program's path, the program's install folder itself has been removed.
GENERIC_FOLDERS = {
    "program files", "program files (x86)", "programdata", "users", Path.home().name.lower(), "appdata", "local",
    "roaming", "locallow", "programs", "documents", "downloads", "desktop", "windows", "system32", "syswow64",
}
# A version folder that is replaced on update: app-1.0.3, 13.743.3.6251 or v2.1
VERSION_FOLDER = re.compile(r"^(?:app-|v)?\d+(?:\.\d+)+", re.I)
# Kernel process names that have no file on disk.
KERNEL_NAMES = {"system", "registry", "idle", "secure system", "memory compression", "system idle process"}

_APPX_SCRIPT = (
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference='SilentlyContinue';"
    "@{procs=@(Get-Process | ForEach-Object {$_.ProcessName} | Sort-Object -Unique);"
    "appx=@(Get-AppxPackage | ForEach-Object {@{name=$_.Name;loc=$_.InstallLocation}})} | ConvertTo-Json -Depth 4 -Compress"
)


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _epoch(value: str) -> float:
    try:
        return datetime.fromisoformat(value).timestamp()
    except (TypeError, ValueError):
        return 0.0


def scan_machine() -> dict[str, Any]:
    """Collects the names of all exe files on the disks, Appx packages and live processes. Called in the subprocess."""
    names: set[str] = set()
    started = time.time()
    output = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", _APPX_SCRIPT],
        capture_output=True, timeout=180, creationflags=CREATE_NO_WINDOW, startupinfo=hidden_window.startupinfo(),
    ).stdout.decode("utf-8", "replace").strip()
    extra = json.loads(output) if output else {}
    packages = sorted({str(a.get("name") or "").lower() for a in extra.get("appx") or [] if a.get("name")})
    processes = sorted({str(p).lower() + ".exe" for p in extra.get("procs") or [] if p})
    roots = [f"{letter}:\\" for letter in string.ascii_uppercase if os.path.isdir(f"{letter}:\\")]
    # The WindowsApps folder cannot be listed, but each package's folder can be read; so package folders are scanned directly.
    roots += [str(a.get("loc")) for a in extra.get("appx") or [] if a.get("loc")]
    for root in roots:
        for folder, dirs, files in os.walk(root, onerror=lambda _e: None):
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
            for name in files:
                lower = name.lower()
                if lower.endswith((".exe", ".bin")):
                    names.add(lower)
    return {
        "scannedAt": datetime.fromtimestamp(started).astimezone().isoformat(timespec="seconds"),
        "seconds": round(time.time() - started),
        "complete": True,
        "names": sorted(names),
        "packages": packages,
        "processes": processes,
    }
class ProgramInventory:
    def __init__(self, directory: Path):
        self.path = Path(directory) / "installed-programs.json"
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.scan: dict[str, Any] = {}
        self.removed: dict[str, Any] = {"pc": {}, "phone": {}}
        self.phone_state: dict[str, Any] = {"state": "idle", "lastRunAt": "", "lastOkAt": "", "error": ""}
        self._names: set[str] = set()
        self._packages: set[str] = set()
        self._load()

    def _load(self) -> None:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        self.scan = payload.get("scan") or {}
        self.removed = {"pc": {}, "phone": {}, **(payload.get("removed") or {})}
        self.phone_state.update(payload.get("phone") or {})
        self._index()

    def _index(self) -> None:
        self._names = set(self.scan.get("names") or []) | set(self.scan.get("processes") or [])
        self._packages = set(self.scan.get("packages") or [])

    def save(self) -> None:
        with self.lock:
            text = json.dumps({"scan": self.scan, "removed": self.removed, "phone": self.phone_state},
                              ensure_ascii=False, indent=1)
        temp = self.path.with_suffix(".tmp")
        temp.write_text(text + "\n", encoding="utf-8")
        os.replace(temp, self.path)

    @property
    def scanned_at(self) -> float:
        return _epoch(str(self.scan.get("scannedAt") or "")) if self.scan.get("complete") else 0.0

    def present(self, name: str, path: str = "", last_seen: float = 0.0, by_name: bool = False) -> bool:
        """Certain absence only: without a complete scan, or with a sighting after the scan,
        the program is considered present.

        Permissions are identified by path, so they are judged by the install folder: QtWebEngineProcess.exe
        stays in other programs after Plex is removed. Domains are identified by program name (`by_name`),
        so whatever still carries its name anywhere remains: Calendaral moved from AppData to Program Files
        and was not removed."""
        scanned = self.scanned_at
        if not scanned or not name or (last_seen and last_seen >= scanned):
            return True
        lower = name.lower()
        if lower in KERNEL_NAMES:
            return True
        if path:
            if os.path.exists(path) or self._install_folder_remains(path):
                return True
            if not by_name:
                return False
        if lower in self._names or lower in self._packages:
            return True
        # The package name in permissions may carry its publisher or version: Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe
        return any(lower.startswith(package) or package.startswith(lower) for package in self._packages if len(package) > 6)

    def _install_folder_remains(self, path: str) -> bool:
        """The old path disappears when the program updates into a new version folder (claude.exe and
        Store packages), so the verdict rests on the install folder rather than the path: the file's own
        folder, or whatever sits above the version folders (app-1.2.3 and 13.743.3).
        (Lesson 2026-10-28: judging by path alone removed claude.exe, python.exe and Calendaral from their domains.)"""
        parts = [part.lower() for part in Path(path).parts]
        if "windowsapps" in parts:
            index = parts.index("windowsapps")
            if index + 1 >= len(parts):
                return True
            return parts[index + 1].split("_")[0] in self._packages
        folder = Path(path).parent
        if folder.exists():
            return True
        replaced = False   # a version folder went with it: an update, not a removal, so what sits above it remains
        while not folder.exists() and folder != folder.parent:
            replaced = replaced or bool(VERSION_FOLDER.search(folder.name))
            folder = folder.parent
        return replaced and folder.name.lower() not in GENERIC_FOLDERS and len(folder.parts) > 1

    # -- Periodic scan --------------------------------------------------------
    def refresh_scan(self) -> bool:
        """Scans in a hidden child process at low priority, so the DNS engine is not slowed down."""
        out = self.path.with_suffix(".scan.json")
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--scan", str(out)],
            capture_output=True, timeout=1800, cwd=str(Path(__file__).resolve().parent),
            creationflags=CREATE_NO_WINDOW | BELOW_NORMAL, startupinfo=hidden_window.startupinfo(),
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        try:
            scan = json.loads(out.read_text(encoding="utf-8"))
            out.unlink()
        except (OSError, ValueError):
            logging.warning("program scan failed: %s", result.stderr.decode("utf-8", "replace")[-300:])
            return False
        if not scan.get("complete") or len(scan.get("names") or []) < 200:
            return False  # an incomplete scan removes nothing
        with self.lock:
            self.scan = scan
            self._index()
        self.save()
        return True

    def removed_phone_ids(self) -> set[str]:
        """What was removed from the phone and has not been restored by a later reading
        (a reading that sees it installed clears it from the list)."""
        with self.lock:
            return {key.lower() for key in self.removed["phone"]}

    def apply_pc(self, pc: Any, capabilities: Any = None) -> list[str]:
        removed = pc.prune_programs(
            lambda name, path, last: self.present(name, path, last, by_name=True)
        ) if pc is not None else []
        if capabilities is not None:
            capabilities.program_filter = self.present
        if removed:
            with self.lock:
                for name in removed:
                    self.removed["pc"][name] = _now_iso()
            self.save()
        return removed

    def sync_phone(self, scanner: Callable[[], dict[str, Any]], profiles: Any) -> dict[str, Any]:
        self.phone_state.update(state="running", lastRunAt=_now_iso())
        scan = scanner()
        if not scan.get("ok"):
            self.phone_state.update(state="unreachable", error=str(scan.get("error") or "")[:300])
            self.save()
            return scan
        gone = profiles.sync_detected(scan["apps"])
        with self.lock:
            for app in scan["apps"]:
                # Reinstalled: no longer counted as removed in Apple's report
                self.removed["phone"].pop(str(app.get("bundleID") or ""), None)
            for app in gone:
                self.removed["phone"][app.get("bundleID", "")] = {"name": app.get("name", ""), "at": _now_iso()}
        self.phone_state.update(state="ok", lastOkAt=_now_iso(), error="", count=scan.get("count", 0), removed=len(gone))
        self.save()
        return {**scan, "removed": gone}

    def start(self, pc: Any, capabilities: Any, phone_scanner: Callable[[], dict[str, Any]], profiles: Any) -> None:
        def loop() -> None:
            if self.stop_event.wait(120.0):
                return
            next_phone = 0.0
            while not self.stop_event.is_set():
                try:
                    if time.time() - self.scanned_at > SCAN_MAX_AGE:
                        self.refresh_scan()
                    self.apply_pc(pc, capabilities)
                except Exception as error:  # noqa: BLE001 - the inventory must not bring down the server
                    logging.warning("program inventory: %s", error)
                if time.time() >= next_phone:
                    try:
                        self.sync_phone(phone_scanner, profiles)
                    except Exception as error:  # noqa: BLE001
                        self.phone_state.update(state="error", error=str(error)[:300])
                    next_phone = time.time() + PHONE_SCAN_INTERVAL
                if self.stop_event.wait(3600.0):
                    return

        threading.Thread(target=loop, name="program-inventory", daemon=True).start()

    def snapshot(self) -> dict[str, Any]:
        return {"scannedAt": self.scan.get("scannedAt", ""), "seconds": self.scan.get("seconds", 0),
                "programs": len(self._names), "packages": len(self._packages),
                "removed": self.removed, "phone": dict(self.phone_state)}

    def shutdown(self) -> None:
        self.stop_event.set()
if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--scan":
        Path(sys.argv[2]).write_text(json.dumps(scan_machine(), ensure_ascii=False), encoding="utf-8")
