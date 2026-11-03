"""Temp cleanup in place of Norton.

Every day at 9 PM, or at the first run after that if the machine was off, entries in the Temp folders
that have not been modified for more than seven days are deleted. The decision unit is each entry at the
top of a Temp folder: a file alone, or a folder as a whole or not at all, so that half a folder is never
deleted while it holds a file that was used recently. The following are never touched:
- Agent session folders (`claude` and `codex-*`) regardless of age, and any exceptions in the config file.
- A file open in another program: it is skipped, not forced.
- Symbolic links and junctions: the link itself is deleted and not followed to its target; any path that
  leaves its folder is skipped.
- Installer or Windows update time: deferred one hour, until midnight.
The first run is a trial without deletion, shown to the user, and nothing is deleted until they approve.
Everything deleted is written to a log that is never trimmed.
"""

from __future__ import annotations

import ctypes
import fnmatch
import json
import logging
import os
import stat
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterable

import hidden_window

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
AGE_DAYS = 7
RUN_HOUR = 21
POSTPONE = 3600
MISSED_AFTER = 36 * 3600
# The signed-in user's folders by full path: a process with administrator or system rights has a different %TEMP%.
_LOCAL = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
DEFAULT_SCOPES = [
    os.path.join(_LOCAL, "Temp"),
    r"C:\Windows\Temp",
    os.path.join(_LOCAL, "CrashDumps"),
    r"C:\ProgramData\Microsoft\Windows\WER",
]
DEFAULT_KEEP: list[str] = []
# Installers and updaters: no cleanup while they run, as they may still need what is in Temp.
INSTALLER_PATTERNS = ["msiexec.exe", "setup*.exe", "*installer*.exe", "*install.exe", "winget.exe", "tiworker.exe", "wusa.exe", "dismhost.exe"]


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _epoch(value: str) -> float:
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except (TypeError, ValueError):
        return 0.0


def idle_seconds() -> float:
    """Seconds since the last mouse or keyboard input. Zero if the reading fails (the user is treated as present)."""
    try:
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

        info = LASTINPUTINFO(ctypes.sizeof(LASTINPUTINFO), 0)
        if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
            return 0.0
        return max(0.0, (ctypes.windll.kernel32.GetTickCount() - info.dwTime) / 1000.0)
    except (AttributeError, OSError):
        return 0.0


def running_installers() -> list[str]:
    try:
        output = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"], capture_output=True, timeout=30,
            creationflags=CREATE_NO_WINDOW, startupinfo=hidden_window.startupinfo(),
        ).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return []
    names = {line.split('","')[0].strip('"').lower() for line in output.splitlines() if line.strip()}
    return sorted(n for n in names if any(fnmatch.fnmatch(n, p) for p in INSTALLER_PATTERNS))


def _is_link(path: str) -> bool:
    try:
        return os.path.islink(path) or os.path.isjunction(path)
    except (OSError, AttributeError):
        return os.path.islink(path)
def _inside(path: str, scope: str) -> bool:
    try:
        real = os.path.realpath(os.path.dirname(path))
        return os.path.commonpath([os.path.normcase(real), os.path.normcase(os.path.realpath(scope))]) == os.path.normcase(os.path.realpath(scope))
    except ValueError:
        return False


def _old(path: str, cutoff: float) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return info.st_mtime < cutoff and info.st_ctime < cutoff


def plan_entry(path: str, cutoff: float) -> tuple[bool, list[tuple[str, int]]]:
    """(Delete?, [(path, size)]). The folder is deleted entirely if all its contents are old; links inside are not followed."""
    if _is_link(path):
        return _old(path, cutoff), [(path, 0)]
    if not os.path.isdir(path):
        try:
            size = os.lstat(path).st_size
        except OSError:
            return False, []
        return _old(path, cutoff), [(path, size)]
    if not _old(path, cutoff):
        return False, []   # Folder changed recently (created, added to, or removed from): some program is using it
    files: list[tuple[str, int]] = []
    for folder, dirs, names in os.walk(path, followlinks=False, onerror=lambda _e: None):
        for name in list(dirs):
            full = os.path.join(folder, name)
            if _is_link(full):
                dirs.remove(name)
                if not _old(full, cutoff):
                    return False, []
                files.append((full, 0))
        for name in names:
            full = os.path.join(folder, name)
            try:
                info = os.lstat(full)
            except OSError:
                return False, []
            if info.st_mtime >= cutoff or info.st_ctime >= cutoff:
                return False, []
            files.append((full, info.st_size))
    return True, files


def _remove(path: str) -> bool:
    try:
        if _is_link(path):
            # The link itself only: rmdir for the junction, unlink for the symlink.
            (os.rmdir if os.path.isdir(path) else os.unlink)(path)
        else:
            os.chmod(path, stat.S_IWRITE)
            os.unlink(path)
        return True
    except OSError:
        return False


def _remove_empty_dirs(root: str) -> None:
    for folder, _dirs, _names in sorted(os.walk(root, followlinks=False), key=lambda item: -len(item[0])):
        try:
            os.rmdir(folder)
        except OSError:
            pass


class TempCleanup:
    def __init__(self, directory: Path):
        self.state_path = Path(directory) / "temp-cleanup.json"
        self.config_path = Path(directory) / "temp-cleanup-config.json"
        self.log_path = Path(directory) / "temp-cleanup-log.ndjson"
        self.lock = threading.Lock()
        self.run_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.wake = threading.Event()
        self.state: dict[str, Any] = {"approved": False, "preview": None, "lastRun": None, "lastRunDay": "",
                                      "totalBytes": 0, "postponedUntil": "", "state": "idle"}
        self._load()
        self.config = self._config()

    def _load(self) -> None:
        try:
            self.state.update(json.loads(self.state_path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass

    def _config(self) -> dict[str, Any]:
        try:
            config = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            config = {"note": "Excluded top-level names in each Temp folder (glob, case-insensitive). docs/plan-temp-cleanup.md",
                      "scopes": DEFAULT_SCOPES, "keep": DEFAULT_KEEP, "ageDays": AGE_DAYS, "hour": RUN_HOUR}
            try:
                self.config_path.write_text(json.dumps(config, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
            except OSError:
                pass
        # Agent exclusions persist even if removed from the file.
        config["keep"] = sorted(set(config.get("keep") or []) | set(DEFAULT_KEEP))
        return config

    def save(self) -> None:
        with self.lock:
            text = json.dumps(self.state, ensure_ascii=False, indent=1)
        temp = self.state_path.with_suffix(".tmp")
        temp.write_text(text + "\n", encoding="utf-8")
        os.replace(temp, self.state_path)

    def _kept(self, name: str) -> bool:
        lower = name.lower()
        return any(fnmatch.fnmatch(lower, pattern.lower()) for pattern in self.config["keep"])

    # -- Scan folders ---------------------------------------------------------
    def survey(self, scopes: Iterable[str] | None = None, now: float | None = None) -> dict[str, Any]:
        """What would be deleted without deleting: for each folder its size and largest entries, and what wasn't read due to lack of permission."""
        now = time.time() if now is None else now
        cutoff = now - float(self.config.get("ageDays", AGE_DAYS)) * 86400
        result: dict[str, Any] = {"at": _now_iso(), "bytes": 0, "files": 0, "scopes": [], "skipped": [], "entries": []}
        for scope in scopes or self.config["scopes"]:
            try:
                entries = list(os.scandir(scope))
            except FileNotFoundError:
                continue
            except OSError:
                result["skipped"].append(scope)
                continue
            total = count = 0
            for entry in entries:
                if self._kept(entry.name):
                    continue
                delete, files = plan_entry(entry.path, cutoff)
                if not delete:
                    continue
                size = sum(s for _p, s in files)
                total += size
                count += len(files)
                result["entries"].append({"path": entry.path, "scope": scope, "bytes": size, "files": [p for p, _s in files]})
            result["scopes"].append({"path": scope, "bytes": total, "files": count})
            result["bytes"] += total
            result["files"] += count
        return result

    def preview(self) -> dict[str, Any]:
        survey = self.survey()
        top = sorted(survey["entries"], key=lambda e: -e["bytes"])[:12]
        preview = {"at": survey["at"], "bytes": survey["bytes"], "files": survey["files"], "scopes": survey["scopes"],
                   "skipped": survey["skipped"], "top": [{"path": e["path"], "bytes": e["bytes"]} for e in top]}
        with self.lock:
            self.state["preview"] = preview
        self.save()
        return preview

    def clean(self, reason: str, pause: Callable[[], None] | None = None) -> dict[str, Any]:
        """Deletes what the scan decides, and logs every deleted file. Two instances do not run together."""
        if not self.run_lock.acquire(blocking=False):
            return {"error": "Cleaning is currently running"}
        try:
            self.state["state"] = "running"
            survey = self.survey()
            deleted = locked = freed = 0
            with self.log_path.open("a", encoding="utf-8") as log:
                for index, entry in enumerate(survey["entries"]):
                    if self.stop_event.is_set():
                        break
                    if pause and index % 20 == 0:
                        pause()
                    for path in entry["files"]:
                        if not _inside(path, entry["scope"]):
                            log.write(json.dumps({"at": _now_iso(), "skipped": path, "why": "outside scope"}, ensure_ascii=False) + "\n")
                            continue
                        try:
                            size = 0 if _is_link(path) else os.lstat(path).st_size
                        except OSError:
                            continue
                        if _remove(path):
                            deleted += 1
                            freed += size
                            log.write(json.dumps({"at": _now_iso(), "deleted": path, "bytes": size}, ensure_ascii=False) + "\n")
                        else:
                            locked += 1
                    if os.path.isdir(entry["path"]) and not _is_link(entry["path"]):
                        _remove_empty_dirs(entry["path"])
            run = {"at": _now_iso(), "reason": reason, "deleted": deleted, "locked": locked, "bytes": freed,
                   "skipped": survey["skipped"]}
            with self.lock:
                self.state.update(lastRun=run, lastRunDay=datetime.now().date().isoformat(), state="idle",
                                  totalBytes=int(self.state.get("totalBytes", 0)) + freed, postponedUntil="")
            self.save()
            return run
        finally:
            self.state["state"] = "idle"
            self.run_lock.release()

    def approve(self) -> dict[str, Any]:
        """The user's approval for the first cleanup: starts now, then runs automatically every day."""
        with self.lock:
            self.state["approved"] = True
        self.save()
        self.wake.set()
        return {"ok": True}

    # -- Scheduling -----------------------------------------------------------
    def due(self, now: datetime | None = None) -> bool:
        now = now or datetime.now()
        if not self.state.get("approved") or self.state.get("lastRunDay") == now.date().isoformat():
            return False
        if self.state.get("postponedUntil") and time.time() < _epoch(self.state["postponedUntil"]):
            return False
        last = self.state.get("lastRun") or {}
        if not last:
            return True   # First run after approval
        # Missed 9 AM because the device was off: last cleanup was more than 36 hours ago, so run now even if before 9 AM.
        missed = now.timestamp() - _epoch(last.get("at", "")) > MISSED_AFTER
        return now.hour >= int(self.config.get("hour", RUN_HOUR)) or missed

    def _pause_while_active(self) -> None:
        """Slows down when the user is active: one second between batches as long as the device is being touched."""
        if idle_seconds() < 5:
            time.sleep(1.0)

    def tick(self) -> dict[str, Any] | None:
        if not self.state.get("approved"):
            if not self.state.get("preview"):
                self.preview()
            return None
        if not self.due():
            return None
        busy = running_installers()
        if busy:
            until = datetime.now() + timedelta(seconds=POSTPONE)
            midnight = datetime.now().replace(hour=23, minute=59, second=0)
            with self.lock:
                self.state["postponedUntil"] = min(until, midnight).astimezone().isoformat(timespec="seconds")
                self.state["postponedFor"] = busy[:5]
            if until > midnight:
                self.state["lastRunDay"] = datetime.now().date().isoformat()   # Skip today and retry tomorrow
            self.save()
            return None
        return self.clean("scheduled", self._pause_while_active)

    def start(self) -> None:
        def loop() -> None:
            if self.stop_event.wait(120.0):
                return
            while not self.stop_event.is_set():
                try:
                    self.tick()
                except Exception as error:  # noqa: BLE001 - Cleanup does not crash the engine
                    logging.warning("temp cleanup: %s", error)
                self.wake.wait(600.0)
                self.wake.clear()

        threading.Thread(target=loop, name="temp-cleanup", daemon=True).start()

    def view(self) -> dict[str, Any]:
        with self.lock:
            state = dict(self.state)
        state["hour"] = int(self.config.get("hour", RUN_HOUR))
        state["ageDays"] = int(self.config.get("ageDays", AGE_DAYS))
        state["keep"] = self.config["keep"]
        return state

    def shutdown(self) -> None:
        self.stop_event.set()
        self.wake.set()
