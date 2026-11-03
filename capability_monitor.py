"""Sensitive capability monitoring ("the capabilities"): who used the microphone, camera,
location and contacts, and when.

Three sources, each with its own stated limits:

1. Full Windows history (`CapabilityAccessManager.db`): start and end of every use, to the
   second, for all capabilities. Only the SYSTEM account can read it, so a scheduled task
   copies it every 5 minutes (`scripts/Enable-Capability-History.ps1`) into a folder the
   user can read. Windows keeps roughly seven days only, so the app keeps what it reads.
2. Live microphone sessions (`capability_audio.py`): the process ID, its path and its command
   line at the time of use; this identifies the Python script that opened the microphone.
3. Registry last-use record: was the only source, and Windows stopped updating it on
   2026-09-23. It is read for what precedes that date, and for the permission state of each
   program.

The saved log `data/pc/capability-events.ndjson` is appended to and never trimmed: use
chains (consecutive uses of the same program are merged into one line with their count and
duration, so nothing is hidden and the file does not grow without bound), and monitoring
gaps. The resume state is in `data/pc/capability-state.json`, and permission changes in
`data/pc/capability-permissions.json`.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import capability_judge
import hidden_window
import paths

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000

CONSENT_ROOT = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
HISTORY_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "PrivacyProtector" / "capability-history"
HISTORY_DB = "CapabilityAccessManager.db"
HISTORY_TASK = "PrivacyProtector-CapabilityHistory"

LIVE_POLL_SECONDS = 5.0
HISTORY_CHECK_SECONDS = 60.0
REGISTRY_POLL_SECONDS = 600.0
SAVE_SECONDS = 60.0
# Two uses of the same program less than half an hour apart belong to one chain.
MERGE_GAP_SECONDS = 1800.0
# The task copies every 5 minutes; a copy older than 20 minutes means copying has stopped.
HISTORY_STALE_SECONDS = 20 * 60
# Windows keeps about seven days; a longer gap may have lost events.
HISTORY_RETENTION_SECONDS = 6 * 86400
LINK_WINDOW_SECONDS = 2 * 3600
LINK_MARGIN_SECONDS = 5.0

CAPABILITY_LABELS = {
    "location": "Location",
    "webcam": "Camera",
    "microphone": "Microphone",
    "contacts": "Contacts",
    "appointments": "Calendar",
    "phoneCallHistory": "Call history",
    "email": "Email",
    "userDataTasks": "Tasks",
    "chat": "Messages",
    "radios": "Bluetooth and radios",
    "bluetoothSync": "Bluetooth sync",
    "documentsLibrary": "Documents",
    "picturesLibrary": "Pictures",
    "videosLibrary": "Videos",
    "broadFileSystemAccess": "Entire file system",
    "userAccountInformation": "Account information",
    "screenCapture": "Screen capture",
    "graphicsCaptureProgrammatic": "Programmatic screen capture",
    "graphicsCaptureWithoutBorder": "Screen capture without border",
    "passkeys": "Passkeys",
    "passkeysEnumeration": "Passkey enumeration",
    "activity": "Activity and movement",
    "humanPresence": "Presence detection",
}

SOURCES = {
    "windows-history": {"label": "Full Windows history", "precision": "seconds; start and end of every use"},
    "live-audio": {"label": "Live microphone sessions", "precision": "5 seconds; with process ID and command line"},
    "registry-last-use": {"label": "Last-use record (registry)", "precision": "last use only, per program"},
}
PERMISSION_STATES = {
    "recommended": "Recommended to block, not yet applied",
    "setting-changed": "Setting changed to block; effect not yet confirmed",
    "verified-blocked": "Block confirmed: Windows logged a blocked attempt",
    "not-effective": "Setting changed but Windows has not blocked any use since",
    "restored": "Setting restored to its original value",
}

# What is kept from the identity with each record: what proves which file it was, not its description.
RECORD_IDENTITY_FIELDS = frozenset({
    "path", "package", "name", "appName", "service", "scope", "script", "commandLine",
    "fileState", "version", "sha256", "signature", "signer", "identityObservedAt",
})

INTERPRETER_NAMES = re.compile(r"^(python|pythonw|py|node|bun|deno|pwsh|powershell|wscript|cscript|java|javaw)\.exe$", re.I)


# ---------------------------------------------------------------------------
# Time utilities
# ---------------------------------------------------------------------------

def filetime_to_epoch(value: int) -> float:
    return value / 10_000_000 - 11644473600 if value else 0.0


def iso(epoch: float) -> str:
    if not epoch:
        return ""
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).astimezone().isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return ""


def _now() -> float:
    return time.time()


def package_family_from_path(path: str) -> str:
    """C:\\Program Files\\WindowsApps\\Claude_2.3.1.0_x64__pzs8 ... → Claude_pzs8."""
    match = re.search(r"\\WindowsApps\\([^\\_]+)_[^\\]*__([a-z0-9]+)\\", path or "", re.I)
    return f"{match.group(1)}_{match.group(2)}" if match else ""


def identity_key(identity: dict[str, Any]) -> str:
    if identity.get("package"):
        return "pkg:" + str(identity["package"]).lower()
    if identity.get("path"):
        return "path:" + str(identity["path"]).lower()
    return "name:" + str(identity.get("name") or "").lower()


def display_name(identity: dict[str, Any]) -> str:
    if identity.get("package"):
        return str(identity["package"]).split("_")[0]
    return str(identity.get("name") or identity.get("appName") or "unknown")


# ---------------------------------------------------------------------------
# Registry: last use and permission state
# ---------------------------------------------------------------------------

def registry_rows() -> tuple[list[dict[str, Any]], dict[str, dict[str, str]]]:
    """(each program's permission rows, and the global setting per permission) from HKCU and HKLM."""
    if not IS_WINDOWS:
        return [], {}
    import winreg

    rows: list[dict[str, Any]] = []
    globals_: dict[str, dict[str, str]] = {}

    def value(key: Any, name: str) -> Any:
        try:
            return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return None

    def children(key: Any) -> list[str]:
        out = []
        index = 0
        while True:
            try:
                out.append(winreg.EnumKey(key, index))
            except OSError:
                return out
            index += 1

    for hive, hive_name in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
        try:
            store = winreg.OpenKey(hive, CONSENT_ROOT)
        except OSError:
            continue
        with store:
            for capability in children(store):
                if capability not in CAPABILITY_LABELS:
                    continue
                try:
                    cap_key = winreg.OpenKey(store, capability)
                except OSError:
                    continue
                with cap_key:
                    globals_.setdefault(capability, {})[hive_name] = str(value(cap_key, "Value") or "")
                    for child in children(cap_key):
                        try:
                            child_key = winreg.OpenKey(cap_key, child)
                        except OSError:
                            continue
                        with child_key:
                            if child == "NonPackaged":
                                globals_[capability][hive_name + "-desktop"] = str(value(child_key, "Value") or "")
                                for app_id in children(child_key):
                                    try:
                                        with winreg.OpenKey(child_key, app_id) as app_key:
                                            path = app_id.replace("#", "\\")
                                            rows.append({
                                                "hive": hive_name, "capability": capability, "appKey": app_id,
                                                "identity": {"path": path, "name": Path(path).name},
                                                "start": int(value(app_key, "LastUsedTimeStart") or 0),
                                                "stop": int(value(app_key, "LastUsedTimeStop") or 0),
                                                "permission": str(value(app_key, "Value") or ""),
                                            })
                                    except OSError:
                                        continue
                            else:
                                rows.append({
                                    "hive": hive_name, "capability": capability, "appKey": child,
                                    "identity": {"package": child, "name": child.split("_")[0]},
                                    "start": int(value(child_key, "LastUsedTimeStart") or 0),
                                    "stop": int(value(child_key, "LastUsedTimeStop") or 0),
                                    "permission": str(value(child_key, "Value") or ""),
                                })
    return rows, globals_
_SERVICES_CACHE: dict[str, Any] = {"at": 0.0, "rows": []}


def _service_images() -> list[tuple[str, str, int]]:
    """(Name, lowercase image path, start type) for each service, read from the registry without PowerShell, cached for five minutes."""
    if not IS_WINDOWS:
        return []
    now = time.monotonic()
    if now - float(_SERVICES_CACHE["at"]) < 300 and _SERVICES_CACHE["at"]:
        return _SERVICES_CACHE["rows"]
    import winreg

    rows: list[tuple[str, str, int]] = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services") as root:
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(root, name) as key:
                        image = str(winreg.QueryValueEx(key, "ImagePath")[0])
                        start = int(winreg.QueryValueEx(key, "Start")[0])
                except OSError:
                    continue
                match = re.match(r'\s*"([^"]+)"|\s*(\S+\.exe)', image, re.I)
                if match:
                    rows.append((name, (match.group(1) or match.group(2)).lower(), start))
    except OSError:
        return []
    _SERVICES_CACHE.update(at=now, rows=rows)
    return rows


def disabled_service_for(path: str) -> str:
    """Name of the disabled service this file runs under, if no service for it is left to start on its own.

    Windows does not stop a given desktop program from holding a permission, so disabling its service is the
    enforced block: Intel SUR kept reading location every half hour until its two services were disabled. A
    manual service that is stopped only starts on request, so it does not undo the disabling."""
    clean = path.strip().lower()
    if not clean:
        return ""
    own = [(name, start) for name, image, start in _service_images() if image == clean]
    if not own or any(start in (0, 1, 2) for _, start in own):
        return ""
    return next((name for name, start in own if start == 4), "")


def permission_key_for(capability: str, identity: dict[str, Any]) -> str:
    """Permission key in HKCU for this program and capability."""
    if identity.get("package"):
        return f"{CONSENT_ROOT}\\{capability}\\{identity['package']}"
    if identity.get("path"):
        return f"{CONSENT_ROOT}\\{capability}\\NonPackaged\\{str(identity['path']).replace(chr(92), '#')}"
    return ""


# ---------------------------------------------------------------------------
# Full Windows history log
# ---------------------------------------------------------------------------

def read_history(snapshot_dir: Path, work_dir: Path, cursors: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """New usage rows since the cursor, read from a private copy of the database (the shared copy is not touched)."""
    work_dir.mkdir(parents=True, exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        source = snapshot_dir / (HISTORY_DB + suffix)
        target = work_dir / (HISTORY_DB + suffix)
        if source.exists():
            shutil.copyfile(source, target)
        elif target.exists():
            target.unlink()
    rows: list[dict[str, Any]] = []
    new_cursors = dict(cursors)
    connection = sqlite3.connect(str(work_dir / HISTORY_DB), timeout=5)
    try:
        def lookup(table: str) -> dict[int, str]:
            try:
                return dict(connection.execute(f"SELECT ID, StringValue FROM {table}").fetchall())
            except sqlite3.Error:
                return {}

        capabilities = lookup("Capabilities")
        paths = lookup("BinaryFullPaths")
        packages = lookup("PackageFamilyNames")
        apps = lookup("AppNames")
        services = lookup("ServiceNames")
        specs = (
            ("NonPackagedUsageHistory", "BinaryFullPath, ServiceName"),
            ("PackagedUsageHistory", "PackageFamilyName, 0"),
        )
        for table, extra in specs:
            cursor = cursors.get(table) or {}
            last_id = int(cursor.get("id") or 0)
            last_start = int(cursor.get("start") or 0)
            try:
                top = connection.execute(f"SELECT MAX(ID) FROM {table}").fetchone()[0] or 0
            except sqlite3.Error:
                continue
            if top < last_id:
                # The database was recreated: IDs started over, so the reference is the last time of use read.
                last_id = 0
            query = (
                f"SELECT ID, LastUsedTimeStart, LastUsedTimeStop, AccessBlocked, Capability, AppName, {extra} "
                f"FROM {table} WHERE ID > ? AND LastUsedTimeStart >= ? ORDER BY LastUsedTimeStart"
            )
            max_id, max_start = last_id, last_start
            fetched = list(connection.execute(query, (last_id, last_start if last_id == 0 and last_start else 0)))
            # A use that was still running at the previous read: Windows writes its end into the same row later.
            still_open: list[int] = []
            previous_open = [int(i) for i in cursor.get("open") or [] if int(i) <= last_id]
            if previous_open:
                marks = ",".join("?" * len(previous_open))
                for item in connection.execute(
                        f"SELECT ID, LastUsedTimeStart, LastUsedTimeStop, AccessBlocked, Capability, AppName, {extra} "
                        f"FROM {table} WHERE ID IN ({marks})", previous_open):
                    if item[2]:
                        fetched.append(item + ("update",))
                    else:
                        still_open.append(int(item[0]))
            for fetched_row in fetched:
                row_id, start, stop, blocked, cap_id, app_id, ident_id, service_id = fetched_row[:8]
                update = len(fetched_row) > 8
                if not stop and not update:
                    still_open.append(int(row_id))
                capability = capabilities.get(cap_id, str(cap_id))
                if table.startswith("NonPackaged"):
                    path = paths.get(ident_id, "")
                    identity = {"path": path, "name": Path(path).name if path else "", "appName": apps.get(app_id, "")}
                    if service_id:
                        identity["service"] = services.get(service_id, "")
                else:
                    package = packages.get(ident_id, "")
                    identity = {"package": package, "name": package.split("_")[0], "appName": apps.get(app_id, "")}
                rows.append({
                    "capability": capability, "identity": identity, "start": int(start), "stop": int(stop),
                    "blocked": bool(blocked), "rowId": int(row_id), "table": table, "update": update,
                })
                max_id = max(max_id, int(row_id))
                max_start = max(max_start, int(start))
            new_cursors[table] = {"id": max_id, "start": max_start, "open": sorted(set(still_open))[-200:]}
    finally:
        connection.close()
    return rows, new_cursors


# ---------------------------------------------------------------------------
# File and package identity
# ---------------------------------------------------------------------------
_UTF8_PREFIX = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $OutputEncoding=[System.Text.Encoding]::UTF8; "

_IDENTITY_SCRIPT = _UTF8_PREFIX + r"""
$in = $env:PP_IDENTITY_INPUT | ConvertFrom-Json
$files = foreach ($p in @($in.paths)) {
  if (Test-Path -LiteralPath $p -PathType Leaf) {
    $s = Get-AuthenticodeSignature -LiteralPath $p
    $v = (Get-Item -LiteralPath $p).VersionInfo
    $signer = ''
    if ($s.SignerCertificate) { $signer = $s.SignerCertificate.GetNameInfo('SimpleName', $false) }
    [pscustomobject]@{ path = $p; exists = $true; status = [string]$s.Status; signer = $signer;
      company = $v.CompanyName; product = $v.ProductName; fileVersion = $v.FileVersion }
  } else { [pscustomobject]@{ path = $p; exists = $false } }
}
$packages = @()
if (@($in.packages).Count -gt 0) {
  $all = Get-AppxPackage
  $packages = foreach ($f in @($in.packages)) {
    $a = $all | Where-Object { $_.PackageFamilyName -eq $f } | Select-Object -First 1
    if ($a) { [pscustomobject]@{ package = $f; exists = $true; version = [string]$a.Version; publisher = $a.Publisher;
      signatureKind = [string]$a.SignatureKind } }
    else { [pscustomobject]@{ package = $f; exists = $false } }
  }
}
@{ files = @($files); packages = @($packages) } | ConvertTo-Json -Depth 4 -Compress
"""

_CMDLINE_SCRIPT = _UTF8_PREFIX + r"""
$p = Get-CimInstance Win32_Process -Filter "ProcessId = $env:PP_PID"
if ($p) { @{ commandLine = $p.CommandLine; parent = $p.ParentProcessId } | ConvertTo-Json -Compress }
"""


def _powershell(script: str, env: dict[str, str], timeout: float = 120.0) -> str:
    environment = {**os.environ, **env}
    # The inherited PowerShell 7 module path makes Windows PowerShell load the wrong security module,
    # so Get-AuthenticodeSignature silently returns nothing; PSModulePath is pinned to the Windows PowerShell paths.
    windir = os.environ.get("SystemRoot", r"C:\Windows")
    environment["PSModulePath"] = ";".join((
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "WindowsPowerShell", "Modules"),
        os.path.join(windir, "system32", "WindowsPowerShell", "v1.0", "Modules"),
    ))
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, timeout=timeout, env=environment, creationflags=CREATE_NO_WINDOW, startupinfo=hidden_window.startupinfo(),
    )
    return result.stdout.decode("utf-8", "replace").strip()


def resolve_identities(paths: list[str], packages: list[str]) -> dict[str, dict[str, Any]]:
    """Signature and version for each file, version and publisher for each package; keyed by identity_key."""
    if not IS_WINDOWS or not (paths or packages):
        return {}
    output = _powershell(_IDENTITY_SCRIPT, {"PP_IDENTITY_INPUT": json.dumps({"paths": paths, "packages": packages})})
    payload = json.loads(output) if output else {}
    found: dict[str, dict[str, Any]] = {}
    for item in payload.get("files") or []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "")
        info: dict[str, Any] = {"exists": bool(item.get("exists"))}
        if info["exists"]:
            status = str(item.get("status") or "")
            info.update(
                signature={"Valid": "valid", "NotSigned": "unsigned", "HashMismatch": "invalid",
                           "NotTrusted": "invalid", "Incompatible": "invalid"}.get(status, "unknown"),
                signatureStatus=status, signer=item.get("signer") or "", company=item.get("company") or "",
                product=item.get("product") or "", version=item.get("fileVersion") or "",
            )
            try:
                stat = os.stat(path)
                info.update(size=stat.st_size, mtime=stat.st_mtime, sha256=_sha256(path))
            except OSError:
                pass
        found["path:" + path.lower()] = info
    for item in payload.get("packages") or []:
        if not isinstance(item, dict):
            continue
        info = {"exists": bool(item.get("exists"))}
        if info["exists"]:
            info.update(version=item.get("version") or "", signer=item.get("publisher") or "",
                        signature="valid", signatureStatus=item.get("signatureKind") or "")
        found["pkg:" + str(item.get("package") or "").lower()] = info
    return found


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()
def process_details(pid: int) -> dict[str, Any]:
    """Process path and start time; command line for executables only (to identify the script)."""
    details: dict[str, Any] = {"pid": pid}
    if not IS_WINDOWS:
        return details
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(0x1000, False, int(pid))
    if not handle:
        return details
    try:
        size = ctypes.c_ulong(1024)
        buffer = ctypes.create_unicode_buffer(1024)
        if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            details["path"] = buffer.value
            details["name"] = Path(buffer.value).name
        created, exited, kernel, user = (ctypes.c_ulonglong() for _ in range(4))
        if kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)):
            details["processStart"] = filetime_to_epoch(created.value)
    finally:
        kernel32.CloseHandle(handle)
    if INTERPRETER_NAMES.search(details.get("name", "")):
        try:
            output = _powershell(_CMDLINE_SCRIPT, {"PP_PID": str(int(pid))}, timeout=30)
            info = json.loads(output) if output else {}
            details["commandLine"] = str(info.get("commandLine") or "")[:2000]
            details["script"] = script_from_command(details["commandLine"])
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
    family = package_family_from_path(details.get("path", ""))
    if family:
        details["package"] = family
    return details


def process_is_alive(pid: int, started: float) -> bool:
    """Is the process itself still running? Its PID and start time together, so it is not fooled by PID reuse."""
    if not IS_WINDOWS or not pid:
        return False
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(0x1000, False, int(pid))
    if not handle:
        return False
    try:
        exit_code = ctypes.c_ulong()
        if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)) and exit_code.value != 259:  # 259 = STILL_ACTIVE
            return False
        created, exited, kernel, user = (ctypes.c_ulonglong() for _ in range(4))
        if not kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)):
            return False
        return not started or abs(filetime_to_epoch(created.value) - started) < 1.0
    finally:
        kernel32.CloseHandle(handle)


def script_from_command(command: str) -> str:
    """First argument resembling a script file in the command line."""
    for match in re.finditer(r'"([^"]+)"|(\S+)', command or ""):
        token = match.group(1) or match.group(2) or ""
        if re.search(r"\.(py|pyw|js|mjs|cjs|ts|ps1|vbs|jar)$", token, re.I):
            return token
    module = re.search(r"\s-m\s+(\S+)", command or "")
    return ("-m " + module.group(1)) if module else ""


# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------

class CapabilityMonitor:
    def __init__(
        self,
        directory: Path,
        history_dir: Path = HISTORY_DIR,
        work_dir: Path | None = None,
        audio_reader_factory: Callable[[], Any] | None = None,
        registry_reader: Callable[[], tuple[list[dict[str, Any]], dict[str, dict[str, str]]]] = registry_rows,
        identity_resolver: Callable[[list[str], list[str]], dict[str, dict[str, Any]]] = resolve_identities,
        process_resolver: Callable[[int], dict[str, Any]] = process_details,
        process_alive: Callable[[int, float], bool] | None = None,
        clock: Callable[[], float] = _now,
    ):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.events_path = self.directory / "capability-events.ndjson"
        self.state_path = self.directory / "capability-state.json"
        self.permissions_path = self.directory / "capability-permissions.json"
        self.history_dir = Path(history_dir)
        self.work_dir = Path(work_dir) if work_dir else paths.RUNTIME_ROOT / "capability-work"
        self.audio_reader_factory = audio_reader_factory
        self.registry_reader = registry_reader
        self.identity_resolver = identity_resolver
        self.process_resolver = process_resolver
        self.process_alive = process_alive or process_is_alive
        self.clock = clock
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []
        self.dirty = False
        self.closed: list[dict[str, Any]] = []
        self.state: dict[str, Any] = {}
        self.permissions: dict[str, Any] = {"changes": [], "current": {}}
        self.registry_globals: dict[str, dict[str, str]] = {}
        self.registry_permissions: dict[str, str] = {}
        self.identities: dict[str, dict[str, Any]] = {}
        # Inventory of installed programs (program_inventory): permissions are not displayed for items removed from the device.
        self.program_filter: Callable[[str, str, float], bool] | None = None
        # The kinds you chose to watch in Settings (microphone, webcam, location, contacts); None watches all.
        self.kind_filter: Callable[[str], bool] | None = None
        self.pending_identities: set[str] = set()
        self.live: dict[str, dict[str, Any]] = {}
        self.attribution: deque[tuple[float, int, str, str]] = deque(maxlen=50000)
        self.status: dict[str, Any] = {
            "live-audio": {"state": "stopped", "lastPollAt": 0.0, "error": "", "sessions": 0},
            "windows-history": {"state": "not-installed", "lastCopyAt": 0.0, "lastIngestAt": 0.0, "error": ""},
            "registry-last-use": {"state": "unknown", "lastRecordAt": 0.0, "error": ""},
        }
        self._load()

    # -- Storage -----------------------------------------------------------
    def _load(self) -> None:
        try:
            self.state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.state = {}
        self.state.setdefault("version", 1)
        self.state.setdefault("open", {})
        self.state.setdefault("cursors", {})
        self.state.setdefault("registrySeen", {})
        self.state.setdefault("identities", {})
        self.identities = dict(self.state.get("identities") or {})
        try:
            self.permissions = json.loads(self.permissions_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.permissions = {"changes": [], "current": {}}
        self.permissions.setdefault("changes", [])
        self.permissions.setdefault("current", {})
        self.closed = []
        try:
            with self.events_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self.closed.append(json.loads(line))
                    except ValueError:
                        continue  # Truncated line from an interrupted write; preceding and following parts are intact
        except OSError:
            pass

    def watched(self, capability: str) -> bool:
        return self.kind_filter is None or bool(self.kind_filter(str(capability)))

    def _append(self, record: dict[str, Any]) -> None:
        if record.get("capability") and not self.watched(record["capability"]):
            return
        with self.events_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.closed.append(record)

    def save(self) -> None:
        with self.lock:
            if not self.dirty:
                return
            self.state["identities"] = self.identities
            self.state["savedAt"] = iso(self.clock())
            text = json.dumps(self.state, ensure_ascii=False, indent=1)
            self.dirty = False
        temp = self.state_path.with_suffix(".tmp")
        temp.write_text(text + "\n", encoding="utf-8")
        os.replace(temp, self.state_path)

    def _save_permissions(self) -> None:
        temp = self.permissions_path.with_suffix(".tmp")
        temp.write_text(json.dumps(self.permissions, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        os.replace(temp, self.permissions_path)

    # -- Series -----------------------------------------------------------
    def add_use(self, source: str, capability: str, identity: dict[str, Any], start: float, stop: float,
                blocked: bool = False, extra: dict[str, Any] | None = None, update: bool = False) -> None:
        """Single usage (in seconds since 1970). stop=0 means it is ongoing, and update marks the end of a previously counted usage."""
        key = f"{source}|{capability}|{identity_key(identity)}"
        duration = max(0.0, stop - start) if stop else 0.0
        with self.lock:
            series = self.state["open"].get(key)
            if update and series:
                series["lastStop"] = max(series["lastStop"], stop)
                series["inUse"] = False
                series["activeSeconds"] = round(series["activeSeconds"] + duration, 2)
                series["longest"] = max(series.get("longest", 0.0), duration)
                self.dirty = True
                return
            end = max(series["lastStop"], series["lastStart"]) if series else 0.0
            if series and start - end <= MERGE_GAP_SECONDS:
                series["count"] += 1
                series["lastStart"] = max(series["lastStart"], start)
                series["lastStop"] = max(series["lastStop"], stop) if stop else series["lastStop"]
                series["inUse"] = not stop
                series["activeSeconds"] = round(series["activeSeconds"] + duration, 2)
                series["longest"] = max(series.get("longest", 0.0), duration)
                series["blocked"] += int(blocked)
                if extra:
                    series.setdefault("extra", {}).update(extra)
            else:
                if series:
                    self._close(key)
                self.state["open"][key] = {
                    "type": "series", "key": key, "source": source, "capability": capability,
                    "identity": dict(identity), "firstStart": start, "lastStart": start, "lastStop": stop,
                    "inUse": not stop, "count": 1, "activeSeconds": round(duration, 2), "longest": duration,
                    "blocked": int(blocked), "detectedAt": self.clock(), "extra": dict(extra or {}),
                }
                self._want_identity(identity)
            self.dirty = True

    def _close(self, key: str) -> None:
        series = self.state["open"].pop(key, None)
        if not series:
            return
        series["closedAt"] = self.clock()
        identity = self._identity_at(series["identity"], series["firstStart"])
        series["identity"] = {k: v for k, v in identity.items() if k in RECORD_IDENTITY_FIELDS and v not in ("", None)}
        if "commandLine" in series["identity"]:
            series["identity"]["commandLine"] = str(series["identity"]["commandLine"])[:300]
        for field in ("firstStart", "lastStart", "lastStop", "detectedAt", "closedAt", "longest", "activeSeconds"):
            series[field] = round(float(series.get(field) or 0.0), 1)
        link = self.network_link(series)
        if link.get("state") in ("linked", "not-attributable"):
            series["link"] = link
        if not series.get("extra"):
            series.pop("extra", None)
        self._append(series)
        self.dirty = True

    def sweep(self, now: float | None = None) -> None:
        """Closes series whose last usage was long enough ago, based on the recency of their source."""
        now = now if now is not None else self.clock()
        history_seen = float(self.status["windows-history"].get("lastCopyAt") or 0.0)
        with self.lock:
            for key, series in list(self.state["open"].items()):
                if series.get("inUse"):
                    continue
                if identity_key(series["identity"]) in self.pending_identities:
                    continue  # Closed after identifying its file, so the identity is saved with it
                last = max(series["lastStop"], series["lastStart"])
                if series["source"] == "windows-history":
                    # Do not close before a later version confirms that no subsequent usage is attached to it.
                    if history_seen - last > MERGE_GAP_SECONDS:
                        self._close(key)
                elif series["source"] == "registry-last-use":
                    self._close(key)
                elif series["source"] == "live-audio" and key not in self.live:
                    self._close(key)

    def gap(self, source: str, start: float, end: float, reason: str) -> None:
        with self.lock:
            self._append({"type": "gap", "source": source, "from": start, "to": end, "reason": reason, "detectedAt": self.clock()})

    # -- Identity ------------------------------------------------------------
    def _want_identity(self, identity: dict[str, Any]) -> None:
        key = identity_key(identity)
        if key.startswith(("path:", "pkg:")) and key not in self.identities:
            self.pending_identities.add(key)

    def resolve_pending(self) -> None:
        with self.lock:
            pending = sorted(self.pending_identities)[:40]
        if not pending:
            return
        paths = [key[5:] for key in pending if key.startswith("path:")]
        packages = [key[4:] for key in pending if key.startswith("pkg:")]
        try:
            found = self.identity_resolver(paths, packages)
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            self.status["windows-history"]["identityError"] = str(error)[:200]
            return
        now = self.clock()
        with self.lock:
            for key in pending:
                info = found.get(key)
                self.pending_identities.discard(key)
                if info is None:
                    continue
                previous = self.identities.get(key)
                info["observedAt"] = now
                if previous and previous.get("sha256") and info.get("sha256") and previous["sha256"] != info["sha256"]:
                    info["previousSha256"] = previous["sha256"]
                    info["changedAt"] = now
                elif previous and previous.get("version") and info.get("version") and previous["version"] != info["version"]:
                    info["previousVersion"] = previous["version"]
                    info["changedAt"] = now
                self.identities[key] = info
            self.dirty = True

    def refresh_identity(self, key: str) -> None:
        """Re-examine a known file (e.g., after a program update)."""
        with self.lock:
            self.pending_identities.add(key)

    def _identity_at(self, identity: dict[str, Any], start: float) -> dict[str, Any]:
        """Identity as known at the time of the event, not today's file identity without evidence."""
        out = dict(identity)
        info = self.identities.get(identity_key(identity))
        if not info:
            out["fileState"] = out.get("fileState") or "unknown"
            return out
        for field in ("signature", "signer", "company", "product", "version", "sha256"):
            if info.get(field):
                out[field] = info[field]
        if not info.get("exists"):
            out["fileState"] = "missing"
            for field in ("signature", "signer", "company", "product", "version", "sha256"):
                out.pop(field, None)
        elif info.get("mtime") and info["mtime"] > start:
            # File was written after the event: its current identity does not pertain to it.
            out["fileState"] = "changed-after"
        elif identity.get("package"):
            out["fileState"] = "present"
        else:
            out["fileState"] = "unchanged-since"
        out["identityObservedAt"] = info.get("observedAt", 0.0)
        return out

    # -- Source 1: Full Windows Event Log ---------------------------------------
    def history_snapshot_time(self) -> float:
        try:
            return (self.history_dir / HISTORY_DB).stat().st_mtime
        except OSError:
            return 0.0

    def poll_history(self) -> int:
        status = self.status["windows-history"]
        copied = self.history_snapshot_time()
        if not copied:
            status["state"] = "not-installed"
            return 0
        status["lastCopyAt"] = copied
        now = self.clock()
        status["state"] = "live" if now - copied <= HISTORY_STALE_SECONDS else "stale"
        if copied <= float(self.state.get("historyCopyIngested") or 0.0):
            return 0
        try:
            rows, cursors = read_history(self.history_dir, self.work_dir, self.state["cursors"])
        except (OSError, sqlite3.Error) as error:
            status["error"] = str(error)[:200]
            status["state"] = "error"
            return 0
        previous_ingest = float(self.state.get("historyIngestedAt") or 0.0)
        if previous_ingest and rows and now - previous_ingest > HISTORY_RETENTION_SECONDS:
            self.gap("windows-history", previous_ingest, now,
                     "Windows Event Log reading interrupted for more than six days; what Windows deleted during this period cannot be recovered")
        for row in rows:
            self.add_use("windows-history", row["capability"], row["identity"],
                         filetime_to_epoch(row["start"]), filetime_to_epoch(row["stop"]), blocked=row["blocked"],
                         update=bool(row.get("update")))
        with self.lock:
            if rows and not self.state.get("historyCoverageFrom"):
                self.state["historyCoverageFrom"] = min(filetime_to_epoch(row["start"]) for row in rows)
            self.state["cursors"] = cursors
            self.state["historyCopyIngested"] = copied
            self.state["historyIngestedAt"] = now
            self.dirty = True
        status["lastIngestAt"] = now
        status["error"] = ""
        self.sweep(now)
        return len(rows)

    # -- Source 2: Microphone sessions -----------------------------------------
    def poll_live(self, sessions: list[dict[str, Any]]) -> None:
        now = self.clock()
        seen: set[str] = set()
        for session in sessions:
            pid = int(session.get("pid") or 0)
            if not pid or pid == os.getpid():
                continue
            existing = next((k for k, v in self.live.items() if v["pid"] == pid), None)
            if existing is None:
                details = self.process_resolver(pid)
                identity = {key: details[key] for key in ("path", "name", "package", "script", "commandLine") if details.get(key)}
                if not identity.get("name"):
                    continue
                key = f"live-audio|microphone|{identity_key(identity)}|{pid}|{int(details.get('processStart') or 0)}"
                self.live[key] = {"pid": pid, "identity": identity, "processStart": details.get("processStart", 0.0),
                                  "activeSince": 0.0, "firstSeen": now}
                existing = key
                with self.lock:
                    self.state["open"][key] = {
                        "type": "series", "key": key, "source": "live-audio", "capability": "microphone",
                        "identity": identity, "firstStart": now, "lastStart": now, "lastStop": 0.0, "inUse": False,
                        "count": 0, "activeSeconds": 0.0, "longest": 0.0, "blocked": 0, "detectedAt": now,
                        "extra": {"pid": pid, "processStart": details.get("processStart", 0.0),
                                  "note": "Microphone opened before appearing here; first appearance is not necessarily the start of usage"},
                    }
                    self.dirty = True
                self._want_identity(identity)
            seen.add(existing)
            live = self.live[existing]
            active = int(session.get("state", 0)) == 1
            with self.lock:
                series = self.state["open"].get(existing)
                if series is None:
                    continue
                if active and not live["activeSince"]:
                    live["activeSince"] = now
                    series["count"] += 1
                    series["lastStart"] = now
                    series["inUse"] = True
                    self.dirty = True
                elif not active and live["activeSince"]:
                    span = now - live["activeSince"]
                    series["activeSeconds"] = round(series["activeSeconds"] + span, 2)
                    series["longest"] = max(series["longest"], span)
                    series["lastStop"] = now
                    series["inUse"] = False
                    live["activeSince"] = 0.0
                    self.dirty = True
        for key in list(self.live):
            live = self.live[key]
            if key in seen:
                live["absentSince"] = 0.0
                continue
            with self.lock:
                series = self.state["open"].get(key)
                if series and live["activeSince"]:
                    span = now - live["activeSince"]
                    series["activeSeconds"] = round(series["activeSeconds"] + span, 2)
                    series["longest"] = max(series["longest"], span)
                    series["lastStop"] = now
                    series["inUse"] = False
                    live["activeSince"] = 0.0
                    self.dirty = True
            # The program releases the audio session and reopens it; its series remains as long as the process persists.
            live["absentSince"] = live.get("absentSince") or now
            if self.process_alive(live["pid"], live.get("processStart") or 0.0) and now - live["absentSince"] < MERGE_GAP_SECONDS:
                continue
            self.live.pop(key)
            with self.lock:
                self._close(key)
        status = self.status["live-audio"]
        status.update(state="live", lastPollAt=now, sessions=len(self.live), error="")
        with self.lock:
            last_alive = float(self.state.get("liveAliveAt") or 0.0)
            if not self.state.get("liveAliveAt") or now - last_alive >= 60:
                self.state["liveAliveAt"] = now
                self.dirty = True

    def start_live_gap(self) -> None:
        """Period of live monitor inactivity since its last action; closes sessions that were not closed."""
        now = self.clock()
        with self.lock:
            last_alive = float(self.state.get("liveAliveAt") or 0.0)
            for key in [k for k, v in self.state["open"].items() if v["source"] == "live-audio"]:
                series = self.state["open"][key]
                series.setdefault("extra", {})["endedBy"] = "Monitor stopped before session ended; end is unknown"
                series["inUse"] = False
                self._close(key)
        if last_alive and now - last_alive > 120:
            self.gap("live-audio", last_alive, now, "Application was paused; microphone usage during this period is tracked only by the Windows Event Log if enabled")

    # -- Source 3: Registry ------------------------------------------------
    def poll_registry(self) -> int:
        status = self.status["registry-last-use"]
        try:
            rows, globals_ = self.registry_reader()
        except OSError as error:
            status.update(state="error", error=str(error)[:200])
            return 0
        added = 0
        latest = 0.0
        permissions: dict[str, str] = {}
        first_run = not self.state.get("baselineImported")
        for row in rows:
            permissions[f"{row['hive']}|{row['capability']}|{identity_key(row['identity'])}"] = row.get("permission", "")
            start = filetime_to_epoch(row["start"])
            if not start:
                continue
            latest = max(latest, start)
            seen_key = f"{row['hive']}|{row['capability']}|{row['appKey']}"
            if self.state["registrySeen"].get(seen_key) == row["start"]:
                continue
            identity = dict(row["identity"])
            if row["hive"] == "HKLM":
                identity["scope"] = "system"
            self.add_use("registry-last-use", row["capability"], identity, start, filetime_to_epoch(row["stop"]),
                         extra={"hive": row["hive"], "baseline": first_run})
            with self.lock:
                self.state["registrySeen"][seen_key] = row["start"]
            added += 1
        with self.lock:
            self.registry_globals = globals_
            self.registry_permissions = permissions
            self.state["baselineImported"] = True
            self.state["registryLatest"] = latest
            self.dirty = True
        status.update(lastRecordAt=latest, error="")
        self.sweep()
        return added

    # -- Network Attribution ---------------------------------------------------------
    def observe_attribution(self, pid: int, identity: dict[str, Any], domain: str) -> None:
        """Called from domain attribution in the Computer section; saves only what is necessary for attribution."""
        path = str(identity.get("path") or "").lower()
        if path and domain:
            self.attribution.append((self.clock(), int(pid), path, domain))

    def network_link(self, series: dict[str, Any]) -> dict[str, Any]:
        identity = series.get("identity") or {}
        name = str(identity.get("name") or "")
        if capability_judge.SHARED_HOSTS.search(name):
            return {"state": "not-attributable", "text": "Shared host: its connections are not attributed to the permission requester"}
        start = float(series.get("firstStart") or 0.0) - LINK_MARGIN_SECONDS
        stop = float(series.get("lastStop") or series.get("lastStart") or 0.0) + LINK_MARGIN_SECONDS
        if not start or self.clock() - start > LINK_WINDOW_SECONDS + 3600:
            return {"state": "unavailable", "text": "Attribution was not available for this period"}
        pid = int((series.get("extra") or {}).get("pid") or 0)
        path = str(identity.get("path") or "").lower()
        family = str(identity.get("package") or "").lower()
        counts: dict[str, int] = {}
        strength = "pid" if pid else "path-time"
        for moment, event_pid, event_path, domain in list(self.attribution):
            if moment < start or moment > stop:
                continue
            if pid:
                if event_pid != pid:
                    continue
            elif path:
                if event_path != path:
                    continue
            elif family:
                if package_family_from_path(event_path).lower() != family:
                    continue
            else:
                continue
            counts[domain] = counts.get(domain, 0) + 1
        domains = [{"domain": d, "count": c} for d, c in sorted(counts.items(), key=lambda kv: -kv[1])[:12]]
        return {
            "state": "linked" if domains else "none",
            "strength": strength,
            "domains": domains,
            "text": ("Domains called by the app itself " + ("(by process ID)" if pid else "(by path)") +
                     " during usage; concurrency does not prove that audio or location was sent to them") if domains
            else "No connection by the app itself was detected during usage",
        }

    # -- Permission: Read, Modify, and Revert -------------------------------------
    def permission_state(self, capability: str, identity: dict[str, Any]) -> dict[str, Any]:
        key = identity_key(identity)
        system = identity.get("scope") == "system"
        hive = "HKLM" if system else "HKCU"
        value = self.registry_permissions.get(f"{hive}|{capability}|{key}", "")
        globals_ = self.registry_globals.get(capability, {})
        change = self.permissions["current"].get(f"{capability}|{key}") or {}
        writable = IS_WINDOWS and not system and bool(permission_key_for(capability, identity))
        note = "" if writable else "Device-level setting; the app does not change it"
        desktop = (self.permissions.get("platform") or {}).get("desktopPerAppDeny") or {}
        if writable and not identity.get("package") and desktop.get("result") == "not-effective":
            # Do not show a non-functional button: tests confirmed that Windows here does not block a specific desktop app.
            writable = False
            note = ("Windows on this device does not block a specific desktop app (confirmed by test on "
                    f"{iso(float(desktop.get('at') or 0))[:10]}). Available options: disable 'Allow desktop apps' "
                    "in Privacy settings, which blocks all of them, configure the app itself, or uninstall it")
        disabled = disabled_service_for(str(identity.get("path") or ""))
        if disabled:
            note = f"Block effective: its service {disabled} is disabled so it does not run, and if restarted, the monitor detects it"
        # The deleted file does not use permission: blocking is effective upon its removal, and if it returns with the same path, a new event is recorded
        # (2026-10-30: Plex, ChatGPT-RTL build, and old EA build remained yellow and their files were missing).
        file_path = str(identity.get("path") or "")
        removed = IS_WINDOWS and bool(file_path) and not os.path.exists(file_path)
        if removed:
            note = "Block effective: the file is no longer on the device" + (". And before deletion: " + note if note else "")
        return {
            "value": value or "",
            "disabledService": disabled,
            "removed": removed,
            "global": globals_.get("HKCU", ""),
            "desktopGlobal": globals_.get("HKCU-desktop", ""),
            "machineGlobal": globals_.get("HKLM", ""),
            "writable": writable,
            "restorable": bool(change) and change.get("state") != "restored" and not system,
            "note": note,
            "change": change,
            "changeLabel": PERMISSION_STATES.get(change.get("state", ""), ""),
        }

    def set_permission(self, capability: str, identity: dict[str, Any], action: str) -> dict[str, Any]:
        """Called only by the user's button: deny writes Deny and saves the previous state, and restore reverts it."""
        if not IS_WINDOWS:
            raise ValueError("Available on Windows only")
        import winreg

        if action not in ("deny", "restore"):
            raise ValueError("Unknown action")
        if identity.get("scope") == "system":
            raise ValueError("Device-level setting; the app does not change it")
        path = permission_key_for(capability, identity)
        if not path:
            raise ValueError("No permission key for this identity")
        record_key = f"{capability}|{identity_key(identity)}"
        now = self.clock()
        with self.lock:
            current = self.permissions["current"].get(record_key) or {}
            if action == "deny":
                existed = True
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ) as key:
                        try:
                            before = str(winreg.QueryValueEx(key, "Value")[0])
                        except OSError:
                            before = ""
                except OSError:
                    existed, before = False, ""
                with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "Value", 0, winreg.REG_SZ, "Deny")
                after = self._read_permission(path)
                current = {
                    "state": "setting-changed" if after == "Deny" else "recommended",
                    "requestedAt": now, "changedAt": now if after == "Deny" else 0.0,
                    "before": before, "keyExisted": existed, "after": after, "registryPath": "HKCU\\" + path,
                    "identity": identity,
                }
            else:
                if not current or current.get("state") == "restored":
                    raise ValueError("No previous change to revert")
                if current.get("keyExisted") is False:
                    try:
                        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
                    except OSError:
                        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
                            winreg.DeleteValue(key, "Value")
                elif current.get("before"):
                    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.SetValueEx(key, "Value", 0, winreg.REG_SZ, current["before"])
                else:
                    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
                        try:
                            winreg.DeleteValue(key, "Value")
                        except OSError:
                            pass
                current = {**current, "state": "restored", "restoredAt": now, "after": self._read_permission(path)}
            self.permissions["current"][record_key] = current
            self.permissions["changes"].append({"at": now, "capability": capability, "identityKey": identity_key(identity),
                                                "action": action, "result": current["state"], "after": current.get("after", "")})
            self._save_permissions()
        self.poll_registry()
        return current

    @staticmethod
    def _read_permission(path: str) -> str:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                return str(winreg.QueryValueEx(key, "Value")[0])
        except OSError:
            return ""

    def verify_permissions(self) -> None:
        """Did Windows actually block? Based on log events after the change: blocked or effective."""
        changed = False
        with self.lock:
            series_all = list(self.closed) + list(self.state["open"].values())
            for record_key, current in self.permissions["current"].items():
                capability, _, ident = record_key.partition("|")
                if (current.get("state") == "not-effective" or current.get("evidence", {}).get("allowed")) and ident.startswith("path:") \
                        and not (self.permissions.get("platform") or {}).get("desktopPerAppDeny"):
                    # A result preceding this save (or remaining after revert) remains evidence for the same version.
                    self.permissions.setdefault("platform", {})["desktopPerAppDeny"] = {
                        "result": "not-effective", "provenBy": record_key, "at": float(current.get("verifiedAt") or self.clock()),
                    }
                    changed = True
                if current.get("state") not in ("setting-changed", "not-effective", "verified-blocked"):
                    continue
                since = float(current.get("changedAt") or 0.0)
                blocked = allowed = 0
                for series in series_all:
                    if series.get("type") != "series" or series.get("capability") != capability:
                        continue
                    if identity_key(series.get("identity") or {}) != ident or series.get("source") != "windows-history":
                        continue
                    if float(series.get("lastStart") or 0.0) <= since:
                        continue
                    blocked += int(series.get("blocked") or 0)
                    allowed += max(0, int(series.get("count") or 0) - int(series.get("blocked") or 0))
                state = "verified-blocked" if blocked and not allowed else ("not-effective" if allowed else current["state"])
                if state != current.get("state"):
                    current.update(state=state, verifiedAt=self.clock(), evidence={"blocked": blocked, "allowed": allowed})
                    changed = True
                    if ident.startswith("path:"):
                        # What is established for a desktop program is established to prevent them all on this version of Windows.
                        self.permissions.setdefault("platform", {})["desktopPerAppDeny"] = {
                            "result": state, "provenBy": record_key, "at": self.clock(),
                        }
            if changed:
                self._save_permissions()

    # -- Status and display -----------------------------------------------------
    def source_status(self) -> dict[str, Any]:
        now = self.clock()
        history = dict(self.status["windows-history"])
        live = dict(self.status["live-audio"])
        registry = dict(self.status["registry-last-use"])
        if live["state"] == "live" and now - float(live.get("lastPollAt") or 0) > 60:
            live["state"] = "stopped"
        registry_latest = float(self.state.get("registryLatest") or registry.get("lastRecordAt") or 0.0)
        history_latest = max((float(s.get("lastStart") or 0) for s in self._all_series() if s.get("source") == "windows-history"), default=0.0)
        if history_latest and registry_latest and history_latest - registry_latest > 86400:
            registry["state"] = "stale"
            registry["detail"] = f"Windows stopped updating it since {iso(registry_latest)[:10]}; the full Windows log replaces it"
        elif registry_latest and now - registry_latest > 7 * 86400:
            registry["state"] = "stale"
            registry["detail"] = f"Nothing has been recorded in it since {iso(registry_latest)[:10]}; it may be stopped, not quiet"
        else:
            registry["state"] = "live" if registry_latest else "empty"
        coverage: dict[str, Any] = {}
        problems: list[str] = []
        for capability in capability_judge.FOCUS_CAPABILITIES:
            if not self.watched(capability):
                continue
            by = []
            if history["state"] == "live":
                by.append("windows-history")
            if capability == "microphone" and live["state"] == "live":
                by.append("live-audio")
            blind_since = "" if by else iso(max(registry_latest, float(self.state.get("historyIngestedAt") or 0)))
            coverage[capability] = {"label": CAPABILITY_LABELS[capability], "covered": bool(by), "by": by, "blindSince": blind_since}
            if not by:
                problems.append(f"{CAPABILITY_LABELS[capability]}: Unobserved" + (f" since {blind_since[:10]}" if blind_since else ""))
        sources = []
        for source_id, info in (("windows-history", history), ("live-audio", live), ("registry-last-use", registry)):
            sources.append({"id": source_id, **SOURCES[source_id], **{k: (iso(v) if k.endswith("At") and isinstance(v, (int, float)) else v) for k, v in info.items()}})
        return {
            "sources": sources,
            "coverage": coverage,
            "coverageFrom": iso(float(self.state.get("historyCoverageFrom") or 0.0)),
            "healthy": not problems,
            "problems": problems,
        }

    def _all_series(self) -> list[dict[str, Any]]:
        with self.lock:
            return [r for r in self.closed if r.get("type") == "series"] + list(self.state["open"].values())

    def groups(self) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        series_all = self._all_series()
        for series in series_all:
            if not self.watched(series.get("capability", "")):
                continue
            identity = series.get("identity") or {}
            key = f"{series['capability']}|{identity_key(identity)}"
            group = grouped.get(key)
            if group is None:
                group = grouped[key] = {
                    "key": key, "capability": series["capability"],
                    "capabilityLabel": CAPABILITY_LABELS.get(series["capability"], series["capability"]),
                    "program": display_name(identity), "identity": {}, "sources": set(), "series": [],
                    "uses": 0, "activeSeconds": 0.0, "blocked": 0, "firstAt": series["firstStart"],
                    "lastAt": 0.0, "inUse": False,
                }
            group["series"].append(series)
            group["sources"].add(series["source"])
            group["uses"] += int(series.get("count") or 0)
            group["activeSeconds"] += float(series.get("activeSeconds") or 0.0)
            group["blocked"] += int(series.get("blocked") or 0)
            group["firstAt"] = min(group["firstAt"], series["firstStart"])
            last = max(float(series.get("lastStart") or 0), float(series.get("firstStart") or 0))
            if last >= group["lastAt"]:
                group["lastAt"] = last
                # Latest known identity, with the script if known by the live observer.
                group["identity"] = {**group["identity"], **identity}
            if series.get("inUse") and self.state["open"].get(series["key"]) is series:
                group["inUse"] = True
        out = []
        severity = {"deny": 0, "undetermined": 1, "monitor": 2, "allow": 3}
        for group in grouped.values():
            if self.program_filter and not self.program_filter(
                group["program"], str(group["identity"].get("path") or ""), float(group["lastAt"] or 0)
            ):
                continue
            identity = self._identity_at(group["identity"], group["lastAt"])
            info = self.identities.get(identity_key(identity)) or {}
            change = self.permissions["current"].get(group["key"]) or {}
            if info.get("changedAt") and change and float(info["changedAt"]) > float(change.get("requestedAt") or 0):
                identity["identityChanged"] = True
            scripts = sorted({str((s.get("identity") or {}).get("script") or "") for s in group["series"]} - {""})
            if scripts and not identity.get("script"):
                identity["script"] = scripts[-1]
            verdict = capability_judge.judge(group["capability"], identity)
            recent = sorted(group["series"], key=lambda s: -float(s.get("lastStart") or 0))
            link = next((s.get("link") for s in recent if (s.get("link") or {}).get("state") == "linked"), None)
            out.append({
                "key": group["key"], "capability": group["capability"], "capabilityLabel": group["capabilityLabel"],
                "program": group["program"], "identity": identity, "scripts": scripts[-5:],
                "sources": [SOURCES[s]["label"] for s in sorted(group["sources"])],
                "uses": group["uses"], "seriesCount": len(group["series"]),
                "activeSeconds": round(group["activeSeconds"], 1), "blocked": group["blocked"],
                "firstAt": iso(group["firstAt"]), "lastAt": iso(group["lastAt"]), "inUse": group["inUse"],
                "verdict": verdict, "permission": self.permission_state(group["capability"], identity),
                "link": link or {"state": "none", "text": "No saved link"},
                "recent": [self._series_view(s) for s in recent[:8]],
            })
        out.sort(key=lambda g: (not g["inUse"], severity.get(g["verdict"]["verdict"], 4), -(datetime.fromisoformat(g["lastAt"]).timestamp() if g["lastAt"] else 0)))
        return out

    def _series_view(self, series: dict[str, Any]) -> dict[str, Any]:
        return {
            "source": SOURCES[series["source"]]["label"], "precision": SOURCES[series["source"]]["precision"],
            "firstStart": iso(series["firstStart"]), "lastStart": iso(series.get("lastStart") or 0),
            "lastStop": iso(series.get("lastStop") or 0), "count": series.get("count", 0),
            "activeSeconds": series.get("activeSeconds", 0), "longest": round(float(series.get("longest") or 0), 1),
            "blocked": series.get("blocked", 0), "inUse": bool(series.get("inUse")) and self.state["open"].get(series["key"]) is series,
            "detectedAt": iso(series.get("detectedAt") or 0), "open": self.state["open"].get(series["key"]) is series,
            "script": (series.get("identity") or {}).get("script", ""), "pid": (series.get("extra") or {}).get("pid", 0),
            "baseline": bool((series.get("extra") or {}).get("baseline")),
            "note": (series.get("extra") or {}).get("note", "") or (series.get("extra") or {}).get("endedBy", ""),
        }

    def timeline(self, key: str, limit: int = 200) -> dict[str, Any]:
        rows = [s for s in self._all_series() if f"{s['capability']}|{identity_key(s.get('identity') or {})}" == key]
        rows.sort(key=lambda s: -float(s.get("lastStart") or 0))
        gaps = [r for r in self.closed if r.get("type") == "gap"]
        return {
            "key": key,
            "series": [{**self._series_view(s), "link": s.get("link") or {}} for s in rows[:limit]],
            "gaps": [{"source": SOURCES.get(g["source"], {}).get("label", g["source"]), "from": iso(g["from"]), "to": iso(g["to"]), "reason": g["reason"]} for g in gaps[-50:]],
        }

    def snapshot(self) -> dict[str, Any]:
        groups = self.groups()
        status = self.source_status()
        quiet = []
        for capability, info in status["coverage"].items():
            if info["covered"] and not any(g["capability"] == capability for g in groups):
                quiet.append({"capability": capability, "label": info["label"],
                              "text": f"No usage recorded since {status['coverageFrom'][:10] or 'source start'}"})
        counts: dict[str, int] = {}
        for group in groups:
            counts[group["verdict"]["verdict"]] = counts.get(group["verdict"]["verdict"], 0) + 1
        gaps = [r for r in self.closed if r.get("type") == "gap"][-5:]
        return {
            "status": status, "groups": groups, "quiet": quiet, "counts": counts,
            "gaps": [{"source": SOURCES.get(g["source"], {}).get("label", g["source"]), "from": iso(g["from"]), "to": iso(g["to"]), "reason": g["reason"]} for g in gaps],
            "historyTask": HISTORY_TASK,
        }

    def find_identity(self, key: str) -> dict[str, Any] | None:
        for series in reversed(self._all_series()):
            if f"{series['capability']}|{identity_key(series.get('identity') or {})}" == key:
                return dict(series.get("identity") or {})
        return None

    # -- Execution -----------------------------------------------------------
    def start(self) -> None:
        def main_loop() -> None:
            reader = None
            if self.audio_reader_factory:
                try:
                    reader = self.audio_reader_factory()
                except OSError as error:
                    self.status["live-audio"].update(state="error", error=str(error)[:200])
            self.start_live_gap()
            next_history = next_registry = next_save = 0.0
            try:
                while not self.stop_event.is_set():
                    now = time.monotonic()
                    if reader is not None:
                        try:
                            self.poll_live(reader.read())
                        except OSError as error:
                            self.status["live-audio"].update(state="error", error=str(error)[:200])
                    if now >= next_registry:
                        next_registry = now + REGISTRY_POLL_SECONDS
                        self._guard(self.poll_registry)
                    if now >= next_history:
                        next_history = now + HISTORY_CHECK_SECONDS
                        self._guard(self.poll_history)
                        self._guard(self.sweep)
                        self._guard(self.verify_permissions)
                    if now >= next_save:
                        next_save = now + SAVE_SECONDS
                        self._guard(self.save)
                    self.stop_event.wait(LIVE_POLL_SECONDS)
            finally:
                if reader is not None:
                    reader.close()

        def identity_loop() -> None:
            while not self.stop_event.wait(10.0):
                self._guard(self.resolve_pending)

        for target, name in ((main_loop, "pc-capabilities"), (identity_loop, "pc-capability-identity")):
            thread = threading.Thread(target=target, name=name, daemon=True)
            thread.start()
            self.threads.append(thread)

    @staticmethod
    def _guard(function: Callable[[], Any]) -> None:
        try:
            function()
        except Exception:  # noqa: BLE001 - The observer does not crash the application
            import logging

            logging.exception("capability monitor step failed")

    def shutdown(self) -> None:
        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=3)
        try:
            self.save()
        except OSError:
            pass
