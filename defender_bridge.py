"""Working with Windows Defender.

Defender is the engine and the app coordinates it: it reads its state and asks it to scan and update signatures. It never weakens it: it does not change its settings, delete, quarantine, or allow anything. All reading is done without administrator rights:
- Every 15 minutes: Defender's state, what it detected, the registered protection programs, what Smart App Control blocked from the user's launchers, and the one-week monitoring window's events for ransomware protection, Office rules, and mail.
- Every minute: a new executable in the Downloads folder is scanned on Defender's request and its signature is read.
The original log data/pc/defender-events.ndjson is appended to and never trimmed, and the state file keeps only the latest data to display.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any

import hidden_window
import paths

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
BELOW_NORMAL = getattr(subprocess, "BELOW_NORMAL_PRIORITY_CLASS", 0)
POLL_EVERY = 15 * 60
DOWNLOADS_EVERY = 60
SIGNATURE_MAX_AGE = 2 * 24 * 3600
MP_CMD = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe"
DOWNLOADS = Path.home() / "Downloads"
# What gets run or installed, so it deserves an explicit scan when it arrives.
RISKY_SUFFIXES = (".exe", ".msi", ".msix", ".appx", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".jar", ".dll", ".zip", ".7z", ".rar", ".iso")
SAC_KEY = r"SYSTEM\CurrentControlSet\Control\CI\Policy"
AFTER_SNAPSHOT = paths.PC_ROOT / "defender-after.json"
EXCLUDE_SCRIPT = Path(__file__).resolve().parent / "scripts" / "Exclude-Launchers.ps1"
RECENT_LIMIT = 100
SAC_STALE_AFTER = 30 * 60
# Monitoring-window events: 1122 for ASR rules, and 1124 for ransomware protection.
AUDIT_EVENTS = {1122: "asr", 1124: "folders"}

_READ_SCRIPT = r"""
[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='SilentlyContinue'
$s = Get-MpComputerStatus
$names = @{}; Get-MpThreat | ForEach-Object { $names[[string]$_.ThreatID] = @{name=$_.ThreatName; severity=$_.SeverityID} }
$threats = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 50 | ForEach-Object {
  $n = $names[[string]$_.ThreatID]
  @{id=[string]$_.DetectionID; threatId=[string]$_.ThreatID; name=$n.name; severity=$n.severity; at=$_.InitialDetectionTime.ToString('o');
    resources=@($_.Resources); process=$_.ProcessName; actionOk=[bool]$_.ActionSuccess; status=$_.ThreatStatusID} })
$since = (Get-Date).AddDays(-1)
# A block the user overrode does not count: the launcher that is running now is no longer blocked.
$running = @{}; Get-Process | ForEach-Object { $running[$_.ProcessName.ToLower()] = 1 }
$latest = @{}
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational'; Id=3077; StartTime=$since} -MaxEvents 200 |
  ForEach-Object { if ($_.Message -match 'attempted to load (.+?) that' -and -not $latest[$Matches[1]]) { $latest[$Matches[1]] = $_.TimeCreated.ToString('o') } }
$blocked = @($latest.Keys | Where-Object { -not $running[[IO.Path]::GetFileNameWithoutExtension($_).ToLower()] } |
  ForEach-Object { @{path=$_; at=$latest[$_]} })
$audit = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1122,1124; StartTime=$since} -MaxEvents 500 |
  ForEach-Object { $p = if ($_.Message -match 'Process Name:\s*(.+)') { $Matches[1].Trim() } else { '' }; @{id=$_.Id; process=$p} })
$av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { $_.displayName })
$launchers = @(Get-ChildItem $env:ProgramFiles -Directory | ForEach-Object { Get-ChildItem $_.FullName -Filter *.exe -File } |
  Where-Object { (Get-AuthenticodeSignature $_.FullName).SignerCertificate.Subject -match 'Local Signing' } | ForEach-Object FullName)
@{ status = @{ mode=[string]$s.AMRunningMode; antivirus=[bool]$s.AntivirusEnabled; realtime=[bool]$s.RealTimeProtectionEnabled;
    behavior=[bool]$s.BehaviorMonitorEnabled; tamper=[bool]$s.IsTamperProtected; signatures=$s.AntivirusSignatureLastUpdated.ToString('o');
    signatureVersion=$s.AntivirusSignatureVersion; quickScan=$(if($s.QuickScanEndTime){$s.QuickScanEndTime.ToString('o')}else{''});
    fullScan=$(if($s.FullScanEndTime){$s.FullScanEndTime.ToString('o')}else{''}) };
   threats=$threats; blocked=$blocked; audit=$audit; antivirus=$av; launchers=$launchers } | ConvertTo-Json -Depth 5 -Compress
"""

_SIGNATURE_SCRIPT = (
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$s=Get-AuthenticodeSignature -LiteralPath $env:PP_TARGET;"
    "@{status=[string]$s.Status;signer=[string]$s.SignerCertificate.Subject} | ConvertTo-Json -Compress"
)


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _epoch(value: str) -> float:
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _run(command: list[str], timeout: int, target: str = "") -> subprocess.CompletedProcess:
    # The inherited PowerShell 7 module path stops Windows PowerShell from loading Get-AuthenticodeSignature (tested 2026-10-29).
    # -Command pastes what follows it into the script text, so the path is passed through an environment variable.
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    if target:
        env["PP_TARGET"] = target
    return subprocess.run(
        command, capture_output=True, timeout=timeout, env=env,
        creationflags=CREATE_NO_WINDOW | BELOW_NORMAL, startupinfo=hidden_window.startupinfo(),
    )
def _powershell(script: str, target: str = "", timeout: int = 180) -> Any:
    result = _run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                   "-Command", script], timeout, target)
    text = result.stdout.decode("utf-8", "replace").strip()
    return json.loads(text) if text else {}


def smart_app_control() -> int | None:
    """0 is off, 1 blocks, and 2 evaluates. None if reading fails."""
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SAC_KEY) as key:
            return int(winreg.QueryValueEx(key, "VerifiedAndReputablePolicyState")[0])
    except (ImportError, OSError, ValueError):
        return None


def excluded_processes(path: Path = AFTER_SNAPSHOT) -> set[str]:
    """Operation exceptions as read by the configuration file with admin privileges, because reading them requires admin access."""
    try:
        pref = json.loads(path.read_text(encoding="utf-8-sig")).get("pref") or {}
    except (OSError, ValueError):
        return set()
    return {str(item).lower() for item in pref.get("ExclusionProcess") or []}


def marked_excluded(launchers: list[str]) -> set[str]:
    """Launchers whose installer excluded them with admin rights and left defender-exclusion.json beside them,
    since the preference snapshot is not refreshed after a launcher is added."""
    return {str(path).lower() for path in launchers if (Path(str(path)).parent / "defender-exclusion.json").is_file()}


def assess(snapshot: dict[str, Any], sac: int | None, excluded: set[str], now: float | None = None) -> list[dict[str, str]]:
    """Notable items in case of Defender: each entry {level, title, text}. Red indicates an actual protection flaw."""
    now = time.time() if now is None else now
    status = snapshot.get("status") or {}
    issues: list[dict[str, str]] = []
    if not status:
        return [{"level": "yellow", "title": "Defender state unreadable", "text": "Failed to read Defender status in the last attempt."}]
    others = [name for name in snapshot.get("antivirus") or [] if "defender" not in str(name).lower()]
    if others:
        issues.append({"level": "red", "title": "Another antivirus took over", "text": "Another protection program registered: " + ", ".join(others)})
    if status.get("mode") != "Normal" or not status.get("antivirus"):
        issues.append({"level": "red", "title": "Defender isn't running", "text": f"Current Defender mode: {status.get('mode') or 'unknown'}."})
    elif not status.get("realtime"):
        issues.append({"level": "red", "title": "Real-time protection is off", "text": "Real-time protection is off, so files are not scanned when opened."})
    if not status.get("tamper"):
        issues.append({"level": "yellow", "title": "Tamper Protection is off", "text": "Tamper Protection is off, so malware could disable Defender."})
    signatures = _epoch(status.get("signatures", ""))
    if signatures and now - signatures > SIGNATURE_MAX_AGE:
        issues.append({"level": "yellow", "title": "Signatures are old", "text": f"Last signature update was {int((now - signatures) // 86400)} days ago, and the app requests updates automatically."})
    active = [t for t in snapshot.get("threats") or [] if not t.get("actionOk")]
    if active:
        issues.append({"level": "red", "title": "A threat wasn't removed", "text": "Unresolved threat: " + ", ".join(str(t.get("name") or t.get("threatId")) for t in active[:3])})
    # Disabled Smart App Control no longer blocks, so what was blocked before disabling it is not mentioned; recent blocks (last half hour) from other policies remain.
    recent = SAC_STALE_AFTER if sac != 1 else 86400
    owner = [str(item.get("path")) for item in snapshot.get("blocked") or [] if isinstance(item, dict)
             and "\\program files\\" in str(item.get("path")).lower() and str(item.get("path")).lower().endswith(".exe")
             and now - _epoch(item.get("at", "")) <= recent]
    if sac == 1:
        issues.append({"level": "red" if owner else "yellow", "title": "Smart App Control is on",
                       "text": "Smart App Control blocks locally signed launchers" + (": " + ", ".join(Path(p).name for p in owner[:4]) if owner else ".")})
    elif owner:
        issues.append({"level": "red", "title": "Windows blocked a user launcher", "text": "Blocked by Windows: " + ", ".join(Path(p).name for p in owner[:4])})
    if excluded:
        excluded = excluded | marked_excluded(snapshot.get("launchers") or [])
        missing = [path for path in snapshot.get("launchers") or [] if str(path).lower() not in excluded]
        if missing:
            command = f'& "{EXCLUDE_SCRIPT}"'
            issues.append({"level": "yellow", "title": "New app not excluded from scanning",
                           "text": "A new launcher has not yet been excluded from Defender scans. The user runs this command in an admin window:", "command": command})
    return issues


class DefenderBridge:
    def __init__(self, directory: Path):
        self.state_path = Path(directory) / "defender.json"
        self.events_path = Path(directory) / "defender-events.ndjson"
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.snapshot: dict[str, Any] = {}
        self.read_at = ""
        self.read_error = ""
        self.scans: deque[dict[str, Any]] = deque(maxlen=RECENT_LIMIT)
        self.seen_threats: set[str] = set()
        self.seen_downloads: dict[str, float] = {}
        self.last_update_request = 0.0
        self._load()

    def _load(self) -> None:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        self.snapshot = payload.get("snapshot") or {}
        self.read_at = payload.get("readAt", "")
        self.scans.extend(payload.get("scans") or [])
        self.seen_threats = set(payload.get("seenThreats") or [])
        self.seen_downloads = dict(payload.get("seenDownloads") or {})

    def save(self) -> None:
        with self.lock:
            text = json.dumps({"snapshot": self.snapshot, "readAt": self.read_at, "scans": list(self.scans),
                               "seenThreats": sorted(self.seen_threats), "seenDownloads": self.seen_downloads},
                              ensure_ascii=False, indent=1)
        temp = self.state_path.with_suffix(".tmp")
        temp.write_text(text + "\n", encoding="utf-8")
        os.replace(temp, self.state_path)

    def _event(self, kind: str, **fields: Any) -> None:
        line = json.dumps({"at": _now_iso(), "kind": kind, **fields}, ensure_ascii=False)
        with self.lock, self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    # -- Periodic reading -----------------------------------------------------
    def refresh(self) -> bool:
        try:
            snapshot = _powershell(_READ_SCRIPT)
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            self.read_error = str(error)[:300]
            return False
        if not isinstance(snapshot, dict) or not snapshot.get("status"):
            self.read_error = "Empty read"
            return False
        for key in ("threats", "blocked", "audit", "antivirus", "launchers"):
            value = snapshot.get(key)
            snapshot[key] = [] if value is None else value if isinstance(value, list) else [value]
        new = [t for t in snapshot["threats"] if t.get("id") and t["id"] not in self.seen_threats]
        with self.lock:
            self.snapshot = snapshot
            self.read_at = _now_iso()
            self.read_error = ""
            self.seen_threats.update(t["id"] for t in new)
        for threat in new:
            self._event("detection", **threat)
        self._renew_signatures(snapshot.get("status") or {})
        self.save()
        return True

    def _renew_signatures(self, status: dict[str, Any]) -> None:
        """The app automatically renews old signatures, at most once every six hours."""
        signatures = _epoch(status.get("signatures", ""))
        if not signatures or time.time() - signatures <= SIGNATURE_MAX_AGE or time.time() - self.last_update_request < 6 * 3600:
            return
        self.last_update_request = time.time()
        try:
            result = _run([str(MP_CMD), "-SignatureUpdate"], 900)
            self._event("signature-update", exitCode=result.returncode)
        except (OSError, subprocess.SubprocessError) as error:
            self._event("signature-update", error=str(error)[:300])

    # -- Scan up to Downloads --------------------------------------------
    def scan_file(self, path: Path, reason: str) -> dict[str, Any]:
        record: dict[str, Any] = {"at": _now_iso(), "path": str(path), "reason": reason}
        try:
            result = _run([str(MP_CMD), "-Scan", "-ScanType", "3", "-File", str(path), "-DisableRemediation"], 600)
            output = result.stdout.decode("utf-8", "replace")
            # 0 means no threat, 2 means threat found; deletion and quarantine are handled by Defender itself via real-time protection.
            record["verdict"] = "clean" if result.returncode == 0 else "threat" if result.returncode == 2 else "error"
            if record["verdict"] == "error":
                record["detail"] = output.strip()[-200:]
        except (OSError, subprocess.SubprocessError) as error:
            record.update(verdict="error", detail=str(error)[:200])
        if path.suffix.lower() in (".exe", ".msi", ".msix", ".appx", ".dll", ".ps1", ".scr") and path.exists():
            try:
                signature = _powershell(_SIGNATURE_SCRIPT, str(path), timeout=60)
                record["signature"] = signature.get("status", "")
                record["signer"] = str(signature.get("signer", "")).split(",")[0].removeprefix("CN=")
            except (OSError, subprocess.SubprocessError, ValueError):
                record["signature"] = "unknown"
        with self.lock:
            self.scans.appendleft(record)
        self._event("scan", **record)
        self.save()
        return record

    def check_downloads(self, folder: Path = DOWNLOADS, settle: float = 30.0) -> list[dict[str, Any]]:
        """Scans each new file in Downloads once, after its size stabilizes (download completes)."""
        done: list[dict[str, Any]] = []
        try:
            entries = list(os.scandir(folder))
        except OSError:
            return done
        for entry in entries:
            if not entry.is_file() or not entry.name.lower().endswith(RISKY_SUFFIXES):
                continue
            try:
                stat = entry.stat()
            except OSError:
                continue
            key = entry.path.lower()
            if self.seen_downloads.get(key) == stat.st_mtime or time.time() - stat.st_mtime < settle:
                continue
            self.seen_downloads[key] = stat.st_mtime
            done.append(self.scan_file(Path(entry.path), "downloads"))
        if not done and len(self.seen_downloads) > 2000:
            self.seen_downloads = {k: v for k, v in self.seen_downloads.items() if os.path.exists(k)}
        return done

    def start(self) -> None:
        def loop() -> None:
            if self.stop_event.wait(60.0):
                return
            if not self.seen_downloads:
                # First run: files in Downloads before pairing are not scanned all at once, only those added afterward.
                try:
                    self.seen_downloads = {e.path.lower(): e.stat().st_mtime for e in os.scandir(DOWNLOADS) if e.is_file()}
                except OSError:
                    pass
            next_read = 0.0
            while not self.stop_event.is_set():
                try:
                    if time.time() >= next_read:
                        self.refresh()
                        next_read = time.time() + POLL_EVERY
                    self.check_downloads()
                except Exception as error:  # noqa: BLE001 - Pairing does not crash the engine
                    logging.warning("defender bridge: %s", error)
                if self.stop_event.wait(DOWNLOADS_EVERY):
                    return

        threading.Thread(target=loop, name="defender-bridge", daemon=True).start()

    def issues(self) -> list[dict[str, str]]:
        with self.lock:
            snapshot = dict(self.snapshot)
        return assess(snapshot, smart_app_control(), excluded_processes())

    def view(self) -> dict[str, Any]:
        with self.lock:
            snapshot = dict(self.snapshot)
            scans = list(self.scans)
        audit = snapshot.get("audit") or []
        counts = {name: 0 for name in AUDIT_EVENTS.values()}
        processes: dict[str, dict[str, int]] = {name: {} for name in AUDIT_EVENTS.values()}
        for item in audit:
            kind = AUDIT_EVENTS.get(int(item.get("id") or 0))
            if kind:
                counts[kind] += 1
                name = Path(str(item.get("process") or "?")).name
                processes[kind][name] = processes[kind].get(name, 0) + 1
        return {
            "readAt": self.read_at, "readError": self.read_error, "status": snapshot.get("status") or {},
            "smartAppControl": smart_app_control(), "antivirus": snapshot.get("antivirus") or [],
            "threats": (snapshot.get("threats") or [])[:20], "scans": scans[:30],
            "audit": {"counts": counts, "processes": processes},
            "issues": assess(snapshot, smart_app_control(), excluded_processes()),
        }

    def shutdown(self) -> None:
        self.stop_event.set()
