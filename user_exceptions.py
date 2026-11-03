"""Your trusted hosts, programs and apps: never blocked and never flagged.

Kept in ``<data dir>/user-exceptions.json`` and edited from Settings. Each
entry is checked as data, not trusted blindly: a host must be a full host name
(not a shared platform's base domain such as ``amazonaws.com``), and a program
must be a folder under Program Files, AppData\\Local\\Programs or your
Documents folder.
"""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime
from typing import Any

import paths

FILE = paths.DATA_ROOT / "user-exceptions.json"

HOST = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
# Shared platforms: their base domain hosts thousands of tenants and trackers, so only a host under it can be trusted.
SHARED_BASES = frozenset({
    "amazonaws.com", "cloudfront.net", "googleapis.com", "google.com", "gstatic.com", "googleusercontent.com",
    "apple.com", "icloud.com", "microsoft.com", "azurewebsites.net", "azureedge.net", "windows.net",
    "akamaized.net", "akamaiedge.net", "fastly.net", "cloudflare.com", "workers.dev", "pages.dev",
    "github.io", "githubusercontent.com", "vercel.app", "netlify.app", "herokuapp.com", "firebaseapp.com",
    "web.app", "facebook.com", "doubleclick.net", "co.uk", "com.sa", "com.kw",
})
PROGRAM_DIR = re.compile(
    r"^[a-z]:\\(users\\[^\\]+\\(documents|appdata\\local\\programs)|program files( \(x86\))?)\\[^\\]+", re.I)

_lock = threading.Lock()
_cache: dict[str, Any] = {"mtime": None, "data": {"hosts": {}, "programs": [], "apps": []}}


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load() -> dict[str, Any]:
    try:
        st = FILE.stat()
        mtime = (st.st_mtime_ns, st.st_size)
    except OSError:
        return {"hosts": {}, "programs": [], "apps": []}
    with _lock:
        if _cache["mtime"] != mtime:
            try:
                _cache["data"] = json.loads(FILE.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return _cache["data"]
            _cache["mtime"] = mtime
        return _cache["data"]


def domain_reason(domain: str) -> str:
    domain = str(domain or "").strip().lower().rstrip(".")
    for host, note in (load().get("hosts") or {}).items():
        if domain == host or domain.endswith("." + host):
            return "trusted by you" + (f": {note}" if note else "")
    return ""


def program_allowed(path: str) -> str:
    path = str(path or "").lower().rstrip("\\")
    for folder in load().get("programs") or ():
        folder = str(folder).lower().rstrip("\\")
        if path == folder or path.startswith(folder + "\\"):
            return folder
    return ""


def trusted_app(callers: tuple[str, ...]) -> str:
    """The first caller you marked as trusted, or an empty string."""
    apps = {str(a).strip().lower() for a in load().get("apps") or () if str(a).strip()}
    if not apps:
        return ""
    for caller in callers:
        lower = str(caller).strip().lower()
        if lower in apps or (lower.endswith(".exe") and lower[:-4] in apps) or lower + ".exe" in apps:
            return str(caller)
    return ""


def check_host(host: str) -> str:
    """Why a host cannot be trusted, or an empty string."""
    if not HOST.match(host):
        return "not a valid host name"
    if host in SHARED_BASES:
        return "a shared platform's base domain; trust the host under it instead"
    return ""


def check_program(folder: str) -> str:
    if PROGRAM_DIR.match(folder) and ".." not in folder:
        return ""
    return "not under Program Files, AppData\\Local\\Programs or your Documents folder"


def apply(params: dict[str, Any]) -> tuple[bool, list[str]]:
    """Replaces the trusted lists with what Settings sent. Returns (saved, rejected entries with reasons)."""
    hosts: dict[str, str] = {}
    programs: list[str] = []
    rejected: list[str] = []
    raw = params.get("hosts") or {}
    if isinstance(raw, list):
        raw = {h: "" for h in raw}
    for host, note in dict(raw).items():
        host = str(host).strip().lower().rstrip(".")
        why = check_host(host)
        if why:
            rejected.append(f"{host}: {why}")
        else:
            hosts[host] = str(note or "")[:120]
    for folder in params.get("programs") or ():
        folder = str(folder).strip().rstrip("\\")
        why = check_program(folder)
        if why:
            rejected.append(f"{folder}: {why}")
        else:
            programs.append(folder)
    apps: list[str] = []
    for app in params.get("apps") or ():
        app = str(app).strip()
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{1,120}", app):
            apps.append(app)
        elif app:
            rejected.append(f"{app}: not a bundle ID or program name")
    with _lock:
        _write({"hosts": hosts, "programs": programs, "apps": apps})
    return True, rejected


def _write(data: dict[str, Any]) -> None:
    data["version"] = 1
    data["savedAt"] = _now()
    FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, FILE)
    _cache["mtime"] = None
