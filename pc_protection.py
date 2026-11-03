"""PC protection: a section independent of the phone, blocks automatically without disabling any program.

The phone can only detect which app called a domain from partial evidence. The PC detects it:
the Windows DNS client log carries the process ID for each query, and the TCP connection table
carries the process ID for each remote address, and the engine knows which domain answered with
that address. So for each domain the program that called it, its publisher and its purpose are
known, and from that we distinguish a domain that is part of the program's function from a
domain added on top of it.

The verdict path for each domain:
1. Safety gate first: system infrastructure, development tools, model providers and the
   calling program's own publisher domains. These are protected: they are not shown to a model and are not blocked.
2. What remains is presented to the court (the writer reads, the jurors decide, the judge
   upholds or overturns) by the PC standard, without sending any program name, path or statement
   concerning the user.
3. Automatic blocking happens only when all of the following hold: red, safe blocking, confirmation
   by a second independent provider or a verdict upheld by the judge, permission from the local
   engine, and the domain does not belong to the publisher of any program that calls it.
4. Post-block guard: if a new caller appears that is the domain's owner, or a program repeatedly
   retries the blocked domain with an urgency that indicates it needs it, blocking is lifted automatically.

The blocking rule lives in a separate file (`<data dir>/pc/policy.json`) and does not touch the phone policy.
"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

import mail_images
import user_exceptions
import user_rules
import hidden_window
from domain_verdicts import (
    ai_block_gate,
    domain_function_role,
    verdict_for,
)

PC_REVIEW_VERSION = 1
REVIEW_INTERVAL_SECONDS = 90.0
REVIEW_BATCH_LIMIT = 60
REREVIEW_AFTER_SECONDS = 14 * 86400
ATTRIBUTION_WAIT_SECONDS = 120.0
RETRY_STORM_WINDOW = 600.0
RETRY_STORM_CALLS = 60

NIGHT_HOURS = frozenset({0, 1, 2, 3, 4, 5})
CREATE_NO_WINDOW = 0x08000000
DNS_CLIENT_LOG = "Microsoft-Windows-DNS-Client/Operational"


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _needs_main_model(verdict: dict[str, Any], entry: dict[str, Any], now: float) -> bool:
    """A verdict the main model has not upheld does not wait out its age: it is sent back to it while the domain is alive.
    Example ip-api.com: green on kimi's opinion alone, so it kept revealing the user's location for two weeks until its due date."""
    from ai_reviewer import decided_by_main

    if decided_by_main(verdict):
        return False
    try:
        seen = datetime.fromisoformat(str(entry.get("lastSeen"))).timestamp()
    except ValueError:
        return False
    return now - seen < REREVIEW_AFTER_SECONDS


def _clean_domain(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _base_domain(domain: str) -> str:
    labels = _clean_domain(domain).split(".")
    if len(labels) >= 3 and labels[-2] in {"co", "com", "net", "org", "gov", "ac"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else ""
def _suffix_match(domain: str, suffixes: Iterable[str]) -> str:
    for suffix in suffixes:
        if domain == suffix or domain.endswith("." + suffix):
            return suffix
    return ""


# ---------------------------------------------------------------------------
# What is never blocked on the computer
# ---------------------------------------------------------------------------
# Blocking any of these would break the machine or the tools used on it, not the tracker: Windows
# updates and activation, the internet connectivity check (without it Windows shows "No internet"),
# time and certificates, sign-in with a Microsoft account, the development tools and models the
# user works with, and the AI providers this program depends on.

PROTECTED_SUFFIXES: dict[str, str] = {
    # AI coding tools
    "anthropic.com": "Claude — the development tool itself",
    "claude.ai": "Claude — the development tool itself",
    "claude.com": "Claude — the development tool itself",
    "claudeusercontent.com": "Claude — the development tool itself",
    "openai.com": "Codex and ChatGPT",
    "chatgpt.com": "Codex and ChatGPT",
    "oaiusercontent.com": "Codex and ChatGPT",
    "oaistatic.com": "Codex and ChatGPT",
    "opencode.ai": "OpenCode",
    "models.dev": "OpenCode — model catalog",
    # Code and packages
    "github.com": "GitHub",
    "githubusercontent.com": "GitHub",
    "githubassets.com": "GitHub",
    "github.io": "GitHub",
    "ghcr.io": "GitHub",
    "npmjs.org": "npm package registry",
    "npmjs.com": "npm package registry",
    "yarnpkg.com": "package registry",
    "pypi.org": "Python package registry",
    "pythonhosted.org": "Python package registry",
    "python.org": "Python",
    "nodejs.org": "Node.js",
    "bun.sh": "Bun",
    "deno.land": "Deno",
    "jsdelivr.net": "library delivery",
    "unpkg.com": "library delivery",
    "cdnjs.cloudflare.com": "library delivery",
    # Model providers this program relies on and other projects
    "deepseek.com": "model provider (DeepSeek)",
    "groq.com": "model provider",
    "cohere.com": "model provider",
    "cohere.ai": "model provider",
    "mistral.ai": "model provider",
    "z.ai": "model provider",
    "bigmodel.cn": "model provider",
    "integrate.api.nvidia.com": "model provider",
    "api.nvidia.com": "model provider",
    "huggingface.co": "model provider",
    "hf.co": "model provider",
    "openrouter.ai": "model provider",
    "kilo.ai": "model provider",
    "generativelanguage.googleapis.com": "model provider (Gemini)",
    "api.cloudflare.com": "Cloudflare — account and models API",
    "dash.cloudflare.com": "Cloudflare — account dashboard",
    "cloudflare-dns.com": "encrypted DNS resolver",
    "one.one.one.one": "encrypted DNS resolver",
    "dns.google": "Windows internet connectivity check",
    # Windows infrastructure
    "msftconnecttest.com": "Windows internet connectivity check",
    "msftncsi.com": "Windows internet connectivity check",
    "time.windows.com": "time sync",
    "windowsupdate.com": "time sync",
    "update.microsoft.com": "Windows Update",
    "delivery.mp.microsoft.com": "Windows Update and Store",
    "dsp.mp.microsoft.com": "Windows Update and Store",
    "licensing.mp.microsoft.com": "Windows licensing",
    "sls.microsoft.com": "Windows activation",
    "microsoftonline.com": "sign-in with a Microsoft account",
    "login.live.com": "sign-in with a Microsoft account",
    "account.live.com": "SmartScreen protection",
    "smartscreen.microsoft.com": "SmartScreen protection",
    "smartscreen-prod.microsoft.com": "SmartScreen protection",
    "wd.microsoft.com": "Microsoft Defender",
    "wdcp.microsoft.com": "Microsoft Defender",
    "wdcpalt.microsoft.com": "Microsoft Defender",
    "pki.microsoft.com": "security certificates",
    "pki.goog": "security certificates",
    "digicert.com": "security certificates",
    "globalsign.com": "security certificates",
    "sectigo.com": "security certificates",
    "usertrust.com": "security certificates",
    "lencr.org": "security certificates",
    "letsencrypt.org": "security certificates",
    "identrust.com": "security certificates",
    "entrust.net": "security certificates",
    "comodoca.com": "security certificates",
    # Connected iPhone: development tools on iPhone need Apple's servers
    "albert.apple.com": "security certificates",
    "gs.apple.com": "security certificates",
    "ppq.apple.com": "developer app verification",
    "sideloadly.io": "iPhone app signing",
    # Banking apps: adding a card to Apple Pay was refused on the
    # program's network but accepted on others, and at that time only blocking the bank app's
    # tracking was not enough; so bank tracking and device risk assessment are functional.
    "alinma.api.dataroid.com": "Al Inma Bank app — card adding and device assessment",
    "rum.alinma.com": "Al Inma Bank app — card adding and device assessment",
    "dynaapm.anb.com.sa": "Arab National Bank app",
    "dynatraceag.saib.com.sa": "Arab National Bank app",
    "dynatrace.almubasher.com.sa": "Al Rajhi Bank app",
    "eum.sabb.com": "SABB Bank app",
    "incognia.com": "location-based fraud check at sign-in and payment",
    "location.plex.bz": "Plex — region detection for playing content",
}

def protected_reason(domain: str) -> str:
    trusted = user_exceptions.domain_reason(domain)  # hosts you trusted in Settings
    if trusted:
        return trusted
    mail_image = mail_images.host_reason(domain)  # images in mail content
    if mail_image:
        return mail_image
    suffix = _suffix_match(domain, PROTECTED_SUFFIXES)
    return PROTECTED_SUFFIXES[suffix] if suffix else ""


# ---------------------------------------------------------------------------
# Purpose of the calling program — by category, sent with its name since 2026-10-05
# ---------------------------------------------------------------------------

PURPOSES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"^(chrome|msedge|firefox|opera|brave|vivaldi|iexplore|arc)\.exe$", re.I),
     "browser", "web browser: its job is to display the sites the user opens themselves"),
    (re.compile(r"msedgewebview2\.exe$", re.I),
     "webview", "web view embedded in another program: its job is to display that program's interface"),
    (re.compile(r"^(claude|codex|opencode|cursor|windsurf|code|code - insiders|node|bun|deno|"
                r"python|pythonw|py|git|git-remote-https|gh|npm|npx|uv|pip|wrangler|"
                r"conhost|powershell|pwsh|cmd|windowsterminal|wt)\.exe$", re.I),
     "developer", "development and programming tool: its job is calling AI model APIs, code repositories and packages"),
    (re.compile(r"ianygo|tenorshare|3utools|itunes|applemobiledevice|sideloadly|imazing|"
                r"anytrans|ultfone|imyfone|dr\.?fone|wondershare|altserver", re.I),
     "phone-tools", "development and management tool for the connected phone: its job is controlling the device and changing its location for testing, and it needs its vendor's licensing and update servers"),
    (re.compile(r"norton|symantec|avast|avg|mcafee|kaspersky|bitdefender|eset|malwarebytes|"
                r"msmpeng|mpdefender|nissrv|securityhealth|smartscreen", re.I),
     "security", "security software: its job is updating protection definitions and scanning files and links"),
    (re.compile(r"^(svchost|system|lsass|services|wininit|winlogon|explorer|searchhost|"
                r"searchapp|startmenuexperiencehost|shellexperiencehost|runtimebroker|"
                r"backgroundtaskhost|taskhostw|compattelrunner|wuauclt|mousocoreworker|"
                r"usoclient|tiworker|trustedinstaller|sihclient|systemsettings|widgets|"
                r"widgetservice|phoneexperiencehost|crossdeviceservice|smss|dllhost|"
                r"wermgr|devicecensus|ctfmon|textinputhost|lockapp|onedrive|"
                r"microsoft\.sharepoint|filecoauth|netsh|svchost|locationnotificationwindows)\.exe$", re.I),
     "system", "Windows system component: its job is updates, authentication, notifications, sync and system services"),
    (re.compile(r"whatsapp|telegram|teams|ms-teams|zoom|discord|slack|skype|outlook|"
                r"olk|signal|viber|messenger", re.I),
     "communication", "communication app: its job is messages, calls and notifications"),
    (re.compile(r"winword|excel|powerpnt|onenote|msaccess|mspub|acrobat|acrord|"
                r"foxit|notion|obsidian", re.I),
     "office", "office program: its job is editing, saving and syncing documents"),
    (re.compile(r"dropbox|googledrivefs|google drive|icloud|onedrive|megasync|box", re.I),
     "cloud", "cloud sync: its job is uploading and downloading the user's files"),
    (re.compile(r"windowscamera|camera|spotify|vlc|mpc-hc|potplayer|netflix|anghami|shahid|steam|epicgames|"
                r"battle\.net|riotclient|ea(desktop|app)|obs64|obs", re.I),
     "media", "media or gaming program: its job is playing content, downloading it and signing into the account"),
)


def process_purpose(name: str, company: str = "", product: str = "") -> tuple[str, str]:
    text = str(name or "")
    for pattern, key, label in PURPOSES:
        if pattern.search(text):
            return key, label
    joined = f"{company} {product}"
    for pattern, key, label in PURPOSES:
        if key not in {"system", "developer", "browser", "webview"} and pattern.search(joined):
            return key, label
    if re.search(r"microsoft", company, re.I):
        return "system", "program from Microsoft: its job is Windows system services or its own programs"
    return "", ""
_GENERIC_TOKENS = frozenset(
    {
        "corporation", "company", "limited", "software", "technologies", "technology",
        "inc", "ltd", "llc", "gmbh", "co", "the", "windows", "operating", "system",
        "application", "applications", "service", "services", "host", "client",
        "update", "updater", "helper", "desktop", "program", "shenzhen", "beijing",
        "network", "networks", "digital", "studio", "group", "international",
        "global", "online", "cloud", "tools", "tool", "app",
    }
)


def caller_tokens(identities: Iterable[dict[str, Any]]) -> tuple[str, ...]:
    """Caller identities as text for the 'domain belongs to the software's own maker' guard,
    local only."""
    out: list[str] = []
    for identity in identities:
        for field in ("company", "product"):
            for token in re.split(r"[^a-z0-9]+", str(identity.get(field) or "").lower()):
                if len(token) >= 4 and token not in _GENERIC_TOKENS:
                    out.append(token)
        stem = re.sub(r"\.exe$", "", str(identity.get("name") or "").lower())
        for token in re.split(r"[^a-z0-9]+", stem):
            if len(token) >= 4 and token not in _GENERIC_TOKENS:
                out.append(token)
    return tuple(dict.fromkeys(out))


# ---------------------------------------------------------------------------
# Windows tools: process identity, connection table, DNS client log
# ---------------------------------------------------------------------------

IS_WINDOWS = os.name == "nt"


class ProcessInspector:
    """Process ID -> name, path, company and product, with short-lived caching."""

    TTL = 600.0

    def __init__(self) -> None:
        self.cache: dict[int, tuple[float, dict[str, Any]]] = {}
        self.version_cache: dict[str, dict[str, str]] = {}
        self.lock = threading.Lock()

    def identity(self, pid: int) -> dict[str, Any] | None:
        if pid <= 4 or not IS_WINDOWS:
            return {"name": "System", "path": "", "company": "Microsoft Corporation", "product": "Windows"} if pid == 4 else None
        now = time.monotonic()
        with self.lock:
            cached = self.cache.get(pid)
            if cached and now - cached[0] < self.TTL:
                return cached[1]
        path = self._image_path(pid)
        if not path:
            # The path of protected system processes cannot be read without administrator
            # rights, but their name is read from the process snapshot, which is enough to
            # know they are from Windows.
            name = self._snapshot_name(pid)
            if not name:
                return None
            identity = {"name": name, "path": "", "company": "", "product": ""}
            with self.lock:
                self.cache[pid] = (now, identity)
            return identity
        version = self._version(path)
        identity = {
            "name": Path(path).name,
            "path": path,
            "company": version.get("CompanyName", ""),
            "product": version.get("ProductName", "") or version.get("FileDescription", ""),
        }
        with self.lock:
            self.cache[pid] = (now, identity)
            if len(self.cache) > 4000:
                for key in list(self.cache)[:1000]:
                    self.cache.pop(key, None)
        return identity

    def watch_once(self) -> int:
        """Saves the identity of every new process the moment it appears, so it stays known
        after it exits.

        The DNS client log is read every three seconds, and curl and python scripts end before
        that, so their PID meant nothing by the time it was read, and 1127 domains stayed
        without a program. A process that changes its name under the same PID is read again."""
        if not IS_WINDOWS:
            return 0
        now = time.monotonic()
        fresh = 0
        for pid, name in self._snapshot_all():
            if pid <= 4:
                continue
            with self.lock:
                cached = self.cache.get(pid)
                if cached and cached[1].get("name", "").lower() == name.lower():
                    self.cache[pid] = (now, cached[1])
                    continue
                self.cache.pop(pid, None)
            if self.identity(pid):
                fresh += 1
        return fresh

    @staticmethod
    def _snapshot_all() -> list[tuple[int, str]]:
        class Entry(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.c_uint32), ("cntUsage", ctypes.c_uint32), ("th32ProcessID", ctypes.c_uint32),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", ctypes.c_uint32), ("cntThreads", ctypes.c_uint32),
                ("th32ParentProcessID", ctypes.c_uint32), ("pcPriClassBase", ctypes.c_long), ("dwFlags", ctypes.c_uint32),
                ("szExeFile", ctypes.c_wchar * 260),
            ]

        kernel32 = ctypes.windll.kernel32
        kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        snapshot = kernel32.CreateToolhelp32Snapshot(0x2, 0)
        if not snapshot or snapshot == ctypes.c_void_p(-1).value:
            return []
        rows: list[tuple[int, str]] = []
        try:
            entry = Entry()
            entry.dwSize = ctypes.sizeof(Entry)
            found = kernel32.Process32FirstW(ctypes.c_void_p(snapshot), ctypes.byref(entry))
            while found:
                rows.append((int(entry.th32ProcessID), str(entry.szExeFile)))
                found = kernel32.Process32NextW(ctypes.c_void_p(snapshot), ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(snapshot))
        return rows

    @staticmethod
    def _snapshot_name(pid: int) -> str:
        class Entry(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.c_uint32), ("cntUsage", ctypes.c_uint32), ("th32ProcessID", ctypes.c_uint32),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", ctypes.c_uint32), ("cntThreads", ctypes.c_uint32),
                ("th32ParentProcessID", ctypes.c_uint32), ("pcPriClassBase", ctypes.c_long), ("dwFlags", ctypes.c_uint32),
                ("szExeFile", ctypes.c_wchar * 260),
            ]

        kernel32 = ctypes.windll.kernel32
        kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        snapshot = kernel32.CreateToolhelp32Snapshot(0x2, 0)
        if not snapshot or snapshot == ctypes.c_void_p(-1).value:
            return ""
        try:
            entry = Entry()
            entry.dwSize = ctypes.sizeof(Entry)
            found = kernel32.Process32FirstW(ctypes.c_void_p(snapshot), ctypes.byref(entry))
            while found:
                if entry.th32ProcessID == pid:
                    return entry.szExeFile
                found = kernel32.Process32NextW(ctypes.c_void_p(snapshot), ctypes.byref(entry))
            return ""
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(snapshot))

    @staticmethod
    def _image_path(pid: int) -> str:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, int(pid))
        if not handle:
            return ""
        try:
            size = ctypes.c_ulong(1024)
            buffer = ctypes.create_unicode_buffer(1024)
            if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                return buffer.value
            return ""
        finally:
            kernel32.CloseHandle(handle)

    def _version(self, path: str) -> dict[str, str]:
        with self.lock:
            if path in self.version_cache:
                return self.version_cache[path]
        result: dict[str, str] = {}
        try:
            version = ctypes.windll.version
            size = version.GetFileVersionInfoSizeW(path, None)
            if size:
                data = ctypes.create_string_buffer(size)
                if version.GetFileVersionInfoW(path, 0, size, data):
                    pointer = ctypes.c_void_p()
                    length = ctypes.c_uint()
                    pairs: list[tuple[int, int]] = []
                    if version.VerQueryValueW(data, "\\VarFileInfo\\Translation", ctypes.byref(pointer), ctypes.byref(length)) and length.value >= 4:
                        raw = ctypes.string_at(pointer.value, length.value)
                        for index in range(0, len(raw) - 3, 4):
                            pairs.append(struct.unpack("<HH", raw[index:index + 4]))
                    pairs += [(0x0409, 0x04B0), (0x0409, 0x04E4)]
                    for key in ("CompanyName", "ProductName", "FileDescription"):
                        for language, codepage in pairs:
                            query = f"\\StringFileInfo\\{language:04x}{codepage:04x}\\{key}"
                            if version.VerQueryValueW(data, query, ctypes.byref(pointer), ctypes.byref(length)) and length.value:
                                value = ctypes.wstring_at(pointer.value, length.value).rstrip("\x00").strip()
                                if value:
                                    result[key] = value[:120]
                                    break
        except (OSError, AttributeError, ValueError):
            pass
        with self.lock:
            self.version_cache[path] = result
        return result
class _TCPRow(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_uint32), ("local_addr", ctypes.c_uint32), ("local_port", ctypes.c_uint32),
        ("remote_addr", ctypes.c_uint32), ("remote_port", ctypes.c_uint32), ("pid", ctypes.c_uint32),
    ]


class _TCP6Row(ctypes.Structure):
    _fields_ = [
        ("local_addr", ctypes.c_ubyte * 16), ("local_scope", ctypes.c_uint32), ("local_port", ctypes.c_uint32),
        ("remote_addr", ctypes.c_ubyte * 16), ("remote_scope", ctypes.c_uint32), ("remote_port", ctypes.c_uint32),
        ("state", ctypes.c_uint32), ("pid", ctypes.c_uint32),
    ]


def tcp_connections() -> list[tuple[str, int]]:
    """(Remote address, process ID) for each established TCP connection, without admin rights."""
    if not IS_WINDOWS:
        return []
    out: list[tuple[str, int]] = []
    iphlpapi = ctypes.windll.iphlpapi
    for family, row_type in ((2, _TCPRow), (23, _TCP6Row)):
        size = ctypes.c_ulong(0)
        iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, family, 5, 0)
        for _ in range(3):
            buffer = ctypes.create_string_buffer(size.value + 4096)
            size = ctypes.c_ulong(len(buffer))
            status = iphlpapi.GetExtendedTcpTable(buffer, ctypes.byref(size), False, family, 5, 0)
            if status == 0:
                break
        else:
            continue
        count = struct.unpack_from("<I", buffer.raw, 0)[0]
        offset = 4 if family == 2 else 4
        row_size = ctypes.sizeof(row_type)
        for index in range(count):
            row = row_type.from_buffer_copy(buffer.raw, offset + index * row_size)
            if not row.pid:
                continue
            if family == 2:
                address = socket.inet_ntoa(struct.pack("<I", row.remote_addr))
            else:
                address = str(ipaddress.IPv6Address(bytes(row.remote_addr)))
            if address in {"0.0.0.0", "::", "127.0.0.1", "::1"}:
                continue
            out.append((address, int(row.pid)))
    return out


def dns_client_log_enabled() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        output = subprocess.run(
            ["wevtutil", "gl", DNS_CLIENT_LOG], capture_output=True, text=True,
            timeout=8, creationflags=CREATE_NO_WINDOW, startupinfo=hidden_window.startupinfo(),
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return bool(re.search(r"enabled:\s*true", output, re.I))


def parse_dns_client_events(xml_text: str) -> list[dict[str, Any]]:
    """Extracts (record ID, process ID, domain) from event 3006 XML."""
    events: list[dict[str, Any]] = []
    for chunk in re.split(r"(?=<Event xmlns)", xml_text or ""):
        record = re.search(r"<EventRecordID>(\d+)</EventRecordID>", chunk)
        pid = re.search(r"<Execution ProcessID=['\"](\d+)['\"]", chunk)
        name = re.search(r"<Data Name=['\"]QueryName['\"]>([^<]*)</Data>", chunk)
        if not (record and pid and name):
            continue
        events.append(
            {
                "record": int(record.group(1)),
                "pid": int(pid.group(1)),
                "domain": _clean_domain(name.group(1)),
            }
        )
    return events


class DNSClientLogReader:
    """Reads new event 3006 entries from the DNS client log: who queried which domain."""

    def __init__(self) -> None:
        self.last_record = 0
        self.enabled = False
        self.checked_at = 0.0
        self.error = ""

    def poll(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        if now - self.checked_at > 60:
            self.enabled = dns_client_log_enabled()
            self.checked_at = now
        if not self.enabled:
            return []
        if self.last_record == 0:
            query = "*[System[(EventID=3006)]]"
            count = "400"
        else:
            query = f"*[System[(EventID=3006) and (EventRecordID>{self.last_record})]]"
            count = "3000"
        try:
            completed = subprocess.run(
                ["wevtutil", "qe", DNS_CLIENT_LOG, f"/q:{query}", "/f:xml", f"/c:{count}", "/rd:false" if self.last_record else "/rd:true"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=20, creationflags=CREATE_NO_WINDOW, startupinfo=hidden_window.startupinfo(),
            )
        except (OSError, subprocess.SubprocessError) as error:
            self.error = str(error)[:160]
            return []
        events = parse_dns_client_events(completed.stdout)
        if events:
            self.last_record = max(self.last_record, max(item["record"] for item in events))
        self.error = ""
        return events
def answer_addresses(response: bytes) -> list[tuple[str, int]]:
    """A and AAAA addresses in a DNS response, with their time to live."""
    out: list[tuple[str, int]] = []
    if len(response) < 12:
        return out
    try:
        qd, an = struct.unpack("!HH", response[4:8])
        offset = 12

        def skip_name(position: int) -> int:
            while position < len(response):
                length = response[position]
                if length == 0:
                    return position + 1
                if length & 0xC0 == 0xC0:
                    return position + 2
                position += 1 + length
            return position

        for _ in range(qd):
            offset = skip_name(offset) + 4
        for _ in range(an):
            offset = skip_name(offset)
            rtype, _, ttl, length = struct.unpack("!HHIH", response[offset:offset + 10])
            offset += 10
            data = response[offset:offset + length]
            offset += length
            if rtype == 1 and length == 4:
                out.append((socket.inet_ntoa(data), ttl))
            elif rtype == 28 and length == 16:
                out.append((str(ipaddress.IPv6Address(data)), ttl))
    except (struct.error, ValueError, IndexError):
        return out
    return out


class LocalMachine:
    """Is this address the computer itself? The lookup and its network card addresses."""

    def __init__(self) -> None:
        self.addresses: set[str] = set()
        self.refreshed = 0.0
        self.lock = threading.Lock()

    def _refresh(self) -> None:
        found: set[str] = set()
        try:
            for item in socket.getaddrinfo(socket.gethostname(), None):
                found.add(str(item[4][0]).split("%")[0])
        except OSError:
            pass
        with self.lock:
            self.addresses = found
            self.refreshed = time.monotonic()

    def is_local(self, client_ip: str) -> bool:
        address = str(client_ip or "").split("%")[0]
        try:
            if ipaddress.ip_address(address).is_loopback:
                return True
        except ValueError:
            return False
        if time.monotonic() - self.refreshed > 120:
            self._refresh()
        with self.lock:
            return address in self.addresses


# Device permissions (camera, microphone, location...) are in capability_monitor.py.


BROWSERS = (
    ("Chrome", r"Google\Chrome\User Data\Local State", r"SOFTWARE\Policies\Google\Chrome"),
    ("Edge", r"Microsoft\Edge\User Data\Local State", r"SOFTWARE\Policies\Microsoft\Edge"),
    ("Brave", r"BraveSoftware\Brave-Browser\User Data\Local State", r"SOFTWARE\Policies\BraveSoftware\Brave"),
)


def browser_secure_dns() -> list[dict[str, Any]]:
    """Browsers that bypass the system DNS with their own encrypted resolver."""
    rows: list[dict[str, Any]] = []
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    for name, relative, policy_key in BROWSERS:
        path = local / relative
        if not path.exists():
            continue
        mode = ""
        try:
            mode = str((json.loads(path.read_text(encoding="utf-8")).get("dns_over_https") or {}).get("mode") or "")
        except (OSError, ValueError):
            pass
        forced = ""
        if IS_WINDOWS:
            import winreg

            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                try:
                    with winreg.OpenKey(hive, policy_key) as key:
                        forced = str(winreg.QueryValueEx(key, "DnsOverHttpsMode")[0] or "")
                        break
                except OSError:
                    continue
        effective = forced or mode or "automatic"
        rows.append({"browser": name, "mode": mode, "policy": forced, "bypasses": effective == "secure"})
    return rows


# ---------------------------------------------------------------------------
# The computer benchmark for the model
# ---------------------------------------------------------------------------
PC_SYSTEM_PROMPT = """You are a network privacy auditor. You are shown DNS domains detected by a personal Windows PC, along with the names of the programs that called them, their stated purpose, information gathered from public sources, and aggregated statistics. Your task is to assign one verdict per domain using one of three colors, accompanied by a reason and the impact of blocking.

Color criteria — adhere to them strictly:

Green: Explicit use requested and seen by the user, or infrastructure without which the program or system breaks: updates, activation, licensing, authentication, login, certificates, notifications, user file synchronization, content and update downloads, and service interfaces on which the program relies.

Red: Data collection beyond the program's function: behavior analytics and usage measurement, crash reports and diagnostics sent to the program maker or third party, ads and attribution and audience files, device inventory and fingerprinting, background monitoring without user action, and selling or sharing data with brokers.

Orange: Genuine uncertainty that cannot be resolved with the available information. Do not mark a domain green merely because its name lacks tracking indicators.

Verdict rules:
- **One program calls two types; distinguish between them.** Domains that perform the function for which it was installed — blocking them causes disruption — and domains extra to that: usage measurement, crash reports, marketing messages, performance monitoring, and advertising. The latter are blocked even if the caller is an essential program.
- callerPrograms lists the calling program names and their makers. Read them alongside callerPurpose and ask: Does this domain perform something described? Answer in servesAppFunction.
- A mobile development tool whose function is to change the device location for testing: its licensing, update, and account domains with its maker are functional, not a violation, blockSafe=false. However, built-in analytics are extra.
- Windows system telemetry (such as events.data.microsoft.com and watson.telemetry) is extra to function and blocking it does not stop Windows. However, updates, activation, login, time, connectivity checks, and the store are functional.
- The browser calls sites opened by the user: the site itself, its services, and its content are green. Tracking and ad packages embedded in pages are red and safe to block. Human verification and fraud detection systems are functional and must not be blocked.
- An edge domain for a Content Delivery Network with no evidence identifying its owner: orange and blockSafe=false.
- Do not raise confidence above 60 when the only evidence is the domain name.
- Regular pulses throughout the day and during sleep hours, without being an update or sync = background monitoring, favoring red.
- blockSafe means: Does the program continue to work with all its functions if this domain is blocked? Authentication, payment, notifications, certificates, content updates, and licensing are not safe to block even if they collect data.

Respond with JSON only, with no text before or after, in this format:
{"verdicts": [{"domain": "", "color": "green|orange|red", "confidence": 0, "category": "", "purpose": "", "reason": "", "collects": [], "firstParty": true, "servesAppFunction": true, "blockSafe": true, "blockImpact": ""}]}

And `blockSafe` is true only if servesAppFunction is false. purpose, reason, blockImpact, and category are in Arabic, one concise sentence each. confidence between 0 and 100."""
PC_SYSTEM_PROMPT += "\n\n" + user_rules.rules_prompt()


# ---------------------------------------------------------------------------
# Store and Coordinator
# ---------------------------------------------------------------------------


class PCProtection:
    """Monitors PC domains, attributes them to programs, reviews them, and blocks the safe ones."""

    def __init__(
        self,
        directory: Path,
        policy: Any,
        reviewer: Any = None,
        study: Callable[[str], dict[str, Any]] | None = None,
        invalidate: Callable[[str], Any] | None = None,
        inspector: ProcessInspector | None = None,
        connections: Callable[[], list[tuple[str, int]]] | None = None,
        log_reader: DNSClientLogReader | None = None,
    ):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "domains.json"
        self.events_path = self.directory / "decisions.ndjson"
        self.policy = policy
        self.reviewer = reviewer
        self.study = study
        self.invalidate = invalidate
        self.inspector = inspector or ProcessInspector()
        self.connections = connections or tcp_connections
        self.log_reader = log_reader or DNSClientLogReader()
        self.local = LocalMachine()
        self.lock = threading.RLock()
        self.domains: dict[str, dict[str, Any]] = {}
        # IP -> {domain: expiry}. Major network IPs are shared by dozens
        # of domains, so a connection via them is attributed only if a single domain owns it.
        self.ip_map: dict[str, dict[str, float]] = {}
        self.blocked_calls: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=400))
        self.dirty = False
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []
        self.review_state: dict[str, Any] = {
            "state": "idle", "lastRunAt": "", "reviewed": 0, "blocked": 0,
            "protected": 0, "lastError": "", "cycles": 0,
        }
        self.attribution_state = {"logEvents": 0, "logUnresolved": 0, "connectionMatches": 0, "lastPollAt": ""}
        # Who wants every attribution at the moment it occurs (the permission monitor links usage to connections here).
        self.attribution_hooks: list[Callable[[int, dict[str, Any], str], None]] = []
        self._load()

    # -- Storage -----------------------------------------------------------
    def _load(self) -> None:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(payload.get("domains"), dict):
                self.domains = payload["domains"]
        except (OSError, ValueError):
            self.domains = {}

    def flush(self) -> None:
        with self.lock:
            if not self.dirty:
                return
            payload = {"version": PC_REVIEW_VERSION, "savedAt": _now_iso(), "domains": self.domains}
            text = json.dumps(payload, ensure_ascii=False, indent=1)
            self.dirty = False
        temp = self.path.with_suffix(".tmp")
        temp.write_text(text + "\n", encoding="utf-8")
        os.replace(temp, self.path)

    def _record_decision(self, domain: str, action: str, reason: str, extra: dict[str, Any] | None = None) -> None:
        row = {"time": _now_iso(), "domain": domain, "action": action, "reason": reason, **(extra or {})}
        with self.events_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    def _entry(self, domain: str) -> dict[str, Any]:
        entry = self.domains.get(domain)
        if entry is None:
            entry = {
                "hits": 0, "firstSeen": _now_iso(), "lastSeen": "", "hours": [], "night": 0,
                "days": [], "qtypes": [], "cname": [], "processes": {},
                "verdict": None, "decision": {"state": "watching", "reason": "Awaiting review"},
            }
            self.domains[domain] = entry
        return entry

    # -- Monitoring from engine --------------------------------------------
    def is_pc_client(self, client_ip: str) -> bool:
        return self.local.is_local(client_ip)

    def observe_answer(
        self, domain: str, qtype: str, response: bytes | None, cname_chain: list[str] | None,
        blocked: bool = False,
    ) -> None:
        clean = _clean_domain(domain)
        if not clean or "." not in clean or clean.endswith((".arpa", ".local", ".lan", ".home")):
            return
        moment = datetime.now().astimezone()
        with self.lock:
            entry = self._entry(clean)
            entry["hits"] += 1
            entry["lastSeen"] = moment.isoformat(timespec="seconds")
            if moment.hour not in entry["hours"]:
                entry["hours"].append(moment.hour)
            if moment.hour in NIGHT_HOURS:
                entry["night"] += 1
            day = moment.date().isoformat()
            if day not in entry["days"]:
                entry["days"] = (entry["days"] + [day])[-30:]
            if qtype and qtype not in entry["qtypes"]:
                entry["qtypes"] = (entry["qtypes"] + [qtype])[-6:]
            if cname_chain:
                entry["cname"] = [str(item) for item in cname_chain][-4:]
            # The DNS client log counts every call even if answered by cache, making it more accurate
            # for detecting urgency; the engine counts alone only when the log is disabled.
            if blocked and not self.log_reader.enabled:
                self.blocked_calls[clean].append(time.monotonic())
            self.dirty = True
        if response and not blocked:
            expiry = time.monotonic()
            with self.lock:
                for address, ttl in answer_addresses(response):
                    self.ip_map.setdefault(address, {})[clean] = expiry + max(60, min(int(ttl), 3600)) + 600

    # -- Attribution to programs -------------------------------------------
    def _attribute(self, domain: str, pid: int, source: str) -> bool:
        if pid == os.getpid():
            # The engine itself checks each domain's certificate before reviewing; if attributed to it, it would
            # appear as the caller for every domain on the machine.
            return False
        identity = self.inspector.identity(pid)
        if not identity:
            return False
        name = str(identity.get("name") or "")
        if not name:
            return False
        for hook in self.attribution_hooks:
            try:
                hook(pid, identity, domain)
            except Exception:  # noqa: BLE001 - listener does not stop attribution
                pass
        with self.lock:
            entry = self.domains.get(domain)
            if entry is None:
                entry = self._entry(domain)
            processes = entry.setdefault("processes", {})
            known = processes.get(name)
            if known is None:
                key, purpose = process_purpose(name, identity.get("company", ""), identity.get("product", ""))
                processes[name] = {
                    "count": 1,
                    "company": identity.get("company", ""),
                    "product": identity.get("product", ""),
                    "path": identity.get("path", ""),
                    "purposeKey": key,
                    "purpose": purpose,
                    "source": source,
                    "firstSeen": _now_iso(),
                    "lastSeen": _now_iso(),
                }
                # New caller for a previously judged domain: re-evaluate, as it might be
                # the owner whose function is disrupted by blocking.
                entry["needsRecheck"] = True
            else:
                known["count"] = int(known.get("count", 0)) + 1
                known["lastSeen"] = _now_iso()
            self.dirty = True
        return True

    def poll_attribution(self) -> None:
        events = self.log_reader.poll()
        for event in events:
            domain = event["domain"]
            if not domain or "." not in domain:
                continue
            if self._attribute(domain, event["pid"], "dns-client-log"):
                self.attribution_state["logEvents"] += 1
            elif event["pid"] != os.getpid():
                # Process exited before the monitor saw it: count what was missed, measure attribution, do not guess.
                self.attribution_state["logUnresolved"] = self.attribution_state.get("logUnresolved", 0) + 1
            if self.policy.action_for(domain) == "block":
                with self.lock:
                    self.blocked_calls[domain].append(time.monotonic())
        now = time.monotonic()
        try:
            connections = self.connections()
        except (OSError, ValueError):
            connections = []
        seen: set[tuple[str, int]] = set()
        for address, pid in connections:
            with self.lock:
                live = [d for d, expiry in (self.ip_map.get(address) or {}).items() if expiry >= now]
            if len(live) != 1:
                continue
            key = (live[0], pid)
            if key in seen:
                continue
            seen.add(key)
            if self._attribute(live[0], pid, "tcp-table"):
                self.attribution_state["connectionMatches"] += 1
        with self.lock:
            if len(self.ip_map) > 20000:
                self.ip_map = {
                    address: {d: e for d, e in domains.items() if e >= now}
                    for address, domains in self.ip_map.items()
                    if any(e >= now for e in domains.values())
                }
        self.attribution_state["lastPollAt"] = _now_iso()

    def prune_programs(self, present: Callable[[str, str, float], bool]) -> list[str]:
        """Removes from domains any program removed from the machine, so its constellation
        does not remain and its old need does not protect a domain. The domain itself remains with its verdict and decision."""
        removed: set[str] = set()
        with self.lock:
            for entry in self.domains.values():
                processes = entry.get("processes") or {}
                for name, info in list(processes.items()):
                    last = datetime.fromisoformat(info["lastSeen"]).timestamp() if info.get("lastSeen") else 0.0
                    if not present(name, str(info.get("path") or ""), last):
                        del processes[name]
                        removed.add(name)
            if removed:
                self.dirty = True
        for name in sorted(removed):
            self._record_decision("", "program-removed", f"{name} removed from machine, deleted from its domains", {"program": name})
        return sorted(removed)

    # -- Safety gate ----------------------------------------------------
    def identities(self, entry: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"name": name, "company": info.get("company", ""), "product": info.get("product", ""),
             "purposeKey": info.get("purposeKey", ""), "purpose": info.get("purpose", "")}
            for name, info in (entry.get("processes") or {}).items()
        ]

    def local_guard(self, domain: str, entry: dict[str, Any]) -> tuple[str, str]:
        """(protected|additional|unknown, reason) without any external call."""
        reason = protected_reason(domain)
        if reason:
            return "protected", "Infrastructure not to be blocked: " + reason
        identities = self.identities(entry)
        tokens = caller_tokens(identities)
        role, why = domain_function_role(domain, tokens)
        if role == "function":
            return "protected", why
        if role == "additional":
            return "additional", why
        return "unknown", ""

    # -- Smart review ------------------------------------------------------
    def _timing(self, entry: dict[str, Any]) -> dict[str, Any]:
        hits = int(entry.get("hits") or 0)
        hours = len(entry.get("hours") or [])
        night = int(entry.get("night") or 0)
        if hits < 6:
            pattern = "insufficient"
        elif hours >= 12 and night > 0:
            pattern = "Regular background pulse throughout the day and during sleep hours"
        elif hours >= 8 and night * 100 >= hits * 10:
            pattern = "Distributed activity with notable night share"
        elif hours <= 5:
            pattern = "Concentrated bursts linked to user session"
        else:
            pattern = "Intermittent daytime activity"
        return {"pattern": pattern, "hours": hours, "nightShare": round(night * 100 / hits) if hits else 0}

    def build_packet(self, domain: str, entry: dict[str, Any], role_hint: str) -> dict[str, Any]:
        identities = self.identities(entry)
        purposes = list(dict.fromkeys(item["purpose"] for item in identities if item.get("purpose")))
        timing = self._timing(entry)
        catalog = verdict_for(domain) or {}
        study = entry.get("study") or {}
        packet = {
            "domain": domain,
            "callerPurpose": " | ".join(purposes[:3]) or "Unclassified program",
            # Calling program names and makers: no data privacy concern for the models.
            "callerPrograms": [
                " — ".join(part for part in (item["name"], item.get("product") or item.get("company")) if part)
                for item in identities[:8]
            ],
            "distinctPrograms": len(identities),
            "firstPartyForCaller": False,
            "localRole": {"additional": "Appears locally to be extra to program function"}.get(role_hint, ""),
            "cnameChain": list(entry.get("cname") or [])[-3:],
            "queryTypes": list(entry.get("qtypes") or [])[:6],
            "lookups": int(entry.get("hits") or 0),
            "timingPattern": timing["pattern"],
            "activeHoursOfDay": timing["hours"],
            "nightSharePercent": timing["nightShare"],
            "currentLocalCategory": str(catalog.get("category") or ""),
            "tlsSubject": str(study.get("certificateSubject") or "")[:200],
            "pageTitle": str(study.get("title") or "")[:160],
            "pageDescription": str(study.get("description") or "")[:280],
        }
        return {key: value for key, value in packet.items() if value not in ("", [], None)}

    def candidates(self, limit: int = REVIEW_BATCH_LIMIT) -> list[str]:
        from ai_reviewer import awaits_judge, judge_due, reserved_name, risk_priority

        now = time.time()
        rows: list[tuple[int, str]] = []
        memory = getattr(self.reviewer, "memory", None)
        with self.lock:
            # What lacks only the judge is presented collectively when due (ai_reviewer.judge_due).
            judge_now = judge_due([entry.get("verdict") for entry in self.domains.values()
                                   if awaits_judge(entry.get("verdict"))])
            for domain, entry in self.domains.items():
                if reserved_name(domain):
                    continue   # Reserved name never resolves: not shown to models (ai_reviewer.RESERVED_SUFFIXES)
                if memory is not None and not memory.ready(domain):
                    # Recently failed review: waits for a doubling duration, not retried every cycle (review_memory).
                    continue
                decision = entry.get("decision") or {}
                state = decision.get("state")
                if state in {"user-allowed", "user-blocked", "guard-released", "session-blocked"}:
                    # Released by the safety gate is not returned to models: its verdict would block it again and the program needs it.
                    continue
                verdict = entry.get("verdict")
                if isinstance(verdict, dict) and verdict.get("agreement") == "Your ruling":
                    # User session verdict is not returned to models even if a new caller appears: needsRecheck preceded it, causing
                    # the writer to recolor 1337x.to red a day after the session's green verdict when NisSrv called it.
                    continue
                if entry.get("needsRecheck"):
                    rows.append((10**9, domain))
                    continue
                if state == "protected":
                    # Re-evaluated only when a new caller appears (needsRecheck).
                    continue
                if isinstance(verdict, dict) and verdict.get("pendingSonnet"):
                    memory = getattr(self.reviewer, "memory", None)
                    if (memory is None or memory.sonnet_ready()) and (judge_now or not awaits_judge(verdict)):
                        # Preliminary red takes precedence: daily quota may not suffice for all (ai_reviewer.risk_priority)
                        rows.append((risk_priority(verdict) * 10**8 + int(entry.get("hits") or 0), domain))
                    continue
                if verdict:
                    try:
                        age = now - datetime.fromisoformat(str(verdict.get("reviewedAt"))).timestamp()
                    except ValueError:
                        age = REREVIEW_AFTER_SECONDS + 1
                    if age < REREVIEW_AFTER_SECONDS and not _needs_main_model(verdict, entry, now):
                        continue
                rows.append((int(entry.get("hits") or 0), domain))
        rows.sort(reverse=True)
        return [domain for _, domain in rows[:limit]]

    def _set_decision(self, domain: str, state: str, reason: str, **extra: Any) -> None:
        with self.lock:
            entry = self._entry(domain)
            previous = (entry.get("decision") or {}).get("state")
            entry["decision"] = {"state": state, "reason": reason, "at": _now_iso(), **extra}
            entry.pop("needsRecheck", None)
            self.dirty = True
        if previous != state:
            self._record_decision(domain, state, reason)

    def _block(self, domain: str, verdict: dict[str, Any]) -> None:
        label = str(verdict.get("category") or domain)[:120]
        self.policy.update(domain, "block", label=label, note=str(verdict.get("reason") or "")[:300], source="pc-auto")
        if self.invalidate:
            self.invalidate(domain)
        self._set_decision(
            domain, "auto-blocked",
            str(verdict.get("reason") or "Red confirmed by two providers and allowed for blocking by safety gate"),
            reviewers=list(verdict.get("reviewers") or []),
        )

    def _unblock(self, domain: str, reason: str) -> None:
        if self.policy.action_for(domain) == "block":
            self.policy.update(domain, "monitor", note=reason[:300], source="pc-guard")
            if self.invalidate:
                self.invalidate(domain)
        self._set_decision(domain, "guard-released", reason)

    def decide(self, domain: str, verdict: dict[str, Any], role_hint: str) -> str:
        """Applies blocking gates to a reviewed verdict and returns the decision."""
        with self.lock:
            entry = dict(self.domains.get(domain) or {})
        identities = self.identities(entry)
        tokens = caller_tokens(identities)
        catalog = verdict_for(domain) or {}
        allowed, gate_reason = ai_block_gate(domain, str(catalog.get("category") or ""), tokens)
        if (entry.get("decision") or {}).get("state") == "guard-released":
            # Released by the safety gate because a program insisted on requesting it; blocking it again would disrupt it for hours until released again.
            return "guard-released"
        if verdict.get("pendingSonnet"):
            self._set_decision(domain, "watching", "Preliminary verdict awaiting court (the judge judge confirmation); monitored but not blocked")
            return "watching"
        if verdict.get("color") != "red":
            self._set_decision(domain, "watching", "Model verdict: " + ("Green" if verdict.get("color") == "green" else "Orange — monitored"))
            return "watching"
        if not verdict.get("blockSafe"):
            self._set_decision(domain, "red-kept", "Red, but blocking it disrupts function: " + str(verdict.get("blockImpact") or "")[:200])
            return "red-kept"
        from ai_reviewer import BLOCK_AGREEMENTS

        if verdict.get("agreement") not in BLOCK_AGREEMENTS:
            self._set_decision(domain, "red-kept", "Red not confirmed by judge; doubt does not warrant blocking")
            return "red-kept"
        if not allowed:
            self._set_decision(domain, "red-kept", "Blocked by safety gate: " + gate_reason)
            return "red-kept"
        if not identities and role_hint != "additional":
            self._set_decision(domain, "red-kept", "Calling program not yet identified, and its name does not indicate collection; waiting")
            return "red-kept"
        self._block(domain, verdict)
        return "auto-blocked"

    def regate(self) -> int:
        """Re-applies blocking gates to every red kept open by a verdict confirmed by the main model, without calling a model.

        Keeping was written once and not reviewed: held by the safety gate before the company entered the collector list, or waiting
        to identify the calling program which was identified later. The gate is asked again every cycle, and what it allows is now blocked."""
        from ai_reviewer import decided_by_main

        with self.lock:
            kept = [
                (domain, dict(entry)) for domain, entry in self.domains.items()
                if (entry.get("decision") or {}).get("state") == "red-kept"
                and isinstance(entry.get("verdict"), dict) and entry["verdict"].get("color") == "red"
                and entry["verdict"].get("blockSafe") and decided_by_main(entry["verdict"])
            ]
        blocked = 0
        for domain, entry in kept:
            guard, _ = self.local_guard(domain, entry)
            if guard == "protected":
                continue
            if self.decide(domain, entry["verdict"], guard) == "auto-blocked":
                blocked += 1
        return blocked

    def review_cycle(self, limit: int = REVIEW_BATCH_LIMIT) -> dict[str, Any]:
        from ai_domain_review import BATCH_SIZE, review_batch

        targets = self.candidates(limit)
        self.review_state.update(state="running", lastRunAt=_now_iso())
        counts = {"reviewed": 0, "blocked": 0, "protected": 0}
        pending: list[tuple[str, str, dict[str, Any]]] = []
        now = time.time()
        for domain in targets:
            with self.lock:
                entry = dict(self.domains.get(domain) or {})
            guard, reason = self.local_guard(domain, entry)
            if guard == "protected":
                if self.policy.action_for(domain) == "block" and (entry.get("decision") or {}).get("state") == "auto-blocked":
                    self._unblock(domain, "block lifted: " + reason)
                else:
                    self._set_decision(domain, "protected", reason)
                counts["protected"] += 1
                continue
            if not entry.get("processes") and guard != "additional":
                try:
                    first = datetime.fromisoformat(str(entry.get("firstSeen"))).timestamp()
                except ValueError:
                    first = now
                if now - first < ATTRIBUTION_WAIT_SECONDS:
                    continue
            pending.append((domain, guard, {}))

        memory = getattr(self.reviewer, "memory", None)
        if pending and memory is not None and memory.hold([domain for domain, _, _ in pending], "pc"):
            # Domains are grouped into one request instead of one per domain (review_memory.hold).
            pending = []

        # Certificate and public page title are evidence for the model; collected in parallel because each
        # check waits seconds, and sixty sequential checks would delay blocking by minutes.
        unstudied = [domain for domain, _, _ in pending if not (self.domains.get(domain) or {}).get("study")]
        if self.study and unstudied:
            from concurrent.futures import ThreadPoolExecutor

            def run_study(domain: str) -> tuple[str, dict[str, Any]]:
                try:
                    return domain, self.study(domain) or {}
                except Exception:  # Public study does not abort review
                    return domain, {}

            with ThreadPoolExecutor(max_workers=8) as executor:
                for domain, study in executor.map(run_study, unstudied):
                    with self.lock:
                        self._entry(domain)["study"] = {
                            key: study.get(key, "") for key in ("certificateSubject", "title", "description")
                        } if study.get("ok") else {"ok": False}
        with self.lock:
            pending = [
                (domain, guard, self.build_packet(domain, dict(self.domains.get(domain) or {}), guard))
                for domain, guard, _ in pending
            ]

        if pending and self.reviewer is not None:
            try:
                pool = self.reviewer.ensure_pool()
            except Exception as error:
                pool = None
                self.review_state["lastError"] = str(error)[:200]
            if pool is not None and getattr(self.reviewer, "trusted", None):
                # Waiters in one batch so the judge rules on them collectively (ai_reviewer.JUDGE_BATCH), and new ones six by six.
                with self.lock:
                    waiting = [item for item in pending
                               if ((self.domains.get(item[0]) or {}).get("verdict") or {}).get("pendingSonnet")]
                fresh_items = [item for item in pending if item[0] not in {name for name, _, _ in waiting}]
                batches = ([waiting] if waiting else []) + [
                    fresh_items[start:start + BATCH_SIZE] for start in range(0, len(fresh_items), BATCH_SIZE)
                ]
                for batch in batches:
                    if self.stop_event.is_set():
                        break
                    # What awaits court is not read again: its reading and saved jury verdict are shown to those remaining.
                    stored: dict[str, dict[str, Any]] = {}
                    with self.lock:
                        for domain, _, _ in batch:
                            saved = (self.domains.get(domain) or {}).get("verdict")
                            if isinstance(saved, dict) and saved.get("pendingSonnet"):
                                first = dict(saved)
                                for key in ("agreement", "vote", "votes", "reviewers", "reviewedAt", "pendingSonnet"):
                                    first.pop(key, None)
                                stored[domain] = first
                    fresh = [item[2] for item in batch if item[0] not in stored]
                    result = review_batch(pool, fresh, system_prompt=PC_SYSTEM_PROMPT) if fresh else {}
                    verdicts = {**(result.get("verdicts", {}) or {}), **stored}
                    memory = getattr(self.reviewer, "memory", None)
                    if memory is not None:
                        memory.failed([domain for domain, _, _ in batch if not verdicts.get(domain)])
                        memory.succeeded([domain for domain, _, _ in batch if verdicts.get(domain)])
                    packets: dict[str, dict[str, Any]] = {}
                    research = getattr(self.reviewer, "research", None)
                    for domain, _, packet in batch:
                        if domain in verdicts and research is not None and domain not in stored:
                            packet, verdicts[domain] = research(packet, verdicts[domain], system_prompt=PC_SYSTEM_PROMPT)
                        packets[domain] = packet
                    decide_batch = getattr(self.reviewer, "decide_batch", None)
                    if decide_batch is not None and verdicts:
                        # Court on the batch: jurors in one call then the judge judge in one call.
                        verdicts = decide_batch(
                            [packets[domain] for domain in verdicts], verdicts, system_prompt=PC_SYSTEM_PROMPT
                        )
                    for domain, guard, packet in batch:
                        verdict = verdicts.get(domain)
                        if not verdict:
                            continue
                        verdict.setdefault("agreement", "Single opinion")
                        # User rules override model verdicts and voting.
                        with self.lock:
                            known = dict(self.domains.get(domain) or {})
                        verdict = user_rules.enforce(
                            domain, verdict, caller_tokens(self.identities(known)),
                            str((verdict_for(domain) or {}).get("category") or ""),
                        )
                        verdict["reviewedAt"] = _now_iso()
                        with self.lock:
                            self._entry(domain)["verdict"] = verdict
                            self.dirty = True
                        counts["reviewed"] += 1
                        if self.decide(domain, verdict, guard) == "auto-blocked":
                            counts["blocked"] += 1
            elif pending:
                self.review_state["lastError"] = "No provider passed calibration"
        self.guard_blocked()
        self.flush()
        self.review_state.update(
            state="idle",
            reviewed=self.review_state.get("reviewed", 0) + counts["reviewed"],
            blocked=self.review_state.get("blocked", 0) + counts["blocked"],
            protected=self.review_state.get("protected", 0) + counts["protected"],
            cycles=self.review_state.get("cycles", 0) + 1,
        )
        return counts

    def apply_session_verdict(self, domain: str, verdict: dict[str, Any]) -> str:
        """Your own verdict instead of the judge's, without calling a model.

        User rules and safety gate override it just as they do for the judge. And red blocked by its verdict is not lifted
        by the urgency guard: browser urgency for an ad script or stats is page repetition, not program need."""
        from ai_reviewer import DECIDED_BY_SESSION, SESSION_REVIEWER

        clean = _clean_domain(domain)
        with self.lock:
            entry = dict(self.domains.get(clean) or {})
        if not entry:
            raise ValueError(f"Domain not monitored on PC: {clean}")
        verdict = {**verdict, "agreement": DECIDED_BY_SESSION, "reviewers": [SESSION_REVIEWER],
                   "provider": "user-review", "model": ""}
        verdict = user_rules.enforce(
            clean, verdict, caller_tokens(self.identities(entry)), str((verdict_for(clean) or {}).get("category") or ""),
        )
        verdict["reviewedAt"] = _now_iso()
        with self.lock:
            self._entry(clean)["verdict"] = verdict
            self.dirty = True
        state = (entry.get("decision") or {}).get("state")
        if state in {"user-allowed", "user-blocked"}:
            return state  # User decision is in their hands, untouched by others
        guard, reason = self.local_guard(clean, entry)
        if guard == "protected":
            self._set_decision(clean, "protected", reason)
            return "protected"
        if verdict.get("color") == "red" and verdict.get("blockSafe"):
            allowed, gate_reason = ai_block_gate(
                clean, str((verdict_for(clean) or {}).get("category") or ""), caller_tokens(self.identities(entry))
            )
            if not allowed:
                self._set_decision(clean, "red-kept", "Blocked by safety gate: " + gate_reason)
                return "red-kept"
            self.policy.update(clean, "block", label=str(verdict.get("category") or clean)[:120],
                               note=str(verdict.get("reason") or "")[:300], source="pc-session")
            if self.invalidate:
                self.invalidate(clean)
            self._set_decision(clean, "session-blocked", str(verdict.get("reason") or "Red blocked by user session verdict"))
            return "session-blocked"
        if self.policy.action_for(clean) == "block":
            # User decision is in their hands returned before this. And the condition was while "blocked", so instagram.com remained blocked after
            # a preliminary verdict from the writer changed its status to "monitored" while blocking persisted in policy.
            self.policy.update(clean, "monitor", note="Lifted by user session", source="pc-session")
            if self.invalidate:
                self.invalidate(clean)
        if verdict.get("color") == "red":
            self._set_decision(clean, "red-kept", "Red, but blocking it disrupts function: " + str(verdict.get("blockImpact") or "")[:200])
            return "red-kept"
        label = "Green" if verdict.get("color") == "green" else "Orange — monitored"
        self._set_decision(clean, "watching", "User session verdict: " + label)
        return "watching"

    # -- Post-block guard --------------------------------------------
    def guard_blocked(self) -> list[str]:
        """Lifts automatic blocking if evidence shows a program needs the domain."""
        released: list[str] = []
        now = time.monotonic()
        with self.lock:
            # And user session blocking is also lifted if it appears that a program from user projects or a function needs it, not by urgency alone.
            auto = [d for d, e in self.domains.items() if (e.get("decision") or {}).get("state") in {"auto-blocked", "session-blocked"}]
        for domain in auto:
            with self.lock:
                entry = dict(self.domains.get(domain) or {})
                calls = [stamp for stamp in self.blocked_calls.get(domain, ()) if now - stamp <= RETRY_STORM_WINDOW]
            guard, reason = self.local_guard(domain, entry)
            if guard == "protected":
                self._unblock(domain, "Blocking lifted automatically: " + reason)
                released.append(domain)
                continue
            if len(calls) >= RETRY_STORM_CALLS and (entry.get("decision") or {}).get("state") == "auto-blocked":
                self._unblock(
                    domain,
                    f"Blocking lifted automatically: a program repeated its request {len(calls)} times in ten minutes, indicating need rather than a tracker sending and leaving",
                )
                released.append(domain)
        return released

    # -- User decisions ----------------------------------------------------
    def user_decision(self, domain: str, action: str) -> dict[str, Any]:
        clean = _clean_domain(domain)
        if action == "allow":
            self.policy.update(clean, "allow", source="pc-user")
            state, reason = "user-allowed", "Allowed by user; not automatically re-blocked"
        elif action == "block":
            self.policy.update(clean, "block", source="pc-user")
            state, reason = "user-blocked", "Blocked by user themselves"
        elif action == "reset":
            self.policy.delete(clean)
            state, reason = "watching", "Returned to automatic review"
            with self.lock:
                self._entry(clean)["verdict"] = None
        else:
            raise ValueError("Invalid action")
        if self.invalidate:
            self.invalidate(clean)
        self._set_decision(clean, state, reason)
        self.flush()
        return {"domain": clean, "state": state}

    # -- Operation ---------------------------------------------------------
    def start(self) -> None:
        def attribution_loop() -> None:
            while not self.stop_event.wait(3.0):
                try:
                    self.poll_attribution()
                except Exception:  # Attribution does not crash server
                    pass

        def process_watch_loop() -> None:
            # Every quarter second: shorter than curl and python script lifetime, so their identity is saved before exit.
            watch = getattr(self.inspector, "watch_once", None)
            while watch and not self.stop_event.wait(0.25):
                try:
                    watch()
                except Exception:  # noqa: BLE001 - monitor does not crash server
                    pass

        def review_loop() -> None:
            if self.stop_event.wait(45.0):
                return
            while not self.stop_event.is_set():
                try:
                    self.regate()
                    self.review_cycle()
                except Exception as error:
                    self.review_state.update(state="idle", lastError=str(error)[:200])
                if self.stop_event.wait(REVIEW_INTERVAL_SECONDS):
                    return

        def flush_loop() -> None:
            while not self.stop_event.wait(30.0):
                try:
                    self.flush()
                except OSError:
                    pass

        for target, name in ((attribution_loop, "pc-attribution"), (process_watch_loop, "pc-process-watch"),
                             (review_loop, "pc-review"), (flush_loop, "pc-flush")):
            thread = threading.Thread(target=target, name=name, daemon=True)
            thread.start()
            self.threads.append(thread)

    def shutdown(self) -> None:
        self.stop_event.set()
        try:
            self.flush()
        except OSError:
            pass

    # -- Display -----------------------------------------------------------
    _ROUTING_SCRIPT = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$ids=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty ifIndex -Unique);"
        "@(foreach($i in $ids){$a=Get-NetAdapter -InterfaceIndex $i;"
        "[pscustomobject]@{name=$a.Name;v4=@((Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4).ServerAddresses);"
        "v6=@((Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv6).ServerAddresses)}}) | ConvertTo-Json -Compress"
    )

    def routing_status(self) -> dict[str, Any]:
        """Is the PC actually routing through the engine? From network cards with default route."""
        now = time.monotonic()
        cached = getattr(self, "_routing_cache", None)
        if cached and now - cached[0] < 30:
            return cached[1]
        status: dict[str, Any] = {"routed": False, "adapters": [], "logEnabled": self.log_reader.enabled}
        if IS_WINDOWS:
            try:
                output = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", self._ROUTING_SCRIPT],
                    capture_output=True, text=True, timeout=20, creationflags=CREATE_NO_WINDOW, startupinfo=hidden_window.startupinfo(),
                ).stdout.strip()
                rows = json.loads(output) if output else []
                if isinstance(rows, dict):
                    rows = [rows]
                for row in rows:
                    status["adapters"].append(
                        {
                            "name": row.get("name", ""),
                            "dns": [str(item) for item in (row.get("v4") or [])],
                            "dns6": [str(item) for item in (row.get("v6") or [])],
                        }
                    )
            except (OSError, subprocess.SubprocessError, ValueError):
                pass
        adapters = status["adapters"]
        status["routed"] = bool(adapters) and all(
            item["dns"][:1] == ["127.0.0.1"] and all(server == "::1" for server in item["dns6"])
            for item in adapters
        )
        try:
            status["watchdog"] = json.loads((self.directory / "watchdog.json").read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            status["watchdog"] = {}
        status["browsers"] = browser_secure_dns()
        self._routing_cache = (now, status)
        return status

    def _link_unattributed(self, items: list[dict[str, Any]]) -> None:
        """A domain without a program does not appear in any constellation, so its red disappears.
        Attributed by evidence alone: CNAME target of an attributed domain takes its programs, and a domain whose base site was called by only one program
        is attributed to it. What has no evidence remains without a program, and the inference is not written in processes. Called while lock is held."""
        by_domain = {item["domain"]: item for item in items}
        via_cname: dict[str, list[dict[str, Any]]] = defaultdict(list)
        site: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
        for item in items:
            if not item["programs"]:
                continue
            for target in (self.domains.get(item["domain"]) or {}).get("cname") or []:
                via_cname[_clean_domain(target)].extend(item["programs"])
            for program in item["programs"]:
                site[_base_domain(item["domain"])].setdefault(program["name"], program)
        for item in items:
            if item["programs"]:
                continue
            chain = [_clean_domain(t) for t in (self.domains.get(item["domain"]) or {}).get("cname") or []]
            linked = via_cname.get(item["domain"]) or [p for t in chain for p in (by_domain.get(t) or {}).get("programs") or []]
            how = "cname"
            if not linked:
                owners = site.get(_base_domain(item["domain"])) or {}
                linked, how = (list(owners.values()), "site") if len(owners) == 1 else ([], "")
            unique: dict[str, dict[str, Any]] = {}
            for program in linked:
                if program.get("inferred"):
                    continue
                unique.setdefault(program["name"], {**program, "count": 0, "inferred": how})
            item["programs"] = list(unique.values())[:6]

    def snapshot(self, limit: int = 600) -> dict[str, Any]:
        with self.lock:
            items = []
            for domain, entry in self.domains.items():
                verdict = entry.get("verdict") or {}
                items.append(
                    {
                        "domain": domain,
                        "hits": entry.get("hits", 0),
                        "lastSeen": entry.get("lastSeen", ""),
                        "programs": [
                            {"name": name, "company": info.get("company", ""), "purpose": info.get("purpose", ""), "count": info.get("count", 0)}
                            for name, info in sorted((entry.get("processes") or {}).items(), key=lambda kv: -int(kv[1].get("count", 0)))
                        ][:6],
                        "color": verdict.get("color", ""),
                        "confidence": verdict.get("confidence", 0),
                        "reason": verdict.get("reason", ""),
                        "collects": verdict.get("collects", []),
                        "blockImpact": verdict.get("blockImpact", ""),
                        "agreement": verdict.get("agreement", ""),
                        "pending": bool(verdict.get("pendingSonnet")),   # Awaits judge: does not color the constellation
                        "reviewers": verdict.get("reviewers", []),
                        "decision": entry.get("decision") or {},
                        "action": self.policy.action_for(domain),
                    }
                )
            self._link_unattributed(items)
            for item in items:
                # Red kept has two decisions: "for function" is a correct decision that does not color the constellation, and "pending" is a deficiency that does
                #.
                if item["decision"].get("state") == "red-kept" and item["color"] == "red":
                    entry = self.domains.get(item["domain"]) or {}
                    verdict = entry.get("verdict") or {}
                    category = str((verdict_for(item["domain"]) or {}).get("category") or "")
                    needed = not verdict.get("blockSafe") or not ai_block_gate(
                        item["domain"], category, caller_tokens(self.identities(entry)),
                    )[0]
                    item["keptFor"] = "function" if needed else "pending"
                item["firstSeen"] = (self.domains.get(item["domain"]) or {}).get("firstSeen", "")
        items.sort(key=lambda item: item.get("lastSeen") or "", reverse=True)
        counts: dict[str, int] = defaultdict(int)
        for item in items:
            counts[(item["decision"] or {}).get("state", "watching")] += 1
            if item["color"]:
                counts["color:" + item["color"]] += 1
        programs: dict[str, dict[str, Any]] = {}
        for item in items:
            for program in item["programs"]:
                row = programs.setdefault(
                    program["name"],
                    {"name": program["name"], "company": program["company"], "purpose": program["purpose"],
                     "domains": 0, "blocked": 0, "red": 0},
                )
                row["domains"] += 1
                if item["action"] == "block":
                    row["blocked"] += 1
                if item["color"] == "red":
                    row["red"] += 1
        return {
            "items": items[:limit],
            "total": len(items),
            "counts": dict(counts),
            "programs": sorted(programs.values(), key=lambda row: (-row["blocked"], -row["domains"])),
            "review": dict(self.review_state),
            "attribution": {**self.attribution_state, "logEnabled": self.log_reader.enabled, "logError": self.log_reader.error},
        }
