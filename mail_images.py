"""Mail-body image hosts are not blocked.

Review blocked image hosts used by mail platforms (Braze, Iterable, Marketo and others),
so logos and banners disappeared from Outlook messages. When ``mail_watch`` scans each
message it records the hosts of its visible images, and ``pc_protection.protected_reason``
reads them, so none of them is blocked on the PC or the phone. A open-tracking pixel is
not among them: its tag is 1×1 or hidden, or its link has no image extension and no image
folder, so it stays blockable.

Only the host name and the date of last sighting are stored from the message; no link is
ever opened.
"""

from __future__ import annotations

import json
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from user_exceptions import SHARED_BASES
import paths

ROOT = Path(__file__).resolve().parent
FILE = paths.PC_ROOT / "mail-image-hosts.json"
REASON = "Hosts the content images of your email messages; blocking it hides them in Outlook"

IMG_TAG = re.compile(r"<img\b[^>]*>", re.I)
SRC = re.compile(r"""\bsrc\s*=\s*["']?(https?://([A-Za-z0-9.-]+)[^"'\s>]*)""", re.I)
PIXEL = re.compile(r"""\b(width|height)\s*=\s*["']?[01](px)?["'\s/>]|display\s*:\s*none|visibility\s*:\s*hidden""", re.I)
# A host whose name is tracking or click redirection stays blockable even if an image passed
# through it. A shared platform under its public name (s3.amazonaws.com and the like) is not
# protected as a whole for the sake of one image.
SHARED_HOST = re.compile(r"^s3([.-][a-z0-9-]+)?\.amazonaws\.com$")
TRACKER_LABEL = re.compile(r"^(track|tracking|click|clicks|link|links|t|r|open|o|e)\.", re.I)
IMAGE_PATH = re.compile(r"\.(png|jpe?g|gif|webp|svg|bmp)(\?|#|$)|/images?/", re.I)

_lock = threading.Lock()
_cache: dict[str, Any] = {"mtime": None, "hosts": {}}


def content_hosts(html: str) -> set[str]:
    """Hosts of the visible images in the message text, excluding the tracking pixel."""
    hosts = set()
    for tag in IMG_TAG.findall(html or ""):
        match = SRC.search(tag)
        if not match or PIXEL.search(tag):
            continue
        host = match.group(2).lower().rstrip(".")
        if TRACKER_LABEL.match(host) or shared(host):
            continue
        if IMAGE_PATH.search(match.group(1).split("://", 1)[1].partition("/")[2]):
            hosts.add(host)
    return hosts


def shared(host: str) -> bool:
    return host in SHARED_BASES or bool(SHARED_HOST.match(host))


def load() -> dict[str, str]:
    try:
        st = FILE.stat()
        mtime = (st.st_mtime_ns, st.st_size)
    except OSError:
        return {}
    with _lock:
        if _cache["mtime"] != mtime:
            try:
                _cache["hosts"] = dict(json.loads(FILE.read_text(encoding="utf-8")).get("hosts") or {})
            except (OSError, ValueError):
                return _cache["hosts"]
            _cache["mtime"] = mtime
        return _cache["hosts"]


def record(hosts: set[str]) -> list[str]:
    """Adds the hosts and returns the new ones among them."""
    if not hosts:
        return []
    today = datetime.now().astimezone().date().isoformat()
    with _lock:
        try:
            current = dict(json.loads(FILE.read_text(encoding="utf-8")).get("hosts") or {})
        except (OSError, ValueError):
            current = {}
        new = sorted(h for h in hosts if h not in current)
        if not new and all(current.get(h) == today for h in hosts):
            return []
        current.update({h: today for h in hosts})
        FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": 1, "hosts": dict(sorted(current.items()))}, ensure_ascii=False, indent=1),
                       encoding="utf-8")
        tmp.replace(FILE)
    return new
def host_reason(domain: str) -> str:
    domain = str(domain or "").strip().lower().rstrip(".")
    return REASON if domain in load() and not shared(domain) else ""
