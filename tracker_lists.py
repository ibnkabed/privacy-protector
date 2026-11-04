"""Public tracker lists: downloaded as plain text and read as data, never as instructions.

Off until you turn on «Public tracker lists» in Settings. A list is one piece of evidence and never blocks alone
(`local_decider.decide`). An update of a strange size is refused and the last good copy stays; a failed download
touches nothing. Only the list files themselves are requested: nothing about you or your domains is sent.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import threading
import time
import urllib.request
from datetime import datetime
from typing import Any

import paths

LISTS_DIR = paths.DATA_ROOT / "tracker-lists"
META_PATH = LISTS_DIR / "meta.json"
TIMEOUT = 60.0
MIN_ENTRIES = 1000
MAX_CHANGE = 0.4          # an update that changes the size by more than 40% may be cut short or poisoned
MAX_BYTES = 40 * 1024 * 1024
UPDATE_EVERY_DAYS = 7
FIRST_UPDATE_AFTER = 60.0
RETRY_SECONDS = 6 * 3600.0

SOURCES = {
    "easyprivacy": ("https://easylist.to/easylist/easyprivacy.txt", "adblock"),
    "adguard-dns": ("https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", "adblock"),
    "oisd-small": ("https://small.oisd.nl/domainswild2", "domains"),
}
ADBLOCK_DOMAIN = re.compile(r"^\|\|([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})\^(?:\$third-party)?$")
PLAIN_DOMAIN = re.compile(r"^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$")


def parse(text: str, kind: str) -> set[str]:
    """Domain names only: URL rules mean nothing at the DNS level."""
    found: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line[0] in "!#":
            continue
        if kind == "adblock":
            match = ADBLOCK_DOMAIN.match(line)
            if match:
                found.add(match.group(1))
        elif PLAIN_DOMAIN.match(line):
            found.add(line)
    return found


def _meta() -> dict[str, Any]:
    try:
        return json.loads(META_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def accept(new_count: int, old_count: int) -> tuple[bool, str]:
    if new_count < MIN_ENTRIES:
        return False, f"list too small: {new_count}"
    if old_count and abs(new_count - old_count) / old_count > MAX_CHANGE:
        return False, f"size changed from {old_count} to {new_count}"
    return True, ""


def _fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "PrivacyProtector"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as reply:
        return reply.read(MAX_BYTES + 1)[:MAX_BYTES].decode("utf-8", "replace")


def update(names: Any = None, fetch: Any = _fetch) -> dict[str, str]:
    """Updates the lists and returns {name: result}. Any failure leaves the previous copy."""
    LISTS_DIR.mkdir(parents=True, exist_ok=True)
    meta = _meta()
    results: dict[str, str] = {}
    for name in names or SOURCES:
        url, kind = SOURCES[name]
        row = meta.setdefault(name, {})
        try:
            items = parse(fetch(url), kind)
        except Exception as error:  # noqa: BLE001 - a list is helping evidence and must never bring anything down
            row["lastError"] = str(error)[:160]
            results[name] = "failed"
            continue
        ok, why = accept(len(items), int(row.get("count") or 0))
        if not ok:
            row["lastError"] = why
            results[name] = "rejected"
            continue
        temporary = LISTS_DIR / f"{name}.tmp"
        temporary.write_text("\n".join(sorted(items)) + "\n", encoding="utf-8", newline="\n")
        temporary.replace(LISTS_DIR / f"{name}.txt")
        row.update(count=len(items), url=url, updatedAt=datetime.now().astimezone().isoformat(timespec="seconds"))
        row.pop("lastError", None)
        results[name] = "updated"
    # Written last: its new time tells `local_decider` to load the lists again.
    META_PATH.write_text(json.dumps(meta, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    return results


def age_days() -> float | None:
    """Days since the newest list was downloaded; None when there is none."""
    stamps = [row.get("updatedAt") for row in _meta().values() if isinstance(row, dict) and row.get("updatedAt")]
    if not stamps:
        return None
    newest = max(datetime.fromisoformat(item) for item in stamps)
    return (datetime.now().astimezone() - newest).total_seconds() / 86400


def clear() -> None:
    """Turning the switch off removes the downloaded lists."""
    shutil.rmtree(LISTS_DIR, ignore_errors=True)


class ListUpdater:
    """Keeps the lists fresh while the switch is on: at start if needed, then weekly."""

    def __init__(self) -> None:
        self.stop_event = threading.Event()

    def start(self) -> None:
        stop = self.stop_event

        def loop() -> None:
            if stop.wait(FIRST_UPDATE_AFTER):
                return
            while not stop.is_set():
                age = age_days()
                if age is None or age >= UPDATE_EVERY_DAYS:
                    logging.info("tracker lists: %s", update())
                if stop.wait(RETRY_SECONDS):
                    return

        threading.Thread(target=loop, name="tracker-lists", daemon=True).start()

    def shutdown(self) -> None:
        self.stop_event.set()


def status() -> dict[str, Any]:
    return {"lists": _meta(), "ageDays": age_days(), "checkedAt": time.time()}
