"""Your choices: what Privacy Protector watches and protects.

Everything is off until you turn it on, from the first-run wizard or from
Settings. Each switch takes effect at once, without reinstalling:

- phone: DNS protection for a phone that uses this computer as its DNS server
- pc: DNS protection for this computer itself
- trackerLists: downloading public tracker lists, for better blocking without models
- capabilities: watching which programs use the microphone, camera, location
  and contacts, each kind on its own switch
- outlook: checking new Outlook mail
- defender: reading Windows Defender's state and scanning new downloads
- tempCleanup: the daily temporary-files cleanup
- models: the optional AI review with your own providers
- language: "en" or "ar"

Kept in ``<data dir>/settings.json``.
"""

from __future__ import annotations

import copy
import json
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import paths

FILE = paths.DATA_ROOT / "settings.json"
CAPABILITY_KINDS = ("microphone", "webcam", "location", "contacts")
LANGUAGES = ("en", "ar")
DEFAULTS: dict[str, Any] = {
    "version": 1,
    "firstRunDone": False,
    "language": "en",
    "phone": False,
    "pc": False,
    "trackerLists": False,
    "capabilities": {"enabled": False, **{kind: True for kind in CAPABILITY_KINDS}},
    "outlook": False,
    "defender": False,
    "tempCleanup": False,
    "models": False,
}
SWITCHES = ("phone", "pc", "trackerLists", "outlook", "defender", "tempCleanup", "models")


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def normalize(raw: Any) -> dict[str, Any]:
    """A complete, valid settings object from whatever was stored or sent."""
    data = copy.deepcopy(DEFAULTS)
    if not isinstance(raw, dict):
        return data
    for key in SWITCHES + ("firstRunDone",):
        if key in raw:
            data[key] = bool(raw[key])
    if raw.get("language") in LANGUAGES:
        data["language"] = raw["language"]
    caps = raw.get("capabilities")
    if isinstance(caps, dict):
        data["capabilities"]["enabled"] = bool(caps.get("enabled", data["capabilities"]["enabled"]))
        for kind in CAPABILITY_KINDS:
            if kind in caps:
                data["capabilities"][kind] = bool(caps[kind])
    elif isinstance(caps, bool):
        data["capabilities"]["enabled"] = caps
    return data


class Settings:
    def __init__(self, path: Path | None = None):
        self.path = Path(path or FILE)
        self.lock = threading.RLock()
        self.listeners: list[Callable[[dict[str, Any], dict[str, Any]], None]] = []
        self.data = self._read()

    def _read(self) -> dict[str, Any]:
        try:
            return normalize(json.loads(self.path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return normalize({})

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return copy.deepcopy(self.data)

    def enabled(self, key: str) -> bool:
        with self.lock:
            if key in CAPABILITY_KINDS:
                return bool(self.data["capabilities"]["enabled"] and self.data["capabilities"][key])
            if key == "capabilities":
                return bool(self.data["capabilities"]["enabled"])
            return bool(self.data.get(key))

    def update(self, patch: dict[str, Any]) -> dict[str, Any]:
        """Applies a partial change, saves it, and tells every listener (old, new)."""
        with self.lock:
            old = copy.deepcopy(self.data)
            merged = copy.deepcopy(self.data)
            for key, value in (patch or {}).items():
                if key == "capabilities" and isinstance(value, dict):
                    merged["capabilities"].update(value)
                else:
                    merged[key] = value
            self.data = normalize(merged)
            self._write()
            new = copy.deepcopy(self.data)
        for listener in list(self.listeners):
            listener(old, new)
        return new

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = {**self.data, "savedAt": _now()}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(record, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)
