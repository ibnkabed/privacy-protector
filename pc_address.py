"""This computer's address on the home network.

A phone uses this address as its manual DNS server on each Wi-Fi network, so if it changes the phone leaves
protection without anyone noticing. The last address is kept across restarts, and a notification arrives when a new
one settles. An address outside the local network (a VPN, for example) doesn't count as a change, and neither does
one seen in a single check: a Wi-Fi drop for a moment means nothing.
"""

from __future__ import annotations

import ipaddress
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

CHECK_SECONDS = 60.0
CONFIRM_CHECKS = 3


def is_lan(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.version == 4 and parsed.is_private and not (parsed.is_loopback or parsed.is_link_local)


class AddressWatch:
    def __init__(self, path: Path, provider: Callable[[], str], notify: Callable[[str], Any]):
        self.path = Path(path)
        self.provider = provider
        self.notify = notify
        self.lock = threading.Lock()
        self.pending = ""
        self.pending_checks = 0
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        self.data = data if isinstance(data, dict) else {}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(self.data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
        temporary.replace(self.path)

    def check(self) -> bool:
        """True when a new address settled just now."""
        address = str(self.provider() or "").strip()
        with self.lock:
            known = str(self.data.get("address") or "")
            if not is_lan(address) or address == known:
                self.pending, self.pending_checks = "", 0
                return False
            if not known:
                self.data = {"address": address, "since": _stamp()}
                self._save()
                return False
            self.pending_checks = self.pending_checks + 1 if address == self.pending else 1
            self.pending = address
            if self.pending_checks < CONFIRM_CHECKS:
                return False
            self.data = {"address": address, "since": _stamp(), "previous": known}
            self.pending, self.pending_checks = "", 0
            self._save()
        self.notify(address)
        return True

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.data)


def _stamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")
