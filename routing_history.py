"""A record of the periods the PC left the engine's protection.

The watchdog task switches the PC to a public resolver when the engine doesn't answer, and writes only its last
switch to `watchdog.json`. So the engine builds the record itself: every minute it notes that it is alive, and when
it returns and finds a new switch it writes the period from its last sign of life to that switch. The record is only
appended to, and a quick engine restart with no switch writes nothing.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

TICK_SECONDS = 60.0
MIN_MINUTES = 1.0


def _stamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _time(value: Any) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.astimezone()


class RoutingHistory:
    def __init__(self, directory: Path):
        self.log_path = Path(directory) / "routing-history.ndjson"
        self.state_path = Path(directory) / "routing-state.json"
        self.watchdog_path = Path(directory) / "watchdog.json"
        self.stop_event = threading.Event()

    def _read(self, path: Path, encoding: str = "utf-8") -> dict[str, Any]:
        try:
            data = json.loads(path.read_text(encoding=encoding))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _period(self, start: Any, end: Any) -> None:
        first, last = _time(start), _time(end)
        if first is None or last is None:
            return
        minutes = (last - first).total_seconds() / 60
        if minutes < MIN_MINUTES:
            return
        row = {"from": first.isoformat(timespec="seconds"), "to": last.isoformat(timespec="seconds"),
               "minutes": round(minutes), "source": "engine"}
        with self.log_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    def tick(self, now: str | None = None) -> None:
        moment = now or _stamp()
        state = self._read(self.state_path)
        watchdog = self._read(self.watchdog_path, "utf-8-sig")
        switch = str(watchdog.get("lastSwitchAt") or "")
        mode = watchdog.get("mode")
        if mode == "fallback":
            # The engine is alive and the watchdog hasn't reached it: the period starts here unless it started earlier.
            state.setdefault("fallbackSince", state.get("aliveAt") or moment)
        elif state.get("switch") and switch and switch != state["switch"]:
            self._period(state.get("fallbackSince") or state.get("aliveAt"), switch)
            state.pop("fallbackSince", None)
        elif mode == "engine":
            state.pop("fallbackSince", None)
        state.update(aliveAt=moment, switch=switch or state.get("switch", ""))
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state) + "\n", encoding="utf-8", newline="\n")
        temporary.replace(self.state_path)

    def recent(self, limit: int = 3) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        try:
            for line in self.log_path.read_text(encoding="utf-8").splitlines():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
        except OSError:
            return []
        rows.sort(key=lambda row: str(row.get("from")))
        return rows[-limit:][::-1]

    def start(self) -> None:
        def loop() -> None:
            while not self.stop_event.is_set():
                try:
                    self.tick()
                except OSError as error:
                    logging.warning("routing history: %s", error)
                if self.stop_event.wait(TICK_SECONDS):
                    return

        threading.Thread(target=loop, name="routing-history", daemon=True).start()

    def shutdown(self) -> None:
        self.stop_event.set()
