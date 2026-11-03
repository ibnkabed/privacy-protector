"""Self-checks behind the tray icon's color, standard library only."""

from __future__ import annotations

import json
import time
import urllib.request
from datetime import datetime
from pathlib import Path

import paths

JSON_STORES = (
    "policy.json", "apps.json", "privacy-controls.json", "domain-classifications.json",
    "pc/policy.json", "pc/domains.json", "pc/capability-state.json", "pc/capability-permissions.json",
    "settings.json",
)
NDJSON_LOGS = (
    "dns-activity.ndjson", "app-attribution.ndjson", "phone-auto-decisions.ndjson",
    "pc/decisions.ndjson", "pc/capability-events.ndjson",
)
# The PC review loop runs every 90 seconds; 20 minutes without a run means it is stuck.
REVIEW_STALE_SECONDS = 20 * 60


def check_data(root: Path | None = None) -> list[str]:
    """Stores that exist but no longer parse. Missing stores are created on first use."""
    root = Path(root or paths.DATA_ROOT)
    problems = []
    for rel in JSON_STORES:
        path = root / rel
        if path.exists():
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                problems.append(f"corrupt {rel}: {type(error).__name__}")
    for rel in NDJSON_LOGS:
        path = root / rel
        if not path.exists():
            continue
        # Only the tail is read: a log is appended to, so damage shows at its end.
        with path.open("rb") as handle:
            handle.seek(max(0, path.stat().st_size - 256 * 1024))
            lines = handle.read().decode("utf-8", "replace").splitlines()[1:]
        bad = 0
        for line in lines[-200:]:
            if line.strip():
                try:
                    json.loads(line)
                except ValueError:
                    bad += 1
        if bad > 1:  # one torn line from a write in progress is normal
            problems.append(f"{bad} corrupt lines at the end of {rel}")
    return problems


def _get(url: str, timeout: float = 10.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as reply:
        return json.loads(reply.read().decode("utf-8"))


def check_classification(api: str) -> list[str]:
    """Only when PC protection runs: is its review loop alive?"""
    try:
        status = _get(api + "/api/pc/status")
    except Exception as error:  # noqa: BLE001
        return [f"PC status unreachable: {type(error).__name__}"]
    if not status.get("enabled", True):
        return []
    review = status.get("review") or {}
    problems = []
    if review.get("lastError"):
        problems.append("PC review error: " + str(review["lastError"])[:120])
    last = review.get("lastRunAt")
    if last:
        age = time.time() - datetime.fromisoformat(last).timestamp()
        if age > REVIEW_STALE_SECONDS:
            problems.append(f"PC review has not run for {int(age // 60)} minutes")
    return problems


def check_capabilities(api: str) -> list[str]:
    """Is every capability you chose to watch covered by a live source?"""
    try:
        status = _get(api + "/api/pc/capabilities/status")
    except Exception as error:  # noqa: BLE001
        return [f"capability monitor unreachable: {type(error).__name__}"]
    if status.get("enabled") is False:
        return []
    problems = []
    for capability, info in (status.get("coverage") or {}).items():
        if not info.get("covered"):
            since = str(info.get("blindSince") or "")[:10]
            problems.append(f"{capability} not monitored" + (f" since {since}" if since else ""))
    for source in status.get("sources") or []:
        if source.get("id") == "windows-history" and source.get("state") != "live":
            problems.append(f"Windows capability history copy is {source.get('state')}")
    return problems
