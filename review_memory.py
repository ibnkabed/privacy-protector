"""Review memory: increasing delay for domains whose review failed, with search results cached.

Measurement showed that failed domains were retried every 90 to 120 seconds without limit,
and that `web_lookup` re-searched on every confirmation of the same domain. So reviews after failure wait
for a duration that doubles up to a one-day cap, and searches are cached: answers for thirty days, failures for one day.
The file is separate from the classification store because the latter is rewritten every five seconds.
Each domain is reviewed and searched individually, even if it is a subdomain of a site whose domains were reviewed.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

FIRST_DELAY_SECONDS = 600.0
MAX_DELAY_SECONDS = 86400.0
MAX_ATTEMPTS = 6
LOOKUP_KEEP_SECONDS = 30 * 86400.0
LOOKUP_EMPTY_KEEP_SECONDS = 86400.0
# Aggregation (measurement 2026-10-18): 317 of 470 requests carried a single domain, and each request had about 2300 fixed
# instruction tokens. With six domains, input per domain dropped from 2278 tokens to 525, and accuracy did not drop until 12 domains,
# beyond which it timed out. So the cycle waits until six accumulate, or ten minutes pass since the oldest.
# Measurement on Monday 2026-11-02: only 44 domains arrived in the day, so the timeout often released the batch with a single domain (49 the writer calls
# for 36 domains). So the timeout became one hour, and the domain is monitored but neither blocked nor allowed until a verdict is reached.
GATHER_SIZE = 6
GATHER_WAIT_SECONDS = 3600.0
# the judge, the decision-maker: If unavailable, usually due to hitting its daily quota, initial verdicts
# wait half an hour then double up to six hours before being presented again. The quota resets at midnight.
SONNET_FIRST_DELAY_SECONDS = 1800.0
SONNET_MAX_DELAY_SECONDS = 6 * 3600.0
# During the wait, the judge is probed with a small call every quarter hour; if it responds, review resumes immediately:
# seven transient failures kept domains "waiting for the judge" for six hours while it was responsive.
SONNET_PROBE_SECONDS = 900.0
# Search budget per day; the app stops before it with a margin.
LOOKUP_DAILY_LIMIT = 40


class ReviewMemory:
    def __init__(self, path: Path, probe: Callable[[], tuple[bool, str]] | None = None):
        self.path = Path(path)
        self.probe = probe  # Small probe call to the main model during wait (sonnet_ready)
        self.lock = threading.Lock()
        self.failures: dict[str, dict[str, float]] = {}
        self.lookups: dict[str, dict[str, Any]] = {}
        self.searches: dict[str, Any] = {"day": "", "count": 0}
        self.sonnet: dict[str, float] = {"failures": 0, "nextAt": 0.0}
        # The jurors: {"until", "reason"} as long as they have hit their daily limit (orange clock icon, 2026-11-03)
        self.jury: dict[str, Any] = {}
        # Each loop has its queue: mobile and PC share memory, so one does not erase the other's timestamps.
        self.waiting: dict[str, dict[str, float]] = {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.failures = dict(data.get("failures") or {})
            self.lookups = dict(data.get("lookups") or {})
            self.searches = dict(data.get("searches") or self.searches)
            self.sonnet = dict(data.get("sonnet") or self.sonnet)
            self.jury = dict(data.get("jury") or {})
        except (OSError, ValueError, AttributeError):
            pass

    def _save(self) -> None:
        temp = self.path.with_suffix(".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temp.write_text(
                json.dumps({"failures": self.failures, "lookups": self.lookups, "searches": self.searches, "sonnet": self.sonnet, "jury": self.jury}, ensure_ascii=False, indent=1),
                encoding="utf-8",
            )
            os.replace(temp, self.path)
        except OSError:
            pass

    # -- Failed domain ---------------------------------------------------
    def ready(self, domain: str) -> bool:
        """Is it time to review it? Those who reached the maximum wait a full day between attempts."""
        with self.lock:
            item = self.failures.get(domain)
        return not item or time.time() >= float(item.get("nextAt") or 0)

    def failed(self, domains: list[str]) -> None:
        if not domains:
            return
        now = time.time()
        with self.lock:
            for domain in domains:
                count = int((self.failures.get(domain) or {}).get("count") or 0) + 1
                delay = MAX_DELAY_SECONDS if count >= MAX_ATTEMPTS else min(
                    MAX_DELAY_SECONDS, FIRST_DELAY_SECONDS * 2 ** (count - 1)
                )
                self.failures[domain] = {"count": count, "nextAt": now + delay}
            self._save()

    def succeeded(self, domains: list[str]) -> None:
        with self.lock:
            hit = [domain for domain in domains if domain in self.failures]
            for domain in hit:
                self.failures.pop(domain, None)
            if hit:
                self._save()

    # -- the judge ------------------------------------------------------------
    def sonnet_ready(self) -> bool:
        if self.sonnet_probe_due() and self.probe is not None:
            # Probed here, not in review: those waiting are not presented for review before the timeout ends, so probing did not notify.
            try:
                ok, why = self.probe()
            except Exception as error:  # noqa: BLE001 - Probe does not crash the review
                ok, why = False, str(error)
            self.sonnet_probed(ok, why)
        with self.lock:
            return time.time() >= float(self.sonnet.get("nextAt") or 0)

    def sonnet_failed(self, reason: str = "", until: float = 0.0) -> None:
        """Transient failure: half an hour then doubling with probing every quarter hour. `until` is a daily quota that resets at a known time:
        wait until it without probing, as probing before it answers via the gateway alternative and does not reach the judge."""
        with self.lock:
            # Start of limit remains as long as capped, and new domains needing a session are counted from it
            since = self.sonnet.get("cappedAt") if self.sonnet.get("capped") else None
            count = int(self.sonnet.get("failures") or 0) + 1
            delay = min(SONNET_MAX_DELAY_SECONDS, SONNET_FIRST_DELAY_SECONDS * 2 ** (count - 1))
            self.sonnet = {"failures": count, "nextAt": until or time.time() + delay, "probedAt": time.time(),
                           "lastError": str(reason)[:200], "lastErrorAt": time.time()}
            if until:
                self.sonnet["capped"] = True
                self.sonnet["cappedAt"] = since or time.time()
            self._save()

    def sonnet_probe_due(self) -> bool:
        """During the wait, and a quarter hour has passed since the last probe."""
        with self.lock:
            if time.time() >= float(self.sonnet.get("nextAt") or 0) or self.sonnet.get("capped"):
                return False
            return time.time() - float(self.sonnet.get("probedAt") or 0) >= SONNET_PROBE_SECONDS

    def sonnet_probed(self, ok: bool, reason: str = "") -> None:
        with self.lock:
            if ok:
                self.sonnet = {"failures": 0, "nextAt": 0.0}
            else:
                self.sonnet = {**self.sonnet, "probedAt": time.time(), "lastError": str(reason)[:200] or self.sonnet.get("lastError", "")}
            self._save()

    def sonnet_answered(self) -> None:
        with self.lock:
            if self.sonnet.get("failures"):
                self.sonnet = {"failures": 0, "nextAt": 0.0}
                self._save()

    # -- Daily limit ----------------------------------------------------------
    def jury_capped(self, reason: str, until: float) -> None:
        with self.lock:
            since = self.jury.get("since") if float(self.jury.get("until") or 0) > time.time() else None
            self.jury = {"until": until, "reason": str(reason)[:200], "since": since or time.time()}
            self._save()

    def jury_answered(self) -> None:
        with self.lock:
            if self.jury:
                self.jury = {}
                self._save()

    def capped(self, now: float | None = None) -> list[str]:
        """Who from the court has hit their daily limit now, as mentioned by the orange icon tooltip."""
        now = now if now is not None else time.time()
        out = []
        with self.lock:
            if float(self.jury.get("until") or 0) > now:
                out.append("The jurors")
            if self.sonnet.get("capped") and float(self.sonnet.get("nextAt") or 0) > now:
                out.append("The judge")
        return out

    def capped_since(self, now: float | None = None) -> float:
        """First moment of the current daily limit, or 0 if no one from the court has reached it."""
        now = now if now is not None else time.time()
        starts = []
        with self.lock:
            if float(self.jury.get("until") or 0) > now:
                starts.append(float(self.jury.get("since") or now))
            if self.sonnet.get("capped") and float(self.sonnet.get("nextAt") or 0) > now:
                starts.append(float(self.sonnet.get("cappedAt") or self.sonnet.get("lastErrorAt") or now))
        return min(starts, default=0.0)

    # -- Aggregation ----------------------------------------------------------
    def hold(self, domains: list[str], queue: str = "default") -> bool:
        """Should the cycle wait? Yes as long as domains are fewer than six and less than an hour has passed since the oldest.

        In memory only: restart resets the count, so no domain waits more than an hour after that.
        """
        now = time.monotonic()
        with self.lock:
            seen = self.waiting.get(queue, {})
            waiting = {domain: seen.get(domain, now) for domain in domains}
            self.waiting[queue] = waiting
            if not domains:
                return False
            if len(domains) >= GATHER_SIZE or now - min(waiting.values()) >= GATHER_WAIT_SECONDS:
                self.waiting[queue] = {}
                return False
            return True

    # -- Search ------------------------------------------------------------
    def lookup(self, domain: str, search: Callable[[str], str]) -> str:
        """Answer cached under the domain name itself, so it is not asked again before its duration expires."""
        key = domain
        now = time.time()
        with self.lock:
            item = self.lookups.get(key)
        if item:
            keep = LOOKUP_KEEP_SECONDS if item.get("answer") else LOOKUP_EMPTY_KEEP_SECONDS
            if now - float(item.get("at") or 0) < keep:
                return str(item.get("answer") or "")
        today = time.strftime("%Y-%m-%d")
        with self.lock:
            if self.searches.get("day") != today:
                self.searches = {"day": today, "count": 0}
            if int(self.searches.get("count") or 0) >= LOOKUP_DAILY_LIMIT:
                # Reached the cap: verdict proceeds without search today, and no failure is saved so it searches tomorrow.
                return ""
            self.searches["count"] = int(self.searches.get("count") or 0) + 1
        answer = search(domain)
        with self.lock:
            self.lookups[key] = {"answer": answer, "at": now, "asked": domain}
            self._save()
        return answer

    def snapshot(self) -> dict[str, int]:
        now = time.time()
        with self.lock:
            return {
                "waiting": sum(1 for item in self.failures.values() if now < float(item.get("nextAt") or 0)),
                "atMaxAttempts": sum(1 for item in self.failures.values() if int(item.get("count") or 0) >= MAX_ATTEMPTS),
                "lookups": len(self.lookups),
                "searchesToday": int(self.searches.get("count") or 0) if self.searches.get("day") == time.strftime("%Y-%m-%d") else 0,
            }
