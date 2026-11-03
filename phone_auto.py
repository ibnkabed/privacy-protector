"""Automatic phone blocking: the providers decide, and the safety gate prevents disabling.

The user's decision: it does not intervene in domain coloring or blocking; the
models were set up for that. It falls back to manual only when an application breaks. This loop
runs in the background: it reviews every domain not yet reviewed (the writer reads, the jurors
rule, and the judge confirms), then blocks what passes the same gates as the computer
section:

- red, and safe blocking approved by the local engine (`ai_block_gate` inside the classification),
- and a verdict confirmed by the judge or issued by a dissenting one,
- and the calling application is known, or the hostname declares itself a collection point,
- and the user has no prior decision on the domain — the user's decision is never overridden.

The post-block guard lifts the automatic block alone if the safety gate later refuses it
(it turned out to be an application function), or if the phone insists on it with the urgency of
something that needs it. It never touches a block the user placed by hand.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ai_reviewer import BLOCK_AGREEMENTS
from domain_verdicts import ai_block_gate, domain_function_role, functional_purpose_veto
from pc_protection import protected_reason

CYCLE_SECONDS = 120.0
CYCLE_LIMIT = 60
RETRY_WINDOW_SECONDS = 600.0
RETRY_CALLS = 60
SOURCE = "phone-auto"


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class PhoneAutoProtection:
    def __init__(self, data_directory: Path, policy: Any, classifier: Any, reviewer: Any,
                 activity: Any, invalidate: Any = None):
        self.path = Path(data_directory) / "phone-auto-decisions.ndjson"
        self.policy = policy
        self.classifier = classifier
        self.reviewer = reviewer
        self.activity = activity
        self.invalidate = invalidate
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.state: dict[str, Any] = {
            "enabled": True, "state": "idle", "lastRunAt": "", "cycles": 0,
            "reviewed": 0, "blocked": 0, "released": 0, "lastError": "",
        }

    # -- the log -----------------------------------------------------------
    def _record(self, domain: str, action: str, reason: str, **extra: Any) -> None:
        row = {"time": _now_iso(), "domain": domain, "action": action, "reason": reason, **extra}
        with self.lock:
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    # -- the decision ------------------------------------------------------
    @staticmethod
    def _callers(entry: dict[str, Any]) -> tuple[str, ...]:
        return tuple(str(item) for item in (entry.get("appBundles") or []) if item) + tuple(
            str(item) for item in (entry.get("appContexts") or []) if item
        )

    def eligible(self, domain: str, entry: dict[str, Any]) -> tuple[bool, str]:
        verdict = entry.get("aiVerdict") if isinstance(entry.get("aiVerdict"), dict) else {}
        if verdict.get("color") != "red":
            return False, "not red"
        callers = self._callers(entry)
        if not verdict.get("blockSafe"):
            if not (verdict.get("modelBlockSafe") and verdict.get("blockVeto")):
                return False, str(verdict.get("blockVeto") or "blocking it would break a function")
            # The safety gate refused it at verdict time, and the gate learns afterward (the
            # aggregators list). So it is asked now rather than reading its saved refusal: fls-eu.amazon.sa
            # stayed open under an old block after it entered the list.
            allowed, why = ai_block_gate(domain, str(entry.get("category") or ""), callers)
            if not allowed:
                return False, why
        if verdict.get("agreement") not in BLOCK_AGREEMENTS:
            return False, "the judge did not confirm it"
        reason = protected_reason(domain)
        if reason:
            return False, "protected structure: " + reason
        vetoed, why = functional_purpose_veto(domain, callers)
        if vetoed:
            return False, why
        if not callers and domain_function_role(domain, ())[0] != "additional":
            return False, "the calling application is unknown and the name does not declare collection"
        return True, str(verdict.get("reason") or "red, confirmed by two providers, safety gate approved")

    def apply_verdicts(self) -> int:
        """Blocks every reviewed domain where the gates converge and the user has made no decision."""
        domains = self.classifier.snapshot().get("domains", {})
        existing = self.policy.snapshot().get("domains", {})
        blocked = 0
        for domain, entry in domains.items():
            if domain in existing or not isinstance(entry, dict):
                continue
            ok, reason = self.eligible(domain, entry)
            if not ok:
                continue
            verdict = entry.get("aiVerdict") or {}
            self.policy.update(
                domain, "block",
                label=str(verdict.get("category") or domain)[:120],
                note=reason[:300], source=SOURCE,
            )
            if self.invalidate:
                self.invalidate(domain)
            self._record(domain, "auto-blocked", reason, reviewers=list(verdict.get("reviewers") or []))
            blocked += 1
        return blocked

    # -- the post-block guard ----------------------------------------------
    def _recent_blocked_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        now = time.time()
        for item in self.activity.snapshot(limit=10000):
            if item.get("action") != "blocked":
                continue
            try:
                moment = datetime.fromisoformat(str(item.get("time"))).timestamp()
            except ValueError:
                continue
            if now - moment > RETRY_WINDOW_SECONDS:
                break
            domain = str(item.get("domain") or "")
            counts[domain] = counts.get(domain, 0) + 1
        return counts

    def guard(self) -> int:
        domains = self.classifier.snapshot().get("domains", {})
        policy = self.policy.snapshot().get("domains", {})
        storms = self._recent_blocked_counts()
        released = 0
        for domain, settings in policy.items():
            if settings.get("source") != SOURCE or settings.get("action") != "block":
                continue
            entry = domains.get(domain) if isinstance(domains.get(domain), dict) else {}
            vetoed, why = functional_purpose_veto(domain, self._callers(entry))
            reason = ""
            if vetoed:
                reason = "Blocking lifted automatically: " + why
            elif storms.get(domain, 0) >= RETRY_CALLS:
                reason = (
                    f"automatic block lifted: the phone retried its request {storms[domain]} times in "
                    "ten minutes, which is the urgency of an application that needs it"
                )
            if not reason:
                continue
            self.policy.update(domain, "monitor", note=reason[:300], source="phone-guard")
            if self.invalidate:
                self.invalidate(domain)
            self._record(domain, "guard-released", reason)
            released += 1
        return released

    # -- the loop ----------------------------------------------------------
    def cycle(self) -> dict[str, int]:
        self.state.update(state="running", lastRunAt=_now_iso())
        reviewed = 0
        try:
            if not getattr(self.reviewer, "running", False):
                targets = self.reviewer.candidates(CYCLE_LIMIT, "unreviewed")
                memory = getattr(self.reviewer, "memory", None)
                if targets and memory is not None and memory.hold(targets, "phone"):
                    # Domains gather into one request instead of one request per domain (review_memory.hold).
                    targets = []
                if targets:
                    result = self.reviewer.review_domains(targets)
                    reviewed = int(result.get("reviewed") or 0)
                    if not result.get("ok"):
                        self.state["lastError"] = str(result.get("error") or "")[:200]
                    else:
                        self.state["lastError"] = ""
            blocked = self.apply_verdicts()
            released = self.guard()
        except Exception as error:  # the loop must not bring down the server
            self.state.update(state="idle", lastError=str(error)[:200])
            return {"reviewed": reviewed, "blocked": 0, "released": 0}
        self.state.update(
            state="idle",
            cycles=self.state["cycles"] + 1,
            reviewed=self.state["reviewed"] + reviewed,
            blocked=self.state["blocked"] + blocked,
            released=self.state["released"] + released,
        )
        return {"reviewed": reviewed, "blocked": blocked, "released": released}

    def start(self) -> None:
        def loop() -> None:
            if self.stop_event.wait(60.0):
                return
            while not self.stop_event.is_set():
                self.cycle()
                if self.stop_event.wait(CYCLE_SECONDS):
                    return

        threading.Thread(target=loop, name="phone-auto", daemon=True).start()

    def shutdown(self) -> None:
        self.stop_event.set()

    def snapshot(self) -> dict[str, Any]:
        policy = self.policy.snapshot().get("domains", {})
        return {
            **self.state,
            "autoBlocked": sum(1 for s in policy.values() if s.get("source") == SOURCE and s.get("action") == "block"),
        }
