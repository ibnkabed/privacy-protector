"""Review service: the optional AI review of domains, with the providers you configure.

Three gates before a model's verdict becomes an approved ruling: the provider's answers are checked
against domains with known verdicts (`ai_calibration`), a blockable red must survive the jury and the
judge, and blocking is declared safe only when the local engine and the protection rules agree that
the domain is not part of what the app needs.

Measurement imposed the first gate: on the first real run, one provider marked `one.one.one.one` as
red, and two marked Apple's Private Relay, which is protection rather than a violation, as red too.
So trust is earned by results, not granted by having a key.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import ai_calibration
import ai_providers
import user_rules
import tray_icon
from review_memory import ReviewMemory
from ai_domain_review import (
    AI_REVIEW_VERSION,
    SYSTEM_PROMPT,
    BATCH_SIZE,
    TimingProfiles,
    build_evidence,
    load_timing_profiles,
    review_batch,
)
from ai_providers import AUTO, ProviderPool
import paths
from domain_verdicts import LOCAL_AGREEMENT

TIMING_MAX_AGE_SECONDS = 900.0
# Old voting task name: kept for earlier log lines.
VOTE_TASK = "Second opinion on red"
REVIEW_TASK = ai_providers.DEFAULT_TASK
# Orange items whose purpose the model could not confirm are searched for and then re-evaluated.
RESEARCH_CONFIDENCE = 70
# The court (optional, with the user's own providers; see ai_providers):
#   - Writer: reads each domain first and proposes a verdict (`auto` among writers).
#   - Jurors: decide block, monitor or allow in rotation (`auto` excluding the writer role), preferring a
#     provider other than the domain's writer.
#   - Judge: confirms or overturns the jury before anything runs, with a single batch call. It does not rule first.
# Only a verdict the judge confirmed, or issued when overturning, is enforced; without the judge the jury's
# verdict stays provisional: monitored, not blocked.
JURY_TASK = "jury verdict"
JUDGE_TASK = "judge's confirmation"
JURY_EXCLUDE = ("writer", "judge")      # role tags: makes `auto` pick among jurors
DECIDER = ai_providers.JUDGE_SLOT
DECIDER_SLOT = (DECIDER, DECIDER)
JUDGE = DECIDER


def jury_names() -> tuple[str, ...]:
    return ai_providers.role_names("juror")


def judge_names() -> tuple[str, ...]:
    return ai_providers.role_names("judge")
JUDGE_CONFIRMED = "Confirmed by judge"
JUDGE_OVERRODE = "Judge's ruling"
PENDING_JUDGE = "Awaiting judge"
PENDING_JURY = "Pending Jury"
# Legacy name for the initial state; the stored field `pendingSonnet` remains meaning 'Pending Court' because both mobile and computer read it.
# Mobile and computer read it.
PENDING_SONNET = PENDING_JUDGE
# Pre-court agreement: remaining in stored verdicts and used for blocking as before.
DECIDED_BY_SONNET = "Judge verdict"
DECISION_FIELDS = (
    "color", "confidence", "category", "purpose", "reason", "collects",
    "firstParty", "servesAppFunction", "blockSafe", "blockImpact", "provider", "model",
)
READING_FIELDS = ("color", "confidence", "purpose", "reason", "blockSafe")
# Added to the verdict criterion when jurors are consulted: they issue the initial verdict, with the writer's reading before them.
JURY_NOTE = (
    "\n\nYou are on the jury: decide for each domain whether to block, monitor, or allow. Each domain has an initial "
    "reading by the writer in the firstReading field (color, confidence, purpose, and reason). Judge by your own standard, and return your verdict for each domain "
    "in the same complete format. The writer's reading is evidence to be weighed, not a ruling to be followed. Your verdict is shown to a judge before execution."
)
# Legacy name, for importers.
DECIDER_NOTE = JURY_NOTE
# Added when the judge is consulted: they affirm or overturn the jury's verdict, but do not issue an initial verdict.
JUDGE_NOTE = (
    "\n\nYou are the judge: do not issue an initial verdict, but review the jury's verdict before execution. For each domain, you have the writer's reading in "
    "firstReading and the jury's verdict in juryVerdict. If their verdict is correct, return it with the same color (affirm); otherwise "
    "return your own verdict (overturn), and write a brief reason in 'reason' for your affirmation or overturn. If uncertain, the safer choice is monitoring "
    "(orange) rather than blocking a domain that might break an app, and blockSafe should only be true with certainty. Return the same complete format for each domain."
    " If you find a domain where you cannot make a definitive decision based on the evidence before you (contradictory evidence, or every verdict either breaks a needed "
    "app function or leaves a real tracker open, or requires the user's decision), return the safest verdict (monitoring) and add "
    "\"needsSession\": true and \"sessionNote\" with a short sentence on what needs review, and \"sessionKind\": \"conflict\" for conflict "
    "between breaking functionality and leaving a tracker, or \"owner\" for a trade-off only the user can make, or \"evidence\" if all that is missing "
    "is evidence (purpose or unknown calling program, unconfirmed ownership) and monitoring suffices until it arrives; unknown purpose is evidence, not owner. "
    "Do not add these for domains you have already decided."
)


def session_worthy(judge: dict[str, Any], votes: list[dict[str, Any]]) -> bool:
    """Does the judge's note need a human review session?

    Lack of evidence alone does not: monitoring is the safe endpoint, and the verdict is revisited when
    evidence arrives. A session is for a conflict or a user decision, for a judge note with no type next
    to a red flag from the jury or the judge or a mention of data collection, and for a writer's red that
    both reviewers overturned. A note the vote already settled does not count."""
    kind = str(judge.get("sessionKind") or "")
    if kind in {"conflict", "owner"}:
        return True
    if kind == "evidence":
        return False
    return any(str(item.get("color")) == "red" or item.get("collects") for item in [judge, *votes[1:]])
# Your own review of domains (the dashboard or `POST /api/pc/session-verdicts`): it counts as a court
# ruling, and models never send it back for review.
DECIDED_BY_SESSION = "Your ruling"
SESSION_REVIEWER = "Your review"
# What is automatically blocked on mobile and desktop: a ruling confirmed or overridden by the judge, or a your own ruling,
# and pre-court agreements in saved rulings.
BLOCK_AGREEMENTS = frozenset({JUDGE_CONFIRMED, JUDGE_OVERRODE, DECIDED_BY_SESSION, "Agreement", DECIDED_BY_SONNET,
                              LOCAL_AGREEMENT})
# What the judge has not decided in their consolidated review: stored here and the icon turns red to ask for your review,
# until the judge rules without note or the User Session handles it. Waiting for the judge itself does not color anything.
JUDGE_NOTES_PATH = paths.DATA_ROOT / "judge-notes.json"
_notes_lock = threading.Lock()


def session_notes() -> dict[str, dict[str, Any]]:
    """Judge's open notes: scope ← {note, at}."""
    try:
        data = json.loads(JUDGE_NOTES_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {key: value for key, value in data.items() if isinstance(value, dict)} if isinstance(data, dict) else {}


def _set_session_note(domain: str, note: str | None) -> None:
    with _notes_lock:
        notes = session_notes()
        if note is None:
            if domain not in notes:
                return
            notes.pop(domain)
        else:
            notes[domain] = {"note": note, "at": _stamp()}
        try:
            JUDGE_NOTES_PATH.parent.mkdir(parents=True, exist_ok=True)
            JUDGE_NOTES_PATH.write_text(json.dumps(notes, ensure_ascii=False, indent=1), encoding="utf-8")
        except OSError:
            pass


def clear_session_note(domain: str) -> None:
    """Ruled by User Session or Judge without note: no intervention required."""
    _set_session_note(str(domain).strip().lower().rstrip("."), None)


# The judge is asked about rulings collectively, not individually: Jury verdicts remain provisional
# 'Awaiting Judge' (monitored but not blocked) until a full batch accumulates or an hour passes since the oldest, then all are presented
# with calls from twelve. Measurement from work log: about 250 decisions per day, and half of review calls
# are single-scope; thus, ruling with each batch was about 91 calls per day, and an hour makes it about 26 with an average wait of fifteen minutes,
# half an hour about 32, and two hours only about 23. And 12 is the approved batch ceiling, so it is not raised without measurement.
JUDGE_BATCH = 12
JUDGE_WINDOW_SECONDS = 3600.0


def risk_priority(verdict: Any, risk: Any = "") -> int:
    """Display order for the judge: initial red, then orange, then the rest.

    A busy day can use up the app's daily model budget before midnight, so the order puts what matters
    first instead of ordering by call count alone, which once let green domains use the share while a red waited."""
    color = (verdict or {}).get("color") if isinstance(verdict, dict) else ""
    return {"red": 2, "orange": 1}.get(str(color or risk or ""), 0)


def decided_by_main(verdict: Any) -> bool:
    """Ruling confirmed by the judge (main model) or User Session; everything else is returned to court."""
    return isinstance(verdict, dict) and (
        verdict.get("decidedBy") in (DECIDER, *judge_names()) or verdict.get("agreement") == DECIDED_BY_SESSION
    )


def jury_age(verdict: Any) -> float:
    """Seconds elapsed since the saved jury verdict; what was saved before `juryAt` is considered old and displayed first."""
    try:
        return time.time() - datetime.fromisoformat(str((verdict or {}).get("juryAt"))).timestamp()
    except (ValueError, TypeError, AttributeError):
        return float("inf")


def judge_due(waiting: list[Any]) -> bool:
    """Is it time to present those awaiting to the judge? A full batch, or the window has passed for the oldest."""
    waiting = [item for item in waiting if isinstance(item, dict)]
    if not waiting:
        return False
    return len(waiting) >= JUDGE_BATCH or max(jury_age(item) for item in waiting) >= JUDGE_WINDOW_SECONDS


def awaits_judge(verdict: Any) -> bool:
    """Preliminary verdict that already has the jury verdict, only the judge is missing."""
    return isinstance(verdict, dict) and bool(verdict.get("pendingSonnet")) and isinstance(verdict.get("jury"), dict)


SEVERITY = {"green": 0, "orange": 1, "red": 2}
COLOR_NAMES = {"green": "Green", "orange": "Orange", "red": "Red"}


def _reading(item: dict[str, Any]) -> dict[str, Any]:
    """Summary of a verdict shown to later reviewers, along with who issued it."""
    out = {key: item.get(key) for key in READING_FIELDS}
    out["provider"] = str(item.get("provider", ""))
    if item.get("model"):
        out["model"] = str(item.get("model"))
    return out


def _haiku_reading(verdict: dict[str, Any]) -> dict[str, Any]:
    """The writer's reading: kept in `firstReading` if the verdict went through the jury, otherwise the verdict itself."""
    saved = verdict.get("firstReading")
    return dict(saved) if isinstance(saved, dict) else _reading(verdict)


def _for_prompt(reading: dict[str, Any]) -> dict[str, Any]:
    return {key: reading.get(key) for key in READING_FIELDS}


def court_verdict(
    domain: str, verdict: dict[str, Any], jury: dict[str, Any] | None, judge: dict[str, Any] | None
) -> dict[str, Any]:
    """The court's verdict on a domain.

    `verdict` is the writer's reading (the writer), or a saved preliminary verdict containing `firstReading`
    and `jury`. `jury` is the jury's verdict and `judge` is the judge's verdict. Without a jury it stays
    preliminary "awaiting the jury", and without a judge "awaiting the judge"; both are monitored and not
    blocked (`pendingSonnet`). If the judge answers with the same color it has confirmed, and blocking is
    safe if both of them secure it together; if it disagrees, its verdict is the one adopted. The user's
    rules and the safety gate's rules still apply above all of this.
    """
    reading = _haiku_reading(verdict)
    first_color = str(reading.get("color", ""))
    # What the store derives from a previous verdict (apply_ai_verdict) is recomputed from the court's verdict,
    # otherwise the safety of the preliminary verdict (false) would remain in `modelBlockSafe` and block
    # what the judge had confirmed.
    for key in ("modelBlockSafe", "localBlockSafe", "blockVeto", "applied", "appliedReason", "judgeReason"):
        verdict.pop(key, None)
    verdict["firstReading"] = reading
    votes = [reading]
    if jury is not None:
        jury = {key: jury[key] for key in DECISION_FIELDS if key in jury}
        votes.append(jury)
    if judge is not None and jury is not None:
        worthy = judge.get("needsSession") and session_worthy(judge, votes)
        note = str(judge.get("sessionNote") or "verdict not settled by the judge") if worthy else None
        _set_session_note(domain, note)
        if note:
            verdict["needsSession"], verdict["sessionNote"] = True, note
        else:
            verdict.pop("needsSession", None)
            verdict.pop("sessionNote", None)
        judge = {key: judge[key] for key in DECISION_FIELDS if key in judge}
        votes.append(judge)
    verdict["reviewers"] = [str(item.get("provider", "")) for item in votes]
    verdict["votes"] = [
        {
            "provider": str(item.get("provider", "")),
            "color": item.get("color", ""),
            "confidence": item.get("confidence", 0),
            "blockSafe": bool(item.get("blockSafe")),
        }
        for item in votes
    ]
    if jury is None:
        verdict.pop("jury", None)
        verdict["agreement"] = PENDING_JURY
        verdict["pendingSonnet"] = True
        verdict.setdefault("pendingAt", _stamp())   # stable across redisplays: the new domain's daily limit is known from it
        verdict["blockSafe"] = False
        verdict["vote"] = "awaiting the jury verdict"
        return verdict
    for key in DECISION_FIELDS:
        if key in jury:
            verdict[key] = jury[key]
    verdict["jury"] = jury
    verdict["juryBy"] = str(jury.get("provider", ""))
    verdict.setdefault("juryAt", _stamp())
    if judge is None:
        verdict.pop("judge", None)
        verdict["agreement"] = PENDING_JUDGE
        verdict["pendingSonnet"] = True
        verdict.setdefault("pendingAt", _stamp())
        verdict["blockSafe"] = False
        verdict["vote"] = "awaiting confirmation from the judge"
        return verdict
    confirmed = judge.get("color") == jury.get("color")
    verdict["judge"] = judge
    if confirmed:
        # Confirmed: the jury's verdict stands, and blocking is safe if both secure it together (the safer choice on a disagreement about safety).
        verdict["blockSafe"] = bool(jury.get("blockSafe")) and bool(judge.get("blockSafe"))
        verdict["judgeReason"] = str(judge.get("reason", ""))
    else:
        for key in DECISION_FIELDS:
            if key in judge:
                verdict[key] = judge[key]
    verdict.pop("pendingSonnet", None)
    verdict.pop("juryAt", None)
    verdict.pop("pendingAt", None)
    verdict["decidedBy"] = DECIDER
    verdict["agreement"] = JUDGE_CONFIRMED if confirmed else JUDGE_OVERRODE
    verdict["vote"] = (
        COLOR_NAMES.get(str(reading.get("color")), "?") + " writer " + str(reading.get("provider", ""))
        + " ← " + COLOR_NAMES.get(str(jury.get("color")), "?") + " jury " + str(jury.get("provider", ""))
        + " ← " + COLOR_NAMES.get(str(judge.get("color")), "?") + " judge " + str(judge.get("provider", ""))
        + (" (confirmed)" if confirmed else " (overrode)")
    )
    if verdict.get("color") != "red":
        verdict["blockSafe"] = False
    try:
        import model_ledger

        model_ledger.record_judgement(domain, jury, judge, confirmed)
        if first_color == "red":
            # Confirming or overturning the first red verdict, as it was recorded before.
            model_ledger.record_confirmation(domain, dict(verdict), verdict["color"] == "red", verdict["vote"], verdict["color"])
    except Exception:  # noqa: BLE001 - the ledger does not affect the decision
        pass
    return verdict
def tally_votes(domain: str, verdict: dict[str, Any], answers: list[dict[str, Any]]) -> dict[str, Any]:
    """Old name: Ruling without jury or judge remains provisional. The active path is `court_verdict`."""
    return court_verdict(domain, verdict, None, None)


def _stamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


# Reserved names that are never resolved to a server (RFC 2606 and RFC 6761): not presented to models, as asking about them is pointless expenditure
#.
# And DNS responds with NXDOMAIN as before, so leaving it has no impact on protection.
RESERVED_SUFFIXES = (".invalid", ".test", ".example", ".localhost", ".onion", ".home.arpa")


def reserved_name(domain: str) -> bool:
    clean = str(domain or "").strip().lower().rstrip(".")
    return any(clean == suffix[1:] or clean.endswith(suffix) for suffix in RESERVED_SUFFIXES)


def _clean_domains(domains: Any) -> list[str]:
    items = [str(item).strip().lower().rstrip(".") for item in (domains or [])]
    return list(dict.fromkeys(item for item in items if item))


class DomainAIReviewer:
    """Connects trusted providers to the classification engine and guards the blocking decision."""

    def __init__(
        self,
        data_directory: Path,
        classifier: Any = None,
        pool: ProviderPool | None = None,
        allow_paid: bool = True,
    ):
        self.data_directory = Path(data_directory)
        self.classifier = classifier
        self.memory = ReviewMemory(
            self.data_directory / "review-memory.json",
            probe=lambda: ProviderPool(slots=(DECIDER_SLOT,), allow_paid=True).probe_model((judge_names() or (DECIDER,))[0]),
        )
        # Your providers give the writer's reading, the jury's verdict and the judge's confirmation;
        # `allow_paid` remains for testing a model by name only.
        self.allow_paid = bool(allow_paid)
        self.lock = threading.Lock()
        self.pool = pool
        self.trusted: list[str] = []
        self.timing: TimingProfiles | None = None
        self.timing_loaded_at = 0.0
        self.running = False
        self.stop_flag = threading.Event()
        self.progress: dict[str, Any] = {
            "state": "idle",
            "requested": 0,
            "reviewed": 0,
            "changed": 0,
            "failed": 0,
            "startedAt": "",
            "finishedAt": "",
            "lastDomain": "",
        }

    # -- Initialization ----------------------------------------------------------
    def ensure_pool(self, refresh: bool = False) -> ProviderPool:
        """Single `auto` slot: the provider layer rotates among your writers with each request.

        The model check informs you; it does not remove a provider. Turn one off in Settings instead.
        """
        if refresh:
            ai_calibration.recalibrate(self.data_directory, allow_paid=self.allow_paid)
        if self.pool is None or refresh or not self.trusted:
            self.pool = ProviderPool(slots=((AUTO, AUTO),), allow_paid=True)
            self.trusted = [state.slot for state in self.pool.states]
        return self.pool

    def ensure_timing(self, maximum_age_seconds: float = TIMING_MAX_AGE_SECONDS) -> TimingProfiles:
        if self.timing is None or (time.time() - self.timing_loaded_at) > maximum_age_seconds:
            self.timing = load_timing_profiles(self.data_directory)
            self.timing_loaded_at = time.time()
        return self.timing

    def calibrate(self, refresh: bool = True) -> dict[str, Any]:
        self.ensure_pool(refresh=refresh)
        return self.status()

    def status(self) -> dict[str, Any]:
        state = ai_calibration.load_state(self.data_directory)
        providers = state.get("providers", {})
        with self.lock:
            progress = dict(self.progress)
        return {
            "version": AI_REVIEW_VERSION,
            # The provider layer picks a configured provider with each request.
            "available": ai_providers.enabled(),
            "trusted": [AUTO],
            "slots": [
                {
                    "slot": item.get("slot", ""),
                    "provider": item.get("provider", ""),
                    "model": item.get("model", ""),
                    "score": item.get("score", 0),
                    "passed": item.get("passed", False),
                    "answered": item.get("answered", 0),
                    "expected": item.get("expected", 0),
                }
                for item in (state.get("slots") or [])
            ],
            "calibratedAt": state.get("calibratedAt", ""),
            "passScore": state.get("passScore", 0),
            "benchmark": state.get("benchmark", 0),
            "scores": {
                name: {
                    "score": item.get("score", 0),
                    "passed": item.get("passed", False),
                    "model": item.get("model", ""),
                    "seconds": item.get("seconds", 0),
                    "mistakes": len(item.get("mistakes", [])),
                    "reachable": item.get("reachable", True),
                    "answered": item.get("answered", 0),
                    "expected": item.get("expected", 0),
                }
                for name, item in providers.items()
            },
            "runtime": self.pool.snapshot() if self.pool else {"providers": [], "ready": 0, "total": 0},
            "progress": progress,
            "configured": ai_providers.enabled(),
        }

    # -- Review ---------------------------------------------------------
    def _packets(self, domains: list[str]) -> list[dict[str, Any]]:
        timing = self.ensure_timing()
        packets = []
        for domain in domains:
            entry = self.classifier.get(domain) if self.classifier else None
            packets.append(build_evidence(domain, entry or {"domain": domain}, timing.profile(domain)))
        return packets

    def _ask(
        self, packet: dict[str, Any], extra: dict[str, Any], exclude: tuple[str, ...], task: str = VOTE_TASK
    ) -> dict[str, Any] | None:
        pool = ProviderPool(slots=((AUTO, AUTO),), allow_paid=True, task=task)
        if not pool.states:
            return None
        result = review_batch(pool, [packet], maximum_wait=30.0, exclude=exclude, **extra)
        return result.get("verdicts", {}).get(packet["domain"])

    def research(
        self, packet: dict[str, Any], verdict: dict[str, Any], system_prompt: str = ""
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Suspicious orange: the model did not confirm its purpose. It is searched once, then re-evaluated based on search results.

        Search history is kept for thirty days with a daily limit (`review_memory`), and a searched domain
        is not searched again. If search or new judgment fails, the original judgment stands.
        """
        if (
            verdict.get("color") != "orange"
            or int(verdict.get("confidence") or 0) >= RESEARCH_CONFIDENCE
            or packet.get("webSearch")
        ):
            return packet, verdict
        found = self.memory.lookup(packet["domain"], ai_providers.web_lookup)
        if not found:
            return packet, verdict
        packet = {**packet, "webSearch": found}
        extra = {"system_prompt": system_prompt} if system_prompt else {}
        again = self._ask(packet, extra, (), task=REVIEW_TASK)
        if not again:
            return packet, verdict
        again["researched"] = True
        return packet, again

    def decide_batch(
        self, packets: list[dict[str, Any]], firsts: dict[str, dict[str, Any]], system_prompt: str = ""
    ) -> dict[str, dict[str, Any]]:
        """Full-batch court session: jurors called once, then the judge called once.

        `firsts` are writer readings, or preliminary judgments stored in `jury` so jurors are not asked again.
        Red items undefined by their public page are searched before jury review.
        1. Jury: the jurors via `auto` excluding the writer role (`exclude`), with each domain's writer reading.
        2. The judge: given evidence, writer reading, and jury verdicts to confirm or overturn each judgment.
        If the judge is unavailable, judgments remain preliminary 'awaiting judge' with the jury verdict preserved, and presented to him alone
        when he returns (`review_memory`). Nothing is presented to the judge unless the jury has ruled.
        """
        prompt = system_prompt or SYSTEM_PROMPT
        packets_by: dict[str, dict[str, Any]] = {}
        jury_asked: list[dict[str, Any]] = []
        juries: dict[str, dict[str, Any]] = {}
        for packet in packets:
            domain = packet["domain"]
            first = firsts.get(domain)
            if not first:
                continue
            if (first.get("color") == "red" and not packet.get("pageTitle")
                    and not packet.get("pageDescription") and not packet.get("webSearch")):
                found = self.memory.lookup(domain, ai_providers.web_lookup)
                if found:
                    packet = {**packet, "webSearch": found}
            packets_by[domain] = packet
            if isinstance(first.get("jury"), dict) and first["jury"].get("color") in SEVERITY:
                juries[domain] = dict(first["jury"])   # Jury verdict preserved: judge only
            else:
                jury_asked.append({**packet, "firstReading": _for_prompt(_haiku_reading(first))})
        tray_icon.decision_started()  # Icon stays green while the court is ruling
        judged: dict[str, dict[str, Any]] = {}
        try:
            if jury_asked:
                juries.update(self._jury(jury_asked, prompt, firsts))
            to_judge = [
                {**packets_by[domain], "firstReading": _for_prompt(_haiku_reading(firsts[domain])),
                 "juryVerdict": _for_prompt(juries[domain])}
                for domain in packets_by if domain in juries
            ]
            # Judge handles all pending cases together (JUDGE_WINDOW_SECONDS), prioritizing red items if quota is tight.
            waiting = [firsts[item["domain"]] if "jury" in firsts[item["domain"]] else {"juryAt": _stamp()}
                       for item in to_judge]
            if to_judge and judge_due(waiting) and self.memory.sonnet_ready():
                to_judge.sort(key=lambda item: -risk_priority(juries[item["domain"]]))
                for start in range(0, len(to_judge), JUDGE_BATCH):
                    judged.update(self._judge(to_judge[start:start + JUDGE_BATCH], prompt))
                    if not self.memory.sonnet_ready():
                        break
        finally:
            tray_icon.decision_finished(bool(judged))
        finals: dict[str, dict[str, Any]] = {}
        for domain, first in firsts.items():
            finals[domain] = court_verdict(domain, dict(first), juries.get(domain), judged.get(domain))
        # During the daily limit, new preliminary judgments turn red immediately for session processing
        if any(item.get("pendingSonnet") for item in finals.values()) and self.memory.capped():
            tray_icon.poke()
        return finals

    def _jury(
        self, asked: list[dict[str, Any]], prompt: str, firsts: dict[str, dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        """The jurors take turns through the configured providers. The provider that wrote the first pass is
        skipped when another is available, so the verdict comes from someone other than the writer."""
        readers = {str((firsts.get(item["domain"]) or {}).get("provider", "")) for item in asked}
        jury = jury_names()
        exclude = JURY_EXCLUDE + tuple(sorted(name for name in readers if name in jury))
        if not set(jury) - set(exclude):
            exclude = JURY_EXCLUDE
        pool = ProviderPool(slots=((AUTO, AUTO),), allow_paid=True, task=JURY_TASK)
        if not pool.states:
            return {}
        out: dict[str, dict[str, Any]] = {}
        others: set[str] = set()
        errors: list[str] = []
        for start in range(0, len(asked), BATCH_SIZE):
            result = review_batch(pool, asked[start:start + BATCH_SIZE], maximum_wait=60.0,
                                  system_prompt=prompt + JURY_NOTE, exclude=exclude)
            errors += [str(e) for e in result.get("errors") or []]
            for domain, verdict in (result.get("verdicts") or {}).items():
                by = str(verdict.get("provider", ""))
                if by and by not in jury:
                    others.add(by)
                else:
                    out[domain] = verdict
        # Today's limit for the orange icon: no juror answered and every failure was a daily limit.
        # One answer clears it; otherwise it expires at midnight.
        if any(str(v.get("provider", "")) in jury for v in out.values()):
            self.memory.jury_answered()
        elif others or (errors and all(ai_providers.is_daily_cap(e) or "Suspended until midnight" in e
                                       or "Bypassed by gateway" in e for e in errors)):
            reason = f"answered by the fallback {', '.join(sorted(others))}" if others else "; ".join(errors)
            self.memory.jury_capped(reason, ai_providers.next_local_midnight())
        return out

    def _judge(self, asked: list[dict[str, Any]], prompt: str) -> dict[str, dict[str, Any]]:
        """The judge, with a single call. No verdict from a provider without the judge role is accepted as the judge's."""
        pool = ProviderPool(slots=(DECIDER_SLOT,), allow_paid=True, task=JUDGE_TASK)
        result = review_batch(pool, asked, maximum_wait=60.0, system_prompt=prompt + JUDGE_NOTE) if pool.states else {}
        answers = {
            domain: verdict for domain, verdict in (result.get("verdicts") or {}).items()
            if str(verdict.get("provider", "")) in judge_names()
        }
        if answers:
            self.memory.sonnet_answered()
        else:
            errors = (result.get("errors") if isinstance(result, dict) else None) or []
            reason = "; ".join(str(e) for e in errors)[:200] or ("No slot" if not pool.states else "No verdict in response")
            # The daily quota resets at midnight: it waits until then without checking or calling, not half an hour but double that.
            capped = ai_providers.is_daily_cap(reason) or "Suspended until midnight" in reason
            self.memory.sonnet_failed(reason, until=ai_providers.next_local_midnight() if capped else 0.0)
        return answers

    def review_domains(
        self,
        domains: Any,
        consensus: bool = True,
        apply_result: bool = True,
    ) -> dict[str, Any]:
        targets = [domain for domain in _clean_domains(domains) if not reserved_name(domain)]
        if not targets:
            return {"ok": True, "reviewed": 0, "changed": 0, "verdicts": []}
        self.ensure_pool()
        if not self.trusted:
            return {"ok": False, "error": "Gateway slot unavailable", "reviewed": 0, "verdicts": []}

        applied: list[dict[str, Any]] = []
        counters = {"changed": 0}
        # What awaits the court is not read again: its saved reading (and the jurors' verdict if found) is shown to whoever remains.
        stored = self.classifier.snapshot().get("domains", {}) if self.classifier else {}
        waiting = [
            domain for domain in targets
            if isinstance((stored.get(domain) or {}).get("aiVerdict"), dict)
            and stored[domain]["aiVerdict"].get("pendingSonnet")
        ]
        if waiting and consensus:
            # All waiting items are handled in a single call: the judge rules on them collectively (JUDGE_BATCH), while jurors work in batches.
            batch = self._packets(waiting)
            firsts = {}
            for packet in batch:
                first = dict(stored[packet["domain"]]["aiVerdict"])
                for key in ("agreement", "vote", "votes", "reviewers", "reviewedAt", "pendingSonnet", "applied"):
                    first.pop(key, None)
                firsts[packet["domain"]] = first
            by_domain = {packet["domain"]: packet for packet in batch}
            for domain, verdict in self.decide_batch(batch, firsts).items():
                self._finalize(domain, by_domain[domain], verdict, consensus, apply_result, counters, applied)
            targets = [domain for domain in targets if domain not in waiting]
        packets = self._packets(targets)
        index = {packet["domain"]: packet for packet in packets}
        batches = [packets[start : start + BATCH_SIZE] for start in range(0, len(packets), BATCH_SIZE)]
        # Batches are distributed across authorized providers together: a single provider makes a thousand domains
        # take a full hour, and progress is committed batch by batch so the user sees movement immediately.
        workers = max(1, min(len(self.trusted), len(batches), 4))
        queue_lock = threading.Lock()
        pending = list(batches)

        attempts: dict[int, int] = {}

        def consume() -> None:
            while not self.stop_flag.is_set():
                with queue_lock:
                    if not pending:
                        return
                    batch = pending.pop(0)
                result = review_batch(self.pool, batch)
                if not result.get("verdicts"):
                    # A batch returned empty because all providers reached their limit at the same
                    # moment. It is returned to the end of the queue twice before being marked as failed,
                    # otherwise hundreds of domains would drop in seconds without review.
                    key = id(batch)
                    attempts[key] = attempts.get(key, 0) + 1
                    if attempts[key] <= 2 and self.pool.wait_for_capacity():
                        with queue_lock:
                            pending.append(batch)
                        continue
                verdicts = dict(result.get("verdicts", {}))
                # Items dropped from a failed batch are retried individually once before being considered failed.
                for domain in result.get("missing", []) or []:
                    if self.stop_flag.is_set() or domain in verdicts or domain not in index:
                        continue
                    verdicts.update(review_batch(self.pool, [index[domain]]).get("verdicts", {}))
                packets_now: dict[str, dict[str, Any]] = {}
                for domain in list(verdicts):
                    packets_now[domain], verdicts[domain] = self.research(index[domain], verdicts[domain])
                if consensus:
                    verdicts = self.decide_batch([packets_now[domain] for domain in verdicts], verdicts)
                for domain, verdict in verdicts.items():
                    self._finalize(domain, packets_now[domain], verdict, consensus, apply_result, counters, applied)

        threads = [threading.Thread(target=consume, daemon=True) for _ in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        with self.lock:
            self.progress["changed"] = self.progress.get("changed", 0) + counters["changed"]
        done = {str(item.get("domain") or "") for item in applied}
        self.memory.succeeded(sorted(done))
        if not self.stop_flag.is_set():
            self.memory.failed([domain for domain in targets if domain not in done])
        return {
            "ok": True,
            "reviewed": len(applied),
            "changed": counters["changed"],
            "requested": len(targets),
            "verdicts": applied,
        }

    def reconfirm(self, domain: str) -> tuple[dict[str, Any], bool] | None:
        """Re-runs the court on a preserved red flag or preliminary verdict without a new first-pass reading (for example from the review tools).

        Does nothing if the preserved verdict is neither red nor preliminary. Otherwise (the verdict after the court, and whether the judge ruled). What the
        jurors ruled on is presented to the judge alone.
        """
        entry = (self.classifier.get(domain) if self.classifier else None) or {}
        verdict = dict(entry.get("aiVerdict") or {})
        if verdict.get("color") != "red" and not verdict.get("pendingSonnet"):
            return None
        for key in ("agreement", "vote", "votes", "reviewers", "reviewedAt", "pendingSonnet"):
            verdict.pop(key, None)
        verdict["domain"] = domain
        packet = self._packets([domain])[0]
        confirmed = self.decide_batch([packet], {domain: verdict}).get(domain) or verdict
        # What the jurors ruled on and is awaiting the judge's schedule (JUDGE_WINDOW_SECONDS) may have been answered: its time is multiplied, not stalled.
        answered = confirmed.get("agreement") != PENDING_JURY and (
            confirmed.get("agreement") != PENDING_JUDGE or self.memory.sonnet_ready()
        )
        applied: list[dict[str, Any]] = []
        self._finalize(domain, packet, confirmed, False, True, {"changed": 0}, applied)
        return (applied[-1] if applied else confirmed), answered

    def _finalize(
        self,
        domain: str,
        packet: dict[str, Any],
        verdict: dict[str, Any],
        consensus: bool,
        apply_result: bool,
        counters: dict[str, int],
        applied: list[dict[str, Any]],
    ) -> None:
        if not consensus and not verdict.get("agreement"):
            # Review requested without court: its ruling is preliminary and not used for blocking.
            verdict = court_verdict(domain, verdict, None, None)
        verdict.setdefault("reviewers", [verdict.get("provider", "")])
        # The user's rules override model rulings and their votes: their consensus does not overturn them.
        entry = (self.classifier.get(domain) if self.classifier else None) or {}
        callers = tuple(str(item) for item in (entry.get("appBundles") or []) if item) + tuple(
            str(item) for item in (entry.get("appContexts") or []) if item
        )
        verdict = user_rules.enforce(domain, verdict, callers, str(entry.get("category") or ""))
        verdict["reviewedAt"] = _stamp()
        verdict["reviewVersion"] = AI_REVIEW_VERSION
        if apply_result and self.classifier is not None:
            outcome = self.classifier.apply_ai_verdict(domain, verdict)
            if outcome and outcome.get("changed"):
                with self.lock:
                    counters["changed"] += 1
            if outcome and outcome.get("verdict"):
                verdict = outcome["verdict"]
        verdict.setdefault("domain", domain)
        with self.lock:
            applied.append(verdict)
            self.progress["reviewed"] = self.progress.get("reviewed", 0) + 1
            self.progress["lastDomain"] = domain

    # -- Blocking list rules that may break an app ---------------------------------
    def block_risks(self, policy_domains: dict[str, Any]) -> list[dict[str, Any]]:
        """Active blocking rules that the safety gate must not block.

        The gate was added after some of these were blocked, so some predate it. They are displayed for the
        user to decide: blocking maps, health, or settings ranges is silent disruption, not protection.
        """
        from domain_verdicts import functional_purpose_veto

        if self.classifier is None:
            return []
        snapshot = self.classifier.snapshot().get("domains", {})
        rows: list[dict[str, Any]] = []
        for domain, settings in (policy_domains or {}).items():
            if not isinstance(settings, dict) or settings.get("action") != "block":
                continue
            entry = snapshot.get(domain) if isinstance(snapshot.get(domain), dict) else {}
            callers = tuple(
                str(item) for item in (entry.get("appBundles") or []) if item
            ) + tuple(str(item) for item in (entry.get("appContexts") or []) if item)
            vetoed, reason = functional_purpose_veto(domain, callers)
            if not vetoed:
                continue
            rows.append(
                {
                    "domain": domain,
                    "reason": reason,
                    "hits": int(entry.get("hits") or 0),
                    "callers": list(dict.fromkeys(callers))[:6],
                    "risk": str(entry.get("risk") or "unclassified"),
                    "label": str(settings.get("label") or domain),
                }
            )
        rows.sort(key=lambda item: -item["hits"])
        return rows

    # -- Large batch in the background -------------------------------------------
    def candidates(self, limit: int = 200, scope: str = "unreviewed") -> list[str]:
        if self.classifier is None:
            return []
        snapshot = self.classifier.snapshot().get("domains", {})
        sonnet_ready = self.memory.sonnet_ready()
        # What only the judge lacks is not displayed until its time (judge_due), then shown together.
        judge_now = judge_due([entry.get("aiVerdict") for entry in snapshot.values()
                               if isinstance(entry, dict) and awaits_judge(entry.get("aiVerdict"))])
        rows: list[tuple[int, str]] = []
        for domain, entry in snapshot.items():
            if not isinstance(entry, dict) or reserved_name(domain):
                continue
            verdict = entry.get("aiVerdict")
            # A non-primary model ruling is not considered a review: it is displayed on the primary as if unreviewed.
            reviewed = isinstance(verdict, dict) and verdict.get("color") and (
                decided_by_main(verdict) or verdict.get("pendingSonnet")
            )
            waiting = bool(reviewed and verdict.get("pendingSonnet") and sonnet_ready
                           and (judge_now or not awaits_judge(verdict)))
            if scope in {"unreviewed", "weak"} and reviewed and not waiting:
                continue
            if scope == "weak" and entry.get("category") not in {"general_network", "unclassified"}:
                continue
            if scope == "red" and entry.get("risk") != "red":
                continue
            if not self.memory.ready(domain):
                continue
            rows.append((risk_priority(verdict, entry.get("risk")), int(entry.get("hits") or 0), domain))
        rows.sort(reverse=True)
        return [domain for *_, domain in rows[: max(0, int(limit))]]

    def start_background(self, limit: int = 200, scope: str = "unreviewed") -> dict[str, Any]:
        with self.lock:
            if self.running:
                return {"ok": False, "error": "A review is already in progress", "progress": dict(self.progress)}
            self.running = True
            self.stop_flag.clear()
            self.progress = {
                "state": "running",
                "requested": 0,
                "reviewed": 0,
                "changed": 0,
                "failed": 0,
                "startedAt": _stamp(),
                "finishedAt": "",
                "lastDomain": "",
                "scope": scope,
            }

        def worker() -> None:
            try:
                targets = self.candidates(limit, scope)
                with self.lock:
                    self.progress["requested"] = len(targets)
                result = self.review_domains(targets)
                with self.lock:
                    self.progress["failed"] = max(0, len(targets) - int(result.get("reviewed", 0)))
                    if not result.get("ok"):
                        self.progress["error"] = str(result.get("error", ""))[:200]
            except Exception as error:  # A failed review must not crash the server
                with self.lock:
                    self.progress["error"] = str(error)[:200]
            finally:
                with self.lock:
                    self.running = False
                    self.progress["state"] = "stopped" if self.stop_flag.is_set() else "done"
                    self.progress["finishedAt"] = _stamp()

        threading.Thread(target=worker, name="ai-domain-review", daemon=True).start()
        return {"ok": True, "progress": dict(self.progress)}

    def stop(self) -> dict[str, Any]:
        self.stop_flag.set()
        with self.lock:
            return {"ok": True, "progress": dict(self.progress)}
