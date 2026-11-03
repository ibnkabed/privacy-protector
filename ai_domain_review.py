"""AI review of domains according to the app's color standard.

The baseline engine judges from the domain name and `regex` pattern, so it makes two errors: it
paints every name without a signal in it green "public network", hiding real tracking, and it
escapes to orange when unsure, inflating the project. This layer reads what has actually been
collected — the TLS certificate, the public page address, the CNAME chain, the timing pattern and
the number of shared apps — and asks the model for an explicit verdict in one of three colors,
with the reason and the blocking impact.

What is sent to the provider: the domain name, public data about it, and aggregated figures. App
names, bundle identifiers, the device address and any statement concerning the user are never sent.
"""

from __future__ import annotations

import json
import re
import threading
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

import user_rules
from ai_providers import ProviderPool, extract_json
from domain_verdicts import caller_purpose, domain_function_role

ROLE_LABELS = {
    "function": "locally appears to be part of the app's function",
    "additional": "locally appears to be additional to the app's function",
    "unknown": "",
}

AI_REVIEW_VERSION = 1
BATCH_SIZE = 6
MAX_TOKENS = 3400

COLORS = ("green", "orange", "red")
COLOR_LABELS = {
    "green": "green — functional and does not infringe on privacy",
    "orange": "orange — suspicious, warrants monitoring without certainty of a privacy violation",
    "red": "red — tracking or a clear privacy infringement",
}

SYSTEM_PROMPT = """You are a network privacy auditor. You are shown DNS domains observed by an iPhone, together with what has been collected about them from public sources and aggregated figures. Your task is one verdict per domain, in one of three colors, along with the reason and the blocking impact.

The color standard — adhere to it literally and do not use any other standard:

Green: an explicit instant use that the user requests and sees at that very moment, or infrastructure without which the service breaks. Clarity of the moment makes the domain green even if the permission is sensitive: an attendance app that reveals the location at the moment of check-in and then stops is green, not orange.

Red: access to device data or settings, tracking inspection and jailbreak detection, developer-mode detection, background monitoring without any action by the user, bulk retrieval of historical archives and old data, advertising, install attribution, behavioral analytics, and selling or sharing data with brokers.

Orange: a real doubt that cannot be settled by what is displayed. It is not an escape from deciding: if the evidence suffices for a verdict, then decide. Do not paint a domain green merely because its name is free of any tracking signal — if the evidence is insufficient, it is orange, not green.

Verdict rules:
- A third-party domain whose endpoint many unrelated apps call is a bundled tracking kit (SDK), not a primary service, and this tilts toward red.
- A regular pulse spread across the day and during sleeping hours = background monitoring = red. Bursts tied to the user's session = functional use.
- A CNAME chain that ends at an advertising network or measurement platform reveals the real purpose regardless of how innocent the visible name is.
- An unidentified edge domain of a content delivery network — an automatically generated name on akamai, cloudfront, fastly, edgekey, llnwd or similar — with no evidence assigning its owner: its verdict is orange and blockSafe=false. Judging it red is condemnation without grounds, and blocking it may break the loading of the app's content. But if the name or the CNAME chain reveals the service's owner, judge the owner, not the network.
- Do not raise confidence above 60 when the evidence is the domain name alone, with no certificate, page or chain.
- The device and system infrastructure is not a subject of privacy verdicts: public DNS resolvers, push notification delivery, certificate checks (OCSP and CRL), app stores, cloud synchronization, and public service endpoints that apps build on, such as googleapis, gstatic and akamai, serve the system. Their color is always green and blockSafe=false, because blocking them cuts the service off from the user, not from the tracker.
- A service that hides the user's identity or protects their connection — a private relay, a virtual network or a tracker blocker — is green, as it is protection, not infringement, even if its activity is regular and in the background.
- **One app calls two kinds of domains, so distinguish between them and do not treat them as one block.** The first kind are domains through which its purpose for which it was installed is carried out; blocking them disables it. The second kind are domains additional to that purpose, unrelated to its function: usage measurement, crash reports, in-app marketing messages, performance monitoring, advertising and attribution. The second kind is blocked entirely, even if the app calling it is one the user needs. Example: an attendance app calls the check-in interface, the national identity service and notification registration — which are its function — and alongside them calls Google measurement domains unrelated to check-in; those are blocked.
- The fields `callerApps` are the names of the calling apps and their bundle identifiers, and `callerPurpose` describes their function. Read them and ask yourself: does something of what was described get done through this domain, or is it additional to it? Answer in `servesAppFunction`.
- An app's declared purpose is not an infringement: the purpose of an attendance app is to know your location at the moment of check-in, so the location domain is, for it, the function itself. A health and fitness app records your steps, pulse and sleep to show them to you and to transfer them to another health app; this aggregation is a service to you, not spying on you. Its color is green and blockSafe=false, even if the upload is regular and in the background.
- Downloading content is not tracking: a domain that downloads an offline map for use without internet, a resource bundle or a configuration file — blocking it prevents the feature from its device owner, not the tracker. blockSafe=false always.
- Unified sign-in and notification delivery: a domain through which sign-in is done via a third party or through which notifications arrive does collect data indeed, but blocking it prevents the user from entering their app or receiving its notifications. Set blockSafe=false and state this in blockImpact.
- blockSafe means: would the app keep working if this domain were blocked? Authentication, payment, push notification delivery, security certificates and content updates domains are not safe to block even if they collect data. Set them to false and explain what breaks.

Reply with JSON only, with no text before or after it, in this format:
{"verdicts": [{"domain": "", "color": "green|orange|red", "confidence": 0, "category": "", "purpose": "", "reason": "", "collects": [], "firstParty": true, "servesAppFunction": true, "blockSafe": true, "blockImpact": ""}]}

servesAppFunction means: does anything of the calling app's function, as described in callerPurpose, get done through this domain? Set it to false for measurement, advertising, crash reports, marketing messages and performance monitoring, even if the app calling them is essential. And `blockSafe` is true only if servesAppFunction is false.

purpose, reason, blockImpact and category are in Arabic, one concise sentence each. confidence is a number between 0 and 100. collects is a short Arabic list of what is likely collected, and is empty if nothing is collected."""
# The binding protection rules are a guide to the models before judging, and are enforced after them in `user_rules.enforce`.
SYSTEM_PROMPT += "\n\n" + user_rules.rules_prompt()


# ---------------------------------------------------------------------------
# Timing pattern: background pulse or session bursts
# ---------------------------------------------------------------------------


class TimingProfiles:
    """Builds a timing summary per domain from the activity log, with no device address and no app."""

    NIGHT_HOURS = frozenset({0, 1, 2, 3, 4, 5})

    def __init__(self) -> None:
        self.hours: dict[str, set[int]] = defaultdict(set)
        self.night: dict[str, int] = defaultdict(int)
        self.total: dict[str, int] = defaultdict(int)
        self.days: dict[str, set[str]] = defaultdict(set)
        self.lines_read = 0

    def ingest(self, path: Path, maximum_lines: int = 400_000) -> "TimingProfiles":
        if not path.exists():
            return self
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for index, line in enumerate(handle):
                    if index >= maximum_lines:
                        break
                    line = line.strip()
                    if not line or not line.startswith("{"):
                        continue
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    domain = str(event.get("domain") or "").strip().lower().rstrip(".")
                    stamp = str(event.get("time") or "")
                    if not domain or not stamp:
                        continue
                    try:
                        moment = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                    except ValueError:
                        continue
                    self.lines_read += 1
                    self.total[domain] += 1
                    self.hours[domain].add(moment.hour)
                    self.days[domain].add(moment.date().isoformat())
                    if moment.hour in self.NIGHT_HOURS:
                        self.night[domain] += 1
        except OSError:
            pass
        return self

    def profile(self, domain: str) -> dict[str, Any]:
        clean = str(domain or "").strip().lower().rstrip(".")
        total = self.total.get(clean, 0)
        if total < 6:
            return {"pattern": "insufficient", "samples": total, "hours": 0, "nightShare": 0, "days": 0}
        hours = len(self.hours.get(clean, ()))
        days = len(self.days.get(clean, ()))
        night = self.night.get(clean, 0)
        night_share = round(night * 100 / total)
        # A pulse spread across most hours of the day with night activity = background, not a session.
        if hours >= 12 and night > 0:
            pattern = "Regular background pulse throughout the day and during sleep hours"
        elif hours >= 8 and night_share >= 10:
            pattern = "Distributed activity with notable night share"
        elif hours <= 5:
            pattern = "Concentrated bursts linked to user session"
        else:
            pattern = "Intermittent daytime activity"
        return {
            "pattern": pattern,
            "samples": total,
            "hours": hours,
            "nightShare": night_share,
            "days": days,
        }
def load_timing_profiles(data_directory: Path) -> TimingProfiles:
    profiles = TimingProfiles()
    profiles.ingest(data_directory / "dns-activity.ndjson")
    profiles.ingest(data_directory / "dns-activity.previous.ndjson", maximum_lines=120_000)
    return profiles


# ---------------------------------------------------------------------------
# Sent evidence bundle — public only
# ---------------------------------------------------------------------------


def _registrable(domain: str) -> str:
    parts = str(domain or "").strip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else ""


def _first_party_match(domain: str, bundles: Iterable[str]) -> bool:
    """Does the domain belong to the calling app? Computed locally; package names are not sent."""
    root = _registrable(domain).split(".")[0]
    if len(root) < 4:
        return False
    for bundle in bundles:
        tokens = re.split(r"[^a-z0-9]+", str(bundle or "").lower())
        for token in tokens:
            if len(token) >= 4 and (token in root or root in token):
                return True
    return False


def build_evidence(domain: str, entry: dict[str, Any], timing: dict[str, Any]) -> dict[str, Any]:
    study = entry.get("networkStudy") or {}
    if not isinstance(study, dict):
        study = {}
    bundles = [str(item) for item in (entry.get("appBundles") or []) if item]
    contexts = [str(item) for item in (entry.get("appContexts") or []) if item]
    chain = [str(item) for item in (entry.get("cnameChain") or []) if item][-3:]
    local_role, _ = domain_function_role(domain, tuple(bundles) + tuple(contexts))
    evidence = {
        "domain": domain,
        "tlsSubject": str(study.get("certificateSubject") or "")[:200],
        "pageTitle": str(study.get("title") or "")[:160],
        "pageDescription": str(study.get("description") or "")[:280],
        "server": str(study.get("server") or "")[:80],
        # Its public root redirect target is a user ownership directory (telesco.pe ← telegram.org), and its absence led the judge to view “the domain name alone”.
        "redirectHost": str(study.get("redirectHost") or "")[:120],
        "cnameChain": chain,
        "queryTypes": [str(item) for item in (entry.get("qtypes") or [])][:6],
        "lookups": int(entry.get("hits") or 0),
        "distinctApps": len(bundles),
        "firstPartyForCaller": _first_party_match(domain, bundles),
        "timingPattern": timing.get("pattern", "insufficient"),
        "activeHoursOfDay": timing.get("hours", 0),
        "nightSharePercent": timing.get("nightShare", 0),
        "observedDays": timing.get("days", 0),
        "currentLocalColor": str(entry.get("risk") or "unclassified"),
        "currentLocalCategory": str(entry.get("categoryLabel") or ""),
        # Describes the caller’s function by category, along with the names of the calling apps themselves: no privacy
        # Data before cloud models, and the name improves judgment.
        "callerPurpose": caller_purpose(tuple(bundles) + tuple(contexts)),
        "callerApps": list(dict.fromkeys(bundles + contexts))[:8],
        "localRole": ROLE_LABELS.get(local_role, ""),
    }
    return {key: value for key, value in evidence.items() if value not in ("", [], None)}


def build_prompt(packets: list[dict[str, Any]]) -> str:
    listing = json.dumps(packets, ensure_ascii=False, indent=1)
    return (
        "Judge these domains, one by one, according to the criterion in the instructions.\n"
        "currentLocalColor is the local rule engine’s verdict, which is weak: override it whenever the evidence contradicts it.\n"
        "Return one item per domain in the same order and with the exact same name.\n\n"
        f"Domains ({len(packets)}):\n{listing}"
    )


# ---------------------------------------------------------------------------
# Verify model verdict
# ---------------------------------------------------------------------------

_COLOR_ALIASES = {
    "green": "green", "Green": "green", "اخضر": "green",
    "orange": "orange", "Orange": "orange", "amber": "orange", "yellow": "orange",
    "red": "red", "Red": "red", "احمر": "red",
}


def _clean_text(value: Any, maximum: int = 240) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:maximum]


def normalize_verdict(raw: Any, allowed: set[str]) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    domain = str(raw.get("domain") or "").strip().lower().rstrip(".")
    if domain not in allowed:
        return None
    color = _COLOR_ALIASES.get(str(raw.get("color") or "").strip().lower())
    if color not in COLORS:
        return None
    try:
        confidence = int(float(raw.get("confidence", 0)))
    except (TypeError, ValueError):
        confidence = 0
    collects = raw.get("collects")
    if isinstance(collects, str):
        collects = [collects]
    if not isinstance(collects, list):
        collects = []
    out = {
        "domain": domain,
        "color": color,
        "confidence": max(0, min(100, confidence)),
        "category": _clean_text(raw.get("category"), 80),
        "purpose": _clean_text(raw.get("purpose"), 300),
        "reason": _clean_text(raw.get("reason"), 300),
        "collects": [_clean_text(item, 60) for item in collects[:6] if _clean_text(item, 60)],
        "firstParty": bool(raw.get("firstParty")),
        "servesAppFunction": bool(raw.get("servesAppFunction")),
        # The model is prohibited from declaring blocking safe while acknowledging that the domain belongs to an app function;
        # such a contradiction is resolved in favor of not disabling.
        "blockSafe": bool(raw.get("blockSafe")) and not bool(raw.get("servesAppFunction")),
        "blockImpact": _clean_text(raw.get("blockImpact"), 240),
    }
    # Only the judge is asked for this: a note that could not be resolved needs your review (ai_reviewer.JUDGE_NOTE).
    if raw.get("needsSession") is True or str(raw.get("needsSession")).lower() == "true":
        out["needsSession"] = True
        out["sessionNote"] = _clean_text(raw.get("sessionNote"), 300)
        kind = str(raw.get("sessionKind") or "").strip().lower()
        if kind in {"evidence", "conflict", "owner"}:
            out["sessionKind"] = kind
    return out


def _ledger_batch(task_name: str, response: dict[str, Any], packets: list[dict[str, Any]],
                  verdicts: dict[str, dict[str, Any]]) -> None:
    """Human-readable copy of the app’s verdict on the batch in the model work log. The exam writes its own lines."""
    if task_name == "model exam":
        return
    if not response.get("ok") and response.get("paused"):
        # Slot suspended due to daily quota or bypassed by the gateway: no one judged, so no “not completed” line is returned and it is counted as “no solution”,
        # and the domain remains “awaiting judge” with a completed juror line, and is presented after midnight.
        return
    try:
        import model_ledger

        model_ledger.record_batch(task_name or "Domain Review", response,
                                  [str(item["domain"]) for item in packets], verdicts)
    except Exception:  # noqa: BLE001 - the log does not affect review
        pass


def review_batch(
    pool: ProviderPool,
    packets: list[dict[str, Any]],
    maximum_wait: float = 180.0,
    system_prompt: str = "",
    exclude: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Reviews a batch of domains and returns {domain: verdict} with the provider name.

    `system_prompt` replaces the iPhone criterion with another device’s criterion (computer) without
    The form of the rule changes, as well as the verification gates.
    """
    if not packets:
        return {"ok": True, "verdicts": {}, "provider": "", "seconds": 0}
    allowed = {str(item["domain"]) for item in packets}
    response = pool.complete(
        system_prompt or SYSTEM_PROMPT,
        build_prompt(packets),
        max_tokens=MAX_TOKENS,
        temperature=0.0,
        maximum_wait=maximum_wait,
        exclude=exclude,
    )
    task_name = getattr(pool, "task", "")
    if not response.get("ok"):
        _ledger_batch(task_name, response, packets, {})
        return {"ok": False, "verdicts": {}, "errors": response.get("errors", [])}
    payload = extract_json(response.get("text", ""))
    items: list[Any] = []
    if isinstance(payload, dict):
        for key in ("verdicts", "results", "domains", "items", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                items = value
                break
        else:
            if payload.get("domain"):
                items = [payload]
    elif isinstance(payload, list):
        items = payload
    verdicts: dict[str, dict[str, Any]] = {}
    for item in items:
        clean = normalize_verdict(item, allowed)
        if clean:
            clean["provider"] = response.get("provider", "")
            clean["model"] = response.get("model", "")
            verdicts[clean["domain"]] = clean
    _ledger_batch(task_name, response, packets, verdicts)
    return {
        "ok": bool(verdicts),
        "verdicts": verdicts,
        "provider": response.get("provider", ""),
        "model": response.get("model", ""),
        "seconds": response.get("seconds", 0),
        "missing": sorted(allowed - set(verdicts)),
    }


# ---------------------------------------------------------------------------
# Review executor — parallel batches on available providers
# ---------------------------------------------------------------------------


class ReviewRunner:
    """Distributes domains into batches and runs them in rotation across the available providers."""

    def __init__(self, pool: ProviderPool | None = None, workers: int = 0):
        self.pool = pool or ProviderPool()
        self.workers = workers or max(1, min(4, len(self.pool.states)))
        self.lock = threading.Lock()
        self.stop_flag = threading.Event()
        self.stats = {
            "requested": 0,
            "reviewed": 0,
            "failed": 0,
            "batches": 0,
            "startedAt": "",
            "finishedAt": "",
        }

    def run(
        self,
        packets: list[dict[str, Any]],
        on_verdict=None,
        batch_size: int = BATCH_SIZE,
    ) -> dict[str, Any]:
        batches = [packets[index : index + batch_size] for index in range(0, len(packets), batch_size)]
        self.stats["requested"] = len(packets)
        self.stats["startedAt"] = datetime.now().astimezone().isoformat(timespec="seconds")
        queue: list[list[dict[str, Any]]] = list(batches)
        queue_lock = threading.Lock()

        def worker() -> None:
            while not self.stop_flag.is_set():
                with queue_lock:
                    if not queue:
                        return
                    batch = queue.pop(0)
                result = review_batch(self.pool, batch)
                with self.lock:
                    self.stats["batches"] += 1
                    self.stats["reviewed"] += len(result.get("verdicts", {}))
                    self.stats["failed"] += len(result.get("missing", []) or []) if result.get("ok") else len(batch)
                if on_verdict:
                    for verdict in result.get("verdicts", {}).values():
                        on_verdict(verdict)

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(self.workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.stats["finishedAt"] = datetime.now().astimezone().isoformat(timespec="seconds")
        return dict(self.stats)

    def stop(self) -> None:
        self.stop_flag.set()
