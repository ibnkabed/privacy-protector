"""Deciding without models: fixed rules that run on this computer, for the phone and the PC.

`decide` judges a domain with no network call, and the first layer that settles it stops the rest: protection rules
and apps you trust, the safety gate, the built-in catalog, public tracker lists with name signals, the calling
program, and finally plain watching.

Limits that never move: outside the catalog, blocking needs two pieces of evidence; one piece is watched. What reveals
the device's location or identity is flagged, not just watched as normal. The block gates (`ai_block_gate` and the
protection rules) still stand above every verdict here when it is applied.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import tracker_lists
import user_rules
from domain_verdicts import (
    COLLECTOR_PATTERN,
    LOCAL_AGREEMENT,
    _first_party_for_caller,
    caller_purpose,
    domain_function_role,
    is_block_safe,
    trusted_app_caller,
    verdict_for,
)

EXTRA_NAME_SIGNAL = re.compile(
    r"(?:^|[.\-_])(?:stats?|crash(?:lytics)?|sentry|tag(?:s|manager)?|clicks?|eum|rum|ingest|fingerprint|sdk-?logs?)"
    r"(?:[.\-_]|$)", re.I)
# What reveals the device's location or identity.
EXPOSURE = re.compile(
    r"(?:^|[.\-_])(?:ip-?api|ipinfo|ipify|ipdata|ipgeo\w*|ipstack|ipwho\w*|geoip\w*|geo-?locat\w*|geolocation|"
    r"whatismyip\w*|myip|checkip|ifconfig|fingerprintjs|fpjs|deviceid|device-?fingerprint|identity-?graph)"
    r"(?:[.\-_]|$)", re.I)

_lock = threading.RLock()
_cache: dict[str, Any] = {"stamp": None, "lists": {}}


@dataclass
class Decision:
    layer: str
    action: str              # block | watch
    color: str               # red | orange | green
    reason: str
    evidence: list[str] = field(default_factory=list)


def clean(domain: Any) -> str:
    return str(domain or "").strip().lower().rstrip(".")


def name_signal(domain: str) -> bool:
    name = clean(domain)
    return bool(COLLECTOR_PATTERN.search(name) or EXTRA_NAME_SIGNAL.search(name))


def exposes_identity(domain: str) -> bool:
    return bool(EXPOSURE.search(clean(domain)))


def loaded_lists() -> dict[str, frozenset[str]]:
    """The downloaded lists: name to domains. Reloaded when an update finishes."""
    try:
        stamp = tracker_lists.META_PATH.stat().st_mtime
    except OSError:
        return {}
    with _lock:
        if _cache["stamp"] == stamp:
            return _cache["lists"]
        loaded: dict[str, frozenset[str]] = {}
        try:
            names = list(json.loads(tracker_lists.META_PATH.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            names = []
        for name in names:
            try:
                text = (tracker_lists.LISTS_DIR / f"{name}.txt").read_text(encoding="utf-8")
            except OSError:
                continue
            loaded[str(name)] = frozenset(line for line in text.split("\n") if line)
        _cache.update(stamp=stamp, lists=loaded)
        return loaded


def list_hits(domain: str) -> list[str]:
    labels = clean(domain).split(".")
    suffixes = [".".join(labels[index:]) for index in range(len(labels) - 1)]
    return [name for name, items in loaded_lists().items() if any(item in items for item in suffixes)]


def _decision(layer: str, action: str, color: str, reason: str, *evidence: str) -> Decision:
    return Decision(layer, action, color, reason, [item for item in evidence if item])


def decide(domain: str, callers: tuple[str, ...] = (), category: str = "") -> Decision:
    """The verdict of the fixed rules on a domain. `callers` are the identities of the programs that called it."""
    from pc_protection import protected_reason

    name = clean(domain)
    # 1. Protection rules and apps you trust
    rule, why = user_rules.matching_rule(name, callers, category)
    if rule:
        return _decision("rules", "watch", "green", why, "rule:" + rule)
    trusted = trusted_app_caller(callers)
    if trusted:
        return _decision("rules", "watch", "green", f"Called by an app you trust ({trusted})", "trusted-app")
    # 2. The safety gate
    reason = protected_reason(name)
    if reason:
        return _decision("gate", "watch", "green", reason, "protected")
    role, role_why = domain_function_role(name, callers)
    if role == "function":
        return _decision("gate", "watch", "green", role_why, "function-role")
    # 3. The built-in catalog
    curated = verdict_for(name)
    risk = str((curated or {}).get("risk") or "")
    if risk:
        why = str(curated.get("reason") or curated.get("summary") or "")
        if risk == "red" and is_block_safe(name, str(curated.get("category") or "")):
            return _decision("catalog", "block", "red", why, "catalog")
        return _decision("catalog", "watch", "orange" if risk == "red" else risk, why, "catalog")
    # 4. Public lists and name signals: blocking needs two pieces of evidence
    signal = name_signal(name)
    hits = list_hits(name)
    if len(hits) >= 2:
        return _decision("lists", "block", "red", "On two public tracker lists", *["list:" + hit for hit in hits[:2]])
    if hits and signal:
        return _decision("lists", "block", "red", "On a public tracker list, and its name says it collects data",
                         "list:" + hits[0], "name")
    if hits or signal:
        evidence = ("list:" + hits[0]) if hits else "name"
        if not (signal and callers and _first_party_for_caller(name, callers)):
            return _decision("lists", "watch", "orange", "One sign of data collection: watched, not blocked", evidence)
    if exposes_identity(name):
        return _decision("exposure", "watch", "orange", "Reveals the device's location or identity", "exposure")
    # 5. The calling program
    if callers and _first_party_for_caller(name, callers):
        return _decision("caller", "watch", "green", "The calling program's own service", "first-party")
    if callers and caller_purpose(callers):
        return _decision("caller", "watch", "orange", "A program with a known purpose, no sign of collection", "known-purpose")
    # 6. Plain watching
    return _decision("default", "watch", "orange", "No sign of collection: watched")


def verdict_of(decision: Decision, domain: str) -> dict[str, Any]:
    """A verdict stored like the review's. The block gates still stand above it when it is applied."""
    return {
        "domain": clean(domain), "color": decision.color, "confidence": 80,
        "category": "", "purpose": "", "reason": decision.reason[:300], "collects": decision.action == "block",
        "blockSafe": decision.action == "block", "blockImpact": "",
        "agreement": LOCAL_AGREEMENT, "decidedBy": "built-in rules", "codeLayer": decision.layer,
        "codeEvidence": decision.evidence[:4], "reviewers": ["built-in rules"], "provider": "built-in rules", "model": "",
        "reviewedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
    }


def verdict_for_domain(domain: str, callers: tuple[str, ...] = (), category: str = "") -> dict[str, Any]:
    return verdict_of(decide(domain, callers, category), domain)
