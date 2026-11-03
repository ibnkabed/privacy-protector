"""Provider calibration: A provider whose verdicts on known domains are not
evaluated does not enter the rotation.

Measurements proved that blind rotation corrupts classification: in the first
real-world test, one provider flagged `one.one.one.one` as red, and two others
flagged Private Relay—a privacy-preserving service—as red as well. Therefore,
the provider is first tested on a set of domains with certain known verdicts,
its score is saved, and its verdicts are not trusted if it fails.

Scoring: color match = 1, adjacent color = 0.4, green vs red = 0. Half a point
is deducted for each infrastructure domain that the provider claims is safe to
block when it is not, because this error is what breaks applications.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from ai_providers import DEFAULT_TASK, ProviderPool, available_providers, request_replacement, send_feedback
import ai_domain_review as review
import paths

PASS_SCORE = 0.70
STATE_FILE = "ai-calibration.json"
CALIBRATION_TTL_HOURS = 72
# The share of questions below which the provider is considered unreachable,
# not bad at judging.
MINIMUM_ANSWER_SHARE = 0.6

# Domains with certainly known verdicts from their owners' documentation or
# their declared nature.
# `blockSafe=False` here means: blocking it disrupts a function the user sees.
BENCHMARK: tuple[dict[str, Any], ...] = (
    {
        "domain": "app-measurement.com",
        "color": "red",
        "blockSafe": True,
        "note": "Google Analytics for Firebase measurement suite",
        "evidence": {"distinctApps": 23, "timingPattern": "Regular background pulse throughout the day and during sleep hours", "lookups": 1840},
    },
    {
        "domain": "app.adjust.com",
        "color": "red",
        "blockSafe": True,
        "note": "App install attribution platform",
        "evidence": {"distinctApps": 9, "timingPattern": "Concentrated bursts linked to user session", "lookups": 210},
    },
    {
        "domain": "googleads.g.doubleclick.net",
        "color": "red",
        "blockSafe": True,
        "note": "Ad network",
        "evidence": {"distinctApps": 14, "timingPattern": "Intermittent daytime activity", "lookups": 900},
    },
    {
        "domain": "t.appsflyer.com",
        "color": "red",
        "blockSafe": True,
        "note": "Attribution and measurement platform",
        "evidence": {"distinctApps": 7, "timingPattern": "Distributed activity with notable night share", "lookups": 430},
    },
    {
        "domain": "mask.icloud.com",
        "color": "green",
        "blockSafe": False,
        "note": "iCloud Private Relay — a service that hides identity, not collects it",
        "evidence": {"distinctApps": 2, "timingPattern": "Regular background pulse throughout the day and during sleep hours", "lookups": 3874},
    },
    {
        "domain": "one.one.one.one",
        "color": "green",
        "blockSafe": False,
        "note": "Public DNS resolver — outage cuts off internet",
        "evidence": {"tlsSubject": "Cloudflare, Inc. / cloudflare-dns.com", "lookups": 4604},
    },
    {
        "domain": "gateway.push.apple.com",
        "color": "green",
        "blockSafe": False,
        "note": "Apple push notifications",
        "evidence": {"distinctApps": 0, "timingPattern": "Regular background pulse throughout the day and during sleep hours", "lookups": 2100},
    },
    {
        "domain": "ocsp.apple.com",
        "color": "green",
        "blockSafe": False,
        "note": "Certificate validity verification",
        "evidence": {"timingPattern": "Intermittent daytime activity", "lookups": 320},
    },
    {
        "domain": "a1838.dscw154.akamai.net",
        "color": "orange",
        "blockSafe": False,
        "note": "Edge node with unknown owner",
        "evidence": {"timingPattern": "Regular background pulse throughout the day and during sleep hours", "lookups": 5192},
    },
    {
        "domain": "d10sbd116h2zht.cloudfront.net",
        "color": "orange",
        "blockSafe": False,
        "note": "Edge node with unknown owner",
        "evidence": {"timingPattern": "Intermittent daytime activity", "lookups": 640},
    },
    {
        "domain": "www.googleapis.com",
        "color": "green",
        "blockSafe": False,
        "note": "Operational services API; apps break without it",
        "evidence": {"distinctApps": 11, "timingPattern": "Intermittent daytime activity", "lookups": 1500},
    },
    {
        "domain": "sdk.iad-06.braze.com",
        "color": "red",
        "blockSafe": True,
        "note": "Behavior tracking and marketing platform",
        "evidence": {"distinctApps": 4, "timingPattern": "Distributed activity with notable night share", "lookups": 260},
    },
    # Three cases measuring the error that actually broke apps: blocking what is
    # an app function, not a violation. Any provider failing these disables the
    # user's device and is dropped from rotation.
    {
        "domain": "sportdata-dra.things.dbankcloud.com",
        "color": "green",
        "blockSafe": False,
        "note": "Sports data uploaded by a health app to display to the user — collection serving the user",
        "evidence": {
            "distinctApps": 1,
            "firstPartyForCaller": False,
            "timingPattern": "Regular background pulse throughout the day and during sleep hours",
            "lookups": 6965,
        },
    },
    {
        "domain": "map-dra.platform.dbankcloud.com",
        "color": "green",
        "blockSafe": False,
        "note": "Offline map download — blocking it actually prevented the feature",
        "evidence": {
            "distinctApps": 1,
            "timingPattern": "Concentrated bursts linked to user session",
            "lookups": 3983,
        },
    },
    {
        "domain": "location-service.attendance-vendor.example",
        "color": "green",
        "blockSafe": False,
        "note": "Location domain for an attendance app — location detection at check-in is its stated purpose",
        "evidence": {
            "distinctApps": 1,
            "firstPartyForCaller": True,
            "timingPattern": "Concentrated bursts linked to user session",
            "lookups": 420,
        },
    },
)
_ADJACENT = {("green", "orange"), ("orange", "green"), ("orange", "red"), ("red", "orange")}


def _score_item(expected: dict[str, Any], verdict: dict[str, Any] | None) -> float:
    if not verdict:
        return 0.0
    pair = (expected["color"], verdict["color"])
    if pair[0] == pair[1]:
        score = 1.0
    elif pair in _ADJACENT:
        score = 0.4
    else:
        score = 0.0
    # The fatal error: an infrastructure domain that is safe to block is claimed as safe to block, which breaks the app.
    if not expected["blockSafe"] and verdict.get("blockSafe"):
        score = max(0.0, score - 0.5)
    return score


CALIBRATION_TASK = "model exam"


def _ledger_exam(name: str, model: str, verdicts: dict[str, Any]) -> None:
    """Each domain in the exam becomes a line in the models' work ledger: correct, wrong, or unanswered."""
    try:
        import model_ledger

        for item in BENCHMARK:
            verdict = verdicts.get(item["domain"])
            expected = model_ledger.COLOR_AR.get(item["color"], item["color"])
            if not verdict:
                ref = f"exam:{name}/{model}:{item['domain']}"
                model_ledger.record(CALIBRATION_TASK, name, model, "not_done", f"{item['domain']}: no answer",
                                    f"Expected: {expected}. {item['note']}", ref=ref)
                continue
            text, detail = model_ledger.verdict_item(item["domain"], verdict)
            column = "done" if _score_item(item, verdict) >= 1.0 else "wrong"
            served = (verdict.get("provider") or name, verdict.get("model") or model)
            model_ledger.record(CALIBRATION_TASK, *served, column, text,
                                f"{detail} Expected: {expected}. {item['note']}",
                                ref=f"exam:{served[0]}/{served[1]}:{item['domain']}")
    except Exception:  # noqa: BLE001 - the ledger never affects the exam
        pass


def calibrate_provider(
    name: str, pool: ProviderPool | None = None, model: str = ""
) -> dict[str, Any]:
    """Exams one model at one provider on the known benchmark set.

    The limit is usually per model rather than per provider, so exam models one by one reveals hidden capacity:
    a model whose quota ran out does not mean the whole provider ran out.
    """
    if model:
        single = ProviderPool(slots=((name, model),), allow_paid=True, task=CALIBRATION_TASK)
    else:
        single = ProviderPool(slots=((name, name),), allow_paid=True, task=CALIBRATION_TASK)
    if single.by_name(name) is None:
        return {"provider": name, "score": 0.0, "passed": False, "error": "no key for this provider"}
    if not model:
        single.verify(name)
    packets = []
    for item in BENCHMARK:
        packet = {"domain": item["domain"], "currentLocalColor": "unclassified"}
        packet.update(item["evidence"])
        packets.append(packet)

    started = time.monotonic()
    verdicts: dict[str, Any] = {}
    for index in range(0, len(packets), review.BATCH_SIZE):
        batch = packets[index : index + review.BATCH_SIZE]
        result = review.review_batch(single, batch, maximum_wait=40.0)
        verdicts.update(result.get("verdicts", {}))
    # A batch that fails once is not a verdict on the provider; it is retried before failure is counted,
    # so what is measured is repeated inability, not one transient glitch.
    remaining = [packet for packet in packets if packet["domain"] not in verdicts]
    for index in range(0, len(remaining), review.BATCH_SIZE):
        retry = review.review_batch(single, remaining[index : index + review.BATCH_SIZE], maximum_wait=40.0)
        verdicts.update(retry.get("verdicts", {}))
    elapsed = round(time.monotonic() - started, 1)

    total = 0.0
    mistakes = []
    for item in BENCHMARK:
        verdict = verdicts.get(item["domain"])
        score = _score_item(item, verdict)
        total += score
        if score < 1.0:
            mistakes.append(
                {
                    "domain": item["domain"],
                    "expected": item["color"],
                    "got": (verdict or {}).get("color", "—"),
                    "blockSafeExpected": item["blockSafe"],
                    "blockSafeGot": (verdict or {}).get("blockSafe"),
                    "note": item["note"],
                }
            )
    score = round(total / len(BENCHMARK), 3)
    state = single.by_name(name)
    _ledger_exam(name, state.model if state else model, verdicts)
    # A provider that answered too little of the exam was never really tested: its daily quota ran out or it hit its cap.
    # That is a temporary shortfall, not poor judgment, so it must not erase an earlier correct verdict.
    answered_enough = len(verdicts) >= len(BENCHMARK) * MINIMUM_ANSWER_SHARE
    chosen_model = state.model if state else model
    if len(verdicts) == len(BENCHMARK):
        # The verdict on the model is recorded only for a complete exam:
        # a quota shortfall is not bad judgment, and `bad` removes the model permanently.
        verdict_word = "keep" if score >= PASS_SCORE else "bad"
        try:
            send_feedback(
                DEFAULT_TASK,
                name,
                chosen_model,
                verdict_word,
                f"domain exam of {len(BENCHMARK)} domains: score {score}",
            )
            if verdict_word == "bad":
                request_replacement(DEFAULT_TASK, name, chosen_model, f"failed the domain exam with score {score}")
        except Exception:  # noqa: BLE001 - evaluation never stops the exam
            pass
    return {
        "provider": name,
        "model": state.model if state else model,
        "slot": name + ":" + (state.model if state else model),
        "score": score,
        "passed": score >= PASS_SCORE,
        "answered": len(verdicts),
        "expected": len(BENCHMARK),
        "seconds": elapsed,
        "mistakes": mistakes,
        "reachable": answered_enough,
        "calibratedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
def discover_slots(
    providers: tuple[str, ...] = (),
    per_provider: int = 3,
    allow_paid: bool = True,
) -> dict[str, Any]:
    """Queries each provider's catalogue, tests its best models, and saves those that passed.

    This is what makes the free models sufficient: one provider may offer several slots, and each
    slot has its own quota. Instead of waiting for a model's quota to return, it moves to another
    model that has one.
    """
    # Testing by name for the review group only, not for the `auto` slot.
    pool = ProviderPool(allow_paid=allow_paid)
    targets = providers or tuple(state.name for state in pool.states)
    slots: list[dict[str, Any]] = []
    for provider in targets:
        catalogue = pool.list_models(provider)
        spec = pool.by_name(provider)
        # The default model and its fallbacks were measured earlier, so they must not drop out
        # of the catalogue ordering.
        known = [spec.model] if spec is not None else []
        ranked = list(catalogue)[: per_provider * 3]
        candidates = list(dict.fromkeys([*known, *ranked]))
        # The live check before testing: a provider's catalogue lists models the key is not
        # authorized to use.
        alive = pool.live_models(provider, candidates, per_provider)
        for model in alive:
            result = calibrate_provider(provider, model=model)
            slots.append(result)
        if not alive:
            slots.append(
                {
                    "provider": provider,
                    "model": candidates[0] if candidates else "",
                    "slot": provider + ":" + (candidates[0] if candidates else ""),
                    "score": 0.0,
                    "passed": False,
                    "answered": 0,
                    "expected": len(BENCHMARK),
                    "reachable": False,
                    "error": "No candidate model responded",
                }
            )
    ranked = sorted(slots, key=lambda item: -item.get("score", 0))
    return {
        "version": review.AI_REVIEW_VERSION,
        "benchmark": len(BENCHMARK),
        "passScore": PASS_SCORE,
        "calibratedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
        "slots": ranked,
        "trustedSlots": [
            [item["provider"], item["model"]] for item in ranked if item.get("passed")
        ],
    }


def merge_slots(previous: dict[str, Any], found: dict[str, Any]) -> dict[str, Any]:
    """Merges a partial discovery into the saved state, keyed by (provider, model).

    Discovering one specific provider does not erase other providers' slots: each slot is the
    result of a test standing on its own, and dropping it because the command did not mention it
    would destroy a valid measurement.
    """
    merged = dict(previous or {})
    by_slot = {
        (str(item.get("provider")), str(item.get("model"))): item
        for item in (merged.get("slots") or [])
        if isinstance(item, dict)
    }
    for item in found.get("slots", []):
        by_slot[(str(item.get("provider")), str(item.get("model")))] = item
    ranked = sorted(by_slot.values(), key=lambda item: -float(item.get("score") or 0))
    merged["slots"] = ranked
    merged["trustedSlots"] = [
        [item["provider"], item["model"]] for item in ranked if item.get("passed")
    ]
    merged["slotsCalibratedAt"] = found.get("calibratedAt", "")
    return merged


def trusted_slots(data_directory: Path) -> tuple[tuple[str, str], ...]:
    """The slots that passed the test from the review group, in their order.

    For display and testing only: the review does not name a slot, and the gate chooses.
    """
    state = load_state(data_directory)
    configured = available_providers()
    return tuple(
        (str(provider), str(model))
        for provider, model in (state.get("trustedSlots") or [])
        if str(provider) in configured
    )
def calibrate_all(
    names: tuple[str, ...] = (),
    allow_paid: bool = True,
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # The named test covers the review group only, not the `auto` slot.
    pool = ProviderPool(allow_paid=allow_paid)
    targets = names or tuple(state.name for state in pool.states)
    earlier = (previous or {}).get("providers", {})
    # Testing one provider must not erase the results of the others: the report is built on top
    # of the earlier one and only the tested entry is replaced, otherwise the state file would
    # lose every provider not named in the command.
    report = {
        name: dict(item)
        for name, item in earlier.items()
        if isinstance(item, dict) and name not in targets
    }
    for name in targets:
        result = calibrate_provider(name)
        was = earlier.get(name)
        if not result.get("reachable") and isinstance(was, dict) and was.get("reachable"):
            # The previously measured verdict is kept, and today's failed access is recorded.
            result = {
                **was,
                "unreachableSince": result.get("calibratedAt", ""),
                "lastAttemptAnswered": result.get("answered", 0),
                "reachable": False,
            }
        report[name] = result
    ranked = sorted(report.values(), key=lambda item: -item["score"])
    return {
        "version": review.AI_REVIEW_VERSION,
        "benchmark": len(BENCHMARK),
        "passScore": PASS_SCORE,
        "calibratedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
        "providers": report,
        # Trust rests on the measured verdict, and access is tried again at use time: a provider
        # whose quota ran out today returns tomorrow, so it is not dropped from the list because of
        # an hour's shortfall.
        "trusted": [item["provider"] for item in ranked if item["passed"]],
        "reachable": [
            item["provider"] for item in ranked if item["passed"] and item.get("reachable", True)
        ],
    }


def load_state(data_directory: Path) -> dict[str, Any]:
    path = Path(data_directory) / STATE_FILE
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(data_directory: Path, state: dict[str, Any]) -> None:
    path = Path(data_directory) / STATE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def merge_calibration(previous: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    """Places the provider-test report on top of the saved state without erasing its slots.

    Testing providers and discovering slots are two separate measurements that live in one file,
    and the report does not carry the slots. So saving the report alone was erasing `slots` and
    `trustedSlots`: this happened with `--calibrate` on the command line, and the review that
    followed found only provider names.
    """
    return {**(previous or {}), **report}


def recalibrate(
    data_directory: Path, names: tuple[str, ...] = (), allow_paid: bool = True
) -> dict[str, Any]:
    """Re-tests the providers on top of the saved state, and saves the report merged into it."""
    previous = load_state(data_directory)
    report = calibrate_all(names, allow_paid=allow_paid, previous=previous)
    state = merge_calibration(previous, report)
    save_state(data_directory, state)
    return state


def trusted_providers(
    data_directory: Path, refresh: bool = False, allow_paid: bool = True
) -> list[str]:
    """Returns the providers that passed the test, and re-runs the test if the result is stale."""
    state = load_state(data_directory)
    stale = True
    stamp = str(state.get("calibratedAt") or "")
    if stamp and not refresh:
        try:
            age = datetime.now().astimezone() - datetime.fromisoformat(stamp)
            stale = age.total_seconds() > CALIBRATION_TTL_HOURS * 3600
        except ValueError:
            stale = True
    if stale or refresh or not state.get("trusted"):
        # Slots measured earlier are kept: testing providers does not cancel model discovery.
        state = recalibrate(data_directory, allow_paid=allow_paid)
    return list(state.get("trusted") or [])
if __name__ == "__main__":
    import sys

    names = tuple(arg for arg in sys.argv[1:] if not arg.startswith("-"))
    # Paid is tested by default; `--no-paid` excludes it, and the old `--paid` remains with no effect.
    allow_paid = "--no-paid" not in sys.argv
    if "--discover" in sys.argv:
        found = discover_slots(names, allow_paid=allow_paid)
        for item in found["slots"]:
            mark = "passed" if item.get("passed") else "failed"
            print(
                f"  {str(item.get('slot', '')).ljust(46)} {mark} "
                f"score={item.get('score', 0):<6} answered={item.get('answered', 0)}/{item.get('expected', 0)}"
            )
        print("\nTrusted slots:", len(found["trustedSlots"]))
        for provider, model in found["trustedSlots"]:
            print("   ", provider, "|", model)
        if "--save" in sys.argv:
            save_state(paths.DATA_ROOT, merge_slots(load_state(paths.DATA_ROOT), found))
            print("Slots saved to data/" + STATE_FILE)
        raise SystemExit(0)
    previous = load_state(paths.DATA_ROOT)
    report = calibrate_all(names, allow_paid=allow_paid, previous=previous)
    for name, item in sorted(report["providers"].items(), key=lambda kv: -kv[1]["score"]):
        mark = "passed" if item["passed"] else "failed"
        reach = "" if item.get("reachable", True) else "  [unreachable today — score is from a previous test]"
        print(
            f"{name.ljust(12)} {mark}  score={item['score']:<6} "
            f"answered={item.get('answered','?')}/{item.get('expected','?')} "
            f"time={item.get('seconds','?')}s  {item.get('model','')}{reach}"
        )
        for mistake in item.get("mistakes", []):
            flag = ""
            if mistake["blockSafeExpected"] is False and mistake["blockSafeGot"]:
                flag = "  ← says blocking it is safe, but it breaks things"
            print(
                f"      {mistake['domain'].ljust(32)} expected={mistake['expected']:<7}"
                f" got={mistake['got']:<7}{flag}"
            )
    print("\nTrusted:", ", ".join(report["trusted"]) or "none")
    if "--save" in sys.argv:
        save_state(paths.DATA_ROOT, merge_calibration(previous, report))
        print("Result saved to data/" + STATE_FILE)
