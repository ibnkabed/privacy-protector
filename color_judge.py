"""the judge the judge is responsible for the colors of the clock icon and the planets.

The colors used to be computed in the code alone: `tray_icon.assess` for the traffic light beside the clock, and `web/orbit.js` for the planets and the panel core.
So every new state that turned red or yellow/orange was shown to the judge once before it was colored: is it real, and is its grade correct?
It either confirms it, lowers it to no color (info), or raises a yellow to red (raise).

- **One call per batch, in the background:** `review` applies the saved verdicts immediately and returns, then starts one thread that asks the judge about the new ones
  (BATCH_MAX per call, and at most one call every ASK_EVERY seconds). So neither the icon nor the panel waits for an answer.
- **The verdict is saved** in data/color-judge.json under the state's key and its grade in the code, so it is not asked about twice. Numbers in the key
  are normalized ("notes: 3" and "notes: 4" are one state). If the code's grade changes, it is a new state that gets shown.
- **If the judge is unavailable,** the code's color remains, and the verdict is "pending" until it answers.
- **Safety alerts are decided by the code alone and immediately** (`safety`): the engine does not answer, the computer bypasses the engine, there is no healthy DNS provider,
  the data is corrupt, and Defender is in a red state. No verdict lowers them.
- **Domain verdicts stay as they are:** the writer reads, the jurors decide, and the judge confirms (`ai_reviewer.py`). This is for colors only."""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable
import paths

APP_ROOT = Path(__file__).resolve().parent
STORE = paths.DATA_ROOT / "color-judge.json"
TASK = "the color judge"
BATCH_MAX = 20
ASK_EVERY = 600          # seconds between calls at most
KEEP_S = 7 * 86400       # a verdict for a state absent for a week is forgotten
VERDICTS = {"confirm", "info", "raise"}
_lock = threading.Lock()
_asking = threading.Lock()
_last_ask = [0.0]

SYSTEM = """You are the judge of "Privacy Protector" and responsible for its colors: the traffic light beside the clock, and the planets of the panel (a program or an app)
and its core. Red says to the user "intervene now", yellow says "look when you are free", and no color says "nothing here needs you". Only what really needs the user
or a session is colored. Judge each state:
- confirm: real, and its grade is correct.
- info: not a real problem, or the app fixes it itself without intervention: it drops to no color.
- raise: yellow while it is in fact a violation that passes or a fault that needs intervention now: it rises to red.
When in doubt: confirm. Answer with JSON only: {"verdicts": [{"key": "<key>", "verdict": "confirm" or "info" or "raise", "why": "<one sentence in Arabic>"}]}"""


def level(sev: str) -> str:
    """Yellow in the icon and orange in the panel are one grade apart."""
    return "yellow" if sev in ("yellow", "orange") else sev


def key_of(prefix: str, text: str) -> str:
    return prefix + ":" + re.sub(r"\d+", "#", str(text or "")).strip()[:160]


def _read() -> dict[str, Any]:
    try:
        data = json.loads(STORE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(data: dict[str, Any]) -> None:
    try:
        STORE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STORE.with_name(STORE.name + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(STORE)
    except OSError as error:
        logging.debug("color judge: write failed: %s", error)


def _outcome(item: dict[str, Any], row: dict[str, Any] | None) -> dict[str, Any]:
    sev = level(item.get("sev", ""))
    if not row:
        return {"from": item.get("sev"), "sev": item.get("sev"), "judge": "pending"}
    verdict = row.get("verdict")
    new = "none" if verdict == "info" else "red" if verdict == "raise" and sev == "yellow" else item.get("sev")
    return {"from": item.get("sev"), "sev": new, "judge": verdict, "why": row.get("why", "")}


def review(items: list[dict[str, Any]], ask: bool = True, call: Callable[[str, str], str | None] | None = None,
           background: bool = True) -> dict[str, dict[str, Any]]:
    """{key: {"from", "sev" (or "none" if it dropped to no color), "judge"}} for each state, from the saved verdicts. The new ones are
    asked about by the judge in one thread (or here if background=False). A safety alert (safety) is not judged."""
    now = time.time()
    with _lock:
        memo = _read()
        out, fresh, touched = {}, [], False
        for item in items:
            key, sev = str(item.get("key") or ""), level(item.get("sev", ""))
            if not key or sev not in ("red", "yellow"):
                continue
            if item.get("safety"):
                out[key] = {"from": item.get("sev"), "sev": item.get("sev"), "judge": "safety"}
                continue
            row = memo.get(key)
            if row and row.get("sev") == sev and row.get("verdict") in VERDICTS:
                if now - float(row.get("seen") or 0) > 3600:
                    row["seen"], touched = now, True
                out[key] = _outcome(item, row)
            else:
                out[key] = _outcome(item, None)
                fresh.append(item)
        if touched:
            _write(memo)
    if fresh and ask:
        if background:
            threading.Thread(target=ask_now, args=(fresh, call), name="color-judge", daemon=True).start()
        else:
            ask_now(fresh, call)
            return review(items, ask=False)
    return out
def _sonnet(system: str, prompt: str) -> str | None:
    """Calls the judge slot, the same judge ai_reviewer uses."""
    import ai_providers
    from ai_reviewer import DECIDER_SLOT, judge_names

    pool = ai_providers.ProviderPool(slots=(DECIDER_SLOT,), allow_paid=True, task=TASK)
    if not pool.states:
        return None
    result = pool.complete(system, prompt, max_tokens=1500, attempts=1, wait=False, maximum_wait=0)
    if not result.get("ok") or result.get("provider") not in judge_names():
        return None
    try:
        import model_ledger

        model_ledger.record(TASK, result.get("provider", ""), result.get("model", ""), "done",
                            "verdict on icon and planet colors", ref="color-judge:" + time.strftime("%Y%m%d%H%M"))
    except Exception as error:  # noqa: BLE001 - the ledger must not break the verdict
        logging.debug("color judge: ledger failed: %s", error)
    return str(result.get("text") or "")


def ask_now(fresh: list[dict[str, Any]], call: Callable[[str, str], str | None] | None = None) -> int:
    """Asks the judge about a batch of new items in a single call. Returns the number judged. Never runs two at once, and never more than one call per ASK_EVERY."""
    if not _asking.acquire(blocking=False):
        return 0
    try:
        if call is None and time.time() - _last_ask[0] < ASK_EVERY:
            return 0
        _last_ask[0] = time.time()
        batch = fresh[:BATCH_MAX]
        rows = [{"key": i["key"], "severity": level(i.get("sev", "")), "title": str(i.get("title") or "")[:200],
                 "text": str(i.get("text") or "")[:400]} for i in batch]
        prompt = json.dumps(rows, ensure_ascii=False, indent=1)
        try:
            text = (call or _sonnet)(SYSTEM, prompt)
        except Exception as error:  # noqa: BLE001 - a failed judge keeps the code's color
            logging.debug("color judge: call failed: %s", error)
            text = None
        if not text:
            return 0
        try:
            import ai_providers

            parsed = ai_providers.extract_json(text)
        except Exception:  # noqa: BLE001
            parsed = None
        if not isinstance(parsed, dict):
            return 0
        allowed = {i["key"]: level(i.get("sev", "")) for i in batch}
        now = time.time()
        done = 0
        with _lock:
            memo = _read()
            for row in parsed.get("verdicts") or []:
                key = str((row or {}).get("key") or "")
                if key in allowed and row.get("verdict") in VERDICTS:
                    memo[key] = {"sev": allowed[key], "verdict": row["verdict"], "why": str(row.get("why") or "")[:300],
                                 "at": time.strftime("%Y-%m-%dT%H:%M:%S"), "seen": now}
                    done += 1
            for old in [k for k, v in memo.items() if now - float(v.get("seen") or 0) > KEEP_S]:
                del memo[old]
            _write(memo)
        logging.info("color judge: the judge judged %s of %s", done, len(batch))
        return done
    finally:
        _asking.release()
