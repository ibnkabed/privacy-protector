"""A local log of what the optional models did, for the Model log panel.

One JSON line per model action in ``<data dir>/model-ledger/work-ledger.jsonl``:
{"at", "task", "task_ar", "provider", "model", "column", "item", "detail", "ref"}
``column``: done, wrong (done incorrectly), not_done, missed (skipped by the model but required).
``ref`` is the item's stable identifier: ``domain:<domain>`` for reading and voting, ``red:<domain>``
for red confirmation, ``exam:<provider>/<model>:<domain>`` for the model check, and ``search:<domain>``.
A newer entry with the same ``ref`` replaces the earlier one in the view.

The log holds the domain names you visit, so it stays on this computer and is never sent anywhere.
Any failure here never affects review or blocking.
"""

from __future__ import annotations

import json
import sys
import threading
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

import paths

ROOT = Path(__file__).resolve().parent
LEDGER_PATH = paths.DATA_ROOT / "model-ledger" / "work-ledger.jsonl"
_DEFAULT_PATH = LEDGER_PATH
COLUMNS = ("done", "wrong", "not_done", "missed")
# Task name as known by the app and portal → its static ID and Arabic name in the log.
TASKS = {
    "Domain Review": ("domain-review", "Read domain and decide"),
    "Second opinion on red": ("second-opinion", "Second opinion on red"),
    "red confirmation": ("red-confirmation", "Confirm red via voting"),
    "model exam": ("model-exam", "model exam"),
    "Search Domain Purpose": ("domain-search", "Search Domain Purpose"),
    # Review: the jurors decide, and the judge affirms or overturns before anything runs.
    "jury verdict": ("jury-verdict", "Jury verdict"),
    "judge's confirmation": ("judge-review", "Judge's affirmation"),
    # The judge also reviews the icon and planet colors (color_judge.py).
    "the color judge": ("color-judge", "Judge's ruling on colors"),
}
FREE_MODELS: tuple[str, ...] = ()
COLOR_AR = {"green": "Green", "orange": "Orange", "red": "Red"}
WINDOW_HOURS = 2
_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def task_ids(task_name: str) -> tuple[str, str]:
    return TASKS.get(task_name, ("other", task_name or "Other Task"))


def record(task_name: str, provider: str, model: str, column: str, item: str, detail: str = "",
           at: str = "", ref: str = "") -> None:
    """Adds a line. Tests do not write to the real log unless its path is changed."""
    if column not in COLUMNS:
        return
    if "unittest" in sys.modules and LEDGER_PATH == _DEFAULT_PATH:
        return
    task, task_ar = task_ids(task_name)
    row = {
        "at": at or _now(), "task": task, "task_ar": task_ar,
        "provider": str(provider or ""), "model": str(model or ""), "column": column,
        "item": str(item)[:300], "detail": str(detail)[:2000],
    }
    if ref:
        row["ref"] = str(ref)[:300]
    try:
        with _lock:
            LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
            with LEDGER_PATH.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    except OSError:
        pass


def verdict_item(domain: str, verdict: dict[str, Any]) -> tuple[str, str]:
    color = COLOR_AR.get(str(verdict.get("color")), str(verdict.get("color") or ""))
    category = str(verdict.get("category") or "")
    item = f"{domain}: {color}" + (f" — {category}" if category else "")
    detail = " ".join(
        part for part in (
            str(verdict.get("reason") or ""),
            ("Blocking impact: " + str(verdict.get("blockImpact"))) if verdict.get("blockImpact") else "",
            "Blocking it is safe." if verdict.get("blockSafe") else "Blocking it is not safe.",
        ) if part
    )
    return item, detail


def record_batch(task_name: str, response: dict[str, Any], domains: Iterable[str],
                 verdicts: dict[str, dict[str, Any]]) -> None:
    """Read a batch of domains: each valid verdict is done, what was dropped from a successful
    response is missed, and a failure is not done, one line per domain.

    What is not done or missed has no verdict saved for it, so the domain returns to review in the
    next cycle (a read with no effect), and its new verdict is written with the same ``ref``, which
    replaces the earlier one in the view.
    """
    domains = list(domains)
    provider, model = response.get("provider", ""), response.get("model", "")
    if not response.get("ok"):
        errors = "; ".join(str(item) for item in (response.get("errors") or [])[:3])
        for domain in domains:
            record(task_name, provider, model, "not_done",
                   f"{domain}: could not be read in a batch of {len(domains)} domains",
                   "Verdict requested on: " + ", ".join(domains) + (". The error: " + errors if errors else ""),
                   ref="domain:" + domain)
        return
    for domain in domains:
        verdict = verdicts.get(domain)
        if verdict:
            item, detail = verdict_item(domain, verdict)
            record(task_name, provider, model, "done", item, detail, ref="domain:" + domain)
        else:
            record(task_name, provider, model, "missed", f"{domain}: no verdict was returned",
                   "The model answered the batch and dropped this domain, or replied with something that is not a valid verdict.",
                   ref="domain:" + domain)


def record_confirmation(domain: str, verdict: dict[str, Any], agreed: bool, summary: str,
                        winner: str = "") -> None:
    """Second-opinion verdict on the first red: the vote confirmed it so it is done, or overturned
    it so it is written as a mistake.

    The overturn is itself the handling of the error: the vote settled the domain's color, so one
    second after it a done line under "the vote" is written with the same ``ref``, which the
    view resolves and does not carry. The model's error stays in the file and in its done rate.
    """
    item = f"{domain}: its red was " + ("confirmed by the vote" if agreed else "overturned by the vote")
    detail = f"The first verdict was red because: {verdict.get('reason', '')}. The vote: {summary}."
    at = _now()
    record("red confirmation", verdict.get("provider", ""), verdict.get("model", ""),
           "done" if agreed else "wrong", item, detail, at=at, ref="red:" + domain)
    if not agreed:
        later = (datetime.fromisoformat(at) + timedelta(seconds=1)).isoformat(timespec="seconds")
        color = COLOR_AR.get(winner, winner or "not red")
        record("red confirmation", "the vote", "", "done", f"{domain}: the vote settled it as {color}",
               f"The vote: {summary}.", at=later, ref="red:" + domain)


def record_judgement(domain: str, jury: dict[str, Any], judge: dict[str, Any], confirmed: bool) -> None:
    """The judge's ruling on the jury's verdict, with the same
    ``domain:<domain>`` ref.

    Confirmation is a done line under the judge. An overturn is a "done wrongly" line under the
    juror who ruled, followed one second later by a done line under the judge with its verdict, which
    the view resolves and does not carry, while the juror's error stays in its done rate. The
    detail holds both verdicts.
    """
    jury_color = COLOR_AR.get(str(jury.get("color")), str(jury.get("color") or ""))
    judge_color = COLOR_AR.get(str(judge.get("color")), str(judge.get("color") or ""))
    detail = (f"The jury ({jury.get('provider', '')}): {jury_color} — {jury.get('reason', '')}. "
              f"And the judge ({judge.get('provider', '')}): {judge_color} — {judge.get('reason', '')}.")
    ref = "domain:" + domain
    at = _now()
    if confirmed:
        record("judge's confirmation", judge.get("provider", ""), judge.get("model", ""), "done",
               f"{domain}: the judge confirmed the jury's verdict {jury_color}", detail, at=at, ref=ref)
        return
    record("jury verdict", jury.get("provider", ""), jury.get("model", ""), "wrong",
           f"{domain}: the judge overturned the jury's verdict {jury_color}", detail, at=at, ref=ref)
    later = (datetime.fromisoformat(at) + timedelta(seconds=1)).isoformat(timespec="seconds")
    record("judge's confirmation", judge.get("provider", ""), judge.get("model", ""), "done",
           f"{domain}: the judge's verdict is {judge_color} instead of {jury_color}", detail,
           at=later, ref=ref)


# ------------------------------------------------------------ reading ---
def read(days: int | None = None, path: Path | None = None, hours: float | None = None) -> list[dict[str, Any]]:
    path = path or LEDGER_PATH
    span = timedelta(hours=hours) if hours else timedelta(days=days) if days else None
    since = datetime.now(timezone.utc) - span if span else None
    rows: list[dict[str, Any]] = []
    for row in tail_jsonl(path):   # from the end of the file with a fixed bound, not from its start
        try:
            if since and datetime.fromisoformat(str(row.get("at"))) < since:
                continue
            rows.append(row)
        except (ValueError, TypeError):
            continue
    return rows
def window(timeout: float = 4.0) -> dict[str, Any]:
    """The Model log panel: what is unresolved in the last hours of the file."""
    found = unresolved(read(hours=WINDOW_HOURS))
    since = (datetime.now(timezone.utc) - timedelta(hours=WINDOW_HOURS)).isoformat(timespec="seconds")
    return {"source": "file", "since": since, "next_scan_after": "", "rows": found["rows"],
            "summary": found["summary"], "truncated": False}


def detail(ref: str = "", at: str = "") -> dict[str, Any]:
    """Detail of an item on click: from the file tail by ref and time, newest first."""
    if not ref and not at:
        return {"detail": "", "found": False}
    for row in reversed(tail_jsonl(LEDGER_PATH)):
        if (not ref or row.get("ref") == ref) and (not at or row.get("at") == at):
            return {"detail": row.get("detail", ""), "item": row.get("item", ""), "found": True}
    return {"detail": "", "found": False}


def paid_view() -> dict[str, Any]:
    """🏅 From the local log tail: task × model for the paid ones, weakest first."""
    rows = [r for r in tail_jsonl(LEDGER_PATH) if is_paid(str(r.get("provider") or ""), str(r.get("model") or ""))]
    return paid_table(rows)


def is_paid(provider: str, model: str) -> bool:
    """Every configured provider counts, except free model names."""
    return bool(provider) and not str(model).endswith(":free") and model not in FREE_MODELS


# ------------------------------------------------------------ tail helpers ---
TAIL_BYTES = 262144
MAX_ROWS = 200
BAD_COLUMNS = ("wrong", "not_done", "missed")


def tail_jsonl(path: Any, max_bytes: int = TAIL_BYTES) -> list[dict[str, Any]]:
    """JSONL rows from the end of the file, within a fixed size however large it grows."""
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            start = max(0, handle.tell() - max_bytes)
            handle.seek(start)
            data = handle.read()
    except OSError:
        return []
    rows = []
    for raw in data.split(b"\n")[1 if start else 0:]:
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def unresolved(rows: list[dict[str, Any]], max_rows: int = MAX_ROWS) -> dict[str, Any]:
    """The last entry per item (by ref) when it is not done, newest first, without detail; with counts."""
    counts = dict.fromkeys(("done",) + BAD_COLUMNS, 0)
    last: dict[str, dict[str, Any]] = {}
    calls, since = 0, None
    for i, row in enumerate(rows):
        if row.get("column") in counts:
            counts[row["column"]] += 1
        calls += 1
        at = row.get("at")
        since = min(since, at) if since and at else since or at
        last[row.get("rid") or row.get("thread") or row.get("ref") or f"#{i}"] = row
    items = [{k: v for k, v in r.items() if k != "detail"} for r in last.values()
             if r.get("column") != "done" and (r.get("column") in BAD_COLUMNS or r.get("carried"))]
    items.sort(key=lambda r: str(r.get("at") or ""), reverse=True)
    return {"rows": items[:max_rows], "summary": {**counts, "paid_calls": calls, "since": since}}


def paid_table(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Task x model, weakest completion rate first; models at 100% appear only in the summary."""
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        task = str(r.get("task") or "?")
        model = str(r.get("model") or r.get("provider") or "?")
        g = groups.setdefault((task, model), {"task": task, "model": model, "done": 0, "wrong": 0, "not_done": 0, "total": 0})
        g["total"] += 1
        if r.get("column") in ("done", "wrong", "not_done"):
            g[r["column"]] += 1
    for g in groups.values():
        g["rate"] = round(g["done"] / g["total"], 3)
    table = sorted((g for g in groups.values() if g["rate"] < 1), key=lambda g: (g["rate"], -g["total"]))
    worst = {"model": table[0]["model"], "rate": table[0]["rate"]} if table else None
    return {"rows": table, "summary": {"calls": len(rows), "models": len({g["model"] for g in groups.values()}),
                                       "perfect": len(groups) - len(table), "worst": worst}}


def paid_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """For each task and each paid model: counts of ✓ and ✗, not done and missed, and completion rate."""
    table: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        provider, model = str(row.get("provider") or ""), str(row.get("model") or "")
        if not is_paid(provider, model):
            continue
        key = (str(row.get("task_ar") or row.get("task")), provider, model)
        entry = table.setdefault(key, {"task": key[0], "provider": provider, "model": model,
                                       "done": 0, "wrong": 0, "not_done": 0, "missed": 0})
        column = row.get("column")
        if column in COLUMNS:
            entry[column] += 1
    result = []
    for entry in table.values():
        total = entry["done"] + entry["wrong"] + entry["not_done"] + entry["missed"]
        entry["total"] = total
        entry["rate"] = round(entry["done"] * 100 / total) if total else 0
        result.append(entry)
    return sorted(result, key=lambda item: (item["task"], -item["rate"], item["provider"]))
