"""The judge handles icon and planet colors. No real call."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import color_judge  # noqa: E402
import tray_icon  # noqa: E402


def _setup(tmp_path, monkeypatch):
    monkeypatch.setattr(color_judge, "STORE", tmp_path / "color-judge.json")
    color_judge._last_ask[0] = 0.0


def _answer(calls, verdicts):
    def call(system, prompt):
        calls.append(json.loads(prompt))
        return json.dumps({"verdicts": verdicts}, ensure_ascii=False)
    return call


def test_one_batched_call_then_remembered(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    calls = []
    items = [{"key": "planet:pc:a", "sev": "red", "title": "a"}, {"key": "planet:pc:b", "sev": "orange", "title": "b"},
             {"key": "planet:pc:c", "sev": "orange", "title": "c"}]
    call = _answer(calls, [{"key": "planet:pc:a", "verdict": "info", "why": "x"},
                           {"key": "planet:pc:b", "verdict": "raise", "why": "y"},
                           {"key": "planet:pc:c", "verdict": "confirm", "why": "z"}])
    got = color_judge.review(items, call=call, background=False)
    assert len(calls) == 1 and len(calls[0]) == 3
    assert got["planet:pc:a"]["sev"] == "none"
    assert got["planet:pc:b"]["sev"] == "red"
    assert got["planet:pc:c"]["sev"] == "orange"
    again = color_judge.review(items, call=call, background=False)
    assert len(calls) == 1
    assert again == got


def test_unavailable_keeps_code_color(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    got = color_judge.review([{"key": "tray:x", "sev": "red", "title": "x"}], call=lambda s, p: None, background=False)
    assert got["tray:x"] == {"from": "red", "sev": "red", "judge": "pending"}
    assert not (tmp_path / "color-judge.json").exists()


def test_safety_never_judged(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    calls = []
    got = color_judge.review([{"key": "core:engine", "sev": "red", "title": "engine", "safety": True}],
                             call=_answer(calls, []), background=False)
    assert calls == [] and got["core:engine"]["sev"] == "red"


def test_changed_severity_is_new_and_batch_cap(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    calls = []
    call = _answer(calls, [{"key": "tray:x", "verdict": "confirm"}])
    color_judge.review([{"key": "tray:x", "sev": "yellow"}], call=call, background=False)
    color_judge.review([{"key": "tray:x", "sev": "red"}], call=call, background=False)
    assert len(calls) == 2
    many = [{"key": f"planet:{i}", "sev": "red"} for i in range(color_judge.BATCH_MAX + 7)]
    color_judge.review(many, call=_answer(calls, [{"key": i["key"], "verdict": "confirm"} for i in many]),
                       background=False)
    assert len(calls[-1]) == color_judge.BATCH_MAX


def test_numbers_do_not_make_a_new_state():
    assert color_judge.key_of("tray", "Notes from the review: 3") == color_judge.key_of("tray", "Notes from the review: 4")


def test_tray_applies_verdicts(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    lowered, raised, data = "Notes from the review: 2", "Phone not connected", "Corrupted protection data"
    color_judge.review([{"key": color_judge.key_of("tray", lowered), "sev": "red"},
                        {"key": color_judge.key_of("tray", raised), "sev": "yellow"}],
                       call=_answer([], [{"key": color_judge.key_of("tray", lowered), "verdict": "info"},
                                         {"key": color_judge.key_of("tray", raised), "verdict": "raise"}]),
                       background=False)
    monkeypatch.setattr(color_judge, "ask_now", lambda *a, **k: 0)
    red, yellow = tray_icon.judged([lowered, data], [raised], {data})
    assert red == [data, raised] and yellow == []


def test_tray_falls_back_when_judge_breaks(monkeypatch):
    monkeypatch.setattr(color_judge, "review", lambda *a, **k: 1 / 0)
    assert tray_icon.judged(["a"], ["b"]) == (["a"], ["b"])
