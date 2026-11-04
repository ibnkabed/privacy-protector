"""The record of periods the PC left the engine's protection."""

import json
import tempfile
import unittest
from pathlib import Path

from routing_history import RoutingHistory


def at(hour, minute=0):
    return f"2026-11-05T{hour:02d}:{minute:02d}:00+03:00"


class History(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.history = RoutingHistory(self.root)

    def watchdog(self, mode, switch):
        (self.root / "watchdog.json").write_text(
            "﻿" + json.dumps({"mode": mode, "lastSwitchAt": switch}), encoding="utf-8")

    def test_engine_down_writes_one_period_when_it_returns(self):
        self.watchdog("engine", at(1))
        self.history.tick(at(10))
        self.watchdog("engine", at(12, 30))   # switched to the fallback and back while the engine was stopped
        self.history.tick(at(12, 31))
        rows = self.history.recent()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["from"], rows[0]["to"], rows[0]["minutes"]), (at(10), at(12, 30), 150))

    def test_no_switch_writes_nothing(self):
        self.watchdog("engine", at(1))
        self.history.tick(at(10))
        self.history.tick(at(11))
        self.assertEqual(self.history.recent(), [])

    def test_fallback_while_the_engine_runs(self):
        self.watchdog("engine", at(1))
        self.history.tick(at(10))
        self.watchdog("fallback", at(10, 1))
        self.history.tick(at(10, 1))
        self.history.tick(at(10, 5))
        self.watchdog("engine", at(10, 20))
        self.history.tick(at(10, 21))
        self.assertEqual(self.history.recent()[0]["minutes"], 20)

    def test_first_run_has_no_period(self):
        self.watchdog("engine", at(1))
        self.history.tick(at(10))
        self.assertEqual(self.history.recent(), [])


if __name__ == "__main__":
    unittest.main()
