"""A fault that clears by itself paints green "Previous alert resolved" before white; a level that never alerted does not."""
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tray_icon  # noqa: E402


class Resolved(unittest.TestCase):
    def test_cleared_fault_paints_green_then_white(self):
        self.assertGreater(tray_icon.settle("red", "white", 100.0), 100.0)
        icon = mock.Mock()
        with mock.patch.object(tray_icon, "_icon", icon), \
                mock.patch.dict(tray_icon._state, {"level": "white", "reason": "", "deciding": 0, "green_until": 0.0,
                                                   "resolved_until": time.time() + 5}):
            tray_icon._paint()
            self.assertIn(tray_icon.RESOLVED_TIP, icon.title)
            tray_icon._state["resolved_until"] = 0.0
            tray_icon._paint()
            self.assertNotIn(tray_icon.RESOLVED_TIP, icon.title)

    def test_no_alert_no_green(self):
        self.assertEqual(tray_icon.settle("white", "white", 100.0), 0.0)
        self.assertEqual(tray_icon.settle("red", "orange", 100.0), 0.0)


if __name__ == "__main__":
    unittest.main()
