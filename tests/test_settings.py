"""Every switch in Settings turns its part on and off at once, and off leaves no trace."""

import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ai_providers  # noqa: E402
from features import Features, Switch  # noqa: E402
from settings import DEFAULTS, Settings, normalize  # noqa: E402


class FakeService:
    def __init__(self):
        self.stop_event = threading.Event()
        self.starts = 0
        self.stops = 0

    def start(self):
        self.starts += 1

    def shutdown(self):
        self.stops += 1
        self.stop_event.set()


class FakeCapabilities(FakeService):
    kind_filter = None


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "settings.json"

    def test_everything_is_off_until_chosen(self):
        settings = Settings(self.path)
        for key in ("phone", "pc", "outlook", "defender", "tempCleanup", "models", "capabilities"):
            self.assertFalse(settings.enabled(key), key)
        self.assertFalse(settings.snapshot()["firstRunDone"])

    def test_update_is_saved_and_survives_a_restart(self):
        Settings(self.path).update({"pc": True, "capabilities": {"enabled": True, "webcam": False}, "language": "ar"})
        again = Settings(self.path)
        self.assertTrue(again.enabled("pc"))
        self.assertTrue(again.enabled("microphone"))
        self.assertFalse(again.enabled("webcam"))
        self.assertEqual(again.snapshot()["language"], "ar")

    def test_unknown_values_are_ignored(self):
        data = normalize({"language": "xx", "phone": "yes", "evil": 1})
        self.assertEqual(data["language"], "en")
        self.assertTrue(data["phone"])
        self.assertNotIn("evil", data)
        self.assertEqual(set(data), set(DEFAULTS))


class FeatureSwitchTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.settings = Settings(Path(self.folder.name) / "settings.json")
        self.bound: list = []
        self.scripts: list = []
        self.services = {name: FakeService() for name in ("phone", "pc", "mail", "defender", "cleanup", "inventory")}
        self.caps = FakeCapabilities()
        config = {"enabled": False, "providers": []}
        for target, name, value in (
            (ai_providers, "load_config", mock.Mock(side_effect=lambda: dict(config))),
            (ai_providers, "save_config", mock.Mock(side_effect=lambda data: config.update(data))),
        ):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.config = config
        self.features = Features(
            self.settings,
            dns=self.bound.append,
            capabilities=self.caps,
            run_script=lambda name, *args, **kw: self.scripts.append(name) or True,
            switches={
                "phone": [Switch("phone", self.services["phone"])],
                "pc": [Switch("pc", self.services["pc"])],
                "any": [Switch("inventory", self.services["inventory"])],
                "capabilities": [Switch("caps", self.caps)],
                "outlook": [Switch("outlook", self.services["mail"])],
                "defender": [Switch("defender", self.services["defender"])],
                "tempCleanup": [Switch("cleanup", self.services["cleanup"])],
            },
        )
        self.features.start()

    def test_first_start_listens_nowhere_and_changes_nothing(self):
        self.assertEqual(self.bound, [None])
        self.assertEqual(self.scripts, [])
        self.assertTrue(all(s.starts == 0 for s in self.services.values()))

    def test_pc_alone_listens_on_this_computer_and_runs_its_script(self):
        self.settings.update({"pc": True})
        self.assertEqual(self.bound[-1], "127.0.0.1")
        self.assertEqual(self.scripts, ["Enable-PC-Protection.ps1"])
        self.assertEqual(self.services["pc"].starts, 1)
        self.assertEqual(self.services["phone"].starts, 0)

    def test_phone_alone_listens_on_the_network(self):
        self.settings.update({"phone": True})
        self.assertEqual(self.bound[-1], "0.0.0.0")
        self.assertEqual(self.scripts, ["Enable-Phone-Protection.ps1"])
        self.assertEqual(self.services["pc"].starts, 0)

    def test_turning_one_off_keeps_the_other_running(self):
        self.settings.update({"phone": True, "pc": True})
        self.settings.update({"phone": False})
        self.assertEqual(self.bound[-1], "127.0.0.1")
        self.assertEqual(self.scripts[-1], "Disable-Phone-Protection.ps1")
        self.assertEqual(self.services["phone"].stops, 1)
        self.assertEqual(self.services["pc"].stops, 0)
        self.assertEqual(self.services["inventory"].stops, 0)

    def test_both_off_removes_every_trace(self):
        self.settings.update({"phone": True, "pc": True})
        self.settings.update({"phone": False, "pc": False})
        self.assertIsNone(self.bound[-1])
        self.assertIn("Disable-PC-Protection.ps1", self.scripts)
        self.assertIn("Disable-Phone-Protection.ps1", self.scripts)
        self.assertEqual(self.services["inventory"].stops, 1)

    def test_a_service_restarts_after_being_turned_off(self):
        for value in (True, False, True):
            self.settings.update({"outlook": value})
        self.assertEqual((self.services["mail"].starts, self.services["mail"].stops), (2, 1))
        self.assertFalse(self.services["mail"].stop_event.is_set())

    def test_each_capability_kind_has_its_own_switch(self):
        self.settings.update({"capabilities": {"enabled": True, "location": False}})
        self.assertEqual(self.caps.starts, 1)
        self.assertTrue(self.caps.kind_filter("microphone"))
        self.assertFalse(self.caps.kind_filter("location"))
        self.settings.update({"capabilities": {"enabled": False}})
        self.assertEqual(self.caps.stops, 1)
        self.assertFalse(self.caps.kind_filter("microphone"))

    def test_models_follow_their_switch(self):
        self.settings.update({"models": True})
        self.assertTrue(self.config["enabled"])
        self.settings.update({"models": False})
        self.assertFalse(self.config["enabled"])

    def test_a_declined_prompt_is_reported(self):
        self.features.run_script = lambda *a, **k: False
        self.settings.update({"pc": True})
        self.assertIn("did not allow", self.features.last_error)


class CapabilityKindFilterTests(unittest.TestCase):
    def test_a_kind_turned_off_is_not_recorded(self):
        import capability_monitor as cm

        with tempfile.TemporaryDirectory() as folder:
            monitor = cm.CapabilityMonitor(Path(folder), history_dir=Path(folder) / "h", work_dir=Path(folder) / "w")
            monitor.kind_filter = lambda kind: kind != "location"
            monitor._append({"type": "series", "capability": "location"})
            monitor._append({"type": "series", "capability": "microphone"})
            self.assertEqual([r["capability"] for r in monitor.closed], ["microphone"])


if __name__ == "__main__":
    unittest.main()
