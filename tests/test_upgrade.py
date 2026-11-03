"""Version 2 opens the data version 1 left behind, keeping your rules and apps."""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app  # noqa: E402
from privacy_control import PrivacyControlStore  # noqa: E402
from settings import Settings  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "v1-data"


class UpgradeFromVersion1Tests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.data = Path(self.folder.name)
        for item in FIXTURE.iterdir():
            shutil.copy(item, self.data / item.name)

    def test_rules_apps_and_controls_are_kept(self):
        policy = app.PolicyStore(self.data / "policy.json")
        self.assertEqual(policy.action_for("ads.example.net"), "block")
        profiles = app.AppProfileStore(self.data / "apps.json").snapshot()
        self.assertIn("com.example.bank", [p.get("bundleID") for p in profiles["apps"]])
        self.assertIn("com.example.maps", [p.get("bundleID") for p in profiles["detectedApps"]])
        PrivacyControlStore(self.data / "privacy-controls.json").snapshot()

    def test_an_upgrade_asks_what_to_protect_before_changing_anything(self):
        settings = Settings(self.data / "settings.json")
        self.assertFalse(settings.snapshot()["firstRunDone"])
        self.assertFalse(settings.enabled("phone"))
        self.assertFalse(settings.enabled("pc"))


if __name__ == "__main__":
    unittest.main()
