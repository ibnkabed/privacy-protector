import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import privacy_protector  # noqa: E402


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8-sig")


class WindowsScriptContractTests(unittest.TestCase):
    def test_phone_firewall_rules_are_private_and_local_subnet_only(self):
        script = read("scripts/Enable-Phone-Protection.ps1")
        self.assertIn('Profile = "Private"', script)
        self.assertIn('RemoteAddress = "LocalSubnet"', script)
        self.assertIn("-Protocol UDP", script)
        self.assertIn("-Protocol TCP", script)
        self.assertIn("LocalPort = 53", script)

    def test_every_enable_script_has_its_undo(self):
        for enable in (ROOT / "scripts").glob("Enable-*.ps1"):
            with self.subTest(script=enable.name):
                self.assertTrue((ROOT / "scripts" / enable.name.replace("Enable-", "Disable-")).is_file())

    def test_scripts_never_wait_for_a_keypress(self):
        # They run hidden from the app; a prompt would hang them forever.
        for script in (ROOT / "scripts").glob("*.ps1"):
            with self.subTest(script=script.name):
                self.assertNotIn("Read-Host", read(f"scripts/{script.name}"))

    def test_uninstall_undoes_every_windows_change(self):
        script = read("Uninstall-Privacy-Protector.ps1")
        for undo in ("Disable-PC-Protection.ps1", "Disable-Phone-Protection.ps1", "Disable-Capability-History.ps1"):
            self.assertIn(undo, script)
        self.assertIn("-IncludeVersion1", script)
        self.assertIn("CurrentVersion\\Run", script)
        installer = read("packaging/PrivacyProtector.iss")
        self.assertIn("--cleanup-system", installer)
        self.assertIn("uninsdeletevalue", installer)

    def test_names_in_windows_belong_to_this_edition(self):
        for name in ("scripts/Enable-PC-Protection.ps1", "scripts/Enable-Capability-History.ps1"):
            self.assertIn("PrivacyProtector.OpenSource", read(name))

    def test_data_stays_where_version_1_kept_it(self):
        import paths

        with mock.patch.dict("os.environ", {"PRIVACY_PROTECTOR_DATA_DIR": "", "LOCALAPPDATA": r"C:\Users\Example\AppData\Local"}):
            self.assertEqual(paths._data_root(), Path(r"C:\Users\Example\AppData\Local\PrivacyProtector\data"))


class LauncherTests(unittest.TestCase):
    def test_a_running_engine_is_only_opened(self):
        with mock.patch.object(privacy_protector, "engine_running", return_value=True), \
                mock.patch.object(privacy_protector.subprocess, "Popen") as popen, \
                mock.patch.object(privacy_protector.webbrowser, "open") as browser:
            self.assertEqual(privacy_protector.main([]), 0)
        popen.assert_not_called()
        browser.assert_called_once_with(privacy_protector.DASHBOARD)

    def test_background_start_opens_nothing(self):
        with mock.patch.object(privacy_protector, "engine_running", return_value=True), \
                mock.patch.object(privacy_protector.webbrowser, "open") as browser:
            self.assertEqual(privacy_protector.main(["--background"]), 0)
        browser.assert_not_called()

    def test_helper_scripts_run_inside_the_program(self):
        with mock.patch("runpy.run_path") as run_path:
            privacy_protector.main([str(ROOT / "tools" / "list_ios_apps.py"), "--json"])
        run_path.assert_called_once()
        with mock.patch("runpy.run_module") as run_module:
            privacy_protector.main([str(ROOT / "missing" / "program_inventory.py"), "--scan", "x"])
        self.assertEqual(run_module.call_args[0][0], "program_inventory")


if __name__ == "__main__":
    unittest.main()
