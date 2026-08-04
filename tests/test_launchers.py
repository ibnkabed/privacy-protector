import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8-sig")


class WindowsLauncherContractTests(unittest.TestCase):
    def test_runtime_diagnostics_live_outside_the_source_tree(self):
        for name in (
            "Start-Privacy-Protector-Background.ps1",
            "Prepare-iPhone-Connection.ps1",
            "launch_edge_maximized.ps1",
        ):
            script = read(name)
            self.assertIn("LOCALAPPDATA", script)
            self.assertIn("PrivacyProtector", script)
            self.assertNotIn('Join-Path $AppRoot "data"', script)

    def test_background_mode_starts_only_the_dns_and_dashboard_backend(self):
        script = read("Start-Privacy-Protector-Background.ps1")
        self.assertIn('"--dns-port", "53"', script)
        self.assertIn('"--web-port", "8733"', script)
        self.assertNotIn("--continuous-iphone-evidence", script)
        self.assertNotIn("watch_ios_function_events", script)
        self.assertIn("/api/health", script)

    def test_foreground_test_mode_uses_non_privileged_dns_port(self):
        script = read("Start-Privacy-Protector.ps1")
        self.assertIn("53053", script)
        self.assertIn("/api/health", script)

    def test_firewall_rules_are_private_and_local_subnet_only(self):
        script = read("Prepare-iPhone-Connection.ps1")
        self.assertGreaterEqual(script.count("-Profile Private"), 2)
        self.assertGreaterEqual(script.count("-RemoteAddress LocalSubnet"), 2)
        self.assertIn("-Protocol UDP", script)
        self.assertIn("-Protocol TCP", script)

    def test_port_53_coordination_is_limited_to_shared_access(self):
        script = read("Prepare-iPhone-Connection.ps1")
        self.assertIn('$OwnerServices.Count -eq 1 -and $OwnerServices[0].Name -eq "SharedAccess"', script)
        self.assertIn("Restore-SharedAccessStartMode", script)
        self.assertIn("unrelated process", script.lower())

    def test_shortcut_uses_an_english_name_and_relative_project_entry(self):
        script = read("create-shortcut.ps1")
        self.assertIn('"Privacy Protector"', script)
        self.assertIn('Join-Path $PSScriptRoot "Privacy Protector.cmd"', script)
        self.assertNotIn("Desktop\\", script)

    def test_hidden_launcher_prefers_powershell_7(self):
        script = read("launch_hidden.vbs").lower()
        self.assertIn("pwsh.exe", script)
        self.assertIn("powershell.exe", script)

    def test_startup_installer_targets_the_background_script(self):
        script = read("Install-Privacy-Protector-Startup.ps1")
        self.assertIn("Start-Privacy-Protector-Background.ps1", script)
        self.assertIn("Startup", script)


if __name__ == "__main__":
    unittest.main()
