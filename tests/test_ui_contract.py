import re
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB = PROJECT_ROOT / "web"
HTML_PATH = WEB / "orbit.html"
SCRIPT_PATH = WEB / "orbit.js"
PANELS_PATH = WEB / "orbit-panels.js"
STYLES_PATH = WEB / "orbit.css"
NOTIFICATION_PATH = PROJECT_ROOT / "Show-Privacy-Protector-Notification.ps1"
ORIGINAL_LOGO_PATH = PROJECT_ROOT / "web" / "assets" / "Privacy Protector.png"
RED_NOTIFICATION_LOGO_PATH = (
    PROJECT_ROOT / "web" / "assets" / "Privacy Protector notification red.png"
)
GREEN_NOTIFICATION_LOGO_PATH = (
    PROJECT_ROOT / "web" / "assets" / "Privacy Protector notification green.png"
)


class OrbitDashboardTests(unittest.TestCase):
    """The 'Moonlit night' dashboard only; the classic one was removed and its
    tools migrated here."""

    @classmethod
    def setUpClass(cls):
        cls.html = HTML_PATH.read_text(encoding="utf-8")
        cls.script = SCRIPT_PATH.read_text(encoding="utf-8")
        cls.panels = PANELS_PATH.read_text(encoding="utf-8")
        cls.styles = STYLES_PATH.read_text(encoding="utf-8")
        cls.notification = NOTIFICATION_PATH.read_text(encoding="utf-8")

    def test_classic_dashboard_is_gone(self):
        for name in ("Privacy Protector.html", "app.js", "pc.js", "styles.css"):
            self.assertFalse((WEB / name).exists(), name)
        server = (PROJECT_ROOT / "app.py").read_text(encoding="utf-8")
        self.assertIn('self.path = "/orbit.html"', server)
        self.assertNotIn("Privacy%20Protector.html", server)
        self.assertNotIn('id="classic"', self.html)

    def test_page_obeys_same_origin_content_policy(self):
        # Content policy 'self': no inline code or styles in the page or in what
        # the code generates
        self.assertNotIn("<script>", self.html)
        self.assertNotIn("<style>", self.html)
        for source in (self.html, self.script, self.panels):
            self.assertNotIn('style="', source)

    def test_every_moved_tool_has_a_place(self):
        for button in ("open-settings", "open-activity", "open-perms", "review",
                       "open-ledger", "open-paid", "open-models", "dev-pc", "dev-phone"):
            self.assertIn(f'id="{button}"', self.html)
        for endpoint in ("/api/dns/self-test", "/api/pc/setup", "/api/pc/capability-history/setup",
                         "/api/device/apps/scan", "/api/developer-mode/status", "/api/apps/discovered",
                         "/api/logs", "/api/policy", "/api/privacy-controls", "/api/privacy-capture/start",
                         "/api/privacy-capture/stop", "/api/ai/review", "/api/ai/stop", "/api/ai/calibrate",
                         "/api/ai/block-risks", "/api/classifications/analyze"):
            self.assertIn(endpoint, self.panels, endpoint)

    def test_operations_tray_keeps_its_storage_and_stays_manual(self):
        self.assertIn('"privacy-protector-operation-tray-v3"', self.panels)
        self.assertIn("no rule made", self.panels)
        self.assertIn('armed(b,"Confirm block")', self.panels)

    def test_report_import_is_batched_below_server_request_limit(self):
        self.assertIn("IMPORT_LIMIT=96*1024", self.panels)
        self.assertIn("CHUNK=100", self.panels)

    def test_dns_connection_reminder_reaches_the_core(self):
        self.assertIn("rem.dnsAddress", self.script)
        self.assertIn('rem.state==="lost"||rem.state==="disconnected"', self.script)

    def test_every_program_and_app_is_a_planet(self):
        # All programs and apps appear without limit, and their color reflects
        # their state, not decisions
        self.assertNotIn("MAX_PLANETS", self.script)
        self.assertIn("pcPrograms.forEach", self.script)
        self.assertIn("capGroups.forEach", self.script)
        self.assertIn("return phoneApps.map(", self.script)
        self.assertIn('if(d.blocked)return "green";', self.script)

    def test_dns_notifications_are_minimal_and_use_state_specific_logos(self):
        self.assertTrue(ORIGINAL_LOGO_PATH.is_file())
        self.assertTrue(RED_NOTIFICATION_LOGO_PATH.is_file())
        self.assertTrue(GREEN_NOTIFICATION_LOGO_PATH.is_file())
        self.assertIn('Privacy Protector notification red.png', self.notification)
        self.assertIn('Privacy Protector notification green.png', self.notification)
        self.assertIn('"Your phone is not connected"', self.notification)
        self.assertIn('"DNS: $DnsAddress"', self.notification)
        self.assertIn('"Your phone is connected"', self.notification)
        self.assertNotIn('-Attribution', self.notification)
        self.assertNotIn('Configure DNS', self.notification)
        self.assertNotIn('An alert will be sent', self.notification)
        self.assertNotIn('Monitors domains', self.notification)
