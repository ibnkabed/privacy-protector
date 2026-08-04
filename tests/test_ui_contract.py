import re
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HTML_PATH = PROJECT_ROOT / "web" / "Privacy Protector.html"
SCRIPT_PATH = PROJECT_ROOT / "web" / "app.js"
STYLES_PATH = PROJECT_ROOT / "web" / "styles.css"
ARABIC = re.compile(r"[\u0600-\u06ff\u0750-\u077f\u08a0-\u08ff]")


class ContinuousDashboardListsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = HTML_PATH.read_text(encoding="utf-8")
        cls.script = SCRIPT_PATH.read_text(encoding="utf-8")
        cls.styles = STYLES_PATH.read_text(encoding="utf-8")

    def test_interface_is_english_ltr(self):
        self.assertIn('<html lang="en" dir="ltr">', self.html)
        self.assertNotRegex(self.html + self.script + self.styles, ARABIC)
        for term in (
            "Application Activity & Connections",
            "Privacy Protection Actions",
            "Permission Center",
            "Check Developer Mode",
            "Latest observation",
            "Latest block",
        ):
            self.assertIn(term, self.html + self.script)

    def test_activity_and_policy_pagination_controls_are_absent(self):
        for control_id in ("prevPage", "nextPage", "pageLabel", "prevPolicy", "nextPolicy", "policyPageLabel"):
            self.assertNotIn(f'id="{control_id}"', self.html)
        for state_key in ("pageSize", "policyPage", "policyPageSize"):
            self.assertNotIn(state_key, self.script)

    def test_all_matching_items_render_in_continuous_page_flow(self):
        self.assertIn("for (const item of state.filteredRows)", self.script)
        self.assertIn("for (const entry of entries)", self.script)
        self.assertRegex(self.styles, re.compile(r"body\s*\{[^}]*overflow-y\s*:\s*auto", re.DOTALL))
        for selector in ("table-wrap", "policy-list"):
            self.assertNotRegex(self.styles, re.compile(rf"\.{selector}\s*\{{[^}}]*overflow-y\s*:\s*(?:auto|scroll)", re.DOTALL))

    def test_operations_workspace_is_manual_and_policy_independent(self):
        for control_id in ("operationFilter", "operationSort", "clearOperationsView"):
            self.assertIn(f'id="{control_id}"', self.html)
        self.assertIn("function clearOperationsView()", self.script)
        self.assertIn("function removeOperationFromTray(domain)", self.script)
        self.assertIn('const operationTrayStorageKey = "privacy-protector-operation-tray-v2"', self.script)
        self.assertIn('action: ""', self.script)
        self.assertIn("addOperationToTray(key)", self.script)

    def test_activity_controls_manual_transfer_and_sorting(self):
        self.assertIn('id="rowSort"', self.html)
        for value in ("time", "application", "domain", "classification"):
            self.assertIn(f'<option value="{value}"', self.html)
        self.assertIn('rowSort: "time"', self.script)
        self.assertIn("function sortActivityRows()", self.script)
        self.assertIn("!operationIsVisible(operationKeyForRow(row))", self.script)

    def test_activity_exposes_attribution_provenance(self):
        self.assertIn("function applicationNameForRow(row)", self.script)
        self.assertIn("applicationIdentityForRow(item)", self.script)
        self.assertIn("Exact attribution from iOS process metadata over USB", self.script)
        self.assertIn("Confirmed attribution from an Apple App Privacy Report", self.script)
        self.assertIn("Unattributed - DNS only", self.script)
        self.assertIn("rowLastObservedAt(item)", self.script)

    def test_report_import_is_batched_below_server_request_limit(self):
        self.assertIn("REPORT_IMPORT_REQUEST_LIMIT = 96 * 1024", self.script)
        self.assertIn("new TextEncoder()", self.script)
        self.assertIn("buildDiscoveredBatches", self.script)
        self.assertIn("for (const batch of batches)", self.script)

    def test_shared_domain_renders_once_with_expandable_app_names(self):
        self.assertIn("function groupReportRowsByDomain(rows)", self.script)
        self.assertIn("shared.className = \"shared-applications\"", self.script)
        self.assertIn('toggle.setAttribute("aria-expanded"', self.script)
        self.assertIn("expandedSharedDomains: new Set()", self.script)
        self.assertIn("for (const name of identity.names)", self.script)

    def test_v3_uses_permanent_green_orange_red_classifications(self):
        self.assertIn('id="analyzeDomains"', self.html)
        for risk in ("green", "orange", "red"):
            self.assertIn(f'<option value="{risk}">', self.html)
            self.assertIn(f".tag.risk-{risk}", self.styles)
            self.assertIn(f".policy-classification.risk-{risk}", self.styles)
        self.assertIn("state.classifications.domains", self.script)

    def test_private_catalog_and_function_inventory_are_absent(self):
        self.assertIn("const knownAppNames = {};", self.script)
        self.assertNotIn("domainPrivacyCatalog", self.script)
        self.assertNotIn("functionObservation", self.script)
        self.assertNotIn("watch_ios_function_events", self.script)

    def test_system_protection_uses_generic_evidence_schema(self):
        self.assertIn("result.systemProtection", self.script)
        self.assertNotIn("result.groupIB", self.script)
        self.assertIn("Manual enforcement decision", self.html)


if __name__ == "__main__":
    unittest.main()
