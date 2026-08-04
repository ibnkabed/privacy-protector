import json
import re
import unittest
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
README_PATH = PROJECT_ROOT / 'README.md'
APPS_PATH = PROJECT_ROOT / 'data' / 'apps.json'
POLICY_PATH = PROJECT_ROOT / 'data' / 'policy.json'
CONTROLS_PATH = PROJECT_ROOT / 'data' / 'privacy-controls.json'
FORBIDDEN_IDENTIFIER_PATTERNS = {'Windows user profile path': '(?i)\\b[A-Z]:\\\\Users\\\\[^\\\\\\s`]+', 'email address': '(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b', 'Saudi mobile number': '(?<!\\d)(?:\\+?966|0)?5\\d{8}(?!\\d)', 'private IPv4 address': '(?<!\\d)(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3})(?!\\d)'}

class PublicReadmePrivacyTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.readme = README_PATH.read_text(encoding='utf-8')

    def test_private_runtime_snapshot_is_not_documented(self):
        forbidden_phrases = ('Current private runtime inventory', 'Local count or size', 'learned during private use', 'Saved privacy incidents', 'DNS activity events', 'Capture data size', 'Local virtual environment size')
        for phrase in forbidden_phrases:
            with self.subTest(phrase=phrase):
                self.assertNotIn(phrase, self.readme)

    def test_common_personal_identifiers_are_absent(self):
        for label, pattern in FORBIDDEN_IDENTIFIER_PATTERNS.items():
            with self.subTest(label=label):
                self.assertIsNone(re.search(pattern, self.readme))

    def test_identifier_patterns_detect_representative_private_values(self):
        examples = {'Windows user profile path': 'C:\\Users\\Example\\Project', 'email address': 'person@example.test', 'Saudi mobile number': '+966500000000', 'private IPv4 address': '192.168.10.25'}
        for label, example in examples.items():
            with self.subTest(label=label):
                self.assertIsNotNone(re.search(FORBIDDEN_IDENTIFIER_PATTERNS[label], example))

    def test_saved_app_and_domain_values_are_not_repeated(self):

        def read_runtime_json(path):
            if not path.exists():
                return {}
            return json.loads(path.read_text(encoding='utf-8'))
        apps_data = read_runtime_json(APPS_PATH)
        policy_data = read_runtime_json(POLICY_PATH)
        controls_data = read_runtime_json(CONTROLS_PATH)
        sensitive_groups = {'profile identity': [], 'detected app identity': [], 'privacy-control identity': [], 'saved domain': list(policy_data.get('domains', {}).keys())}
        for profile in apps_data.get('apps', []):
            sensitive_groups['profile identity'].extend((profile.get(field, '') for field in ('name', 'bundleID', 'processName')))
            sensitive_groups['saved domain'].extend(profile.get('confirmedDomains', []))
            sensitive_groups['saved domain'].extend(profile.get('observedDomains', []))
        for app in apps_data.get('detectedApps', []):
            sensitive_groups['detected app identity'].append(app.get('bundleID', ''))
            name = app.get('name', '')
            if not str(app.get('bundleID', '')).startswith('com.apple.'):
                sensitive_groups['detected app identity'].append(name)
            sensitive_groups['saved domain'].extend(app.get('domains', []))
        for bundle_id, control in controls_data.get('apps', {}).items():
            sensitive_groups['privacy-control identity'].extend((bundle_id, control.get('bundleID', ''), control.get('appName', '')))
        for incident in controls_data.get('incidents', []):
            sensitive_groups['privacy-control identity'].extend((incident.get('bundleID', ''), incident.get('appName', '')))
        readme_folded = self.readme.casefold()
        documented_public_infrastructure = {'dns.google', 'google.com'}
        for category, values in sensitive_groups.items():
            unique_values = sorted({str(value).strip().casefold() for value in values if value and len(str(value).strip()) >= 4 and (not (category == 'saved domain' and str(value).strip().casefold() in documented_public_infrastructure))})
            for index, value in enumerate(unique_values):
                with self.subTest(category=category, item=index):
                    self.assertFalse(value in readme_folded, f'A {category} value appears in the public README')

    def test_public_documentation_remains_detailed(self):
        required_sections = ('## What the application does', '## Architecture', '## User interface', '## Check Developer Mode', '## Local API', '## Storage layout', '## Runtime requirements', '## Tests', '## Known limitations')
        for heading in required_sections:
            with self.subTest(heading=heading):
                self.assertIn(heading, self.readme)

    def test_separate_source_hosting_topic_is_not_mentioned(self):
        self.assertIsNone(re.search('(?i)\\b(?:git|github|repository)\\b', self.readme))
if __name__ == '__main__':
    unittest.main()
