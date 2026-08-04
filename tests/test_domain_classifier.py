import json
import socket
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from app import APP_PURPOSE_PROFILES, ActivityLog, AppProfileStore, AppState, DashboardHandler, PolicyStore, PrivacyCaptureManager
from dns_engine import Resolver, build_query
from domain_classifier import DomainClassificationEngine, SafeHTTPSStudy
from privacy_control import PrivacyControlStore

class FakeProbe:

    def __init__(self, response=None):
        self.response = response or {'ok': True, 'studiedAt': '2026-08-01T12:00:00+03:00', 'httpStatus': 200, 'contentType': 'application/json', 'server': 'example', 'title': 'Core API', 'description': 'Authentication gateway', 'certificateSubject': 'Example', 'certificateIssuer': 'Example CA', 'bytesRead': 120}

    def study(self, domain):
        return dict(self.response)

class DomainClassificationV3Tests(unittest.TestCase):

    def make_engine(self, folder, probe=None, purposes=None):
        return DomainClassificationEngine(Path(folder) / 'domain-classifications.json', active_analysis=False, probe=probe or FakeProbe(), app_purpose_profiles=purposes or {})

    def test_every_domain_receives_a_preliminary_color_without_unknown_label(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            entry = engine.observe('new-service.example', schedule=False)
            self.assertIn(entry['risk'], {'green', 'orange', 'red'})
            self.assertEqual(entry['stage'], 'preliminary')
            self.assertNotIn('Private Application', json.dumps(entry, ensure_ascii=False))

    def test_developer_mode_and_example_endpoint_are_studied_red(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            entry = engine.observe('integrity.example.test', schedule=False)
            self.assertEqual(entry['risk'], 'red')
            self.assertEqual(entry['stage'], 'studied')
            self.assertTrue(entry['developerModeCheck'])
            self.assertGreaterEqual(entry['confidence'], 90)

    def test_diagnostics_are_orange_and_core_api_is_green(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            crash = engine.observe('crash-reports.example', schedule=False)
            api = engine.observe('api.example', schedule=False)
            self.assertEqual(crash['risk'], 'orange')
            self.assertEqual(api['risk'], 'green')

    def test_reviewed_tracking_families_are_red(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            expected = {
                'analytics.example.test': 'behavior_analytics',
                'attribution.example.test': 'attribution',
                'ads.example.test': 'advertising_tracking',
            }
            for domain, category in expected.items():
                entry = engine.observe(domain, schedule=False)
                self.assertEqual(entry['risk'], 'red', domain)
                self.assertEqual(entry['stage'], 'studied', domain)
                self.assertEqual(entry['category'], category, domain)

    def test_ruleset_upgrade_records_color_change(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'domain-classifications.json'
            path.write_text(json.dumps({'version': 3, 'domains': {'analytics.example.test': {'domain': 'analytics.example.test', 'risk': 'green', 'stage': 'studied'}}}), encoding='utf-8')
            engine = self.make_engine(folder)
            entry = engine.get('analytics.example.test')
            self.assertEqual(entry['risk'], 'red')
            self.assertEqual(entry['classificationHistory'][-1]['from'], 'green')
            self.assertEqual(entry['classificationHistory'][-1]['to'], 'red')

    def test_catalog_refresh_never_downgrades_confirmed_local_red_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.mark_privacy_evidence(['telemetry-config.example.test'], violations=['motion'], app_context='example')
            reloaded = self.make_engine(folder)
            entry = reloaded.get('telemetry-config.example.test')
            self.assertEqual(entry['risk'], 'red')
            self.assertEqual(entry['category'], 'confirmed_privacy_violation')
            self.assertFalse(any((item.get('from') == 'red' and item.get('to') != 'red' for item in entry.get('classificationHistory', []))))

    def test_startup_review_batch_can_be_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            for index in range(10):
                engine.observe(f'host-{index}.example', schedule=False)
            result = engine.request_analysis(limit=3)
            self.assertEqual(result['queued'], 3)
            self.assertEqual(result['pending'], 3)

    def test_optional_health_apps_cap_expected_first_party_access_at_orange(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder, purposes=APP_PURPOSE_PROFILES)
            apple = engine.observe('fitness.example', app_context='Example Fitness', app_bundle='com.example.fitness', schedule=False)
            fitness = engine.observe('fitness.example', app_context='Example Fitness', app_bundle='com.example.fitness', schedule=False)
            me = engine.observe('fitness.example', app_context='ME', app_bundle='com.example.fitness', schedule=False)
            for entry in (apple, fitness, me):
                self.assertEqual(entry['risk'], 'orange')
                self.assertEqual(entry['category'], 'expected_health_data')
                self.assertFalse(entry['privacyRelevant'])

    def test_health_app_context_does_not_exempt_unrelated_tracker(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder, purposes=APP_PURPOSE_PROFILES)
            tracker = engine.observe('analytics.example.test', app_context='ME', app_bundle='com.example.fitness', schedule=False)
            self.assertEqual(tracker['risk'], 'red')
            self.assertEqual(tracker['category'], 'behavior_analytics')

    def test_dns_service_discovery_names_are_permanent_studied_green(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            resolver_discovery = engine.observe('_dns.resolver.arpa', schedule=False)
            local_discovery = engine.observe('lb._dns-sd._udp.1.2.0.192.in-addr.arpa', qtype='PTR', schedule=False)
            self.assertEqual(resolver_discovery['risk'], 'green')
            self.assertEqual(resolver_discovery['stage'], 'studied')
            self.assertEqual(local_discovery['category'], 'dns_service_discovery')
            self.assertIn('PTR', local_discovery['qtypes'])

    def test_safe_public_study_promotes_preliminary_to_studied(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder, FakeProbe())
            engine.observe('api.example', qtype='A', transport='udp', schedule=False)
            entry = engine.analyze('api.example')
            self.assertEqual(entry['stage'], 'studied')
            self.assertTrue(entry['networkStudy']['ok'])
            self.assertIn('Safe public HTTPS root study', entry['evidence'])
            self.assertNotIn('client', entry['networkStudy'])

    def test_last_observed_time_changes_only_for_real_observations(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.observe('timed.example', label='saved policy', schedule=False)
            self.assertEqual(engine.get('timed.example')['lastObservedAt'], '')
            engine.observe('timed.example', qtype='A', observed_at='2026-08-01T10:00:00+03:00', schedule=False)
            engine.observe('timed.example', qtype='AAAA', observed_at='2026-08-01T09:00:00+03:00', schedule=False)
            self.assertEqual(engine.get('timed.example')['lastObservedAt'], '2026-08-01T10:00:00+03:00')

    def test_privacy_capture_evidence_overrides_to_red_and_persists(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'domain-classifications.json'
            engine = DomainClassificationEngine(path, active_analysis=False, probe=FakeProbe())
            engine.observe('sensor.example', schedule=False)
            engine.mark_privacy_evidence(['sensor.example'], violations=['motion', 'tracking'], developer_check=True, app_context='Example App')
            reloaded = DomainClassificationEngine(path, active_analysis=False, probe=FakeProbe())
            entry = reloaded.get('sensor.example')
            self.assertEqual(entry['risk'], 'red')
            self.assertEqual(entry['stage'], 'studied')
            self.assertEqual(entry['confidence'], 99)
            self.assertTrue(entry['developerModeCheck'])
            self.assertNotIn('functions', reloaded.snapshot())

    def test_bootstrap_uses_bundle_maps_and_separates_privacy_from_developer_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.bootstrap({'domains': {}}, {'apps': [], 'detectedApps': [{'bundleID': 'com.example', 'domains': []}]}, [], {'apps': {'com.example': {'appName': 'Example', 'evaluation': {'motion': {'verdict': 'violation'}}, 'lastResult': {'developerChecks': {'detected': True}}}}}, privacy_domains_by_bundle={'com.example': {'telemetry.example': 'events'}}, developer_domains_by_bundle={'com.example': ['integrity.example']})
            privacy = engine.get('telemetry.example')
            developer = engine.get('integrity.example')
            self.assertEqual(privacy['category'], 'confirmed_privacy_violation')
            self.assertFalse(privacy['developerModeCheck'])
            self.assertEqual(developer['category'], 'developer_mode_check')
            self.assertTrue(developer['developerModeCheck'])
            self.assertNotIn('functions', engine.snapshot())

    def test_bootstrap_persists_once_after_bulk_activity_import(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            save_count = 0
            original_save = engine._save_locked

            def count_save():
                nonlocal save_count
                save_count += 1
                original_save()
            engine._save_locked = count_save
            activity = [{'domain': f'service-{index % 5}.example', 'qtypeName': 'A', 'transport': 'udp', 'decision': 'monitor', 'time': f'2026-08-01T21:{index // 60:02d}:{index % 60:02d}+03:00'} for index in range(100)]
            engine.bootstrap({'domains': {}}, {'apps': [], 'detectedApps': []}, activity)
            self.assertEqual(save_count, 1)

    def test_dns_resolver_supplies_qtype_transport_and_cname_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            policy_path = root / 'policy.json'
            policy_path.write_text(json.dumps({'domains': {'integrity.example.test': {'action': 'block', 'label': 'Example policy'}}}), encoding='utf-8')
            engine = self.make_engine(folder)
            resolver = Resolver(PolicyStore(policy_path), ActivityLog(), classifications=engine)
            resolver.resolve(build_query('integrity.example.test'), '127.0.0.1', 'udp')
            entry = engine.get('integrity.example.test')
            self.assertIn('A', entry['qtypes'])
            self.assertIn('udp', entry['transports'])
            self.assertIn('block', entry['decisions'])

    def test_https_study_rejects_private_and_loopback_addresses(self):
        private_results = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('127.0.0.1', 443)), (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('192.168.1.5', 443))]
        with patch('domain_classifier.socket.getaddrinfo', return_value=private_results):
            result = SafeHTTPSStudy().study('private.example')
        self.assertFalse(result['ok'])
        self.assertIn('safe public internet address', result['error'])

    def test_classification_api_and_activity_clear_preserve_permanent_domains(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            policy_path = root / 'policy.json'
            policy_path.write_text(json.dumps({'domains': {}}), encoding='utf-8')
            policy = PolicyStore(policy_path)
            profiles = AppProfileStore(root / 'apps.json')
            controls = PrivacyControlStore(root / 'privacy-controls.json')
            activity = ActivityLog(path=root / 'activity.ndjson')
            classifications = self.make_engine(folder)
            classifications.observe('permanent.example', schedule=False)
            resolver = Resolver(policy, activity, classifications=classifications)
            state = AppState(policy, profiles, activity, controls, PrivacyCaptureManager(controls), resolver, '127.0.0.1', 53053, classifications)
            DashboardHandler.state = state
            server = ThreadingHTTPServer(('127.0.0.1', 0), DashboardHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f'http://127.0.0.1:{server.server_address[1]}'
            try:
                payload = json.loads(urllib.request.urlopen(base + '/api/classifications').read())
                self.assertEqual(payload['version'], 3)
                self.assertIn('permanent.example', payload['domains'])
                clear = urllib.request.Request(base + '/api/logs', method='DELETE')
                json.loads(urllib.request.urlopen(clear).read())
                after = json.loads(urllib.request.urlopen(base + '/api/classifications').read())
                self.assertIn('permanent.example', after['domains'])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
if __name__ == '__main__':
    unittest.main()
