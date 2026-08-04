import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from app import APP_PURPOSE_PROFILES, ActivityLog, AppProfileStore, PolicyStore, check_iphone_developer_mode, enforce_privacy_containment, error_response, normalize_domain, question_details, sync_system_protection
from privacy_control import PrivacyControlStore, analyze_syslog

def dns_query(domain: str, qtype: int=1) -> bytes:
    labels = b''.join((bytes([len(part)]) + part.encode() for part in domain.split('.')))
    return b'\x124' + b'\x01\x00' + b'\x00\x01\x00\x00\x00\x00\x00\x00' + labels + b'\x00' + struct.pack('!HH', qtype, 1)

class CoreTests(unittest.TestCase):

    def test_developer_mode_status_is_read_only_and_parsed(self):
        completed = type('Completed', (), {'stdout': json.dumps({'ok': True, 'enabled': False, 'productVersion': '26.6'}), 'stderr': '', 'returncode': 0})()
        with patch('app._mobiledevice_tool', return_value=Path('tool.exe')), patch('app._pair_record_path', return_value=Path('pair.plist')), patch('app._discover_iphone_host', return_value='192.0.2.13'), patch('app.subprocess.run', return_value=completed) as runner:
            status = check_iphone_developer_mode()
        self.assertTrue(status['ok'])
        self.assertFalse(status['enabled'])
        command = runner.call_args.args[0]
        self.assertIn('check_ios_developer_mode.py', command[1])
        self.assertNotIn('enable-developer-mode', command)

    def test_domain_normalization(self):
        self.assertEqual(normalize_domain(' TELEMETRY.EXAMPLE.TEST. '), 'telemetry.example.test')

    def test_question_parser(self):
        domain, qtype, end = question_details(dns_query('telemetry.example.test'))
        self.assertEqual(domain, 'telemetry.example.test')
        self.assertEqual(qtype, 1)
        self.assertGreater(end, 12)

    def test_nxdomain_response(self):
        answer = error_response(dns_query('telemetry.example.test'), 3)
        flags = struct.unpack('!H', answer[2:4])[0]
        self.assertTrue(flags & 32768)
        self.assertEqual(flags & 15, 3)
        self.assertEqual(answer[:2], b'\x124')

    def test_policy_is_exact_only(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'policy.json'
            path.write_text(json.dumps({'domains': {'telemetry.example.test': {'action': 'block', 'label': 'test'}}}), encoding='utf-8')
            policy = PolicyStore(path)
            self.assertEqual(policy.action_for('telemetry.example.test'), 'block')
            self.assertEqual(policy.action_for('telemetry-config.example.test'), 'monitor')
            self.assertEqual(policy.action_for('telemetry-provider.example'), 'monitor')
            self.assertTrue(policy.delete('telemetry.example.test'))
            self.assertEqual(policy.action_for('telemetry.example.test'), 'monitor')
            self.assertNotIn('telemetry.example.test', PolicyStore(path).snapshot()['domains'])

    def test_app_profiles_are_persistent_and_deletable(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'apps.json'
            profiles = AppProfileStore(path)
            created = profiles.add('Example App', 'com.example.test')
            profiles.add_domains(created['id'], ['API.EXAMPLE.COM.', 'cdn.example.com'], 'observed')
            profiles.merge_detected([{'bundleID': 'com.example.detected', 'name': 'Detected Example', 'domains': ['one.detected.test', 'two.detected.test']}])
            reloaded = AppProfileStore(path)
            saved = next((item for item in reloaded.snapshot()['apps'] if item['id'] == created['id']))
            self.assertEqual(saved['bundleID'], 'com.example.test')
            self.assertEqual(saved['observedDomains'], ['api.example.com', 'cdn.example.com'])
            detected = reloaded.snapshot()['detectedApps']
            self.assertEqual(detected[0]['bundleID'], 'com.example.detected')
            self.assertEqual(len(detected[0]['domains']), 2)
            self.assertEqual(detected[0]['sources'], ['report'])
            self.assertTrue(reloaded.delete(created['id']))
            self.assertFalse(any((item['id'] == created['id'] for item in AppProfileStore(path).snapshot()['apps'])))

    def test_clean_profile_does_not_inherit_private_domains(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'apps.json'
            profiles = AppProfileStore(path)
            created = profiles.add('Example App', 'com.example.app', 'ExampleApp')
            self.assertEqual(created['observedDomains'], [])

    def test_added_detected_app_inherits_report_domains(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'apps.json'
            profiles = AppProfileStore(path)
            profiles.merge_detected([{'bundleID': 'com.example.reported', 'name': 'Reported Example', 'domains': ['api.example.test', 'metrics.example.test']}])
            created = profiles.add('Reported Example', 'com.example.reported')
            self.assertEqual(created['confirmedDomains'], ['api.example.test', 'metrics.example.test'])

    def test_health_app_purpose_profiles_are_exposed_without_changing_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'apps.json'
            profiles = AppProfileStore(path)
            profiles.merge_detected([
                {'bundleID': 'com.example.fitness', 'name': 'Example Fitness', 'domains': []},
                {'bundleID': 'com.example.other', 'name': 'Example Other', 'domains': []},
            ])
            detected = {item['bundleID'].lower(): item for item in profiles.snapshot()['detectedApps']}
            self.assertEqual(detected['com.example.fitness']['purposeRisk'], 'orange')
            self.assertNotIn('purposeRisk', detected['com.example.other'])
            self.assertEqual(set(APP_PURPOSE_PROFILES), {'com.example.fitness'})

    def test_activity_log_cursor_and_persistence(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'activity.ndjson'
            activity = ActivityLog(limit=10, path=path)
            activity.add(domain='one.test', action='monitored', client='127.0.0.1', time='2026-08-01T10:00:00+03:00')
            activity.add(domain='two.test', action='blocked', client='127.0.0.1', time='2026-08-01T11:00:00+03:00')
            activity.add(domain='two.test', action='blocked', client='127.0.0.1', time='2026-08-01T13:00:00+03:00')
            self.assertEqual([item['domain'] for item in activity.snapshot(after_id=0)], ['one.test', 'two.test', 'two.test'])
            self.assertEqual([item['domain'] for item in activity.snapshot(after_id=1)], ['two.test', 'two.test'])
            reloaded = ActivityLog(limit=10, path=path)
            self.assertEqual(reloaded.summary()['lastEventId'], 3)
            self.assertEqual([item['domain'] for item in reloaded.snapshot()], ['two.test', 'two.test', 'one.test'])
            self.assertEqual(reloaded.domain_stats()['two.test'], {'observedCount': 2, 'blockedCount': 2, 'lastObservedAt': '2026-08-01T13:00:00+03:00', 'lastBlockedAt': '2026-08-01T13:00:00+03:00', 'lastAction': 'blocked'})
            cleared = reloaded.clear()
            self.assertEqual(cleared['removed'], 3)
            self.assertEqual(reloaded.snapshot(), [])
            self.assertFalse(path.exists())

    def test_privacy_control_detects_permission_use_and_violation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            log_path = root / 'syslog.txt'
            log_path.write_text('\n'.join(['CoreLocation "_cmd":"startUpdatingLocation"', 'locationManager:didUpdateLocations:', 'CoreMotion [CLSensorFusionServiceSPU] FastPath opened', 'CoreMotion CMDeviceMotion:', '[ATTrackingManager] trackingAuthorizationStatus API call invoked.', '[ATTrackingManager] Returning from trackingAuthorizationStatus - 2', 'DeviceCheck integrity check: Sent 1200 bytes, received 300 bytes', 'Sandbox deny sysctl-read kern.bootargs']), encoding='utf-8')
            result = analyze_syslog(log_path)
            self.assertEqual(result['location']['state'], 'used')
            self.assertEqual(result['motion']['state'], 'used')
            self.assertEqual(result['tracking']['state'], 'denied')
            self.assertEqual(result['systemProtection']['bytesSent'], 1200)
            self.assertTrue(result['developerChecks']['detected'])
            store = PrivacyControlStore(root / 'privacy-controls.json')
            store.update('com.example.test', 'Example App', {'location': 'deny', 'motion': 'deny', 'tracking': 'deny', 'systemState': 'block'})
            entry = store.record_result('com.example.test', 'Example App', result)
            self.assertEqual(entry['evaluation']['location']['verdict'], 'violation')
            self.assertEqual(entry['evaluation']['motion']['verdict'], 'violation')
            self.assertEqual(entry['evaluation']['tracking']['verdict'], 'protected')
            self.assertEqual(entry['evaluation']['motion']['activity'], 'Accesses motion and sensors')
            self.assertEqual(entry['evaluation']['motion']['classification'], 'Privacy choice violation')
            self.assertEqual(entry['evaluation']['tracking']['classification'], 'Blocked by iOS')
            incidents = store.snapshot()['incidents']
            self.assertEqual(len(incidents), 1)
            self.assertEqual(incidents[0]['severity'], 'high')
            self.assertEqual(incidents[0]['protectionMode'], 'monitor')
            self.assertEqual([item['key'] for item in incidents[0]['violations']], ['location', 'motion'])
            self.assertEqual(entry['desired']['systemState'], 'block')

    def test_system_protection_uses_exact_reversible_domain_rule(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'policy.json'
            path.write_text(json.dumps({'domains': {}}), encoding='utf-8')
            policy = PolicyStore(path)
            with patch.dict('app.SYSTEM_PROTECTION_DOMAINS', {'com.example.app': ['integrity.example.test']}):
                rules = sync_system_protection(policy, 'com.example.app', 'Example App', 'block')
                self.assertEqual(rules[0]['domain'], 'integrity.example.test')
                self.assertEqual(policy.action_for('integrity.example.test'), 'block')
                self.assertEqual(policy.action_for('api.integrity.example.test'), 'monitor')
                sync_system_protection(policy, 'com.example.app', 'Example App', 'monitor')
            self.assertEqual(policy.action_for('integrity.example.test'), 'monitor')

    def test_balanced_protection_adds_exact_rules_and_preserves_overrides(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'policy.json'
            path.write_text(json.dumps({'domains': {'telemetry.example.test': {'action': 'allow', 'label': 'Example policy'}}}), encoding='utf-8')
            policy = PolicyStore(path)
            summary = policy.activate_balanced_protection()
            self.assertTrue(summary['enabled'])
            self.assertEqual(policy.action_for('telemetry.example.test'), 'allow')
            self.assertEqual(policy.action_for('ads.example.test'), 'block')
            self.assertEqual(policy.action_for('sub.ads.example.test'), 'monitor')
            self.assertEqual(policy.snapshot()['domains']['ads.example.test']['source'], 'balanced')

    def test_privacy_defaults_are_deny_for_every_new_app(self):
        with tempfile.TemporaryDirectory() as folder:
            store = PrivacyControlStore(Path(folder) / 'privacy-controls.json')
            entry = store.update('com.example.private', 'Private Example', {})
            self.assertEqual(entry['desired']['location'], 'deny')
            self.assertEqual(entry['desired']['motion'], 'deny')
            self.assertEqual(entry['desired']['tracking'], 'deny')
            self.assertEqual(entry['desired']['systemState'], 'monitor')
            self.assertEqual(entry['desired']['containment'], 'monitor')

    def test_containment_recommends_known_privacy_endpoints_without_writing_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'policy.json'
            path.write_text(json.dumps({'domains': {}}), encoding='utf-8')
            policy = PolicyStore(path)
            control = {'desired': {'containment': 'auto_block'}, 'evaluation': {'location': {'verdict': 'allowed'}, 'motion': {'verdict': 'violation'}, 'tracking': {'verdict': 'protected'}}}
            with patch.dict('app.APP_PRIVACY_ENDPOINTS', {'com.example.app': {'rum.example.test': 'Operational telemetry'}}):
                result = enforce_privacy_containment(policy, 'com.example.app', 'Example App', control)
            self.assertFalse(result['triggered'])
            self.assertTrue(result['evidenceDetected'])
            self.assertEqual(result['mode'], 'manual')
            self.assertEqual(result['violations'], ['motion'])
            self.assertIn('rum.example.test', result['recommendedDomains'])
            self.assertEqual(policy.action_for('rum.example.test'), 'monitor')
            self.assertEqual(policy.action_for('api.example.test'), 'monitor')
            self.assertEqual(policy.snapshot()['domains'], {})

    def test_containment_preserves_manual_rules_and_never_auto_blocks(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'policy.json'
            path.write_text(json.dumps({'domains': {'analytics.example.test': {'action': 'allow', 'label': 'Example analytics', 'source': 'manual'}}}), encoding='utf-8')
            policy = PolicyStore(path)
            control = {'desired': {'containment': 'auto_block'}, 'evaluation': {'motion': {'verdict': 'violation'}}}
            result = enforce_privacy_containment(policy, 'com.example.anyapp', 'Example App', control, ['analytics.example.test', 'ads.example.test', 'service.example.test'])
            self.assertEqual(result['allowedExceptions'], ['analytics.example.test'])
            self.assertEqual(policy.action_for('analytics.example.test'), 'allow')
            self.assertIn('ads.example.test', result['recommendedDomains'])
            self.assertEqual(policy.action_for('ads.example.test'), 'monitor')
            self.assertEqual(policy.action_for('service.example.test'), 'monitor')

    def test_balanced_defaults_upgrade_existing_monitor_choices_once(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'privacy-controls.json'
            path.write_text(json.dumps({'version': 1, 'apps': {'com.example.old': {'appName': 'Legacy Example', 'desired': {'location': 'monitor', 'motion': 'allow', 'tracking': 'monitor'}}}}), encoding='utf-8')
            store = PrivacyControlStore(path)
            result = store.activate_balanced_defaults()
            entry = store.snapshot()['apps']['com.example.old']
            self.assertEqual(result['changed'], 2)
            self.assertEqual(entry['desired']['location'], 'deny')
            self.assertEqual(entry['desired']['motion'], 'allow')
            self.assertEqual(entry['desired']['tracking'], 'deny')
            self.assertEqual(store.activate_balanced_defaults()['changed'], 0)
if __name__ == '__main__':
    unittest.main()
