import json
import struct
import tempfile
import unittest
from pathlib import Path
from activity_attribution import extract_dns_query
from app import AppAttributionLog, AppProfileStore, IPhoneEvidenceMonitor
from dns_engine import build_query

def ipv4_udp_dns_frame(domain: str) -> bytes:
    dns = build_query(domain)
    udp_length = 8 + len(dns)
    udp = struct.pack('!HHHH', 53000, 53, udp_length, 0) + dns
    total_length = 20 + len(udp)
    ipv4 = bytes([69, 0]) + struct.pack('!H', total_length) + b'\x00\x00\x00\x00' + bytes([64, 17]) + b'\x00\x00' + b'\n\x00\x00\x02' + b'\n\x00\x00\x01'
    ethernet = b'\x00' * 12 + b'\x08\x00'
    return ethernet + ipv4 + udp

class ActivityAttributionTests(unittest.TestCase):

    def test_background_dns_mode_starts_no_extra_iphone_observer(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            profiles_path = root / 'apps.json'
            profiles_path.write_text(json.dumps({'apps': [], 'detectedApps': []}), encoding='utf-8')
            monitor = IPhoneEvidenceMonitor(AppProfileStore(profiles_path), AppAttributionLog(root / 'attribution.ndjson'), None)
            snapshot = monitor.snapshot()
            self.assertFalse(snapshot['continuousEnabled'])
            self.assertEqual(snapshot['monitorCount'], 0)
            self.assertEqual(snapshot['continuousKinds'], [])
            self.assertEqual(snapshot['packetAttribution']['state'], 'paused')
            self.assertNotIn('functionObservation', snapshot)
            monitor.start()
            self.assertEqual(monitor.workers, [])

    def test_extracts_plain_dns_query_from_ios_packet_frame(self):
        result = extract_dns_query(ipv4_udp_dns_frame('api.example'))
        self.assertIsNotNone(result)
        self.assertEqual(result['domain'], 'api.example')
        self.assertEqual(result['qtypeName'], 'A')
        self.assertEqual(result['transport'], 'udp')

    def test_rejects_non_dns_destination(self):
        frame = bytearray(ipv4_udp_dns_frame('api.example'))
        frame[36:38] = struct.pack('!H', 443)
        self.assertIsNone(extract_dns_query(bytes(frame)))

    def test_process_name_resolves_to_detected_application(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'apps.json'
            path.write_text(json.dumps({'apps': [], 'detectedApps': []}), encoding='utf-8')
            store = AppProfileStore(path)
            store.merge_detected([{'bundleID': 'com.example.app', 'name': 'Example App', 'processName': 'ExampleProcess', 'domains': [], 'source': 'device'}])
            resolved = store.resolve_process('ExampleProcess')
            self.assertEqual(resolved['name'], 'Example App')
            self.assertEqual(resolved['bundleID'], 'com.example.app')

    def test_attribution_log_persists_and_deduplicates_same_packet(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'attribution.ndjson'
            log = AppAttributionLog(path)
            event = {'type': 'appDomain', 'observedAt': '2026-08-01T22:00:00+03:00', 'domain': 'api.example', 'processName': 'ExampleProcess', 'bundleID': 'com.example.app', 'appName': 'Example App', 'source': 'ios-pcap', 'confidence': 'exact-process'}
            self.assertIsNotNone(log.add(event))
            self.assertIsNone(log.add(event))
            reloaded = AppAttributionLog(path)
            self.assertEqual(len(reloaded.snapshot()), 1)
            self.assertEqual(reloaded.snapshot()[0]['appName'], 'Example App')
            self.assertIsNone(reloaded.add(event))

    def test_report_attribution_keeps_same_domain_for_distinct_apps(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'attribution.ndjson'
            log = AppAttributionLog(path)
            base = {'type': 'appDomain', 'observedAt': '2026-08-01T22:00:00+03:00', 'domain': 'shared.example', 'processName': '', 'source': 'app-privacy-report', 'confidence': 'exact-bundle'}
            self.assertIsNotNone(log.add({**base, 'bundleID': 'com.example.one', 'appName': 'One'}))
            self.assertIsNotNone(log.add({**base, 'bundleID': 'com.example.two', 'appName': 'Two'}))
            self.assertEqual(len(log.snapshot()), 2)
if __name__ == '__main__':
    unittest.main()
