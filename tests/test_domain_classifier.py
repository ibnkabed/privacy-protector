import json
import socket
import tempfile
import threading
import time
import unittest
import urllib.request
from datetime import datetime
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import app
from app import (
    APP_PURPOSE_PROFILES,
    ActivityLog,
    AppProfileStore,
    AppState,
    DashboardHandler,
    PolicyStore,
    PrivacyCaptureManager,
)
from dns_engine import Resolver, build_query
from domain_classifier import DomainClassificationEngine, SafeHTTPSStudy
from privacy_control import PrivacyControlStore


class FakeProbe:
    def __init__(self, response=None):
        self.response = response or {
            "ok": True,
            "studiedAt": "2026-08-01T12:00:00+03:00",
            "httpStatus": 200,
            "contentType": "application/json",
            "server": "example",
            "title": "Core API",
            "description": "Authentication gateway",
            "certificateSubject": "Example",
            "certificateIssuer": "Example CA",
            "bytesRead": 120,
        }

    def study(self, domain):
        return dict(self.response)


class DomainClassificationV3Tests(unittest.TestCase):
    def make_engine(self, folder, probe=None, purposes=None):
        return DomainClassificationEngine(
            Path(folder) / "domain-classifications.json",
            active_analysis=False,
            probe=probe or FakeProbe(),
            app_purpose_profiles=purposes or {},
        )

    def test_every_new_domain_receives_an_initial_color_when_classification_is_active(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            entry = engine.observe("new-service.example", schedule=False)
            self.assertEqual(entry["risk"], "green")
            self.assertEqual(entry["stage"], "preliminary")
            self.assertEqual(entry["confidence"], 35)
            self.assertIn("Preliminary classification", json.dumps(entry, ensure_ascii=False))

    def test_new_preliminary_domain_is_queued_for_bounded_study(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = DomainClassificationEngine(
                Path(folder) / "domain-classifications.json",
                active_analysis=True,
                probe=FakeProbe(),
            )
            entry = engine.observe("new-service.example", schedule=True)
            self.assertEqual(entry["risk"], "green")
            self.assertEqual(entry["stage"], "preliminary")
            self.assertEqual(engine.summary()["pending"], 1)

    def test_developer_mode_integrity_endpoint_is_studied_orange(self):
        # The reviewed verdict considers jailbreak detection and developer mode
        # checks in a banking app as defensive fraud protection, but it reads
        # device state: monitored orange with the developer mode check flag raised.
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.observe("smart.alinma.com", schedule=False)
            entry = engine.analyze("smart.alinma.com")
            self.assertEqual(entry["risk"], "orange")
            self.assertEqual(entry["category"], "device_integrity")
            self.assertEqual(entry["stage"], "studied")
            self.assertTrue(entry["developerModeCheck"])
            self.assertGreaterEqual(entry["confidence"], 90)

    def test_diagnostics_are_orange_and_core_api_is_green(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.observe("crash-reports.example", schedule=False)
            engine.observe("api.example", schedule=False)
            crash = engine.analyze("crash-reports.example")
            api = engine.analyze("api.example")
            self.assertEqual(crash["risk"], "orange")
            self.assertEqual(api["risk"], "green")

    def test_reviewed_tracking_families_are_red(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            expected = {
                "api2.amplitude.com": "behavior_analytics",
                "api3.branch.io": "attribution",
                "3qlgc7ng.r.ap-southeast-1.awstrack.me": "email_tracking",
                "googleadservices.com": "advertising",
                "dynatrace.example.com": "real_user_monitoring",
                "got-prod.track.smaato.net": "advertising",
                "telemetry.sdk.inmobi.com": "advertising",
                "api.prod.advertising.amazon.dev": "advertising",
            }
            for domain, category in expected.items():
                engine.observe(domain, schedule=False)
                entry = engine.analyze(domain)
                self.assertEqual(entry["risk"], "red", domain)
                self.assertEqual(entry["stage"], "studied", domain)
                self.assertEqual(entry["category"], category, domain)

    def test_ruleset_upgrade_records_color_change(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "domain-classifications.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 3,
                        "domains": {
                            "api2.amplitude.com": {
                                "domain": "api2.amplitude.com",
                                "risk": "green",
                                "stage": "studied",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            engine = self.make_engine(folder)
            entry = engine.get("api2.amplitude.com")
            self.assertEqual(entry["risk"], "red")
            self.assertEqual(entry["classificationHistory"][-1]["from"], "green")
            self.assertEqual(entry["classificationHistory"][-1]["to"], "red")

    def test_balanced_v7_advertising_and_attribution_families_are_red(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            for domain in (
                "ad.doubleclick.net",
                "aax.amazon-adsystem.com",
                "tr.iadsdk.apple.com",
                "c.clarity.ms",
                "dpm.demdex.net",
                "analytics.adjust.com",
                "launches.appsflyersdk.com",
                "cdn.branch.io",
                "skan.singular.net",
                "app-measurement.com",
                "app-analytics-services.com",
                "firebaselogging-pa.googleapis.com",
                "www.google-analytics.com",
                "alinma.api.dataroid.com",
                "api.mixpanel.com",
                "sdk.iad-07.braze.com",
                "telemetry.tk0x1.com",
                "ads.forzafootball.com",
                "beacon-ams3.rubiconproject.com",
                "pixel.data.platformance.io",
                "static.ads-twitter.com",
            ):
                engine.observe(domain, schedule=False)
                entry = engine.analyze(domain)
                self.assertEqual(entry["risk"], "red", domain)
                self.assertEqual(entry["stage"], "studied", domain)

    def test_balanced_v7_operational_telemetry_is_orange(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            for domain in (
                "crashlyticsreports-pa.googleapis.com",
                "firebase-settings.crashlytics.com",
                "o123.ingest.us.sentry.io",
                "sessions.bugsnag.com",
                "in.appcenter.ms",
                "firebaseinstallations.googleapis.com",
                "device-provisioning.googleapis.com",
                "firebaseremoteconfig.googleapis.com",
                "metrics.icloud.com",
            ):
                engine.observe(domain, schedule=False)
                entry = engine.analyze(domain)
                self.assertEqual(entry["risk"], "orange", domain)
                self.assertEqual(entry["stage"], "studied", domain)

    def test_shared_sdk_evidence_promotes_pattern_domain_to_studied(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            for index in range(6):
                engine.observe(
                    "analytics-unknown-tracker.example",
                    app_bundle=f"com.example.app{index}",
                    schedule=False,
                )
            entry = engine.analyze("analytics-unknown-tracker.example")
            self.assertEqual(entry["risk"], "red")
            self.assertEqual(entry["stage"], "studied")
            self.assertGreaterEqual(entry["confidence"], 88)
            self.assertIn("Sharing evidence", json.dumps(entry, ensure_ascii=False))

    def test_shared_sdk_evidence_leaves_functional_shared_domains_green(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            for index in range(8):
                engine.observe(
                    "play.googleapis.com",
                    app_bundle=f"com.example.app{index}",
                    schedule=False,
                )
            entry = engine.analyze("play.googleapis.com")
            self.assertEqual(entry["risk"], "green")

    def test_reclassify_all_rebuilds_verdicts_and_preserves_observations(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.observe(
                "ad.doubleclick.net",
                qtype="A",
                app_bundle="com.example.one",
                schedule=False,
            )
            engine.observe("api.example", qtype="A", schedule=False)
            engine.defer_all_classifications()
            counts = engine.reclassify_all()
            tracker = engine.get("ad.doubleclick.net")
            api = engine.get("api.example")
            self.assertEqual(tracker["risk"], "red")
            self.assertEqual(tracker["stage"], "studied")
            self.assertEqual(tracker["hits"], 1)
            self.assertEqual(tracker["appBundles"], ["com.example.one"])
            self.assertEqual(api["risk"], "green")
            self.assertGreaterEqual(counts["studied"], 1)

    def test_reclassify_all_reuses_completed_bounded_network_study(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder, FakeProbe())
            engine.observe("api.example", qtype="A", schedule=False)
            studied = engine.analyze("api.example")
            self.assertEqual(studied["stage"], "studied")

            engine.reclassify_all()
            rebuilt = engine.get("api.example")
            self.assertEqual(rebuilt["stage"], "studied")
            self.assertTrue(rebuilt["networkStudy"]["ok"])
            self.assertEqual(rebuilt["networkStudy"], studied["networkStudy"])

    def test_catalog_refresh_never_downgrades_confirmed_local_red_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.mark_privacy_evidence(
                ["cdn-alinma.dataroid.com"],
                violations=["motion"],
                app_context="alinma",
            )
            reloaded = self.make_engine(folder)
            entry = reloaded.get("cdn-alinma.dataroid.com")
            self.assertEqual(entry["risk"], "red")
            self.assertEqual(entry["category"], "confirmed_privacy_violation")
            self.assertFalse(
                any(
                    item.get("from") == "red" and item.get("to") != "red"
                    for item in entry.get("classificationHistory", [])
                )
            )

    def test_startup_review_batch_can_be_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            for index in range(10):
                engine.observe(f"host-{index}.example", schedule=False)
            result = engine.request_analysis(limit=3)
            self.assertEqual(result["queued"], 3)
            self.assertEqual(result["pending"], 3)

    def test_optional_health_apps_cap_expected_first_party_access_at_green(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder, purposes=APP_PURPOSE_PROFILES)
            apple = engine.observe(
                "ontology.health.apple.com",
                app_context="Apple Health",
                app_bundle="com.apple.Health",
                schedule=False,
            )
            huawei = engine.observe(
                "fitness-dra.things.dbankcloud.com",
                app_context="HUAWEI Health",
                app_bundle="com.huawei.global.health",
                schedule=False,
            )
            me = engine.observe(
                "www.mehealthapp.cn",
                app_context="ME",
                app_bundle="Kookybread.Me",
                schedule=False,
            )
            apple = engine.analyze("ontology.health.apple.com")
            huawei = engine.analyze("fitness-dra.things.dbankcloud.com")
            me = engine.analyze("www.mehealthapp.cn")
            for entry in (apple, huawei, me):
                self.assertEqual(entry["risk"], "green")
                self.assertEqual(entry["category"], "expected_health_data")
                self.assertFalse(entry["privacyRelevant"])

    def test_health_app_context_does_not_exempt_unrelated_tracker(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder, purposes=APP_PURPOSE_PROFILES)
            tracker = engine.observe(
                "api2.amplitude.com",
                app_context="ME",
                app_bundle="Kookybread.Me",
                schedule=False,
            )
            tracker = engine.analyze("api2.amplitude.com")
            self.assertEqual(tracker["risk"], "red")
            self.assertEqual(tracker["category"], "behavior_analytics")

    def test_dns_service_discovery_names_are_permanent_studied_green(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            resolver_discovery = engine.observe("_dns.resolver.arpa", schedule=False)
            local_discovery = engine.observe(
                "lb._dns-sd._udp.0.1.168.192.in-addr.arpa",
                qtype="PTR",
                schedule=False,
            )
            resolver_discovery = engine.analyze("_dns.resolver.arpa")
            local_discovery = engine.analyze("lb._dns-sd._udp.0.1.168.192.in-addr.arpa")
            self.assertEqual(resolver_discovery["risk"], "green")
            self.assertEqual(resolver_discovery["stage"], "studied")
            self.assertEqual(local_discovery["category"], "dns_service_discovery")
            self.assertIn("PTR", local_discovery["qtypes"])

    def test_paused_classification_only_collects_observation_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = DomainClassificationEngine(
                Path(folder) / "domain-classifications.json",
                active_analysis=True,
                classification_paused=True,
                probe=FakeProbe(),
            )
            entry = engine.observe("api2.amplitude.com", qtype="A", schedule=False)
            engine.mark_privacy_evidence(
                ["api2.amplitude.com"],
                violations=["tracking"],
                app_context="Test App",
            )
            entry = engine.get("api2.amplitude.com")
            self.assertEqual(entry["risk"], "unclassified")
            self.assertEqual(entry["stage"], "new")
            self.assertIn("A", entry["qtypes"])
            self.assertEqual(engine.request_analysis()["queued"], 0)
            self.assertTrue(engine.summary()["classificationPaused"])

    def test_defer_all_classifications_preserves_domains_and_observations(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.observe(
                "api2.amplitude.com",
                qtype="A",
                transport="udp",
                observed_at="2026-08-18T01:00:00+03:00",
                schedule=False,
            )
            engine.analyze("api2.amplitude.com")
            before = engine.get("api2.amplitude.com")
            self.assertEqual(before["stage"], "studied")

            result = engine.defer_all_classifications()
            after = engine.get("api2.amplitude.com")
            self.assertEqual(result, {"before": 1, "after": 1, "deferred": 1})
            self.assertEqual(after["risk"], "unclassified")
            self.assertEqual(after["stage"], "new")
            self.assertEqual(after["lastObservedAt"], before["lastObservedAt"])
            self.assertEqual(after["hits"], before["hits"])
            self.assertEqual(after["qtypes"], before["qtypes"])
            self.assertEqual(after["networkStudy"], {})
            self.assertEqual(after["classificationHistory"], [])

    def test_safe_public_study_promotes_preliminary_to_studied(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder, FakeProbe())
            engine.observe("api.example", qtype="A", transport="udp", schedule=False)
            entry = engine.analyze("api.example")
            self.assertEqual(entry["stage"], "studied")
            self.assertTrue(entry["networkStudy"]["ok"])
            self.assertTrue(any("Safe scan" in item for item in entry["evidence"]))
            self.assertNotIn("client", entry["networkStudy"])

    def test_last_observed_time_changes_only_for_real_observations(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.observe("timed.example", label="saved policy", schedule=False)
            self.assertEqual(engine.get("timed.example")["lastObservedAt"], "")
            engine.observe(
                "timed.example",
                qtype="A",
                observed_at="2026-08-01T10:00:00+03:00",
                schedule=False,
            )
            engine.observe(
                "timed.example",
                qtype="AAAA",
                observed_at="2026-08-01T09:00:00+03:00",
                schedule=False,
            )
            # The engine normalizes to machine-local time, so compare the instant,
            # not the rendered offset, or the test only passes in one timezone.
            self.assertEqual(
                datetime.fromisoformat(engine.get("timed.example")["lastObservedAt"]),
                datetime.fromisoformat("2026-08-01T10:00:00+03:00"),
            )

    def test_privacy_capture_evidence_overrides_to_red_and_persists(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "domain-classifications.json"
            engine = DomainClassificationEngine(path, active_analysis=False, probe=FakeProbe())
            engine.observe("sensor.example", schedule=False)
            engine.mark_privacy_evidence(
                ["sensor.example"],
                violations=["motion", "tracking"],
                developer_check=True,
                app_context="Test App",
            )
            reloaded = DomainClassificationEngine(path, active_analysis=False, probe=FakeProbe())
            entry = reloaded.get("sensor.example")
            self.assertEqual(entry["risk"], "red")
            self.assertEqual(entry["stage"], "studied")
            self.assertEqual(entry["confidence"], 99)
            self.assertTrue(entry["developerModeCheck"])
            self.assertNotIn("functions", reloaded.snapshot())

    def test_bootstrap_uses_bundle_maps_and_separates_privacy_from_developer_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.bootstrap(
                {"domains": {}},
                {"apps": [], "detectedApps": [{"bundleID": "com.example", "domains": []}]},
                [],
                {
                    "apps": {
                        "com.example": {
                            "appName": "Example",
                            "evaluation": {"motion": {"verdict": "violation"}},
                            "lastResult": {"developerChecks": {"detected": True}},
                        }
                    }
                },
                privacy_domains_by_bundle={"com.example": {"telemetry.example": "events"}},
                developer_domains_by_bundle={"com.example": ["integrity.example"]},
            )
            privacy = engine.get("telemetry.example")
            developer = engine.get("integrity.example")
            self.assertEqual(privacy["category"], "confirmed_privacy_violation")
            self.assertFalse(privacy["developerModeCheck"])
            self.assertEqual(developer["category"], "developer_mode_check")
            self.assertTrue(developer["developerModeCheck"])
            self.assertNotIn("functions", engine.snapshot())

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
            activity = [
                {
                    "domain": f"service-{index % 5}.example",
                    "qtypeName": "A",
                    "transport": "udp",
                    "decision": "monitor",
                    "time": f"2026-08-01T21:{index // 60:02d}:{index % 60:02d}+03:00",
                }
                for index in range(100)
            ]

            engine.bootstrap({"domains": {}}, {"apps": [], "detectedApps": []}, activity)

            self.assertEqual(save_count, 1)

    def test_dns_resolver_supplies_qtype_transport_and_cname_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            policy_path = root / "policy.json"
            policy_path.write_text(
                json.dumps(
                    {
                        "domains": {
                            "smart.alinma.com": {
                                "action": "block",
                                "label": "Protection",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            engine = self.make_engine(folder)
            resolver = Resolver(
                PolicyStore(policy_path),
                ActivityLog(),
                classifications=engine,
            )
            resolver.resolve(build_query("smart.alinma.com"), "127.0.0.1", "udp")
            entry = engine.get("smart.alinma.com")
            self.assertIn("A", entry["qtypes"])
            self.assertIn("udp", entry["transports"])
            self.assertIn("block", entry["decisions"])

    def test_https_study_rejects_private_and_loopback_addresses(self):
        private_results = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.168.1.5", 443)),
        ]
        with patch("domain_classifier.socket.getaddrinfo", return_value=private_results):
            result = SafeHTTPSStudy().study("private.example")
        self.assertFalse(result["ok"])
        self.assertIn("safe public", result["error"])

    def test_classification_api_and_activity_clear_preserve_permanent_domains(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps({"domains": {}}), encoding="utf-8")
            policy = PolicyStore(policy_path)
            profiles = AppProfileStore(root / "apps.json")
            controls = PrivacyControlStore(root / "privacy-controls.json")
            activity = ActivityLog(path=root / "activity.ndjson")
            classifications = self.make_engine(folder)
            classifications.observe("permanent.example", schedule=False)
            resolver = Resolver(policy, activity, classifications=classifications)
            state = AppState(
                policy,
                profiles,
                activity,
                controls,
                PrivacyCaptureManager(controls),
                resolver,
                "127.0.0.1",
                53053,
                classifications,
            )
            DashboardHandler.state = state
            server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                payload = json.loads(urllib.request.urlopen(base + "/api/classifications").read())
                self.assertEqual(payload["version"], 3)
                self.assertIn("permanent.example", payload["domains"])

                clear = urllib.request.Request(base + "/api/logs", method="DELETE", headers={app.TOKEN_HEADER: app.SESSION_TOKEN})
                json.loads(urllib.request.urlopen(clear).read())
                after = json.loads(urllib.request.urlopen(base + "/api/classifications").read())
                self.assertIn("permanent.example", after["domains"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
class DeferredClassificationPersistenceTests(unittest.TestCase):
    """The classification file is rewritten whole, so observing must not wait on it."""

    def make_engine(self, folder: str, **kwargs) -> DomainClassificationEngine:
        return DomainClassificationEngine(
            Path(folder) / "classifications.json",
            active_analysis=False,
            **kwargs,
        )

    def test_observation_defers_the_write_and_flush_persists_it(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.observe("deferred.example", qtype="A", transport="udp", decision="monitor")

            self.assertTrue(engine._dirty)
            self.assertFalse(
                engine.path.exists(),
                "observing must not rewrite the classification file inline",
            )

            self.assertTrue(engine.flush())
            saved = json.loads(engine.path.read_text(encoding="utf-8"))
            self.assertIn("deferred.example", saved["domains"])

            # Nothing changed since the write, so there is nothing left to do.
            self.assertFalse(engine._dirty)
            self.assertFalse(engine.flush())

    def test_shutdown_persists_pending_observations(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.observe("pending.example", qtype="A", transport="udp", decision="monitor")
            engine.shutdown()

            saved = json.loads(engine.path.read_text(encoding="utf-8"))
            self.assertIn("pending.example", saved["domains"])

            reloaded = self.make_engine(folder)
            self.assertIn("pending.example", reloaded.data["domains"])

    def test_background_flusher_writes_without_an_explicit_flush(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.persist_flush_seconds = 0.05
            engine.observe("background.example", qtype="A", transport="udp", decision="monitor")
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and not engine.path.exists():
                    time.sleep(0.02)
                self.assertTrue(engine.path.exists(), "the flusher thread never wrote the file")
                saved = json.loads(engine.path.read_text(encoding="utf-8"))
                self.assertIn("background.example", saved["domains"])
            finally:
                engine.shutdown()

    def test_zero_delay_keeps_the_immediate_write_behaviour(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.persist_flush_seconds = 0
            engine.observe("immediate.example", qtype="A", transport="udp", decision="monitor")

            self.assertFalse(engine._dirty)
            saved = json.loads(engine.path.read_text(encoding="utf-8"))
            self.assertIn("immediate.example", saved["domains"])

    def test_explicit_privacy_evidence_still_persists_immediately(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.mark_privacy_evidence(["evidence.example"], violations=["camera"])

            saved = json.loads(engine.path.read_text(encoding="utf-8"))
            self.assertEqual(saved["domains"]["evidence.example"]["risk"], "red")

    def test_a_failed_write_keeps_the_data_pending(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = self.make_engine(folder)
            engine.observe("retry.example", qtype="A", transport="udp", decision="monitor")

            with patch.object(
                DomainClassificationEngine, "_save_locked", side_effect=OSError("disk full")
            ):
                self.assertFalse(engine.flush())
            self.assertTrue(engine._dirty, "a failed write must leave the data pending")

            self.assertTrue(engine.flush())
            saved = json.loads(engine.path.read_text(encoding="utf-8"))
            self.assertIn("retry.example", saved["domains"])


if __name__ == "__main__":
    unittest.main()
