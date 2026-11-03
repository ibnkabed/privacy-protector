import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import (
    ConnectionReminderMonitor,
    APP_PURPOSE_PROFILES,
    ActivityLog,
    AppProfileStore,
    PolicyStore,
    check_iphone_developer_mode,
    enforce_privacy_containment,
    error_response,
    normalize_domain,
    question_details,
    sync_system_protection,
)
from privacy_control import PrivacyControlStore, analyze_syslog


def dns_query(domain: str, qtype: int = 1) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in domain.split("."))
    return (
        b"\x12\x34"
        + b"\x01\x00"
        + b"\x00\x01\x00\x00\x00\x00\x00\x00"
        + labels
        + b"\x00"
        + struct.pack("!HH", qtype, 1)
    )


class CoreTests(unittest.TestCase):
    def test_connection_reminder_does_not_treat_dns_silence_as_disconnection(self):
        class FakeResolver:
            def __init__(self):
                self.last_seen = ""
                self.client = ""

            def coverage_snapshot(self, recent_seconds=300):
                return {
                    "iphoneClient": {
                        "lastSeenAt": self.last_seen,
                        "lastClient": self.client,
                    }
                }

        class FakeNotifier:
            def __init__(self):
                self.events = []

            def send(self, dns_address, state="disconnected"):
                self.events.append((state, dns_address))
                return True, ""

        with tempfile.TemporaryDirectory() as folder:
            state_path = Path(folder) / "connection-reminder-state.json"
            now = [1000.0]
            resolver = FakeResolver()
            notifier = FakeNotifier()
            monitor = ConnectionReminderMonitor(
                resolver,
                state_path=state_path,
                notifier=notifier,
                grace_seconds=300,
                clock=lambda: now[0],
                boot_key_provider=lambda: "boot-a",
                address_provider=lambda: "192.168.1.193",
            )

            self.assertEqual(monitor.evaluate()["state"], "waiting")
            now[0] = 1299.0
            self.assertEqual(monitor.evaluate()["state"], "waiting")
            self.assertEqual(notifier.events, [])

            now[0] = 1300.0
            first = monitor.evaluate()
            self.assertEqual(first["state"], "disconnected")
            self.assertTrue(first["notificationSent"])
            self.assertEqual(
                notifier.events,
                [("disconnected", "192.168.1.193")],
            )

            now[0] = 1600.0
            monitor.evaluate()
            self.assertEqual(len(notifier.events), 1)

            resolver.last_seen = "1970-01-01T00:26:41+00:00"
            resolver.client = "192.168.1.13"
            now[0] = 1601.0
            connected = monitor.evaluate()
            self.assertEqual(connected["state"], "connected")
            self.assertFalse(connected["notificationSent"])
            self.assertTrue(connected["connectionNotificationSent"])
            self.assertTrue(connected["monitoringComplete"])
            self.assertEqual(connected["secondsUntilReminder"], 0)
            self.assertEqual(
                notifier.events[-1],
                ("connected", "192.168.1.193"),
            )

            now[0] = 1700.0
            resolver.last_seen = "1970-01-01T00:28:20+00:00"
            monitor.evaluate()
            self.assertEqual(
                [event for event in notifier.events if event[0] == "connected"],
                [("connected", "192.168.1.193")],
            )

            now[0] = 2000.0
            quiet = monitor.evaluate()
            self.assertEqual(quiet["state"], "connected")
            self.assertEqual(
                [event for event in notifier.events if event[0] == "disconnected"],
                [("disconnected", "192.168.1.193")],
            )

            restarted_notifier = FakeNotifier()
            restarted = ConnectionReminderMonitor(
                FakeResolver(),
                state_path=state_path,
                notifier=restarted_notifier,
                grace_seconds=300,
                clock=lambda: now[0],
                boot_key_provider=lambda: "boot-a",
                address_provider=lambda: "192.168.1.193",
            )
            restarted.evaluate()
            self.assertEqual(restarted_notifier.events, [])

            new_boot_now = [3000.0]
            new_boot_notifier = FakeNotifier()
            new_boot = ConnectionReminderMonitor(
                FakeResolver(),
                state_path=state_path,
                notifier=new_boot_notifier,
                grace_seconds=300,
                clock=lambda: new_boot_now[0],
                boot_key_provider=lambda: "boot-b",
                address_provider=lambda: "192.168.1.193",
            )
            self.assertEqual(new_boot.evaluate()["state"], "waiting")
            new_boot_now[0] = 3300.0
            self.assertEqual(new_boot.evaluate()["state"], "disconnected")
            self.assertEqual(
                new_boot_notifier.events,
                [("disconnected", "192.168.1.193")],
            )

    def test_connected_phone_that_goes_silent_gets_one_orange_reminder(self):
        class FakeResolver:
            def __init__(self):
                self.last_seen = ""
                self.client = ""

            def coverage_snapshot(self, recent_seconds=300):
                return {"iphoneClient": {"lastSeenAt": self.last_seen, "lastClient": self.client}}

        class FakeNotifier:
            def __init__(self):
                self.events = []

            def send(self, dns_address, state="disconnected"):
                self.events.append(state)
                return True, ""

        with tempfile.TemporaryDirectory() as folder:
            now = [1000.0]
            resolver = FakeResolver()
            notifier = FakeNotifier()
            monitor = ConnectionReminderMonitor(
                resolver,
                state_path=Path(folder) / "state.json",
                notifier=notifier,
                grace_seconds=300,
                lost_seconds=1800,
                clock=lambda: now[0],
                boot_key_provider=lambda: "boot-a",
                address_provider=lambda: "192.168.1.193",
            )
            resolver.last_seen = "1970-01-01T00:16:40+00:00"  # 1000
            resolver.client = "192.168.1.13"
            self.assertEqual(monitor.evaluate()["state"], "connected")
            self.assertEqual(notifier.events, ["connected"])

            now[0] = 2799.0
            self.assertEqual(monitor.evaluate()["state"], "connected")
            now[0] = 2800.0
            lost = monitor.evaluate()
            self.assertEqual(lost["state"], "lost")
            self.assertTrue(lost["reconnectNotificationSent"])
            self.assertEqual(notifier.events, ["connected", "reconnect"])

            now[0] = 9000.0
            monitor.evaluate()
            self.assertEqual(notifier.events, ["connected", "reconnect"])

            # Back on the right modem: green again, and the next silence reminds again.
            resolver.last_seen = "1970-01-01T02:30:00+00:00"  # 9000
            back = monitor.evaluate()
            self.assertEqual(back["state"], "connected")
            self.assertEqual(notifier.events, ["connected", "reconnect", "connected"])
            now[0] = 10800.0
            self.assertEqual(monitor.evaluate()["state"], "lost")
            self.assertEqual(notifier.events[-1], "reconnect")
            self.assertEqual(notifier.events.count("reconnect"), 2)

    def test_connection_notification_is_not_missed_during_feature_upgrade(self):
        class FakeResolver:
            def coverage_snapshot(self, recent_seconds=300):
                return {
                    "iphoneClient": {
                        "lastSeenAt": "1970-01-01T00:33:21+00:00",
                        "lastClient": "192.168.1.13",
                    }
                }

        class FakeNotifier:
            def __init__(self):
                self.events = []

            def send(self, dns_address, state="disconnected"):
                self.events.append((state, dns_address))
                return True, ""

        with tempfile.TemporaryDirectory() as folder:
            state_path = Path(folder) / "connection-reminder-state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "bootKey": "same-boot",
                        "state": "connected",
                        "episodeStartedEpoch": 1900.0,
                        "lastSeenAt": "1970-01-01T00:31:40+00:00",
                        "lastClientIp": "192.168.1.13",
                        "connectionNotificationSent": False,
                    }
                ),
                encoding="utf-8",
            )
            notifier = FakeNotifier()
            monitor = ConnectionReminderMonitor(
                FakeResolver(),
                state_path=state_path,
                notifier=notifier,
                grace_seconds=300,
                clock=lambda: 2001.0,
                boot_key_provider=lambda: "same-boot",
                address_provider=lambda: "192.168.1.193",
            )
            monitor.evaluate()
            monitor.evaluate()
            self.assertEqual(
                notifier.events,
                [("connected", "192.168.1.193")],
            )

    def test_developer_mode_status_is_read_only_and_parsed(self):
        completed = type(
            "Completed",
            (),
            {
                "stdout": json.dumps(
                    {
                        "ok": True,
                        "enabled": False,
                        "productVersion": "26.6",
                    }
                ),
                "stderr": "",
                "returncode": 0,
            },
        )()
        with patch("app._mobiledevice_tool", return_value=Path("tool.exe")), patch(
            "app._pair_record_path", return_value=Path("pair.plist")
        ), patch("app._discover_iphone_host", return_value="192.168.1.13"), patch(
            "app.subprocess.run", return_value=completed
        ) as runner:
            status = check_iphone_developer_mode()
        self.assertTrue(status["ok"])
        self.assertFalse(status["enabled"])
        command = runner.call_args.args[0]
        self.assertIn("check_ios_developer_mode.py", command[1])
        self.assertNotIn("enable-developer-mode", command)

    def test_domain_normalization(self):
        self.assertEqual(normalize_domain(" ALINMA.API.DATAROID.COM. "), "alinma.api.dataroid.com")

    def test_question_parser(self):
        domain, qtype, end = question_details(dns_query("alinma.api.dataroid.com"))
        self.assertEqual(domain, "alinma.api.dataroid.com")
        self.assertEqual(qtype, 1)
        self.assertGreater(end, 12)

    def test_nxdomain_response(self):
        answer = error_response(dns_query("alinma.api.dataroid.com"), 3)
        flags = struct.unpack("!H", answer[2:4])[0]
        self.assertTrue(flags & 0x8000)
        self.assertEqual(flags & 0x000F, 3)
        self.assertEqual(answer[:2], b"\x12\x34")

    def test_policy_is_exact_only(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"
            path.write_text(
                json.dumps(
                    {
                        "domains": {
                            "alinma.api.dataroid.com": {
                                "action": "block",
                                "label": "test",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            policy = PolicyStore(path)
            self.assertEqual(policy.action_for("alinma.api.dataroid.com"), "block")
            self.assertEqual(policy.action_for("cdn-alinma.dataroid.com"), "monitor")
            self.assertEqual(policy.action_for("dataroid.com"), "monitor")
            self.assertTrue(policy.delete("alinma.api.dataroid.com"))
            self.assertEqual(policy.action_for("alinma.api.dataroid.com"), "monitor")
            self.assertNotIn(
                "alinma.api.dataroid.com", PolicyStore(path).snapshot()["domains"]
            )

    def test_app_profiles_are_persistent_and_deletable(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "apps.json"
            profiles = AppProfileStore(path)
            created = profiles.add("Test App", "com.example.test")
            profiles.add_domains(
                created["id"], ["API.EXAMPLE.COM.", "cdn.example.com"], "observed"
            )
            profiles.merge_detected(
                [
                    {
                        "bundleID": "com.example.detected",
                        "name": "Detected App",
                        "domains": ["one.detected.test", "two.detected.test"],
                    }
                ]
            )
            reloaded = AppProfileStore(path)
            saved = next(
                item
                for item in reloaded.snapshot()["apps"]
                if item["id"] == created["id"]
            )
            self.assertEqual(saved["bundleID"], "com.example.test")
            self.assertEqual(
                saved["observedDomains"], ["api.example.com", "cdn.example.com"]
            )
            detected = reloaded.snapshot()["detectedApps"]
            self.assertEqual(detected[0]["bundleID"], "com.example.detected")
            self.assertEqual(len(detected[0]["domains"]), 2)
            self.assertEqual(detected[0]["sources"], ["report"])
            self.assertTrue(reloaded.delete(created["id"]))
            self.assertFalse(
                any(
                    item["id"] == created["id"]
                    for item in AppProfileStore(path).snapshot()["apps"]
                )
            )

    def test_alinma_profile_includes_verified_privacy_domains(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "apps.json"
            profiles = AppProfileStore(path)
            created = profiles.add(
                "Alinma", "com.alinma.retail.mobile.v4", "alinma_bank_app"
            )
            self.assertEqual(
                set(created["observedDomains"]),
                {
                    "smart.alinma.com",
                    "alinma.api.dataroid.com",
                    "cdn-alinma.dataroid.com",
                    "rum.alinma.com",
                },
            )

    def test_added_detected_app_inherits_report_domains(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "apps.json"
            profiles = AppProfileStore(path)
            profiles.merge_detected(
                [
                    {
                        "bundleID": "com.example.reported",
                        "name": "Detected",
                        "domains": ["api.example.test", "metrics.example.test"],
                    }
                ]
            )
            created = profiles.add("Detected", "com.example.reported")
            self.assertEqual(
                created["confirmedDomains"],
                ["api.example.test", "metrics.example.test"],
            )

    def test_health_app_purpose_profiles_are_exposed_without_changing_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "apps.json"
            profiles = AppProfileStore(path)
            profiles.merge_detected(
                [
                    {"bundleID": bundle, "name": name, "domains": []}
                    for bundle, name in (
                        ("com.apple.Health", "Health"),
                        ("com.huawei.global.health", "HUAWEI Health"),
                        ("Kookybread.Me", "Me"),
                        ("com.iaugus.Health", "Valens"),
                        ("com.lean.tetamn", "Sehhaty"),
                    )
                ]
            )
            detected = {
                item["bundleID"].lower(): item
                for item in profiles.snapshot()["detectedApps"]
            }
            for bundle in (
                "com.apple.health",
                "com.huawei.global.health",
                "kookybread.me",
                "com.iaugus.health",
            ):
                self.assertEqual(detected[bundle]["purposeRisk"], "green")
            self.assertEqual(detected["com.lean.tetamn"]["purposeRisk"], "red")
            self.assertEqual(
                set(APP_PURPOSE_PROFILES),
                set(detected),
            )

    def test_activity_log_cursor_and_persistence(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "activity.ndjson"
            activity = ActivityLog(limit=10, path=path)
            activity.add(
                domain="one.test",
                action="monitored",
                client="127.0.0.1",
                time="2026-08-01T10:00:00+03:00",
            )
            activity.add(
                domain="two.test",
                action="blocked",
                client="127.0.0.1",
                time="2026-08-01T11:00:00+03:00",
            )
            activity.add(
                domain="two.test",
                action="blocked",
                client="127.0.0.1",
                time="2026-08-01T13:00:00+03:00",
            )
            self.assertEqual(
                [item["domain"] for item in activity.snapshot(after_id=0)],
                ["one.test", "two.test", "two.test"],
            )
            self.assertEqual(
                [item["domain"] for item in activity.snapshot(after_id=1)],
                ["two.test", "two.test"],
            )
            reloaded = ActivityLog(limit=10, path=path)
            self.assertEqual(reloaded.summary()["lastEventId"], 3)
            self.assertEqual(
                [item["domain"] for item in reloaded.snapshot()],
                ["two.test", "two.test", "one.test"],
            )
            self.assertEqual(
                reloaded.domain_stats()["two.test"],
                {
                    "observedCount": 2,
                    "blockedCount": 2,
                    "lastObservedAt": "2026-08-01T13:00:00+03:00",
                    "lastBlockedAt": "2026-08-01T13:00:00+03:00",
                    "lastAction": "blocked",
                },
            )
            cleared = reloaded.clear()
            self.assertEqual(cleared["removed"], 3)
            self.assertEqual(reloaded.snapshot(), [])
            self.assertFalse(path.exists())

    def test_privacy_control_detects_permission_use_and_violation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            log_path = root / "syslog.txt"
            log_path.write_text(
                "\n".join(
                    [
                        'CoreLocation "_cmd":"startUpdatingLocation"',
                        "locationManager:didUpdateLocations:",
                        "CoreMotion [CLSensorFusionServiceSPU] FastPath opened",
                        "CoreMotion CMDeviceMotion:",
                        "[ATTrackingManager] trackingAuthorizationStatus API call invoked.",
                        "[ATTrackingManager] Returning from trackingAuthorizationStatus - 2",
                        "looked up com.group-ib.GIBMobileSDK.kLogLevel",
                        (
                            "Sent 1200 bytes, received 300 bytes for request "
                            "https://smart.alinma.com/api/fl?x=1"
                        ),
                        "Sandbox deny sysctl-read kern.bootargs",
                    ]
                ),
                encoding="utf-8",
            )
            result = analyze_syslog(log_path)
            self.assertEqual(result["location"]["state"], "used")
            self.assertEqual(result["motion"]["state"], "used")
            self.assertEqual(result["tracking"]["state"], "denied")
            self.assertEqual(result["groupIB"]["bytesSent"], 1200)
            self.assertTrue(result["developerChecks"]["detected"])

            store = PrivacyControlStore(root / "privacy-controls.json")
            store.update(
                "com.example.test",
                "Test",
                {
                    "location": "deny",
                    "motion": "deny",
                    "tracking": "deny",
                    "systemState": "block",
                },
            )
            entry = store.record_result("com.example.test", "Test", result)
            self.assertEqual(entry["evaluation"]["location"]["verdict"], "violation")
            self.assertEqual(entry["evaluation"]["motion"]["verdict"], "violation")
            self.assertEqual(entry["evaluation"]["tracking"]["verdict"], "protected")
            self.assertEqual(
                entry["evaluation"]["motion"]["activity"],
                "monitors motion & sensors",
            )
            self.assertEqual(
                entry["evaluation"]["motion"]["classification"],
                "privacy choice violation",
            )
            self.assertEqual(
                entry["evaluation"]["tracking"]["classification"],
                "Blocked by iOS",
            )
            incidents = store.snapshot()["incidents"]
            self.assertEqual(len(incidents), 1)
            self.assertEqual(incidents[0]["severity"], "high")
            self.assertEqual(incidents[0]["protectionMode"], "monitor")
            self.assertEqual(
                [item["key"] for item in incidents[0]["violations"]],
                ["location", "motion"],
            )
            self.assertEqual(entry["desired"]["systemState"], "block")

    def test_system_protection_uses_exact_reversible_domain_rule(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"
            path.write_text(json.dumps({"domains": {}}), encoding="utf-8")
            policy = PolicyStore(path)
            rules = sync_system_protection(
                policy,
                "com.alinma.retail.mobile.v4",
                "Alinma",
                "block",
            )
            self.assertEqual(rules[0]["domain"], "smart.alinma.com")
            self.assertEqual(policy.action_for("smart.alinma.com"), "block")
            self.assertEqual(policy.action_for("api.smart.alinma.com"), "monitor")
            sync_system_protection(
                policy,
                "com.alinma.retail.mobile.v4",
                "Alinma",
                "monitor",
            )
            self.assertEqual(policy.action_for("smart.alinma.com"), "monitor")

    def test_balanced_protection_adds_exact_rules_and_preserves_overrides(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"
            path.write_text(
                json.dumps(
                    {
                        "domains": {
                            "analytics.tiktok.com": {
                                "action": "allow",
                                "label": "User exception",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            policy = PolicyStore(path)
            summary = policy.activate_balanced_protection()
            self.assertTrue(summary["enabled"])
            self.assertEqual(policy.action_for("analytics.tiktok.com"), "allow")
            self.assertEqual(policy.action_for("ad.doubleclick.net"), "block")
            self.assertEqual(policy.action_for("sub.ad.doubleclick.net"), "monitor")
            self.assertEqual(
                policy.snapshot()["domains"]["ad.doubleclick.net"]["source"],
                "balanced",
            )

    def test_privacy_defaults_are_deny_for_every_new_app(self):
        with tempfile.TemporaryDirectory() as folder:
            store = PrivacyControlStore(Path(folder) / "privacy-controls.json")
            entry = store.update("com.example.private", "App", {})
            self.assertEqual(entry["desired"]["location"], "deny")
            self.assertEqual(entry["desired"]["motion"], "deny")
            self.assertEqual(entry["desired"]["tracking"], "deny")
            self.assertEqual(entry["desired"]["systemState"], "monitor")
            self.assertEqual(entry["desired"]["containment"], "monitor")

    def test_function_access_evidence_survives_store_reload(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "privacy-controls.json"
            path.write_text(
                json.dumps(
                    {
                        "apps": {},
                        "functionAccess": {
                            "com.t2.AvailoHader": {
                                "location": {
                                    "sessions": 13,
                                    "minutes": 4.6,
                                    "lastUsed": "2026-08-18T06:01:00+03:00",
                                    "risk": "green",
                                }
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            store = PrivacyControlStore(path)
            snapshot = store.snapshot()
            entry = snapshot["functionAccess"]["com.t2.AvailoHader"]["location"]
            self.assertEqual(entry["sessions"], 13)
            self.assertEqual(entry["risk"], "green")


    def test_containment_recommends_known_privacy_endpoints_without_writing_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"
            path.write_text(json.dumps({"domains": {}}), encoding="utf-8")
            policy = PolicyStore(path)
            control = {
                "desired": {"containment": "auto_block"},
                "evaluation": {
                    "location": {"verdict": "allowed"},
                    "motion": {"verdict": "violation"},
                    "tracking": {"verdict": "protected"},
                },
            }
            result = enforce_privacy_containment(
                policy,
                "com.alinma.retail.mobile.v4",
                "Alinma",
                control,
            )
            self.assertFalse(result["triggered"])
            self.assertTrue(result["evidenceDetected"])
            self.assertEqual(result["mode"], "manual")
            self.assertEqual(result["violations"], ["motion"])
            self.assertIn("rum.alinma.com", result["recommendedDomains"])
            self.assertEqual(policy.action_for("rum.alinma.com"), "monitor")
            self.assertEqual(policy.action_for("api-gw.alinma.com"), "monitor")
            self.assertEqual(policy.snapshot()["domains"], {})

    def test_containment_preserves_manual_rules_and_never_auto_blocks(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"
            path.write_text(
                json.dumps(
                    {
                        "domains": {
                            "analytics.tiktok.com": {
                                "action": "allow",
                                "label": "Exception",
                                "source": "manual",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            policy = PolicyStore(path)
            control = {
                "desired": {"containment": "auto_block"},
                "evaluation": {"motion": {"verdict": "violation"}},
            }
            result = enforce_privacy_containment(
                policy,
                "com.example.anyapp",
                "Any App",
                control,
                ["analytics.tiktok.com", "ad.doubleclick.net", "api.example.com"],
            )
            self.assertEqual(
                result["allowedExceptions"], ["analytics.tiktok.com"]
            )
            self.assertEqual(policy.action_for("analytics.tiktok.com"), "allow")
            self.assertIn("ad.doubleclick.net", result["recommendedDomains"])
            self.assertEqual(policy.action_for("ad.doubleclick.net"), "monitor")
            self.assertEqual(policy.action_for("api.example.com"), "monitor")

    def test_balanced_defaults_upgrade_existing_monitor_choices_once(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "privacy-controls.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "apps": {
                            "com.example.old": {
                                "appName": "Old",
                                "desired": {
                                    "location": "monitor",
                                    "motion": "allow",
                                    "tracking": "monitor",
                                },
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            store = PrivacyControlStore(path)
            result = store.activate_balanced_defaults()
            entry = store.snapshot()["apps"]["com.example.old"]
            self.assertEqual(result["changed"], 2)
            self.assertEqual(entry["desired"]["location"], "deny")
            self.assertEqual(entry["desired"]["motion"], "allow")
            self.assertEqual(entry["desired"]["tracking"], "deny")
            self.assertEqual(store.activate_balanced_defaults()["changed"], 0)
if __name__ == "__main__":
    unittest.main()
