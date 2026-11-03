import json
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import pc_protection
import user_exceptions  # noqa: E402
from dns_engine import Resolver, build_query  # noqa: E402
from pc_protection import PCProtection, answer_addresses, parse_dns_client_events  # noqa: E402


class MemoryPolicy:
    def __init__(self):
        self.domains = {}

    def action_for(self, domain):
        return self.domains.get(domain, {}).get("action", "monitor")

    def update(self, domain, action, label=None, note=None, source=None):
        self.domains[domain] = {"action": action, "source": source or "manual"}
        return self.domains[domain]

    def delete(self, domain):
        return self.domains.pop(domain, None) is not None


class FakeInspector:
    def __init__(self, table):
        self.table = table

    def identity(self, pid):
        return self.table.get(pid)


class SilentLog:
    enabled = False
    error = ""

    def poll(self):
        return []


class FakeReviewer:
    """Fake provider: returns the specified verdict, validated by a second opinion that may agree or disagree."""

    trusted = ["anthropic:claude-haiku-5-5", "groq:x"]

    def __init__(self, color="red", block_safe=True, second="red"):
        self.color = color
        self.block_safe = block_safe
        self.second = second
        self.asked = []

    def ensure_pool(self):
        return self

    def decide_batch(self, packets, verdicts, system_prompt=""):
        for verdict in verdicts.values():
            verdict["reviewers"] = ["writer", "judge"]
            verdict["agreement"] = "Agreement" if self.second == verdict["color"] else "Judge verdict"
            if self.second != verdict["color"]:
                verdict["color"] = self.second
                verdict["blockSafe"] = False
        return verdicts


def dns_response(addresses):
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, len(addresses), 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    answers = b""
    for address in addresses:
        answers += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes(int(x) for x in address.split("."))
    return header + question + answers


class PCProtectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.policy = MemoryPolicy()
        self.inspector = FakeInspector(
            {
                100: {"name": "iAnyGo.exe", "path": "", "company": "Tenorshare Co., Ltd.", "product": "Tenorshare iAnyGo"},
                200: {"name": "Fantastical.exe", "path": "", "company": "Flexibits", "product": "Fantastical"},
                300: {"name": "claude.exe", "path": "", "company": "Anthropic PBC", "product": "Claude Code"},
            }
        )
        self.connections = []
        self.pc = PCProtection(
            Path(self.directory.name),
            self.policy,
            reviewer=None,
            inspector=self.inspector,
            connections=lambda: self.connections,
            log_reader=SilentLog(),
        )

    def tearDown(self):
        self.directory.cleanup()

    def attribute(self, domain, pid, address="203.0.113.7"):
        self.pc.observe_answer(domain, "A", dns_response([address]), [])
        self.connections = [(address, pid)]
        self.pc.poll_attribution()

    # -- Monitoring and attribution -------------------------------------------
    def test_answer_addresses_and_connection_attribution(self):
        self.assertEqual(answer_addresses(dns_response(["203.0.113.7"])), [("203.0.113.7", 300)])
        self.attribute("api.tenorshare.com", 100)
        entry = self.pc.domains["api.tenorshare.com"]
        self.assertIn("iAnyGo.exe", entry["processes"])
        self.assertEqual(entry["processes"]["iAnyGo.exe"]["purposeKey"], "phone-tools")

    def test_shared_address_is_not_attributed(self):
        # One address answers two domains: it is unclear which one the program called.
        self.pc.observe_answer("fonts.example-cdn.com", "A", dns_response(["203.0.113.50"]), [])
        self.pc.observe_answer("metrics.example-cdn.com", "A", dns_response(["203.0.113.50"]), [])
        self.connections = [("203.0.113.50", 200)]
        self.pc.poll_attribution()
        self.assertEqual(self.pc.domains["fonts.example-cdn.com"]["processes"], {})
        self.assertEqual(self.pc.domains["metrics.example-cdn.com"]["processes"], {})

    def test_dns_client_log_parser_reads_pid_and_name(self):
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            "<EventID>3006</EventID><EventRecordID>77</EventRecordID>"
            "<Execution ProcessID='4321' ThreadID='1'/></System><EventData>"
            "<Data Name='QueryName'>Telemetry.Example.COM</Data></EventData></Event>"
        )
        self.assertEqual(parse_dns_client_events(xml), [{"record": 77, "pid": 4321, "domain": "telemetry.example.com"}])

    # -- Safety gate -------------------------------------------------------
    def test_tools_and_system_domains_are_protected(self):
        for domain in ("api.anthropic.com", "statsig.anthropic.com", "api.deepseek.com",
                       "www.msftconnecttest.com", "registry.npmjs.org", "chatgpt.com"):
            guard, _ = self.pc.local_guard(domain, {})
            self.assertEqual(guard, "protected", domain)

    def test_trusted_hosts_are_protected_but_not_their_siblings(self):
        trusted = {"hosts": {"api.example-sync.dev": "my sync tool"}, "programs": [], "apps": []}
        with mock.patch.object(user_exceptions, "load", return_value=trusted):
            self.assertIn("my sync tool", pc_protection.protected_reason("api.example-sync.dev"))
            self.assertTrue(pc_protection.protected_reason("eu.api.example-sync.dev"))
            self.assertEqual(pc_protection.protected_reason("trk.example-sync.dev"), "")

    def test_program_own_vendor_domain_is_its_function(self):
        self.attribute("license.tenorshare.com", 100)
        guard, reason = self.pc.local_guard("license.tenorshare.com", self.pc.domains["license.tenorshare.com"])
        self.assertEqual(guard, "protected")
        self.assertIn("owner", reason)

    def test_collector_called_by_needed_program_is_additional(self):
        self.attribute("app-measurement.com", 100)
        guard, _ = self.pc.local_guard("app-measurement.com", self.pc.domains["app-measurement.com"])
        self.assertEqual(guard, "additional")

    # -- Blocking gates -------------------------------------------------------
    def red(self, domain, agreement="Agreement", block_safe=True):
        return {"domain": domain, "color": "red", "blockSafe": block_safe, "agreement": agreement,
                "reason": "analytics", "reviewers": ["anthropic", "groq"]}

    def test_red_with_consensus_blocks_only_in_pc_policy(self):
        self.attribute("sdk.tracker-example.io", 200)
        self.assertEqual(self.pc.decide("sdk.tracker-example.io", self.red("sdk.tracker-example.io"), "unknown"), "auto-blocked")
        self.assertEqual(self.policy.action_for("sdk.tracker-example.io"), "block")

    def test_disagreement_or_unsafe_never_blocks(self):
        self.attribute("sdk.tracker-example.io", 200)
        self.assertEqual(self.pc.decide("sdk.tracker-example.io", self.red("sdk.tracker-example.io", "Disagreement"), "unknown"), "red-kept")
        self.assertEqual(self.pc.decide("sdk.tracker-example.io", self.red("sdk.tracker-example.io", block_safe=False), "unknown"), "red-kept")
        self.assertEqual(self.policy.action_for("sdk.tracker-example.io"), "monitor")

    def test_operational_name_is_vetoed_even_when_red(self):
        self.attribute("api.vendor-example.io", 200)
        self.assertEqual(self.pc.decide("api.vendor-example.io", self.red("api.vendor-example.io"), "unknown"), "red-kept")

    def test_regate_blocks_kept_red_once_gate_allows(self):
        # Keeping "pending caller" is queried every cycle: when the program is known, it is blocked without model call.
        self.pc.observe_answer("x.vendor-example.io", "A", None, [])
        verdict = {**self.red("x.vendor-example.io", agreement="Your ruling")}
        self.pc.domains["x.vendor-example.io"]["verdict"] = verdict
        self.assertEqual(self.pc.decide("x.vendor-example.io", verdict, "unknown"), "red-kept")
        items = {i["domain"]: i for i in self.pc.snapshot()["items"]}
        self.assertEqual(items["x.vendor-example.io"]["keptFor"], "pending")
        self.assertEqual(self.pc.regate(), 0)
        self.attribute("x.vendor-example.io", 200)
        self.assertEqual(self.pc.regate(), 1)
        self.assertEqual(self.policy.action_for("x.vendor-example.io"), "block")

    def test_unknown_caller_waits_unless_name_declares_collection(self):
        self.pc.observe_answer("sdk.mystery-example.io", "A", None, [])
        self.assertEqual(self.pc.decide("sdk.mystery-example.io", self.red("sdk.mystery-example.io"), "unknown"), "red-kept")
        self.pc.observe_answer("metrics.mystery-example.io", "A", None, [])
        self.assertEqual(self.pc.decide("metrics.mystery-example.io", self.red("metrics.mystery-example.io"), "additional"), "auto-blocked")

    def test_review_cycle_uses_pc_prompt_and_blocks_confirmed_red(self):
        seen = {}

        def fake_batch(pool, packets, system_prompt=""):
            seen["prompt"] = system_prompt
            seen["packets"] = packets
            return {"verdicts": {p["domain"]: {"domain": p["domain"], "color": "red", "blockSafe": True,
                                               "servesAppFunction": False, "reason": "measurement", "confidence": 90}
                                 for p in packets}}

        import ai_domain_review

        original = ai_domain_review.review_batch
        ai_domain_review.review_batch = fake_batch
        enabled = mock.patch.object(pc_protection.ai_providers, "enabled", return_value=True)
        enabled.start()
        self.addCleanup(enabled.stop)
        try:
            self.pc.reviewer = FakeReviewer()
            self.attribute("events.tracker-example.io", 200)
            self.attribute("api.anthropic.com", 300)
            counts = self.pc.review_cycle()
        finally:
            ai_domain_review.review_batch = original
        self.assertIs(seen["prompt"], pc_protection.PC_SYSTEM_PROMPT)
        sent = json.dumps(seen["packets"], ensure_ascii=False)
        # Program names reach the model, and protected domains are not reviewed at all.
        self.assertIn("Fantastical", sent)
        self.assertNotIn("anthropic", sent)
        self.assertEqual(counts["blocked"], 1)
        self.assertEqual(self.policy.action_for("events.tracker-example.io"), "block")
        self.assertEqual(self.policy.action_for("api.anthropic.com"), "monitor")

    def test_without_ai_review_the_built_in_catalog_blocks_known_trackers(self):
        with mock.patch.object(pc_protection.ai_providers, "enabled", return_value=False):
            self.pc.reviewer = FakeReviewer()
            self.attribute("app-measurement.com", 200)
            self.attribute("calendar-sync.example-unknown.io", 200, "203.0.113.9")
            counts = self.pc.review_cycle()
        self.assertEqual(self.policy.action_for("app-measurement.com"), "block")
        unknown = self.pc.domains["calendar-sync.example-unknown.io"]
        self.assertEqual(unknown["verdict"]["color"], "orange")
        self.assertEqual(self.policy.action_for("calendar-sync.example-unknown.io"), "monitor")
        self.assertGreaterEqual(counts["blocked"], 1)

    # -- Post-block guard -----------------------------------------------
    def test_retry_storm_releases_block(self):
        self.attribute("sdk.tracker-example.io", 200)
        self.pc.decide("sdk.tracker-example.io", self.red("sdk.tracker-example.io"), "unknown")
        now = time.monotonic()
        self.pc.blocked_calls["sdk.tracker-example.io"].extend([now] * pc_protection.RETRY_STORM_CALLS)
        self.assertEqual(self.pc.guard_blocked(), ["sdk.tracker-example.io"])
        self.assertEqual(self.policy.action_for("sdk.tracker-example.io"), "monitor")
        self.assertEqual(self.pc.domains["sdk.tracker-example.io"]["decision"]["state"], "guard-released")

    def test_guard_release_is_never_reblocked(self):
        # datadoghq was blocked and released eight times: the red verdict returns after each release.
        self.attribute("sdk.tracker-example.io", 200)
        self.pc.decide("sdk.tracker-example.io", self.red("sdk.tracker-example.io"), "unknown")
        now = time.monotonic()
        self.pc.blocked_calls["sdk.tracker-example.io"].extend([now] * pc_protection.RETRY_STORM_CALLS)
        self.pc.guard_blocked()
        self.assertNotIn("sdk.tracker-example.io", self.pc.candidates())
        self.assertEqual(
            self.pc.decide("sdk.tracker-example.io", self.red("sdk.tracker-example.io"), "unknown"),
            "guard-released",
        )
        self.assertEqual(self.policy.action_for("sdk.tracker-example.io"), "monitor")

    def test_new_owner_caller_releases_block(self):
        self.attribute("stats.tenorshare-cdn.com", 200)
        self.pc.decide("stats.tenorshare-cdn.com", self.red("stats.tenorshare-cdn.com"), "additional")
        self.assertEqual(self.policy.action_for("stats.tenorshare-cdn.com"), "block")
        # "stats" declares collection, so being owned by the program owner does not protect it.
        self.attribute("stats.tenorshare-cdn.com", 100, "203.0.113.9")
        self.assertEqual(self.pc.guard_blocked(), [])

    def test_verdict_not_decided_by_sonnet_is_due_now(self):
        # A green verdict from a single provider is checked again; one the judge decided waits its full interval.
        self.attribute("geo.example-ip.com", 100)
        self.attribute("license.example-ip.com", 100, "203.0.113.8")
        fresh = pc_protection._now_iso()
        for domain in ("geo.example-ip.com", "license.example-ip.com"):
            self.pc.domains[domain].pop("needsRecheck", None)
        self.pc.domains["geo.example-ip.com"]["verdict"] = {"color": "green", "provider": "alibaba", "reviewedAt": fresh}
        self.pc.domains["license.example-ip.com"]["verdict"] = {
            "color": "green", "decidedBy": "judge", "reviewedAt": fresh,
        }
        due = self.pc.candidates()
        self.assertIn("geo.example-ip.com", due)
        self.assertNotIn("license.example-ip.com", due)

    def test_session_verdict_survives_new_caller(self):
        # A verdict you gave yourself survives a new caller asking for a recheck.
        self.attribute("torrent.example.org", 100)
        self.pc.domains["torrent.example.org"]["verdict"] = {"color": "green", "agreement": "Your ruling"}
        self.pc.domains["torrent.example.org"]["needsRecheck"] = True
        self.assertNotIn("torrent.example.org", self.pc.candidates())

    def test_unattributed_domain_links_by_cname_and_site(self):
        self.attribute("www.fantastical.example", 200)
        self.pc.domains["www.fantastical.example"]["cname"] = ["edge.cdn-host.example"]
        self.pc.observe_answer("edge.cdn-host.example", "A", None, [])
        self.pc.observe_answer("sync.fantastical.example", "A", None, [])
        self.pc.observe_answer("lonely.unknown.example", "A", None, [])
        items = {item["domain"]: item for item in self.pc.snapshot()["items"]}
        self.assertEqual([(p["name"], p["inferred"]) for p in items["edge.cdn-host.example"]["programs"]], [("Fantastical.exe", "cname")])
        self.assertEqual([(p["name"], p["inferred"]) for p in items["sync.fantastical.example"]["programs"]], [("Fantastical.exe", "site")])
        self.assertEqual(items["lonely.unknown.example"]["programs"], [])
        self.assertNotIn("processes", {k for k, v in self.pc.domains["sync.fantastical.example"].items() if v})

    def test_user_allow_is_never_reblocked(self):
        self.attribute("sdk.tracker-example.io", 200)
        self.pc.user_decision("sdk.tracker-example.io", "allow")
        self.assertNotIn("sdk.tracker-example.io", self.pc.candidates())
class ResolverDeviceSplitTests(unittest.TestCase):
    def test_pc_queries_use_pc_policy_and_stay_out_of_phone_log(self):
        class Activity:
            def __init__(self):
                self.rows = []

            def add(self, **row):
                self.rows.append(row)

        phone, pc_policy = MemoryPolicy(), MemoryPolicy()
        pc_policy.update("tracker.example.com", "block")
        activity = Activity()
        resolver = Resolver(phone, activity, urlopen=lambda *a, **k: None)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        pc = PCProtection(Path(directory.name), pc_policy, log_reader=SilentLog(), connections=lambda: [])
        resolver.pc_protection = pc
        resolver.pc_policy = pc_policy

        answer = resolver.resolve(build_query("tracker.example.com"), "127.0.0.1")
        self.assertEqual(answer[3] & 0x0F, 3)
        self.assertEqual(activity.rows, [])
        self.assertEqual(pc.domains["tracker.example.com"]["hits"], 1)

        self.assertEqual(resolver._action_for("tracker.example.com", "192.0.2.50"), "monitor")
        self.assertEqual(resolver._action_for("tracker.example.com", "127.0.0.1"), "block")


if __name__ == "__main__":
    unittest.main()
