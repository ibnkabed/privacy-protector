"""Deciding without models: the built-in rules and the public tracker lists."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import local_decider  # noqa: E402
import tracker_lists  # noqa: E402
import user_exceptions  # noqa: E402
from ai_reviewer import BLOCK_AGREEMENTS  # noqa: E402


class DecideTests(unittest.TestCase):
    def hits(self, *names):
        return mock.patch.object(local_decider, "list_hits", return_value=list(names))

    def test_catalog_trackers_are_blocked(self):
        decision = local_decider.decide("doubleclick.net", ("com.example.game",))
        self.assertEqual((decision.layer, decision.action, decision.color), ("catalog", "block", "red"))

    def test_two_lists_block_and_one_only_watches(self):
        with self.hits("easyprivacy", "adguard-dns"):
            self.assertEqual(local_decider.decide("cdn77-pixel.unknown-example.io").action, "block")
        with self.hits("easyprivacy"):
            decision = local_decider.decide("plain.unknown-example.io")
        self.assertEqual((decision.action, decision.color), ("watch", "orange"))

    def test_a_list_and_a_collection_name_block(self):
        with self.hits("oisd-small"):
            self.assertEqual(local_decider.decide("telemetry.unknown-example.io").action, "block")

    def test_a_name_alone_never_blocks(self):
        with self.hits():
            self.assertEqual(local_decider.decide("stats.unknown-example.io").action, "watch")

    def test_protected_infrastructure_stays_open_even_on_lists(self):
        with self.hits("easyprivacy", "adguard-dns"):
            decision = local_decider.decide("www.msftconnecttest.com")
        self.assertEqual((decision.layer, decision.action), ("gate", "watch"))

    def test_a_trusted_app_is_never_blocked(self):
        trusted = {"hosts": {}, "programs": [], "apps": ["com.example.mine"]}
        with mock.patch.object(user_exceptions, "load", return_value=trusted), self.hits("easyprivacy", "adguard-dns"):
            decision = local_decider.decide("ads.unknown-example.io", ("com.example.mine",))
        self.assertEqual((decision.action, decision.color), ("watch", "green"))

    def test_location_lookups_are_flagged_not_blocked(self):
        with self.hits():
            decision = local_decider.decide("ipinfo.unknown-example.io")
        self.assertEqual((decision.layer, decision.action), ("exposure", "watch"))

    def test_unknown_domains_are_watched(self):
        with self.hits():
            decision = local_decider.decide("calendar.unknown-example.io")
        self.assertEqual((decision.layer, decision.action, decision.color), ("default", "watch", "orange"))

    def test_its_verdict_counts_as_decided(self):
        verdict = local_decider.verdict_for_domain("doubleclick.net", ("com.example.game",))
        self.assertIn(verdict["agreement"], BLOCK_AGREEMENTS)
        self.assertTrue(verdict["blockSafe"])


class TrackerListTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.dir = Path(folder.name) / "tracker-lists"
        for name, value in (("LISTS_DIR", self.dir), ("META_PATH", self.dir / "meta.json")):
            patcher = mock.patch.object(tracker_lists, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        local_decider._cache.update(stamp=None, lists={})
        self.addCleanup(local_decider._cache.update, stamp=None, lists={})

    @staticmethod
    def adblock(count):
        return "! comment\n" + "\n".join(f"||t{i}.example.net^" for i in range(count)) + "\n||x.example.net/path^\n"

    def test_parse_keeps_domains_only(self):
        self.assertEqual(tracker_lists.parse("! c\n||a.example.net^\n||b.example.net/p^\n", "adblock"), {"a.example.net"})
        self.assertEqual(tracker_lists.parse("# c\nc.example.net\nnot a domain\n", "domains"), {"c.example.net"})

    def test_an_update_is_loaded_and_subdomains_match(self):
        self.assertEqual(tracker_lists.update(["easyprivacy"], lambda url: self.adblock(1200)), {"easyprivacy": "updated"})
        self.assertEqual(local_decider.list_hits("deep.t5.example.net"), ["easyprivacy"])
        self.assertEqual(local_decider.list_hits("other.example.org"), [])

    def test_a_small_or_strange_update_keeps_the_last_good_copy(self):
        tracker_lists.update(["easyprivacy"], lambda url: self.adblock(2000))
        self.assertEqual(tracker_lists.update(["easyprivacy"], lambda url: self.adblock(10)), {"easyprivacy": "rejected"})
        self.assertEqual(tracker_lists.update(["easyprivacy"], lambda url: self.adblock(9000)), {"easyprivacy": "rejected"})
        self.assertEqual(len((self.dir / "easyprivacy.txt").read_text(encoding="utf-8").split()), 2000)

    def test_a_failed_download_touches_nothing(self):
        tracker_lists.update(["easyprivacy"], lambda url: self.adblock(1500))

        def down(url):
            raise OSError("offline")

        self.assertEqual(tracker_lists.update(["easyprivacy"], down), {"easyprivacy": "failed"})
        self.assertTrue(local_decider.list_hits("t1.example.net"))

    def test_clear_removes_the_lists(self):
        tracker_lists.update(["easyprivacy"], lambda url: self.adblock(1500))
        tracker_lists.clear()
        self.assertEqual(local_decider.list_hits("t1.example.net"), [])
        self.assertIsNone(tracker_lists.age_days())


if __name__ == "__main__":
    unittest.main()
