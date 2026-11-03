import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import phone_auto  # noqa: E402
from phone_auto import RETRY_CALLS, SOURCE, PhoneAutoProtection  # noqa: E402


class Policy:
    def __init__(self, domains=None):
        self.domains = dict(domains or {})

    def snapshot(self):
        return {"domains": {k: dict(v) for k, v in self.domains.items()}}

    def update(self, domain, action, label=None, note=None, source=None):
        self.domains[domain] = {"action": action, "source": source or "manual"}


class Classifier:
    def __init__(self, domains):
        self.domains = domains

    def snapshot(self):
        return {"domains": self.domains}


class Activity:
    def __init__(self, rows=()):
        self.rows = list(rows)

    def snapshot(self, limit=80):
        return self.rows[:limit]


def red(agreement="Agreement", block_safe=True, bundles=()):
    return {
        "appBundles": list(bundles),
        "aiVerdict": {"color": "red", "blockSafe": block_safe, "agreement": agreement,
                      "reason": "tracking", "reviewers": ["anthropic", "zai"]},
    }


class PhoneAutoTests(unittest.TestCase):
    def make(self, domains, policy=None, activity=()):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.policy = Policy(policy)
        return PhoneAutoProtection(Path(self.directory.name), self.policy, Classifier(domains), None, Activity(activity))

    def test_confirmed_red_with_known_caller_is_blocked(self):
        auto = self.make({"sdk.tracker-example.io": red(bundles=["com.example.game"])})
        self.assertEqual(auto.apply_verdicts(), 1)
        self.assertEqual(self.policy.domains["sdk.tracker-example.io"], {"action": "block", "source": SOURCE})

    def test_without_ai_review_the_built_in_catalog_blocks_known_trackers(self):
        domains = {"doubleclick.net": {"appBundles": ["com.example.game"]},
                   "unknown-sync.example.io": {"appBundles": ["com.example.game"]}}
        with mock.patch.object(phone_auto.ai_providers, "enabled", return_value=False):
            auto = self.make(domains)
            self.assertEqual(auto.apply_verdicts(), 1)
        self.assertEqual(self.policy.domains["doubleclick.net"]["action"], "block")
        self.assertNotIn("unknown-sync.example.io", self.policy.domains)

    def test_with_ai_review_on_the_catalog_alone_does_not_block(self):
        with mock.patch.object(phone_auto.ai_providers, "enabled", return_value=True):
            auto = self.make({"doubleclick.net": {"appBundles": ["com.example.game"]}})
            self.assertEqual(auto.apply_verdicts(), 0)

    def test_gates_hold(self):
        auto = self.make({
            "a.tracker-example.io": red(agreement="Disagreement", bundles=["com.example.game"]),
            "b.tracker-example.io": red(block_safe=False, bundles=["com.example.game"]),
            "c.vendor-example.io": red(),  # no known caller and name does not indicate bundle
            "api.anthropic.com": red(bundles=["com.anthropic.claude"]),
            "metrics.mystery-example.io": red(),  # name indicates bundle
        })
        auto.apply_verdicts()
        self.assertEqual(set(self.policy.domains), {"metrics.mystery-example.io"})

    def test_stale_gate_veto_is_asked_again(self):
        # fls-eu.amazon.sa: held by the safety gate at verdict time, then entered the
        # bundlers list, so it remained open with a saved block.
        def kept(domain, category):
            entry = red(block_safe=False, bundles=["com.example.shop"])
            entry["category"] = category
            entry["aiVerdict"].update(modelBlockSafe=True, blockVeto="the local category is a runtime path that must not be blocked")
            return entry
        auto = self.make({
            "api.instabug.com": kept("api.instabug.com", "functional_service"),
            "api.vendor-example.io": kept("api.vendor-example.io", "functional_service"),
        })
        auto.apply_verdicts()
        self.assertEqual(set(self.policy.domains), {"api.instabug.com"})

    def test_owner_decision_is_never_overridden(self):
        auto = self.make({"sdk.tracker-example.io": red(bundles=["x"])},
                         policy={"sdk.tracker-example.io": {"action": "allow", "source": "manual"}})
        auto.apply_verdicts()
        self.assertEqual(self.policy.domains["sdk.tracker-example.io"]["action"], "allow")

    def test_retry_storm_releases_only_automatic_blocks(self):
        now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        rows = [{"action": "blocked", "domain": d, "time": now}
                for d in ("sdk.tracker-example.io", "manual.tracker-example.io") for _ in range(RETRY_CALLS)]
        auto = self.make({}, policy={
            "sdk.tracker-example.io": {"action": "block", "source": SOURCE},
            "manual.tracker-example.io": {"action": "block", "source": "manual"},
        }, activity=rows)
        self.assertEqual(auto.guard(), 1)
        self.assertEqual(self.policy.domains["sdk.tracker-example.io"]["action"], "monitor")
        self.assertEqual(self.policy.domains["manual.tracker-example.io"]["action"], "block")
if __name__ == "__main__":
    unittest.main()
