"""AI review layer tests — no network calls."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import ai_calibration
import ai_domain_review as review
import ai_providers
import ai_review_domains
import ai_reviewer
from ai_reviewer import DomainAIReviewer
from domain_classifier import DomainClassificationEngine
from domain_verdicts import (
    ai_block_gate,
    caller_purpose,
    domain_function_role,
    functional_purpose_veto,
)


REAL_CONFIGURED = ai_providers.configured_providers


def fake_providers(*extra):
    """Writer, juror and judge as the user would configure them; no request leaves the test."""
    configs = [
        ai_providers.ProviderConfig("anthropic", "anthropic", "https://example.invalid/v1", "writer-model", "k", ("writer",)),
        ai_providers.ProviderConfig("deepseek", "openai", "https://example.invalid/v1", "juror-model", "k", ("juror",)),
        ai_providers.ProviderConfig("anthropic-sonnet", "anthropic", "https://example.invalid/v1", "judge-model", "k", ("judge",)),
    ]
    return configs + list(extra)


class ExtractJSONTests(unittest.TestCase):
    def test_reads_plain_object(self) -> None:
        self.assertEqual(ai_providers.extract_json('{"a": 1}'), {"a": 1})

    def test_reads_fenced_block(self) -> None:
        text = 'text before\n```json\n{"verdicts": []}\n```\ntext after'
        self.assertEqual(ai_providers.extract_json(text), {"verdicts": []})

    def test_reads_object_between_noise(self) -> None:
        self.assertEqual(ai_providers.extract_json('answer: {"color": "red"} end'), {"color": "red"})

    def test_returns_none_for_garbage(self) -> None:
        self.assertIsNone(ai_providers.extract_json("no json here"))


class SecretHandlingTests(unittest.TestCase):
    """Keys come only from the user's local provider settings and go only to that provider."""

    def test_provider_layer_never_touches_the_keys_file(self) -> None:
        source = Path(ai_providers.__file__).read_text(encoding="utf-8")
        self.assertNotIn(".ai-keys", source)
        self.assertNotIn("winreg", source)
        self.assertFalse(hasattr(ai_providers, "load_keys"))

    def test_each_request_carries_only_its_own_providers_key(self) -> None:
        sent = []
        openai = ai_providers.ProviderConfig("o", "openai", "https://o.invalid/v1", "m", "key-o")
        claude = ai_providers.ProviderConfig("c", "anthropic", "https://c.invalid/v1", "m", "key-c")
        with mock.patch.object(ai_providers, "_post_json",
                               side_effect=lambda url, payload, headers, timeout=0.0: sent.append((url, headers)) or (200, None, "")):
            ai_providers.provider_complete(openai, "system", "request", 100, 0.0)
            ai_providers.provider_complete(claude, "system", "request", 100, 0.0)
        self.assertEqual(sent[0], ("https://o.invalid/v1/chat/completions", {"Authorization": "Bearer key-o"}))
        self.assertEqual(sent[1][0], "https://c.invalid/v1/messages")
        self.assertEqual(sent[1][1]["x-api-key"], "key-c")


class EvidencePrivacyTests(unittest.TestCase):
    """The evidence bundle carries calling app names: no data privacy before the models."""

    def setUp(self) -> None:
        self.entry = {
            "domain": "collector.example.com",
            "appBundles": ["com.alinma.mobile", "com.tweetie2.app"],
            "appContexts": ["banking app"],
            "hits": 42,
            "qtypes": ["A"],
            "cnameChain": ["edge.doubleclick.net"],
            "networkStudy": {"title": "Collector", "certificateSubject": "Example Inc"},
            "risk": "green",
            "categoryLabel": "General network service",
        }

    def test_calling_apps_are_named_for_the_model(self) -> None:
        packet = review.build_evidence("collector.example.com", self.entry, {"pattern": "insufficient"})
        self.assertEqual(packet["callerApps"], ["com.alinma.mobile", "com.tweetie2.app", "banking app"])
        self.assertEqual(packet["distinctApps"], 2)

    def test_first_party_is_computed_locally(self) -> None:
        entry = {"appBundles": ["com.alinma.mobile"]}
        self.assertTrue(review._first_party_match("smart.alinma.com", entry["appBundles"]))
        self.assertFalse(review._first_party_match("app-measurement.com", entry["appBundles"]))

    def test_public_study_fields_are_kept(self) -> None:
        packet = review.build_evidence("collector.example.com", self.entry, {"pattern": "insufficient"})
        self.assertEqual(packet["tlsSubject"], "Example Inc")
        self.assertIn("edge.doubleclick.net", packet["cnameChain"])
class TimingProfileTests(unittest.TestCase):
    def test_night_wide_activity_reads_as_background(self) -> None:
        profiles = review.TimingProfiles()
        domain = "beacon.example.com"
        profiles.total[domain] = 60
        profiles.hours[domain] = set(range(0, 20))
        profiles.night[domain] = 9
        profiles.days[domain] = {"2026-09-20", "2026-09-21"}
        self.assertIn("background", profiles.profile(domain)["pattern"])

    def test_clustered_activity_reads_as_session(self) -> None:
        profiles = review.TimingProfiles()
        domain = "api.example.com"
        profiles.total[domain] = 30
        profiles.hours[domain] = {13, 14, 15}
        profiles.days[domain] = {"2026-09-21"}
        self.assertIn("session", profiles.profile(domain)["pattern"])

    def test_thin_sample_is_not_judged(self) -> None:
        profiles = review.TimingProfiles()
        self.assertEqual(profiles.profile("rare.example.com")["pattern"], "insufficient")


class VerdictNormalizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.allowed = {"a.example.com"}

    def test_arabic_color_is_accepted(self) -> None:
        verdict = review.normalize_verdict(
            {"domain": "a.example.com", "color": "Red", "confidence": 88}, self.allowed
        )
        self.assertEqual(verdict["color"], "red")

    def test_unknown_domain_is_rejected(self) -> None:
        self.assertIsNone(
            review.normalize_verdict({"domain": "b.example.com", "color": "red"}, self.allowed)
        )

    def test_invalid_color_is_rejected(self) -> None:
        self.assertIsNone(
            review.normalize_verdict({"domain": "a.example.com", "color": "purple"}, self.allowed)
        )

    def test_function_claim_cancels_block_safety(self) -> None:
        verdict = review.normalize_verdict(
            {
                "domain": "a.example.com",
                "color": "red",
                "confidence": 90,
                "servesAppFunction": True,
                "blockSafe": True,
            },
            self.allowed,
        )
        self.assertTrue(verdict["servesAppFunction"])
        self.assertFalse(verdict["blockSafe"])

    def test_confidence_is_bounded(self) -> None:
        verdict = review.normalize_verdict(
            {"domain": "a.example.com", "color": "green", "confidence": 5000}, self.allowed
        )
        self.assertEqual(verdict["confidence"], 100)


class BlockGateTests(unittest.TestCase):
    def test_operational_hostname_is_vetoed(self) -> None:
        allowed, reason = ai_block_gate("auth.example.com", "")
        self.assertFalse(allowed)
        self.assertTrue(reason)

    def test_collector_hostname_is_allowed(self) -> None:
        self.assertTrue(ai_block_gate("analytics.example.com", "")[0])

    def test_functional_category_is_vetoed(self) -> None:
        self.assertFalse(ai_block_gate("anything.example.com", "authentication")[0])


class FunctionalPurposeVetoTests(unittest.TestCase):
    """Blocking that disables the app's stated purpose is prohibited, even if the model flags it as red."""

    ATTENDANCE = ("com.t2.availohader", "HUDURI")

    def test_attendance_function_domain_is_protected(self) -> None:
        # The provisioning interface and identity service: blocking them stops the very purpose for which the app was installed.
        for domain in ("hather-moblieapi.moe.gov.sa", "hather-nafath.moe.gov.sa"):
            with self.subTest(domain=domain):
                vetoed, reason = functional_purpose_veto(domain, self.ATTENDANCE)
                self.assertTrue(vetoed)
                self.assertTrue(reason)

    def test_attendance_extra_domains_stay_blockable(self) -> None:
        # Telemetry domains called by the app itself are unrelated to provisioning.
        for domain in (
            "firebaselogging-pa.googleapis.com",
            "app-measurement.com",
            "firebase-settings.crashlytics.com",
            "firebaseinappmessaging.googleapis.com",
            "apm.unocm.sdaia.gov.sa",
        ):
            with self.subTest(domain=domain):
                self.assertFalse(functional_purpose_veto(domain, self.ATTENDANCE)[0])

    def test_push_and_config_stay_functional_for_the_same_app(self) -> None:
        for domain in (
            "firebaseinstallations.googleapis.com",
            "firebaseremoteconfig.googleapis.com",
            "fcmtoken.googleapis.com",
            "imagedelivery.net",
        ):
            with self.subTest(domain=domain):
                self.assertTrue(functional_purpose_veto(domain, self.ATTENDANCE)[0])

    def test_health_vendor_domain_is_protected(self) -> None:
        # The app package name does not textually match the manufacturer's domain, so family linking is required.
        self.assertTrue(
            functional_purpose_veto("sportdata-dra.things.dbankcloud.com", ("com.huawei.global.health",))[0]
        )

    def test_offline_map_download_is_protected_for_any_caller(self) -> None:
        # The actual scenario: map download refused due to a blocked domain.
        self.assertTrue(functional_purpose_veto("map-dra.platform.dbankcloud.com", ())[0])
        self.assertTrue(functional_purpose_veto("configdownload-dra.dbankcdn.com", ())[0])

    def test_login_and_push_paths_are_protected(self) -> None:
        for domain in (
            "accounts.google.com",
            "pinpoint.us-east-1.amazonaws.com",
            "login.example.com",
        ):
            with self.subTest(domain=domain):
                self.assertTrue(functional_purpose_veto(domain, ())[0])

    def test_social_sdk_in_another_app_is_blockable(self) -> None:
        # A meta package within a game is not a game function, so it is not protected.
        for domain in ("ep7.facebook.com", "graph.instagram.com", "connect.facebook.net"):
            with self.subTest(domain=domain):
                self.assertFalse(
                    functional_purpose_veto(domain, ("puzzle.woodenblockpuzzle.mania",))[0]
                )

    def test_first_party_telemetry_label_is_still_blockable(self) -> None:
        # The domain belonging to the app owner does not make it a function when its name indicates log transmission.
        self.assertFalse(
            functional_purpose_veto("log22-normal-alisg.tiktokv.com", ("com.zhiliaoapp.musically",))[0]
        )
        self.assertTrue(
            functional_purpose_veto("search19-normal-alisg.tiktokv.com", ("com.zhiliaoapp.musically",))[0]
        )

    def test_login_label_is_not_read_as_logging(self) -> None:
        self.assertEqual(domain_function_role("login.huduri.sa", self.ATTENDANCE)[0], "function")

    def test_caller_purpose_describes_without_naming(self) -> None:
        purpose = caller_purpose(self.ATTENDANCE)
        self.assertIn("attendance", purpose.lower())
        self.assertNotIn("availohader", purpose.lower())
        self.assertNotIn("huduri", purpose.lower())

    def test_named_collector_stays_blockable_even_for_a_health_caller(self) -> None:
        # A name declaring it as a collection point is not protected just because an attendance app calls it.
        self.assertFalse(functional_purpose_veto("app-measurement.com", ("com.t2.availohader",))[0])
        self.assertFalse(functional_purpose_veto("analytics.huawei.com", ("com.huawei.global.health",))[0])

    def test_government_service_is_protected(self) -> None:
        self.assertTrue(functional_purpose_veto("www.iam.gov.sa", ("com.t2.availohader",))[0])

    def test_role_values_are_the_three_known_ones(self) -> None:
        for domain, callers in (
            ("app-measurement.com", ()),
            ("hather-moblieapi.moe.gov.sa", ("com.t2.availohader",)),
            ("unknown-host.example.com", ()),
        ):
            with self.subTest(domain=domain):
                self.assertIn(
                    domain_function_role(domain, callers)[0],
                    {"function", "additional", "unknown"},
                )

    def test_ad_platform_is_not_protected_by_a_delivery_name(self) -> None:
        # A bidding network naming its host 'notify' does not make it a notification gateway.
        self.assertFalse(functional_purpose_veto("notify-eu.rtbuniverse.com", ())[0])
        self.assertFalse(functional_purpose_veto("push.rubiconproject.com", ())[0])
        self.assertTrue(functional_purpose_veto("gateway.push.apple.com", ())[0])

    def test_unrelated_tracker_is_not_protected(self) -> None:
        self.assertFalse(functional_purpose_veto("warp90.com", ("com.tiktok",))[0])

    def test_gate_refuses_when_purpose_veto_applies(self) -> None:
        allowed, reason = ai_block_gate(
            "fitness-dra.things.dbankcloud.com", "", ("com.huawei.global.health",)
        )
        self.assertFalse(allowed)
        self.assertTrue(reason)


class ApplyVerdictTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        path = Path(self.directory.name) / "classifications.json"
        self.engine = DomainClassificationEngine(path, active_analysis=False)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def _verdict(self, **overrides):
        verdict = {
            "color": "red",
            "confidence": 90,
            "category": "behavioral tracking",
            "purpose": "collects user behavior",
            "reason": "background ping with many app shares",
            "collects": ["device identifier"],
            "firstParty": False,
            "blockSafe": True,
            "blockImpact": "nothing breaks",
            "provider": "gemini",
            "agreement": "Agreement",
            "reviewers": ["gemini", "groq"],
        }
        verdict.update(overrides)
        return verdict

    def test_colour_is_applied_and_recorded(self) -> None:
        self.engine.observe("tracker.example.com")
        outcome = self.engine.apply_ai_verdict("tracker.example.com", self._verdict())
        self.assertTrue(outcome["applied"])
        entry = self.engine.get("tracker.example.com")
        self.assertEqual(entry["risk"], "red")
        self.assertEqual(entry["aiVerdict"]["agreement"], "Agreement")
        self.assertTrue(entry["aiReviewedAt"])

    def test_curated_catalog_is_not_overridden(self) -> None:
        self.engine.observe("app-measurement.com")
        outcome = self.engine.apply_ai_verdict(
            "app-measurement.com", self._verdict(color="green", confidence=99)
        )
        self.assertFalse(outcome["applied"])
        self.assertEqual(self.engine.get("app-measurement.com")["risk"], "red")

    def test_local_red_evidence_is_never_downgraded(self) -> None:
        self.engine.mark_privacy_evidence(["proof.example.com"], violations=["Location"])
        outcome = self.engine.apply_ai_verdict("proof.example.com", self._verdict(color="green"))
        self.assertFalse(outcome["applied"])
        self.assertEqual(self.engine.get("proof.example.com")["risk"], "red")

    def test_block_safety_needs_local_permission(self) -> None:
        self.engine.observe("auth.example.com")
        self.engine.apply_ai_verdict("auth.example.com", self._verdict())
        verdict = self.engine.get("auth.example.com")["aiVerdict"]
        self.assertFalse(verdict["blockSafe"])
        self.assertTrue(verdict["blockVeto"])

    def test_reclassification_keeps_the_review(self) -> None:
        self.engine.observe("tracker.example.com")
        self.engine.apply_ai_verdict("tracker.example.com", self._verdict())
        self.engine.reclassify_all()
        entry = self.engine.get("tracker.example.com")
        self.assertEqual(entry["risk"], "red")
        self.assertEqual(entry["aiVerdict"]["color"], "red")

    def test_summary_counts_reviews(self) -> None:
        self.engine.observe("tracker.example.com")
        self.engine.apply_ai_verdict("tracker.example.com", self._verdict())
        summary = self.engine.ai_review_summary()
        self.assertEqual(summary["reviewed"], 1)
        self.assertEqual(summary["colors"]["red"], 1)


class _CourtCase(unittest.TestCase):
    """Set up the court with fake calls, shared across its tests."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        patcher = mock.patch.object(ai_providers, "configured_providers", mock.Mock(return_value=fake_providers(
            ai_providers.ProviderConfig("xai", "openai", "https://example.invalid/v1", "m", "k", ("juror",)))))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.reviewer = DomainAIReviewer(Path(self.directory.name))
        self.calls: list[dict] = []
        self.searched: list[str] = []
        self.jury: dict = {}
        self.judge: dict = {}
        self.jury_provider = "deepseek"
        self.judge_provider = "anthropic-sonnet"

        def fake_lookup(domain):
            self.searched.append(domain)
            return "advertising and tracking network"

        lookup = mock.patch.object(ai_reviewer.ai_providers, "web_lookup", side_effect=fake_lookup)
        lookup.start()
        self.addCleanup(lookup.stop)
        batch = mock.patch.object(ai_reviewer, "review_batch", side_effect=self._fake_batch)
        batch.start()
        self.addCleanup(batch.stop)
        notes = mock.patch.object(ai_reviewer, "JUDGE_NOTES_PATH", Path(self.directory.name) / "judge-notes.json")
        notes.start()
        self.addCleanup(notes.stop)
        # These tests are for the court itself: the judge is immediate.
        # Aggregation by window is in JudgeWindowTests.
        window = mock.patch.object(ai_reviewer, "JUDGE_WINDOW_SECONDS", 0.0)
        window.start()
        self.addCleanup(window.stop)

    def _fake_batch(self, pool, asked, maximum_wait=180.0, system_prompt="", exclude=()):
        self.calls.append({"task": pool.task, "pool": list(pool.slots), "asked": asked,
                           "prompt": system_prompt, "exclude": tuple(exclude)})
        table, provider, why = (
            (self.jury, self.jury_provider, "jury verdict") if pool.task == ai_reviewer.JURY_TASK
            else (self.judge, self.judge_provider, "judge reason")
        )
        verdicts = {
            item["domain"]: {"domain": item["domain"], "color": table[item["domain"]][0], "confidence": 90,
                             "reason": why, "blockSafe": table[item["domain"]][1], "provider": provider,
                             "model": provider + "-m"}
            for item in asked if item["domain"] in table
        }
        for domain, verdict in verdicts.items():
            if len(table[domain]) > 2:   # Note not resolved by the judge
                verdict.update(needsSession=True, sessionNote=table[domain][2])
        return {"ok": bool(verdicts), "verdicts": verdicts, "errors": [] if verdicts else ["HTTP 503"]}

    def _decide(self, firsts, jury, judge, packets=None, reader="anthropic"):
        """`firsts`: domain -> (Haiku color, safe to block). `jury` and `judge`:
        domain -> (color, safe to block)."""
        self.jury, self.judge = jury, judge
        verdicts = {
            domain: {"domain": domain, "color": color, "confidence": 70, "reason": "Haiku reading",
                     "blockSafe": safe, "provider": reader}
            for domain, (color, safe) in firsts.items()
        }
        packets = packets or [{"domain": domain, "pageTitle": "Page"} for domain in firsts]
        return self.reviewer.decide_batch(packets, verdicts)

    def _tasks(self):
        return [call["task"] for call in self.calls]
class ConsensusTests(_CourtCase):
    """The Court: Haiku reads, the five jurors issue one verdict for the batch,
    and Judge Sonnet confirms or overturns with a single call before execution. Only what the judge
    confirms or rules is executed."""

    def test_one_jury_call_then_one_judge_call_for_the_whole_batch(self) -> None:
        firsts = {f"d{i}.example.com": ("green", False) for i in range(6)}
        same = {domain: ("green", False) for domain in firsts}
        result = self._decide(firsts, same, same)
        self.assertEqual(self._tasks(), [ai_reviewer.JURY_TASK, ai_reviewer.JUDGE_TASK])
        jury, judge = self.calls
        self.assertEqual(jury["pool"], ["auto"])
        self.assertIn("writer", jury["exclude"])
        self.assertIn("judge", jury["exclude"])
        self.assertIn(ai_reviewer.JURY_NOTE, jury["prompt"])
        self.assertEqual(jury["asked"][0]["firstReading"]["reason"], "Haiku reading")
        self.assertEqual(len(jury["asked"]), 6)
        self.assertEqual(judge["pool"], ["judge"])
        self.assertIn(ai_reviewer.JUDGE_NOTE, judge["prompt"])
        self.assertEqual(judge["asked"][0]["firstReading"]["reason"], "Haiku reading")
        self.assertEqual(judge["asked"][0]["juryVerdict"]["reason"], "jury verdict")
        self.assertTrue(all(item["agreement"] == ai_reviewer.JUDGE_CONFIRMED for item in result.values()))
        self.assertTrue(all(item["juryBy"] == "deepseek" for item in result.values()))

    def test_jury_then_judge_confirm_is_executed(self) -> None:
        result = self._decide({"x.example.com": ("orange", False)}, {"x.example.com": ("red", True)},
                              {"x.example.com": ("red", True)})["x.example.com"]
        self.assertEqual((result["color"], result["agreement"], result["blockSafe"]),
                         ("red", ai_reviewer.JUDGE_CONFIRMED, True))
        self.assertIn(result["agreement"], ai_reviewer.BLOCK_AGREEMENTS)
        self.assertTrue(ai_reviewer.decided_by_main(result))
        self.assertNotIn("pendingSonnet", result)
        self.assertEqual(result["provider"], "deepseek")   # The verdict is the jury's, confirmed by the judge
        self.assertEqual(result["judge"]["provider"], "anthropic-sonnet")
        self.assertEqual(result["reviewers"], ["anthropic", "deepseek", "anthropic-sonnet"])

    def test_judge_confirming_red_but_unsafe_is_not_blocked(self) -> None:
        result = self._decide({"x.example.com": ("red", True)}, {"x.example.com": ("red", True)},
                              {"x.example.com": ("red", False)})["x.example.com"]
        self.assertEqual(result["agreement"], ai_reviewer.JUDGE_CONFIRMED)
        self.assertFalse(result["blockSafe"])

    def test_judge_override_takes_the_judges_verdict(self) -> None:
        result = self._decide({"x.example.com": ("red", True)}, {"x.example.com": ("red", True)},
                              {"x.example.com": ("orange", False)})["x.example.com"]
        self.assertEqual((result["color"], result["agreement"], result["blockSafe"]),
                         ("orange", ai_reviewer.JUDGE_OVERRODE, False))
        self.assertEqual(result["reason"], "judge reason")
        # Both verdicts are preserved together.
        self.assertEqual((result["jury"]["color"], result["judge"]["color"]), ("red", "orange"))
        self.assertIn("(overrode)", result["vote"])

    def test_judge_override_to_red_blocks_as_judged(self) -> None:
        result = self._decide({"x.example.com": ("orange", False)}, {"x.example.com": ("orange", False)},
                              {"x.example.com": ("red", True)})["x.example.com"]
        self.assertEqual((result["color"], result["agreement"], result["blockSafe"]),
                         ("red", ai_reviewer.JUDGE_OVERRODE, True))
        self.assertIn(result["agreement"], ai_reviewer.BLOCK_AGREEMENTS)

    def test_judge_unavailable_leaves_the_jury_verdict_provisional_and_retries_only_the_judge(self) -> None:
        result = self._decide({"x.example.com": ("orange", False)}, {"x.example.com": ("red", True)}, {})
        verdict = result["x.example.com"]
        self.assertEqual(verdict["agreement"], ai_reviewer.PENDING_JUDGE)
        self.assertTrue(verdict["pendingSonnet"])
        self.assertFalse(verdict["blockSafe"])
        self.assertNotIn(verdict["agreement"], ai_reviewer.BLOCK_AGREEMENTS)
        self.assertFalse(ai_reviewer.decided_by_main(verdict))
        self.assertEqual((verdict["color"], verdict["jury"]["color"], verdict["jury"]["blockSafe"]), ("red", "red", True))
        self.assertEqual(verdict["firstReading"]["color"], "orange")
        self.assertFalse(self.reviewer.memory.sonnet_ready())
        # During the wait, the judge is not queried again, and the jury rules on new items.
        self._decide({"y.example.com": ("green", False)}, {"y.example.com": ("green", False)},
                     {"y.example.com": ("green", False)})
        self.assertEqual(self._tasks(), [ai_reviewer.JURY_TASK, ai_reviewer.JUDGE_TASK, ai_reviewer.JURY_TASK])
        # The judge returns: presented with the stored verdict alone, no Haiku and no jurors.
        self.reviewer.memory.sonnet_probed(True)
        self.calls.clear()
        stored = dict(verdict)
        for key in ("agreement", "vote", "votes", "reviewers", "reviewedAt", "pendingSonnet", "applied"):
            stored.pop(key, None)
        stored["modelBlockSafe"] = False   # What the store saves from the provisional verdict does not block what the judge confirms
        self.judge = {"x.example.com": ("red", True)}
        final = self.reviewer.decide_batch([{"domain": "x.example.com", "pageTitle": "Page"}],
                                           {"x.example.com": stored})["x.example.com"]
        self.assertEqual(self._tasks(), [ai_reviewer.JUDGE_TASK])
        self.assertEqual(self.calls[0]["asked"][0]["juryVerdict"]["color"], "red")
        self.assertEqual(self.calls[0]["asked"][0]["firstReading"]["color"], "orange")
        self.assertEqual((final["color"], final["agreement"], final["blockSafe"]), ("red", ai_reviewer.JUDGE_CONFIRMED, True))
        self.assertNotIn("modelBlockSafe", final)

    def test_without_a_jury_verdict_the_judge_is_not_asked(self) -> None:
        result = self._decide({"x.example.com": ("red", True)}, {}, {"x.example.com": ("red", True)})["x.example.com"]
        self.assertEqual(self._tasks(), [ai_reviewer.JURY_TASK])
        self.assertEqual(result["agreement"], ai_reviewer.PENDING_JURY)
        self.assertTrue(result["pendingSonnet"])
        self.assertFalse(result["blockSafe"])

    def test_an_answer_from_another_model_is_not_the_judge(self) -> None:
        self.judge_provider = "kilo"
        result = self._decide({"x.example.com": ("red", True)}, {"x.example.com": ("red", True)},
                              {"x.example.com": ("red", True)})
        self.assertEqual(result["x.example.com"]["agreement"], ai_reviewer.PENDING_JUDGE)

    def test_claude_is_never_a_juror(self) -> None:
        self.jury_provider = "anthropic-sonnet"
        result = self._decide({"x.example.com": ("red", True)}, {"x.example.com": ("red", True)},
                              {"x.example.com": ("red", True)})
        self.assertEqual(result["x.example.com"]["agreement"], ai_reviewer.PENDING_JURY)
        self.assertEqual(self._tasks(), [ai_reviewer.JURY_TASK])

    def test_an_answer_from_outside_the_jury_marks_it_capped_until_a_juror_answers(self) -> None:
        # Orange icon: no juror answered, so the jurors reached their daily limit
        self.jury_provider = "qwen"
        self._decide({"x.example.com": ("red", True)}, {"x.example.com": ("red", True)}, {})
        self.assertIn("The jurors", self.reviewer.memory.capped())
        self.jury_provider = "deepseek"
        self._decide({"y.example.com": ("red", True)}, {"y.example.com": ("red", True)}, {})
        self.assertNotIn("The jurors", self.reviewer.memory.capped())

    def test_a_juror_who_read_first_does_not_judge_its_own_reading(self) -> None:
        self._decide({"x.example.com": ("red", True)}, {"x.example.com": ("red", True)},
                     {"x.example.com": ("red", True)}, reader="xai")
        self.assertIn("xai", self.calls[0]["exclude"])

    def test_an_obscure_red_is_searched_before_the_jury(self) -> None:
        self._decide({"x.example.com": ("red", True)}, {"x.example.com": ("red", True)},
                     {"x.example.com": ("red", True)}, packets=[{"domain": "x.example.com"}])
        self.assertEqual(self.searched, ["x.example.com"])
        self.assertEqual(self.calls[0]["asked"][0]["webSearch"], "advertising and tracking network")
        self.assertEqual(self.calls[1]["asked"][0]["webSearch"], "advertising and tracking network")

    def test_a_domain_its_page_explains_is_not_searched(self) -> None:
        self._decide({"x.example.com": ("red", True)}, {"x.example.com": ("red", True)},
                     {"x.example.com": ("red", True)})
        self.assertEqual(self.searched, [])

    def test_haiku_still_reads_first(self) -> None:
        self.jury = self.judge = {"x.example.com": ("red", True)}
        haiku_task = []

        def reading(pool, asked, maximum_wait=180.0, system_prompt="", exclude=()):
            if pool.task in (ai_reviewer.JURY_TASK, ai_reviewer.JUDGE_TASK):
                return self._fake_batch(pool, asked, maximum_wait, system_prompt, exclude)
            haiku_task.append(pool.task)
            self.calls.append({"task": pool.task})
            return {"ok": True, "verdicts": {"x.example.com": {
                "domain": "x.example.com", "color": "orange", "confidence": 90, "reason": "Haiku reading",
                "blockSafe": False, "provider": "anthropic", "model": "claude-haiku"}}}

        with mock.patch.object(ai_reviewer, "review_batch", side_effect=reading):
            result = self.reviewer.review_domains(["x.example.com"])
        self.assertEqual(haiku_task, [ai_reviewer.REVIEW_TASK])
        self.assertEqual(self._tasks(), [ai_reviewer.REVIEW_TASK, ai_reviewer.JURY_TASK, ai_reviewer.JUDGE_TASK])
        verdict = result["verdicts"][0]
        self.assertEqual(verdict["firstReading"]["provider"], "anthropic")
        self.assertEqual((verdict["color"], verdict["agreement"]), ("red", ai_reviewer.JUDGE_CONFIRMED))

    def test_the_court_is_recorded_in_the_model_ledger(self) -> None:
        import model_ledger

        path = Path(self.directory.name) / "work-ledger.jsonl"
        with mock.patch.object(model_ledger, "LEDGER_PATH", path):
            self._decide({"a.example.com": ("red", True), "b.example.com": ("green", False)},
                         {"a.example.com": ("red", True), "b.example.com": ("green", False)},
                         {"a.example.com": ("orange", False), "b.example.com": ("green", False)})
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        b_rows = [row for row in rows if row["ref"] == "domain:b.example.com"]
        self.assertEqual([(row["task"], row["column"]) for row in b_rows], [("judge-review", "done")])
        a_rows = [row for row in rows if row["ref"] == "domain:a.example.com"]
        self.assertEqual([(row["task"], row["provider"], row["column"]) for row in a_rows],
                         [("jury-verdict", "deepseek", "wrong"), ("judge-review", "anthropic-sonnet", "done")])
        self.assertIn("The jury (deepseek)", a_rows[0]["detail"])
        self.assertIn("And the judge (anthropic-sonnet)", a_rows[0]["detail"])

    def test_what_the_judge_cannot_settle_waits_for_a_session_until_settled(self) -> None:
        result = self._decide({"x.example.com": ("red", True)}, {"x.example.com": ("red", True)},
                              {"x.example.com": ("orange", False, "Conflicting evidence")})["x.example.com"]
        self.assertEqual((result["color"], result["needsSession"], result["sessionNote"]),
                         ("orange", True, "Conflicting evidence"))
        self.assertEqual(list(ai_reviewer.session_notes()), ["x.example.com"])
        self.calls.clear()
        self._decide({"x.example.com": ("red", True)}, {"x.example.com": ("red", True)},
                     {"x.example.com": ("orange", False)})
        self.assertEqual(ai_reviewer.session_notes(), {})

    def test_missing_evidence_alone_never_asks_for_a_session(self) -> None:
        # cdn4.telesco.pe: All green or orange without collection, and the judge requests
        # "linking it to the caller app".
        result = self._decide({"x.example.com": ("green", False)}, {"x.example.com": ("green", False)},
                              {"x.example.com": ("orange", False, "Needs linking to the caller app")})["x.example.com"]
        self.assertEqual(result["color"], "orange")
        self.assertNotIn("needsSession", result)
        self.assertEqual(ai_reviewer.session_notes(), {})
        # And the author's red that the jurors and judge overturned was settled by voting
        # (zws1.web.telegram.org).
        self._decide({"y.example.com": ("red", False)}, {"y.example.com": ("orange", False)},
                     {"y.example.com": ("orange", False, "Purpose unclear")})
        self.assertEqual(ai_reviewer.session_notes(), {})

    def test_the_judges_kind_decides_the_session(self) -> None:
        judge = {"color": "orange", "needsSession": True}
        quiet = [{"color": "green"}, {"color": "green"}]
        self.assertFalse(ai_reviewer.session_worthy({**judge, "sessionKind": "evidence"}, [{"color": "red"}, {"color": "red"}]))
        self.assertTrue(ai_reviewer.session_worthy({**judge, "sessionKind": "conflict"}, quiet))
        self.assertTrue(ai_reviewer.session_worthy({**judge, "sessionKind": "owner"}, quiet))
        self.assertFalse(ai_reviewer.session_worthy(judge, quiet))
        self.assertTrue(ai_reviewer.session_worthy(judge, [{"color": "green"}, {"color": "orange", "collects": ["Location"]}]))

    def test_the_owner_session_clears_the_judges_note(self) -> None:
        self._decide({"x.example.com": ("red", True)}, {"x.example.com": ("red", True)},
                     {"x.example.com": ("orange", False, "Needs the owner")})
        ai_reviewer.clear_session_note("X.example.com.")
        self.assertEqual(ai_reviewer.session_notes(), {})

    def test_only_a_true_flag_reaches_the_verdict(self) -> None:
        from ai_domain_review import normalize_verdict

        raw = {"domain": "x.example.com", "color": "orange", "needsSession": True, "sessionNote": "Unresolved"}
        self.assertEqual(normalize_verdict(raw, {"x.example.com"})["sessionNote"], "Unresolved")
        self.assertNotIn("needsSession", normalize_verdict({**raw, "needsSession": False}, {"x.example.com"}))
        self.assertEqual(normalize_verdict({**raw, "sessionKind": "Evidence"}, {"x.example.com"})["sessionKind"], "evidence")
        self.assertNotIn("sessionKind", normalize_verdict({**raw, "sessionKind": "maybe"}, {"x.example.com"}))

    def test_waiting_for_the_judge_writes_no_note(self) -> None:
        self._decide({"x.example.com": ("red", True)}, {"x.example.com": ("red", True)}, {})
        self.assertEqual(ai_reviewer.session_notes(), {})
class JudgeWindowTests(_CourtCase):
    """The judge rules on pending items together: full batch or hourly on the oldest."""

    def setUp(self) -> None:
        super().setUp()
        window = mock.patch.object(ai_reviewer, "JUDGE_WINDOW_SECONDS", 3600.0)
        window.start()
        self.addCleanup(window.stop)

    def _stored(self, verdict, age):
        stored = dict(verdict)
        for key in ("agreement", "vote", "votes", "reviewers", "reviewedAt", "pendingSonnet", "applied"):
            stored.pop(key, None)
        stamp = ai_reviewer.datetime.fromtimestamp(ai_reviewer.time.time() - age).astimezone()
        stored["juryAt"] = stamp.isoformat(timespec="seconds")
        return stored

    def test_a_small_fresh_batch_waits_for_the_judge(self) -> None:
        result = self._decide({"x.example.com": ("orange", False)}, {"x.example.com": ("red", True)},
                              {"x.example.com": ("red", True)})["x.example.com"]
        self.assertEqual(self._tasks(), [ai_reviewer.JURY_TASK])
        self.assertEqual(result["agreement"], ai_reviewer.PENDING_JUDGE)
        self.assertFalse(result["blockSafe"])
        self.assertIn("juryAt", result)
        self.assertTrue(self.reviewer.memory.sonnet_ready())   # Waiting for schedule, not stalling

    def test_a_full_batch_is_judged_at_once(self) -> None:
        firsts = {f"d{i}.example.com": ("green", False) for i in range(ai_reviewer.JUDGE_BATCH)}
        result = self._decide(firsts, dict(firsts), dict(firsts))
        self.assertEqual(self._tasks(), [ai_reviewer.JURY_TASK, ai_reviewer.JURY_TASK, ai_reviewer.JUDGE_TASK])
        self.assertEqual(len(self.calls[-1]["asked"]), ai_reviewer.JUDGE_BATCH)
        self.assertTrue(all(item["agreement"] == ai_reviewer.JUDGE_CONFIRMED for item in result.values()))
        self.assertTrue(all("juryAt" not in item for item in result.values()))

    def test_waiting_verdicts_are_judged_together_when_the_oldest_is_due(self) -> None:
        firsts = {f"d{i}.example.com": ("orange", False) for i in range(15)}
        self.jury = {domain: ("red", True) for domain in firsts}
        verdicts = {domain: {"domain": domain, "color": "orange", "confidence": 70, "reason": "Haiku reading",
                             "blockSafe": False, "provider": "anthropic"} for domain in firsts}
        pending = {domain: ai_reviewer.court_verdict(domain, dict(v), dict(v, color="red", provider="deepseek"), None)
                   for domain, v in verdicts.items()}
        stored = {domain: self._stored(v, 120) for domain, v in pending.items()}
        stored["d0.example.com"] = self._stored(pending["d0.example.com"], 4000)
        self.assertTrue(ai_reviewer.judge_due([stored["d0.example.com"]]))
        self.assertFalse(ai_reviewer.judge_due([stored["d1.example.com"]]))
        self.judge = {domain: ("red", True) for domain in firsts}
        packets = [{"domain": domain, "pageTitle": "Page"} for domain in firsts]
        final = self.reviewer.decide_batch(packets, stored)
        self.assertEqual(self._tasks(), [ai_reviewer.JUDGE_TASK, ai_reviewer.JUDGE_TASK])
        self.assertEqual([len(call["asked"]) for call in self.calls], [ai_reviewer.JUDGE_BATCH, 3])
        self.assertTrue(all(item["agreement"] == ai_reviewer.JUDGE_CONFIRMED for item in final.values()))

    def test_waiting_verdicts_before_their_time_are_not_presented(self) -> None:
        verdict = {"domain": "x.example.com", "color": "orange", "provider": "anthropic"}
        waiting = ai_reviewer.court_verdict("x.example.com", dict(verdict), dict(verdict, provider="deepseek"), None)
        self.assertTrue(ai_reviewer.awaits_judge(waiting))
        self.assertFalse(ai_reviewer.judge_due([waiting]))
        self.assertTrue(ai_reviewer.judge_due([dict(waiting, juryAt="")]))   # Stored before window: presented


class QuotaHandlingTests(unittest.TestCase):
    """Inexact daily limit: hitting it wastes until tomorrow."""

    def test_daily_marker_is_recognised(self) -> None:
        self.assertTrue(
            ai_providers._is_daily_quota("GenerateRequestsPerDayPerProjectPerModel-FreeTier")
        )

    def test_per_minute_limit_is_not_daily(self) -> None:
        self.assertFalse(
            ai_providers._is_daily_quota("Rate limit reached, requests per minute exceeded")
        )

    def test_every_provider_declares_a_pace(self) -> None:
        for config in fake_providers():
            with self.subTest(provider=config.name):
                self.assertGreater(config.minimum_interval, 0)


class PartialCalibrationTests(unittest.TestCase):
    """Test that a targeted probe does not wipe other results from the state file."""

    def test_untargeted_providers_are_preserved(self) -> None:
        previous = {
            "providers": {
                "zai": {"provider": "zai", "score": 0.93, "passed": True, "reachable": True},
                "cohere": {"provider": "cohere", "score": 0.5, "passed": False, "reachable": True},
            }
        }
        original = ai_calibration.calibrate_provider
        ai_calibration.calibrate_provider = lambda name: {
            "provider": name, "score": 0.0, "passed": False, "reachable": False,
            "answered": 0, "expected": 15,
        }
        try:
            report = ai_calibration.calibrate_all(("gemini",), previous=previous)
        finally:
            ai_calibration.calibrate_provider = original
        self.assertIn("zai", report["providers"])
        self.assertIn("cohere", report["providers"])
        self.assertEqual(report["providers"]["zai"]["score"], 0.93)
        self.assertIn("zai", report["trusted"])
class CalibrationStateTests(unittest.TestCase):
    """Provider exam is saved over the persisted state, and "re-exam" actually tests."""

    SAVED = {
        "calibratedAt": "2026-09-22T02:10:06+03:00",
        "providers": {
            "anthropic-sonnet": {"provider": "anthropic-sonnet", "model": "z1", "score": 0.93, "passed": True, "reachable": True},
        },
        "trusted": ["anthropic-sonnet"],
        "slots": [{"provider": "anthropic-sonnet", "model": "z1", "slot": "anthropic-sonnet:z1", "score": 0.93, "passed": True}],
        "trustedSlots": [["anthropic-sonnet", "z1"]],
        "slotsCalibratedAt": "2026-09-21T10:00:00+03:00",
    }

    def setUp(self) -> None:
        # Dummy keys and fake exam: no real key is read and no request leaves the device.
        configs = [ai_providers.ProviderConfig(name, "openai", "https://example.invalid/v1", "m-" + name, "test-" + name)
                   for name in ("anthropic", "openai", "anthropic-sonnet")]
        self.examined: list[str] = []
        for target, name, replacement in (
            (ai_providers, "configured_providers", mock.Mock(return_value=configs)),
            (ai_calibration, "calibrate_provider", mock.Mock(side_effect=self._exam)),
            (ai_providers.ProviderPool, "verify", mock.Mock(return_value=None)),
        ):
            patcher = mock.patch.object(target, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.data = Path(directory.name)
        ai_calibration.save_state(self.data, json.loads(json.dumps(self.SAVED)))

    def _exam(self, name, pool=None, model=""):
        self.examined.append(name)
        if name == "anthropic-sonnet":
            # Its quota ran out today so it did not answer.
            return {"provider": name, "model": "z1", "score": 0.0, "passed": False,
                    "reachable": False, "answered": 0, "expected": 15, "calibratedAt": "today"}
        return {"provider": name, "model": "m-" + name, "score": 0.9, "passed": True,
                "reachable": True, "answered": 15, "expected": 15, "calibratedAt": "today"}

    def test_command_line_calibration_keeps_the_saved_slots(self) -> None:
        with mock.patch.object(ai_review_domains, "DATA_ROOT", self.data), \
                mock.patch.object(sys, "argv", ["ai_review_domains.py", "--calibrate"]), \
                mock.patch("builtins.print"):
            self.assertEqual(ai_review_domains.main(), 0)
        state = ai_calibration.load_state(self.data)
        self.assertEqual(state["trustedSlots"], [["anthropic-sonnet", "z1"]])
        self.assertEqual(len(state["slots"]), 1)
        self.assertEqual(state["slotsCalibratedAt"], self.SAVED["slotsCalibratedAt"])
        self.assertNotEqual(state["calibratedAt"], self.SAVED["calibratedAt"])
        # The one that could not take the exam today keeps its previous verdict.
        self.assertTrue(state["providers"]["anthropic-sonnet"]["passed"])
        self.assertTrue(state["providers"]["anthropic"]["passed"])

    def test_rerun_exam_examines_providers_although_slots_are_saved(self) -> None:
        DomainAIReviewer(self.data).calibrate(refresh=True)
        self.assertEqual(sorted(self.examined), ["anthropic", "anthropic-sonnet", "openai"])  # every configured provider
        state = ai_calibration.load_state(self.data)
        self.assertNotEqual(state["calibratedAt"], self.SAVED["calibratedAt"])
        self.assertEqual(state["trustedSlots"], [["anthropic-sonnet", "z1"]])

    def test_rerun_exam_leaves_the_paid_provider_out_when_asked(self) -> None:
        DomainAIReviewer(self.data, allow_paid=False).calibrate(refresh=True)
        self.assertEqual(sorted(self.examined), [])  # Both are paid

    def test_building_the_pool_from_saved_slots_examines_no_one(self) -> None:
        DomainAIReviewer(self.data).ensure_pool()
        self.assertEqual(self.examined, [])


class CalibrationScoringTests(unittest.TestCase):
    def test_exact_match_scores_full(self) -> None:
        expected = {"color": "red", "blockSafe": True}
        self.assertEqual(ai_calibration._score_item(expected, {"color": "red", "blockSafe": True}), 1.0)

    def test_opposite_colour_scores_zero(self) -> None:
        expected = {"color": "red", "blockSafe": True}
        self.assertEqual(ai_calibration._score_item(expected, {"color": "green", "blockSafe": False}), 0.0)

    def test_unsafe_block_claim_is_penalised(self) -> None:
        expected = {"color": "green", "blockSafe": False}
        self.assertEqual(ai_calibration._score_item(expected, {"color": "green", "blockSafe": True}), 0.5)

    def test_missing_answer_scores_zero(self) -> None:
        self.assertEqual(ai_calibration._score_item({"color": "green", "blockSafe": True}, None), 0.0)

    def test_benchmark_covers_every_colour(self) -> None:
        colours = {item["color"] for item in ai_calibration.BENCHMARK}
        self.assertEqual(colours, {"green", "orange", "red"})
class ProviderLayerTests(unittest.TestCase):
    """Direct providers from the user's settings: roles, rotation, cooldowns and daily limits."""

    def setUp(self) -> None:
        ai_providers._states.clear()
        ai_providers._paused_until.clear()
        ai_providers._usage.update(day="", calls={})
        self.answers: dict[str, tuple] = {}
        self.calls: list[str] = []
        juror2 = ai_providers.ProviderConfig("juror-b", "openai", "https://b.invalid/v1", "m", "k", ("juror",), daily_limit=1)
        for target, name, replacement in (
            (ai_providers, "configured_providers", mock.Mock(return_value=fake_providers(juror2))),
            (ai_providers, "provider_complete", mock.Mock(side_effect=self._fake)),
            (ai_providers.time, "sleep", mock.Mock()),
        ):
            patcher = mock.patch.object(target, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _fake(self, config, system, prompt, max_tokens, temperature, **_):
        self.calls.append(config.name)
        return self.answers.get(config.name, (200, {"choices": [{"message": {"content": '{"ok": true}'}}]}, ""))

    def test_auto_uses_writers_and_the_judge_slot_uses_judges(self) -> None:
        writer = ai_providers.ProviderPool().complete("s", "p")
        judge = ai_providers.ProviderPool(slots=(("judge", "judge"),)).complete("s", "p")
        self.assertEqual((writer["provider"], judge["provider"]), ("anthropic", "anthropic-sonnet"))

    def test_excluding_the_writer_role_reaches_the_jurors_in_rotation(self) -> None:
        pool = ai_providers.ProviderPool()
        first = pool.complete("s", "p", exclude=("writer", "judge"))["provider"]
        ai_providers._states[first].next_allowed_at = 0.0
        second = pool.complete("s", "p", exclude=("writer", "judge"))["provider"]
        self.assertEqual({first, second}, {"deepseek", "juror-b"})

    def test_a_refusing_provider_cools_down_and_the_next_answers(self) -> None:
        self.answers["deepseek"] = (401, None, "bad key")
        result = ai_providers.ProviderPool().complete("s", "p", exclude=("writer", "judge"))
        self.assertTrue(result["ok"])
        self.assertEqual(result["provider"], "juror-b")
        self.assertFalse(ai_providers._states["deepseek"].ready)

    def test_daily_limit_pauses_the_provider_until_midnight(self) -> None:
        self.answers["deepseek"] = (500, None, "down")
        pool = ai_providers.ProviderPool()
        self.assertTrue(pool.complete("s", "p", exclude=("writer", "judge", "deepseek"))["ok"])
        ai_providers._states["juror-b"].next_allowed_at = 0.0
        result = pool.complete("s", "p", exclude=("writer", "judge", "deepseek"), wait=False)
        self.assertFalse(result["ok"])
        self.assertTrue(ai_providers.slot_paused("juror-b"))

    def test_without_providers_the_review_is_off(self) -> None:
        with mock.patch.object(ai_providers, "configured_providers", mock.Mock(return_value=[])):
            result = ai_providers.ProviderPool().complete("s", "p")
        self.assertFalse(result["ok"])
        self.assertEqual(self.calls, [])

    def test_config_needs_a_key_unless_the_endpoint_is_local(self) -> None:
        config = {"enabled": True, "providers": [
            {"name": "cloud", "kind": "openai", "baseUrl": "https://x.invalid/v1", "model": "m"},
            {"name": "local", "kind": "openai", "baseUrl": "http://127.0.0.1:11434/v1", "model": "m"},
            {"name": "keyed", "kind": "anthropic", "baseUrl": "https://y.invalid/v1", "model": "m", "apiKey": "k"},
        ]}
        names = [p.name for p in REAL_CONFIGURED(config)]
        self.assertEqual(names, ["local", "keyed"])

class MainModelTests(unittest.TestCase):
    def test_only_the_judge_or_your_own_review_counts_as_decided(self):
        self.assertTrue(ai_reviewer.decided_by_main({"decidedBy": ai_reviewer.DECIDER, "color": "green"}))
        self.assertTrue(ai_reviewer.decided_by_main({"agreement": ai_reviewer.DECIDED_BY_SESSION, "color": "red"}))
        self.assertFalse(ai_reviewer.decided_by_main({"provider": "alibaba", "color": "green"}))
        self.assertFalse(ai_reviewer.decided_by_main(None))


if __name__ == "__main__":
    unittest.main()
