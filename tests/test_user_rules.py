"""Protection rules override the models' verdict: even their consensus does not overturn them."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ai_domain_review
import user_rules


def red() -> dict:
    return {"color": "red", "blockSafe": True, "reason": "models' verdict"}


class OwnerRulesTests(unittest.TestCase):
    def test_health_data_is_green_and_never_blocked_even_without_a_caller(self) -> None:
        verdict = user_rules.enforce("sportdata-dra.things.dbankcloud.com", red())
        self.assertEqual((verdict["color"], verdict["blockSafe"], verdict["ownerRule"]),
                         ("green", False, "health"))
        self.assertIn("protection rule", verdict["reason"])

    def test_health_category_is_protected(self) -> None:
        verdict = user_rules.enforce("www.example-health.cn", red(), (), "expected_health_data")
        self.assertEqual(verdict["ownerRule"], "health")

    def test_tracking_called_by_a_health_app_stays_blockable(self) -> None:
        verdict = user_rules.enforce("app-measurement.com", red(), ("com.huawei.global.health",))
        self.assertEqual((verdict["color"], verdict["blockSafe"]), ("red", True))
        self.assertNotIn("ownerRule", verdict)

    def test_vendor_log_host_is_not_health(self) -> None:
        verdict = user_rules.enforce("logservice.hicloud.com", red())
        self.assertTrue(verdict["blockSafe"])

    def test_attendance_is_green(self) -> None:
        verdict = user_rules.enforce("hather-moblieapi.moe.gov.sa", red())
        self.assertEqual((verdict["color"], verdict["ownerRule"]), ("green", "attendance"))

    def test_offline_map_download_is_never_blocked(self) -> None:
        verdict = user_rules.enforce("map-dra.platform.dbankcloud.com", red())
        self.assertFalse(verdict["blockSafe"])
        self.assertEqual(verdict["ownerRule"], "no-break")

    def test_privacy_protection_is_green(self) -> None:
        verdict = user_rules.enforce("mask.icloud.com", red(), (), "privacy_protection")
        self.assertEqual((verdict["color"], verdict["ownerRule"]), ("green", "infrastructure"))

    def test_plain_tracker_is_untouched(self) -> None:
        self.assertEqual(user_rules.enforce("t.appsflyer.com", red()), red())

    def test_models_are_told_the_rules(self) -> None:
        self.assertIn(user_rules.rules_prompt(), ai_domain_review.SYSTEM_PROMPT)
        for rule in user_rules.RULES:
            self.assertIn(rule["title"], ai_domain_review.SYSTEM_PROMPT)


if __name__ == "__main__":
    unittest.main()
