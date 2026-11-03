import tempfile
import time
import unittest
from pathlib import Path

import review_memory
from review_memory import ReviewMemory


class ReviewMemoryTests(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp()) / "review-memory.json"

    def test_failed_domain_waits_longer_each_time_up_to_a_day(self):
        memory = ReviewMemory(self.path)
        memory.failed(["a.com"])
        self.assertFalse(memory.ready("a.com"))
        first = memory.failures["a.com"]["nextAt"] - time.time()
        memory.failed(["a.com"])
        self.assertGreater(memory.failures["a.com"]["nextAt"] - time.time(), first * 1.5)
        for _ in range(10):
            memory.failed(["a.com"])
        self.assertLessEqual(memory.failures["a.com"]["nextAt"] - time.time(), review_memory.MAX_DELAY_SECONDS + 1)
        memory.succeeded(["a.com"])
        self.assertTrue(memory.ready("a.com"))

    def test_search_is_saved_per_domain_and_survives_restart(self):
        calls = []
        memory = ReviewMemory(self.path)
        search = lambda domain: calls.append(domain) or "Ad network"
        memory.lookup("a.foo.com", search)
        memory.lookup("a.foo.com", search)
        self.assertEqual(ReviewMemory(self.path).lookup("a.foo.com", search), "Ad network")
        memory.lookup("b.foo.com", search)
        self.assertEqual(calls, ["a.foo.com", "b.foo.com"])

    def test_daily_caps_for_the_orange_tray(self):
        memory = ReviewMemory(self.path)
        self.assertEqual(memory.capped(), [])
        memory.jury_capped("Qwen alternative answered", time.time() + 3600)
        memory.sonnet_failed("judge:budget", until=time.time() + 3600)
        self.assertEqual(ReviewMemory(self.path).capped(), ["The jurors", "The judge"])
        self.assertEqual(memory.capped(now=time.time() + 7200), [])
        memory.jury_answered()
        memory.sonnet_failed("HTTP 500")   # Transient failure does not count as a daily limit
        self.assertEqual(memory.capped(), [])

    def test_cap_start_stays_while_capped(self):
        memory = ReviewMemory(self.path)
        self.assertEqual(memory.capped_since(), 0.0)
        memory.jury_capped("a", time.time() + 3600)
        first = memory.capped_since()
        time.sleep(0.01)
        memory.jury_capped("b", time.time() + 3600)
        self.assertEqual(memory.capped_since(), first)

    def test_daily_search_limit(self):
        memory = ReviewMemory(self.path)
        old = review_memory.LOOKUP_DAILY_LIMIT
        review_memory.LOOKUP_DAILY_LIMIT = 1
        try:
            calls = []
            search = lambda domain: calls.append(domain) or "Answer"
            memory.lookup("one.com", search)
            self.assertEqual(memory.lookup("two.com", search), "")
            self.assertEqual(calls, ["one.com"])
        finally:
            review_memory.LOOKUP_DAILY_LIMIT = old

    def test_cycle_waits_until_six_domains_or_ten_minutes(self):
        memory = ReviewMemory(self.path)
        self.assertFalse(memory.hold([]))
        self.assertTrue(memory.hold(["a.com"]))
        self.assertTrue(memory.hold(["a.com", "b.com"]))
        self.assertFalse(memory.hold([f"{i}.com" for i in range(6)]))
        self.assertTrue(memory.hold(["a.com"]))
        memory.waiting["default"]["a.com"] -= review_memory.GATHER_WAIT_SECONDS + 1
        self.assertFalse(memory.hold(["a.com", "b.com"]))

    def test_phone_and_pc_queues_do_not_erase_each_other(self):
        memory = ReviewMemory(self.path)
        self.assertTrue(memory.hold(["a.com"], "phone"))
        memory.waiting["phone"]["a.com"] -= review_memory.GATHER_WAIT_SECONDS + 1
        self.assertTrue(memory.hold(["x.com"], "pc"))
        self.assertFalse(memory.hold(["a.com"], "phone"))


if __name__ == "__main__":
    unittest.main()
class SonnetProbeTests(unittest.TestCase):
    def test_probe_ends_the_wait_when_sonnet_answers(self):
        # Seven transient failures kept domains "waiting for the judge" for six hours
        # before it answered.
        with tempfile.TemporaryDirectory() as folder:
            answers = [(False, "HTTP 503"), (True, "")]
            memory = ReviewMemory(Path(folder) / "m.json", probe=lambda: answers.pop(0))
            for _ in range(7):
                memory.sonnet_failed("timeout")
            self.assertFalse(memory.sonnet_ready())  # Not time to check: checked at failure
            memory.sonnet["probedAt"] = time.time() - review_memory.SONNET_PROBE_SECONDS - 1
            self.assertFalse(memory.sonnet_ready())
            self.assertEqual(memory.sonnet["lastError"], "HTTP 503")
            memory.sonnet["probedAt"] = time.time() - review_memory.SONNET_PROBE_SECONDS - 1
            self.assertTrue(memory.sonnet_ready())
            self.assertEqual(answers, [])
