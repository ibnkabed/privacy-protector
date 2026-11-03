import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import model_ledger


class ModelLedgerTests(unittest.TestCase):
    """Model work ledger: a readable record of the app's verdicts in four columns."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "work-ledger.jsonl"
        patcher = mock.patch.object(model_ledger, "LEDGER_PATH", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_batch_writes_done_missed_and_not_done(self) -> None:
        response = {"ok": True, "provider": "anthropic", "model": "claude-haiku-5-5"}
        verdict = {"color": "red", "category": "tracking", "reason": "reason", "blockSafe": True}
        model_ledger.record_batch("Domain Review", response, ["a.example", "b.example"], {"a.example": verdict})
        model_ledger.record_batch("Domain Review", {"ok": False, "errors": ["503"]}, ["c.example"], {})
        rows = model_ledger.read()
        self.assertEqual([row["column"] for row in rows], ["done", "missed", "not_done"])
        self.assertEqual(rows[0]["task"], "domain-review")
        self.assertEqual(rows[0]["item"], "a.example: Red — tracking")
        self.assertEqual(set(rows[0]), {"at", "task", "task_ar", "provider", "model", "column", "item", "detail", "ref"})
        # The item identifier is static (no timestamp), so its latest verdict replaces the previous one in the view.
        self.assertEqual([row["ref"] for row in rows], ["domain:a.example", "domain:b.example", "domain:c.example"])

    def test_a_failed_batch_writes_a_row_for_each_domain(self) -> None:
        model_ledger.record_batch("Domain Review", {"ok": False}, ["a.example", "b.example"], {})
        rows = model_ledger.read()
        self.assertEqual([(row["column"], row["ref"]) for row in rows],
                         [("not_done", "domain:a.example"), ("not_done", "domain:b.example")])

    def test_paid_summary_skips_free_models(self) -> None:
        for provider, model, column in (("judge", "model-a", "done"), ("judge", "model-a", "wrong"),
                                        ("openrouter", "x:free", "done")):
            model_ledger.record("Domain Review", provider, model, column, "item")
        summary = model_ledger.paid_summary(model_ledger.read(days=7))
        self.assertEqual(len(summary), 1)
        self.assertEqual((summary[0]["done"], summary[0]["wrong"], summary[0]["rate"]), (1, 1, 50))

    def test_red_confirmation_marks_the_first_model(self) -> None:
        first = {"provider": "openai", "model": "gpt", "reason": "tracking"}
        model_ledger.record_confirmation("a.example", first, False, "Green 3 out of 5")
        rows = model_ledger.read()
        row = rows[0]
        self.assertEqual((row["task"], row["column"], row["provider"]), ("red-confirmation", "wrong", "openai"))
        # The vote settled it, so a second 'done' line with the same ref follows; it is not shown again.
        self.assertEqual((rows[1]["column"], rows[1]["provider"], rows[1]["ref"]), ("done", "the vote", "red:a.example"))
        self.assertGreater(rows[1]["at"], row["at"])

    def test_window_falls_back_to_the_last_two_hours_of_the_file(self) -> None:
        # Task 10: 📋 Show only unresolved items; completed ones appear in the summary only.
        model_ledger.record("Domain Review", "anthropic", "m", "wrong", "recent")
        model_ledger.record("Domain Review", "anthropic", "m", "done", "completed")
        model_ledger.record("Domain Review", "anthropic", "m", "wrong", "Old", at="2026-01-01T00:00:00+00:00")
        if True:
            window = model_ledger.window()
        self.assertEqual(window["source"], "file")
        self.assertEqual([row["item"] for row in window["rows"]], ["recent"])
        self.assertEqual(window["summary"]["done"], 1)


if __name__ == "__main__":
    unittest.main()
