import json
import os
import subprocess
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

import temp_cleanup
from temp_cleanup import TempCleanup

OLD = time.time() - 10 * 86400


def age(path: Path, when: float = OLD) -> None:
    os.utime(path, (when, when))


def make(root: Path, rel: str, old: bool = True, data: bytes = b"x" * 10) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if old:
        age(path)
    return path


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.scope = self.base / "Temp"
        self.scope.mkdir()
        self.data = self.base / "data"
        self.data.mkdir()
        # ctime on Windows is creation time and not returned, so advance the limit instead of files.
        self.now = time.time() + 30 * 86400
        self.recent = self.now - 86400

    def tearDown(self):
        self.tmp.cleanup()

    def cleaner(self) -> TempCleanup:
        c = TempCleanup(self.data)
        c.config["scopes"] = [str(self.scope)]
        return c

    def survey_paths(self, cleaner: TempCleanup) -> set[str]:
        return {Path(e["path"]).name for e in cleaner.survey(now=self.now)["entries"]}

    def finish_dirs(self, *names):
        for name in names:
            for folder, _d, _f in os.walk(self.scope / name):
                age(Path(folder))


class SurveyTests(Fixture):
    def test_kept_folders_survive_at_any_age(self):
        make(self.scope, "claude/session/a.txt")
        make(self.scope, "codex-run-1/b.txt")
        make(self.scope, "claude-mock/c.bin")
        self.finish_dirs("claude", "codex-run-1", "claude-mock")
        cleaner = self.cleaner()
        cleaner.config["keep"] = ["claude", "codex-*"]
        self.assertEqual(self.survey_paths(cleaner), {"claude-mock"})

    def test_folder_with_one_recent_file_kept_whole(self):
        make(self.scope, "app/old.txt")
        recent = make(self.scope, "app/new.txt")
        age(recent, self.recent)
        self.finish_dirs("app")
        self.assertEqual(self.survey_paths(self.cleaner()), set())

    def test_config_keep_patterns_are_added(self):
        make(self.scope, "keep-me/a.txt")
        self.finish_dirs("keep-me")
        c = self.cleaner()
        c.config["keep"].append("keep-*")
        self.assertEqual(self.survey_paths(c), set())

    def test_unreadable_scope_is_reported_not_failed(self):
        c = self.cleaner()
        with mock.patch.object(temp_cleanup.os, "scandir", side_effect=PermissionError("denied")):
            result = c.survey(now=self.now)
        self.assertEqual(result["skipped"], [str(self.scope)])


class CleanTests(Fixture):
    def test_clean_deletes_logs_and_removes_empty_folder(self):
        make(self.scope, "old.log")
        make(self.scope, "pkg/inner/a.bin", data=b"y" * 100)
        self.finish_dirs("pkg")
        c = self.cleaner()
        with mock.patch.object(temp_cleanup.time, "time", return_value=self.now):
            run = c.clean("test")
        self.assertEqual(run["deleted"], 2)
        self.assertEqual(run["bytes"], 110)
        self.assertFalse((self.scope / "pkg").exists())
        lines = [json.loads(l) for l in (self.data / "temp-cleanup-log.ndjson").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len([l for l in lines if "deleted" in l]), 2)

    def test_locked_file_is_skipped(self):
        make(self.scope, "busy.tmp")
        c = self.cleaner()
        with mock.patch.object(temp_cleanup.time, "time", return_value=self.now), \
             mock.patch.object(temp_cleanup, "_remove", return_value=False):
            run = c.clean("test")
        self.assertEqual((run["deleted"], run["locked"]), (0, 1))
        self.assertTrue((self.scope / "busy.tmp").exists())

    def test_junction_target_untouched(self):
        outside = self.base / "outside"
        outside.mkdir()
        precious = make(outside, "precious.txt")
        link = self.scope / "link"
        made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True,
                              creationflags=temp_cleanup.CREATE_NO_WINDOW)
        if made.returncode != 0:
            self.skipTest("cannot create a junction here")
        c = self.cleaner()
        with mock.patch.object(temp_cleanup.time, "time", return_value=self.now):
            c.clean("test")
        self.assertTrue(precious.exists())
        self.assertFalse(os.path.lexists(link))

    def test_dry_run_deletes_nothing(self):
        target = make(self.scope, "old.log")
        c = self.cleaner()
        with mock.patch.object(temp_cleanup.time, "time", return_value=self.now):
            preview = c.preview()
        self.assertTrue(target.exists())
        self.assertEqual(preview["files"], 1)
        self.assertFalse(c.state["approved"])
class ScheduleTests(Fixture):
    def test_nothing_runs_before_approval(self):
        make(self.scope, "old.log")
        c = self.cleaner()
        with mock.patch.object(c, "clean") as clean:
            self.assertIsNone(c.tick())
        clean.assert_not_called()
        self.assertIsNotNone(c.state["preview"])

    def test_first_run_after_approval_then_daily_at_nine(self):
        c = self.cleaner()
        c.state["approved"] = True
        self.assertTrue(c.due(datetime(2026, 10, 29, 10, 0)))
        c.state["lastRun"] = {"at": datetime(2026, 10, 29, 10, 0).astimezone().isoformat()}
        c.state["lastRunDay"] = "2026-10-29"
        self.assertFalse(c.due(datetime(2026, 10, 29, 22, 0)))
        self.assertFalse(c.due(datetime(2026, 10, 30, 20, 59)))
        self.assertTrue(c.due(datetime(2026, 10, 30, 21, 0)))
        # Device was off for a full day: clean on first boot even before nine.
        self.assertTrue(c.due(datetime(2026, 10, 31, 9, 0)))

    def test_installer_postpones(self):
        c = self.cleaner()
        c.state["approved"] = True
        with mock.patch.object(temp_cleanup, "running_installers", return_value=["msiexec.exe"]), \
             mock.patch.object(c, "clean") as clean:
            self.assertIsNone(c.tick())
        clean.assert_not_called()
        self.assertTrue(c.state["postponedUntil"])


if __name__ == "__main__":
    unittest.main()
