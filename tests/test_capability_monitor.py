"""Permission Monitor: verdicts for reference cases, sequential log, and resumption with deduplication.

All data here is synthetic in temporary directories; nothing is written to the real data/ folder.
"""

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import capability_judge  # noqa: E402
import capability_monitor as cm  # noqa: E402
import user_exceptions  # noqa: E402

# Live user decisions do not enter the test: reference cases measure rules alone.
capability_judge.USER_DECISIONS_PATH = Path(tempfile.gettempdir()) / "no-user-decisions.json"
TRUSTED = {"hosts": {}, "apps": [], "programs": [
    r"C:\Users\Example\Documents\Projects", r"C:\Users\Example\AppData\Local\Programs\Calendar"]}
NOTHING_TRUSTED = {"hosts": {}, "apps": [], "programs": []}

FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "capability_reference_2026-10-09.json"
EPOCH_TO_FILETIME = 11644473600


def ft(epoch: float) -> int:
    return int((epoch + EPOCH_TO_FILETIME) * 10_000_000) if epoch else 0


class Clock:
    def __init__(self, now: float):
        self.now = now

    def __call__(self) -> float:
        return self.now


def make_history(directory: Path, nonpackaged=(), packaged=()) -> Path:
    """Database with the structure we read from Windows 26300, with synthetic rows."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / cm.HISTORY_DB
    if path.exists():
        path.unlink()
    db = sqlite3.connect(str(path))
    db.executescript(
        """
        CREATE TABLE NonPackagedUsageHistory(ID INTEGER PRIMARY KEY NOT NULL,LastUsedTimeStart INTEGER NOT NULL,LastUsedTimeStop INTEGER NOT NULL,AccessBlocked INTEGER NOT NULL,Capability INTEGER NOT NULL,FileID INTEGER NOT NULL,ProgramID INTEGER NOT NULL,BinaryFullPath INTEGER NOT NULL,UserSid INTEGER NOT NULL,AppName INTEGER NOT NULL,ServiceName INTEGER NOT NULL DEFAULT '0',AccessGUID INTEGER NOT NULL,Label INTEGER NOT NULL, Context INTEGER DEFAULT '0');
        CREATE TABLE PackagedUsageHistory(ID INTEGER PRIMARY KEY NOT NULL,LastUsedTimeStart INTEGER NOT NULL,LastUsedTimeStop INTEGER NOT NULL,AccessBlocked INTEGER NOT NULL,Capability INTEGER NOT NULL,PackageFamilyName INTEGER NOT NULL,UserSid INTEGER NOT NULL,AccessGUID INTEGER NOT NULL,Label INTEGER NOT NULL,AppName INTEGER NOT NULL, Context INTEGER DEFAULT '0');
        CREATE TABLE Capabilities(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT NOT NULL);
        CREATE TABLE BinaryFullPaths(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT NOT NULL);
        CREATE TABLE PackageFamilyNames(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT NOT NULL);
        CREATE TABLE AppNames(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT NOT NULL);
        CREATE TABLE ServiceNames(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT NOT NULL);
        INSERT INTO Capabilities VALUES (1,'location'),(4,'microphone'),(6,'webcam');
        INSERT INTO BinaryFullPaths VALUES (2,'C:\\Program Files\\Norton\\Suite\\VpnSvc.exe'),(3,'C:\\Users\\Example\\AppData\\Local\\Programs\\Python\\Python312\\pythonw.exe');
        INSERT INTO PackageFamilyNames VALUES (10,'Claude_pzs8sxrjxfjjc');
        INSERT INTO AppNames VALUES (1,'Norton VPN Service'),(2,'Python'),(3,'Claude');
        """
    )
    for row in nonpackaged:
        row_id, start, stop, cap, path_id, blocked = row
        db.execute("INSERT INTO NonPackagedUsageHistory VALUES (?,?,?,?,?,0,0,?,1,1,0,0,0,0)",
                   (row_id, ft(start), ft(stop), blocked, cap, path_id))
    for row in packaged:
        row_id, start, stop, cap, family_id, blocked = row
        db.execute("INSERT INTO PackagedUsageHistory VALUES (?,?,?,?,?,?,1,0,0,3,0)",
                   (row_id, ft(start), ft(stop), blocked, cap, family_id))
    db.commit()
    db.close()
    return path


def no_identities(paths, packages):
    return {}


class ReferenceCasesTests(unittest.TestCase):
    """The 26 cases: no errors in the determined, and what the study saw as monitoring does not turn into allow."""

    def test_study_cases_have_no_decided_errors(self):
        cases = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]
        self.assertEqual(len(cases), 26)
        for case in cases:
            with self.subTest(n=case["n"]):
                verdict = capability_judge.judge(case["capability"], case["identity"])["verdict"]
                if case["study"] == "monitor":
                    self.assertIn(verdict, {"monitor", "undetermined"})
                else:
                    self.assertEqual(verdict, case["study"])

    def test_counts_match_the_study(self):
        cases = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]
        verdicts = [capability_judge.judge(c["capability"], c["identity"])["verdict"] for c in cases]
        self.assertEqual(verdicts.count("allow"), 13)
        self.assertEqual(verdicts.count("deny"), 4)
        self.assertEqual(verdicts.count("monitor") + verdicts.count("undetermined"), 9)
class NewCasesTests(unittest.TestCase):
    def test_same_name_two_paths_get_different_identities(self):
        ianygo = capability_judge.judge("location", {"name": "QtWebEngineProcess.exe", "path": r"C:\Program Files (x86)\Tenorshare iAnyGo\QtWebEngineProcess.exe"})
        plex = capability_judge.judge("location", {"name": "QtWebEngineProcess.exe", "path": r"C:\Program Files\Plex\Plex\QtWebEngineProcess.exe"})
        self.assertEqual(ianygo["verdict"], "monitor")
        self.assertEqual(plex["verdict"], "deny")
        self.assertEqual(cm.identity_key({"path": r"C:\A\x.exe"}) == cm.identity_key({"path": r"C:\B\x.exe"}), False)

    @mock.patch.object(user_exceptions, "load", return_value=TRUSTED)
    def test_unknown_script_is_monitored_and_trusted_script_is_known(self, _load):
        # Executor with unknown script is monitored as shared system host, not left "undetermined".
        unknown = capability_judge.judge("microphone", {"name": "pythonw.exe"})
        self.assertEqual(unknown["verdict"], "monitor")
        self.assertIn("next", unknown["cause"])
        owner = capability_judge.judge("microphone", {
            "name": "pythonw.exe",
            "script": r"C:\Users\Example\Documents\Projects\voice\voice_capture.py"})
        self.assertEqual(owner["verdict"], "allow")
        self.assertEqual(owner["cause"]["state"], "established")
        foreign = capability_judge.judge("microphone", {"name": "python.exe", "script": r"C:\Temp\x.py"})
        self.assertEqual(foreign["verdict"], "monitor")

    def test_browser_site_stays_unknown(self):
        result = capability_judge.judge("webcam", {"name": "chrome.exe", "path": r"C:\Program Files\Google\Chrome\Application\chrome.exe"})
        self.assertEqual(result["verdict"], "allow")
        self.assertEqual(result["cause"]["state"], "undetermined")
        self.assertIn("unknown", result["cause"]["text"])

    def test_missing_program_is_not_given_todays_identity(self):
        result = capability_judge.judge("microphone", {"name": "Devin.exe", "fileState": "missing"})
        self.assertEqual(result["cause"]["state"], "undetermined")
        self.assertTrue(any("no longer exists" in note for note in result["notes"]))

    def test_unknown_program_is_never_allowed(self):
        result = capability_judge.judge("contacts", {"name": "random-tool.exe", "path": r"C:\Tools\random-tool.exe"})
        self.assertEqual(result["verdict"], "undetermined")
        result = capability_judge.judge("webcam", {"name": "svchost.exe"})
        self.assertNotEqual(result["verdict"], "allow")

    @mock.patch.object(user_exceptions, "load", return_value=TRUSTED)
    def test_trusted_programs_are_allowed_by_path_not_name(self, _load):
        for path in (r"C:\Users\Example\Documents\Projects\Notes\Notes.exe",
                     r"C:\Users\Example\AppData\Local\Programs\Calendar\Calendar.exe"):
            with self.subTest(path=path):
                result = capability_judge.judge("microphone", {"name": path.rsplit("\\", 1)[-1], "path": path})
                self.assertEqual(result["rule"], "trusted-program")
                self.assertEqual(result["verdict"], "allow")
        result = capability_judge.judge("microphone", {"name": "Notes.exe", "path": r"C:\Tools\Notes.exe"})
        self.assertNotEqual(result["verdict"], "allow")

    def test_identity_change_is_shown_not_revoked(self):
        result = capability_judge.judge("microphone", {"package": "Claude_pzs8sxrjxfjjc", "identityChanged": True})
        self.assertEqual(result["verdict"], "allow")
        self.assertTrue(any("changed" in note for note in result["notes"]))

    def test_invalid_signature_downgrades_allow(self):
        result = capability_judge.judge("microphone", {"name": "chrome.exe", "signature": "invalid"})
        self.assertEqual(result["verdict"], "monitor")


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.clock = Clock(1_800_000_000.0)

    def tearDown(self):
        self.tmp.cleanup()

    def monitor(self, registry=None, process=None, alive=None):
        return cm.CapabilityMonitor(
            self.root / "data" / "pc", history_dir=self.root / "history", work_dir=self.root / "work",
            registry_reader=registry or (lambda: ([], {})), identity_resolver=no_identities,
            process_resolver=process or (lambda pid: {}), process_alive=alive or (lambda pid, start: False),
            clock=self.clock,
        )

    def lines(self):
        path = self.root / "data" / "pc" / "capability-events.ndjson"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def test_history_rows_merge_into_series_and_are_not_repeated(self):
        t = self.clock.now - 7200
        rows = [(i + 1, t + i * 10, t + i * 10 + 5, 1, 2, 0) for i in range(100)]  # Norton every 10 seconds
        rows.append((200, t + 5000, t + 5005, 1, 2, 0))  # after a gap longer than half an hour
        make_history(self.root / "history", nonpackaged=rows)
        monitor = self.monitor()
        self.assertEqual(monitor.poll_history(), 101)
        monitor.status["windows-history"]["lastCopyAt"] = self.clock.now
        monitor.sweep()
        series = [r for r in self.lines() if r["type"] == "series"]
        self.assertEqual(len(series), 1)
        self.assertEqual(series[0]["count"], 100)
        self.assertEqual(series[0]["activeSeconds"], 500.0)
        # Second read of the same copy or a newer copy with no new rows: no repetition.
        monitor.state["historyCopyIngested"] = 0
        self.assertEqual(monitor.poll_history(), 0)
        self.assertEqual(sum(1 for r in self.lines() if r["type"] == "series"), 1)

    def test_restart_resumes_from_cursor_and_open_series(self):
        t = self.clock.now - 600
        make_history(self.root / "history", nonpackaged=[(1, t, t + 5, 1, 2, 0)])
        first = self.monitor()
        first.poll_history()
        first.save()
        make_history(self.root / "history", nonpackaged=[(1, t, t + 5, 1, 2, 0), (2, t + 60, t + 65, 1, 2, 0)])
        second = self.monitor()
        second.state["historyCopyIngested"] = 0
        self.assertEqual(second.poll_history(), 1)
        open_series = list(second.state["open"].values())
        self.assertEqual(len(open_series), 1)
        self.assertEqual(open_series[0]["count"], 2)

    def test_in_use_row_gets_its_end_later(self):
        t = self.clock.now - 300
        make_history(self.root / "history", packaged=[(1, t, 0, 4, 10, 0)])
        monitor = self.monitor()
        monitor.poll_history()
        series = next(iter(monitor.state["open"].values()))
        self.assertTrue(series["inUse"])
        make_history(self.root / "history", packaged=[(1, t, t + 40, 4, 10, 0)])
        monitor.state["historyCopyIngested"] = 0
        monitor.poll_history()
        series = next(iter(monitor.state["open"].values()))
        self.assertFalse(series["inUse"])
        self.assertEqual(series["count"], 1)
        self.assertEqual(series["activeSeconds"], 40.0)

    def test_blocked_attempts_verify_a_permission_change(self):
        t = self.clock.now - 300
        make_history(self.root / "history", nonpackaged=[(1, t, t + 5, 1, 2, 1)])
        monitor = self.monitor()
        key = "location|path:" + r"C:\Program Files\Norton\Suite\VpnSvc.exe".lower()
        monitor.permissions["current"][key] = {"state": "setting-changed", "changedAt": t - 10}
        monitor.poll_history()
        monitor.verify_permissions()
        self.assertEqual(monitor.permissions["current"][key]["state"], "verified-blocked")

    def test_permission_change_without_effect_is_reported(self):
        t = self.clock.now - 300
        make_history(self.root / "history", nonpackaged=[(1, t, t + 5, 1, 2, 0)])
        monitor = self.monitor()
        key = "location|path:" + r"C:\Program Files\Norton\Suite\VpnSvc.exe".lower()
        monitor.permissions["current"][key] = {"state": "setting-changed", "changedAt": t - 10}
        monitor.poll_history()
        monitor.verify_permissions()
        self.assertEqual(monitor.permissions["current"][key]["state"], "not-effective")
        # Not established for desktop app: no block button for desktop apps afterwards, remains for Store apps.
        desktop = monitor.permission_state("location", {"path": r"C:\Other	ool.exe", "name": "tool.exe"})
        self.assertFalse(desktop["writable"])
        self.assertIn("does not block a specific desktop app", desktop["note"])
        if cm.IS_WINDOWS:
            packaged = monitor.permission_state("microphone", {"package": "Claude_x"})
            self.assertTrue(packaged["writable"])

    @mock.patch.object(user_exceptions, "load", return_value=TRUSTED)
    def test_live_sessions_keep_script_and_spans(self, _load):
        def process(pid):
            return {"pid": pid, "name": "pythonw.exe", "path": r"C:\Python\pythonw.exe", "processStart": 1.0,
                    "script": r"C:\Users\Example\Documents\Projects\x\voice.py", "commandLine": "pythonw voice.py"}

        monitor = self.monitor(process=process)
        monitor.poll_live([{"pid": 50, "state": 1}])
        self.clock.now += 20
        monitor.poll_live([{"pid": 50, "state": 0}])
        self.clock.now += 5
        monitor.poll_live([])  # process ended
        series = [r for r in self.lines() if r["type"] == "series"]
        self.assertEqual(len(series), 1)
        self.assertEqual(series[0]["count"], 1)
        self.assertEqual(series[0]["activeSeconds"], 20.0)
        self.assertEqual(series[0]["identity"]["script"], r"C:\Users\Example\Documents\Projects\x\voice.py")
        group = monitor.groups()[0]
        self.assertEqual(group["verdict"]["verdict"], "allow")

    def test_session_released_and_reopened_stays_one_series(self):
        alive = {"value": True}
        monitor = self.monitor(process=lambda pid: {"pid": pid, "name": "Claude.exe", "path": r"C:\c\Claude.exe", "processStart": 5.0},
                               alive=lambda pid, start: alive["value"])
        monitor.poll_live([{"pid": 3, "state": 1}])
        self.clock.now += 10
        monitor.poll_live([])  # app released session and process is alive
        self.clock.now += 60
        monitor.poll_live([{"pid": 3, "state": 1}])
        self.clock.now += 5
        monitor.poll_live([{"pid": 3, "state": 0}])
        self.assertEqual(self.lines(), [])
        series = next(iter(monitor.state["open"].values()))
        self.assertEqual(series["count"], 2)
        self.assertEqual(series["activeSeconds"], 15.0)
        view = monitor.groups()[0]["recent"][0]
        self.assertTrue(view["open"])
        alive["value"] = False
        self.clock.now += 5
        monitor.poll_live([])
        self.assertEqual(len(self.lines()), 1)
        self.assertFalse(monitor.groups()[0]["recent"][0]["open"])

    def test_downtime_is_a_gap_and_open_live_session_is_closed_honestly(self):
        monitor = self.monitor(process=lambda pid: {"pid": pid, "name": "x.exe", "path": r"C:\x.exe"})
        monitor.poll_live([{"pid": 7, "state": 1}])
        monitor.save()
        self.clock.now += 3600
        restarted = self.monitor()
        restarted.start_live_gap()
        records = self.lines()
        self.assertEqual([r["type"] for r in records], ["series", "gap"])
        self.assertIn("end is unknown", records[0]["extra"]["endedBy"])
        self.assertEqual(records[1]["source"], "live-audio")

    def test_registry_baseline_is_imported_once(self):
        start = ft(self.clock.now - 86400 * 20)
        rows = [{"hive": "HKCU", "capability": "microphone", "appKey": "C:#x#a.exe",
                 "identity": {"path": r"C:\x\a.exe", "name": "a.exe"}, "start": start, "stop": start, "permission": "Deny"}]
        monitor = self.monitor(registry=lambda: (rows, {"microphone": {"HKCU": "Allow"}}))
        self.assertEqual(monitor.poll_registry(), 1)
        self.assertEqual(monitor.poll_registry(), 0)
        group = monitor.groups()[0]
        self.assertEqual(group["permission"]["value"], "Deny")
        self.assertEqual(group["permission"]["global"], "Allow")

    def test_status_reports_blindness_instead_of_quiet(self):
        start = ft(self.clock.now - 86400 * 17)
        rows = [{"hive": "HKCU", "capability": "location", "appKey": "k", "identity": {"path": r"C:\a.exe", "name": "a.exe"},
                 "start": start, "stop": start, "permission": ""}]
        monitor = self.monitor(registry=lambda: (rows, {}))
        monitor.poll_registry()
        status = monitor.source_status()
        self.assertFalse(status["healthy"])
        self.assertFalse(status["coverage"]["webcam"]["covered"])
        registry = next(s for s in status["sources"] if s["id"] == "registry-last-use")
        self.assertEqual(registry["state"], "stale")
        self.assertEqual(monitor.snapshot()["quiet"], [])

    def test_network_link_uses_same_process_and_time(self):
        monitor = self.monitor(process=lambda pid: {"pid": pid, "name": "app.exe", "path": r"C:\app.exe"})
        monitor.poll_live([{"pid": 9, "state": 1}])
        monitor.observe_attribution(9, {"path": r"C:\app.exe"}, "api.example.com")
        monitor.observe_attribution(10, {"path": r"C:\other.exe"}, "other.example.com")
        self.clock.now += 10
        monitor.poll_live([])
        series = [r for r in self.lines() if r["type"] == "series"][0]
        self.assertEqual(series["link"]["strength"], "pid")
        self.assertEqual([d["domain"] for d in series["link"]["domains"]], ["api.example.com"])

    def test_shared_host_is_not_linked(self):
        monitor = self.monitor()
        link = monitor.network_link({"identity": {"name": "svchost.exe"}, "firstStart": self.clock.now})
        self.assertEqual(link["state"], "not-attributable")

    def test_torn_line_does_not_break_loading(self):
        path = self.root / "data" / "pc" / "capability-events.ndjson"
        path.parent.mkdir(parents=True)
        path.write_text('{"type": "gap", "source": "live-audio", "from": 1, "to": 2, "reason": "x"}\n{"type": "ser', encoding="utf-8")
        monitor = self.monitor()
        self.assertEqual(len(monitor.closed), 1)
class HelpersTests(unittest.TestCase):
    def test_package_family_from_path(self):
        path = r"C:\Program Files\WindowsApps\Claude_2.31226.1.0_x64__pzs8sxrjxfjjc\app\Claude.exe"
        self.assertEqual(cm.package_family_from_path(path), "Claude_pzs8sxrjxfjjc")

    def test_script_from_command(self):
        self.assertEqual(cm.script_from_command(r'"C:\Py\pythonw.exe" "C:\A B\voice.py" --x'), r"C:\A B\voice.py")
        self.assertEqual(cm.script_from_command(r"python -m http.server"), "-m http.server")

    def test_permission_key(self):
        self.assertTrue(cm.permission_key_for("location", {"path": r"C:\a\b.exe"}).endswith(r"location\NonPackaged\C:#a#b.exe"))
        self.assertTrue(cm.permission_key_for("microphone", {"package": "Claude_x"}).endswith(r"microphone\Claude_x"))


if __name__ == "__main__":
    unittest.main()


class UserDecisionTests(unittest.TestCase):
    def test_user_decision_covers_every_version_in_the_folder(self):
        # User decision 2026-10-30: EA stays monitored, covering all its versions in the folder.
        import json as _json
        import tempfile as _tempfile
        from pathlib import Path as _Path

        with _tempfile.TemporaryDirectory() as folder:
            target = _Path(folder) / "decisions.json"
            target.write_text(_json.dumps({"decisions": [{
                "capability": "location", "folder": r"C:\Program Files\Electronic Arts\EA Desktop",
                "verdict": "monitor", "at": "2026-10-30", "reason": "monitored"}]}), encoding="utf-8")
            original = capability_judge.USER_DECISIONS_PATH
            capability_judge.USER_DECISIONS_PATH = target
            try:
                ea = {"name": "EACefSubProcess.exe",
                      "path": r"C:\Program Files\Electronic Arts\EA Desktop\13.743.3.6251\EA Desktop\EACefSubProcess.exe"}
                result = capability_judge.judge("location", ea)
                self.assertEqual((result["verdict"], result["rule"], result["ruleVerdict"]), ("monitor", "user-decision", "deny"))
                self.assertNotEqual(capability_judge.judge("microphone", ea)["rule"], "user-decision")
            finally:
                capability_judge.USER_DECISIONS_PATH = original
