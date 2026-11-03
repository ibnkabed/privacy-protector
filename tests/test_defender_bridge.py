import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import defender_bridge
from defender_bridge import DefenderBridge, assess

NOW = time.time()
FRESH = defender_bridge.datetime.fromtimestamp(NOW - 3600).astimezone().isoformat()
OLD = defender_bridge.datetime.fromtimestamp(NOW - 5 * 86400).astimezone().isoformat()
LAUNCHER = r"C:\Program Files\Calendaral\Calendaral.exe"


def _healthy(**status):
    return {"status": {"mode": "Normal", "antivirus": True, "realtime": True, "tamper": True, "signatures": FRESH, **status},
            "threats": [], "blocked": [], "antivirus": ["Windows Defender"], "launchers": [LAUNCHER]}


class AssessTests(unittest.TestCase):
    def titles(self, snapshot, sac=0, excluded=frozenset({LAUNCHER.lower()})):
        return {i["title"]: i["level"] for i in assess(snapshot, sac, set(excluded), NOW)}

    def test_healthy_has_nothing(self):
        self.assertEqual(self.titles(_healthy()), {})

    def test_defender_off_or_realtime_off_is_red(self):
        self.assertEqual(self.titles(_healthy(mode="Passive"))["Defender isn't running"], "red")
        self.assertEqual(self.titles(_healthy(realtime=False))["Real-time protection is off"], "red")

    def test_another_antivirus_is_red(self):
        snap = _healthy()
        snap["antivirus"] = ["Windows Defender", "Norton 360"]
        self.assertEqual(self.titles(snap)["Another antivirus took over"], "red")

    def test_old_signatures_and_tamper_off_are_yellow(self):
        got = self.titles(_healthy(signatures=OLD, tamper=False))
        self.assertEqual(got["Signatures are old"], "yellow")
        self.assertEqual(got["Tamper Protection is off"], "yellow")

    def test_unhandled_threat_is_red_and_handled_is_quiet(self):
        snap = _healthy()
        snap["threats"] = [{"id": "1", "name": "Virus:DOS/EICAR_Test_File", "actionOk": True}]
        self.assertEqual(self.titles(snap), {})
        snap["threats"].append({"id": "2", "name": "Trojan:X", "actionOk": False})
        self.assertEqual(self.titles(snap)["A threat wasn't removed"], "red")

    def test_smart_app_control_blocking_owner_launcher_is_red(self):
        snap = _healthy()
        snap["blocked"] = [{"path": r"\Device\HarddiskVolume3\Program Files\Gustal\Gustal.exe", "at": FRESH}]
        self.assertEqual(self.titles(snap, sac=1)["Smart App Control is on"], "red")
        self.assertEqual(self.titles(_healthy(), sac=1)["Smart App Control is on"], "yellow")
        # After turning it off: a block from an hour ago is ignored, but one
        # from minutes ago is reported.
        self.assertEqual(self.titles(snap, sac=0), {})
        recent = defender_bridge.datetime.fromtimestamp(NOW - 300).astimezone().isoformat()
        snap["blocked"] = [{"path": r"\Device\HarddiskVolume3\Program Files\Gustal\Gustal.exe", "at": recent}]
        self.assertEqual(self.titles(snap, sac=0)["Windows blocked a user launcher"], "red")

    def test_new_launcher_gets_the_exclusion_command(self):
        snap = _healthy()
        snap["launchers"].append(r"C:\Program Files\New App\NewApp.exe")
        issue = next(i for i in assess(snap, 0, {LAUNCHER.lower()}, NOW) if i["title"] == "New app not excluded from scanning")
        self.assertIn("Exclude-Launchers.ps1", issue["command"])
        # Without the config file, exclusions are unknown, so nothing is
        # reported as missing.
        self.assertEqual(self.titles(snap, excluded=frozenset()), {})

    def test_launcher_marked_by_its_installer_counts_as_excluded(self):
        # The config snapshot doesn't refresh, so a launcher excluded by its
        # installer and leaving defender-exclusion.json remains uncolored
        # (PdfCraft, 2026-10-31).
        with tempfile.TemporaryDirectory() as tmp:
            snap = _healthy()
            snap["launchers"].append(str(Path(tmp) / "NewApp.exe"))
            self.assertIn("New app not excluded from scanning", self.titles(snap))
            (Path(tmp) / "defender-exclusion.json").write_text("{}", encoding="utf-8")
            self.assertNotIn("New app not excluded from scanning", self.titles(snap))


class BridgeTests(unittest.TestCase):
    def test_refresh_logs_each_detection_once_and_keeps_the_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = DefenderBridge(Path(tmp))
            snap = _healthy()
            snap["threats"] = {"id": "a1", "name": "Virus:DOS/EICAR_Test_File", "actionOk": True}
            with mock.patch.object(defender_bridge, "_powershell", return_value=json.loads(json.dumps(snap))):
                self.assertTrue(bridge.refresh())
                self.assertTrue(bridge.refresh())
            lines = (Path(tmp) / "defender-events.ndjson").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["kind"], "detection")
            self.assertEqual(DefenderBridge(Path(tmp)).seen_threats, {"a1"})

    def test_downloads_scanned_once_after_settling(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "dl"
            folder.mkdir()
            setup = folder / "setup.exe"
            setup.write_bytes(b"MZ")
            (folder / "notes.txt").write_text("x", encoding="utf-8")
            old = NOW - 120
            os.utime(setup, (old, old))
            bridge = DefenderBridge(Path(tmp))
            with mock.patch.object(bridge, "scan_file", side_effect=lambda p, r: {"path": str(p)}) as scan:
                self.assertEqual(len(bridge.check_downloads(folder)), 1)
                self.assertEqual(bridge.check_downloads(folder), [])
                fresh = folder / "busy.msi"
                fresh.write_bytes(b"x")   # still downloading: not scanned yet
                self.assertEqual(bridge.check_downloads(folder), [])
            self.assertEqual(scan.call_count, 1)

    def test_scan_reads_defender_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "a.zip"
            target.write_bytes(b"x")
            bridge = DefenderBridge(Path(tmp))
            for code, verdict in ((0, "clean"), (2, "threat"), (5, "error")):
                done = mock.Mock(returncode=code, stdout=b"", stderr=b"")
                with mock.patch.object(defender_bridge, "_run", return_value=done):
                    self.assertEqual(bridge.scan_file(target, "test")["verdict"], verdict)

    def test_excluded_processes_reads_setup_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            snap = Path(tmp) / "after.json"
            snap.write_text("\ufeff" + json.dumps({"pref": {"ExclusionProcess": [LAUNCHER]}}), encoding="utf-8")
            self.assertEqual(defender_bridge.excluded_processes(snap), {LAUNCHER.lower()})
            self.assertEqual(defender_bridge.excluded_processes(Path(tmp) / "missing.json"), set())
if __name__ == "__main__":
    unittest.main()
