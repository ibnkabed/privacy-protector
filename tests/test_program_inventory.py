import json
import tempfile
import unittest
from pathlib import Path

from app import AppProfileStore
from pc_protection import PCProtection
from program_inventory import ProgramInventory


class _Policy:
    def action_for(self, _domain):
        return ""


def _inventory(folder: Path, names, at="2026-10-28T12:00:00+03:00") -> ProgramInventory:
    (folder / "installed-programs.json").write_text(json.dumps({"scan": {
        "scannedAt": at, "complete": True, "names": names, "packages": ["microsoft.windows.photos"], "processes": []}}),
        encoding="utf-8")
    return ProgramInventory(folder)


class ProgramInventoryTests(unittest.TestCase):
    def test_present_needs_full_scan_and_spares_newer_programs(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = ProgramInventory(Path(tmp))
            self.assertTrue(empty.present("gone.exe"))
            inv = _inventory(Path(tmp), ["chrome.exe"])
            self.assertTrue(inv.present("Chrome.exe"))
            self.assertTrue(inv.present("Microsoft.Windows.Photos"))
            self.assertFalse(inv.present("gone.exe", "", inv.scanned_at - 10))
            self.assertTrue(inv.present("new.exe", "", inv.scanned_at + 10))
            # Install folder is gone entirely: do not consider the same name
            # present in another program
            self.assertFalse(inv.present("chrome.exe", r"C:\Program Files\NoSuchVendor\chrome.exe", inv.scanned_at - 10))
            self.assertTrue(inv.present("chrome.exe", r"C:\Program Files\NoSuchVendor\chrome.exe", inv.scanned_at - 10, by_name=True))
            # Update to a new version folder: old path is gone but install
            # folder remains
            self.assertTrue(inv.present("chrome.exe", str(Path(tmp) / "app-1.0" / "chrome.exe"), inv.scanned_at - 10))
            self.assertTrue(inv.present("Photos.exe", r"C:\Program Files\WindowsApps\Microsoft.Windows.Photos_1.0_x64__8w\Photos.exe", 1))
            self.assertTrue(inv.present("x.exe", __file__, inv.scanned_at - 10))

    def test_prune_removes_only_missing_programs(self):
        with tempfile.TemporaryDirectory() as tmp:
            inv = _inventory(Path(tmp), ["chrome.exe"])
            pc = PCProtection(Path(tmp), _Policy())
            old = "2026-10-01T10:00:00+03:00"
            pc.domains = {"a.com": {"processes": {"chrome.exe": {"lastSeen": old}, "gone.exe": {"lastSeen": old}}}}
            self.assertEqual(inv.apply_pc(pc), ["gone.exe"])
            self.assertEqual(list(pc.domains["a.com"]["processes"]), ["chrome.exe"])
            self.assertIn("gone.exe", inv.removed["pc"])

    def test_phone_sync_drops_uninstalled_but_keeps_apple_apps(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AppProfileStore(Path(tmp) / "apps.json")
            store.merge_detected([{"bundleID": "com.old.app", "name": "Old"}, {"bundleID": "com.apple.mobilesafari"},
                                  {"bundleID": "com.keep.app", "name": "Keep", "domains": ["k.com"]}])
            gone = store.sync_detected([{"bundleID": "com.keep.app", "name": "Keep"}, {"bundleID": "com.new.app", "name": "New"}])
            self.assertEqual([g["bundleID"] for g in gone], ["com.old.app"])
            ids = {a["bundleID"]: a for a in store.snapshot()["detectedApps"]}
            self.assertEqual(set(ids), {"com.keep.app", "com.new.app", "com.apple.mobilesafari"})
            self.assertEqual(ids["com.keep.app"]["domains"], ["k.com"])
            self.assertEqual(store.sync_detected([]), [])

    def test_report_cannot_bring_back_removed_app_but_reinstall_clears_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AppProfileStore(Path(tmp) / "apps.json")
            inv = ProgramInventory(Path(tmp))
            store.merge_detected([{"bundleID": "com.old.app"}, {"bundleID": "com.keep.app"}])
            inv.sync_phone(lambda: {"ok": True, "apps": [{"bundleID": "com.keep.app"}], "count": 1}, store)
            store.merge_detected([{"bundleID": "com.old.app"}, {"bundleID": "com.brand.new"}])
            store.prune_detected(inv.removed_phone_ids())
            self.assertEqual({a["bundleID"] for a in store.snapshot()["detectedApps"]}, {"com.keep.app", "com.brand.new"})
            inv.sync_phone(lambda: {"ok": True, "apps": [{"bundleID": "com.old.app"}], "count": 1}, store)
            self.assertEqual(inv.removed_phone_ids(), {"com.keep.app", "com.brand.new"})


if __name__ == "__main__":
    unittest.main()
