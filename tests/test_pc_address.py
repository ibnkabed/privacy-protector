"""The PC address and its change notice."""

import tempfile
import unittest
from pathlib import Path

import pc_address


class Watch(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp()) / "pc-address.json"
        self.address = "192.168.50.10"
        self.sent = []

    def watch(self):
        return pc_address.AddressWatch(self.path, lambda: self.address, self.sent.append)

    def test_first_address_is_stored_without_a_notice(self):
        watch = self.watch()
        self.assertFalse(watch.check())
        self.assertEqual(watch.snapshot()["address"], "192.168.50.10")
        self.assertEqual(self.sent, [])

    def test_change_notifies_once_after_it_settles(self):
        watch = self.watch()
        watch.check()
        self.address = "192.168.50.20"
        results = [watch.check() for _ in range(pc_address.CONFIRM_CHECKS + 2)]
        self.assertEqual(results.count(True), 1)
        self.assertEqual(self.sent, ["192.168.50.20"])
        self.assertEqual(watch.snapshot()["previous"], "192.168.50.10")

    def test_a_blip_is_not_a_change(self):
        watch = self.watch()
        watch.check()
        self.address = "192.168.50.20"
        watch.check()
        self.address = "192.168.50.10"
        watch.check()
        self.address = "192.168.50.20"
        for _ in range(pc_address.CONFIRM_CHECKS - 1):
            watch.check()
        self.assertEqual(self.sent, [])

    def test_no_network_and_vpn_addresses_are_ignored(self):
        watch = self.watch()
        watch.check()
        for address in ("", "127.0.0.1", "169.254.1.1", "100.64.0.9", "8.8.8.8"):
            self.address = address
            for _ in range(pc_address.CONFIRM_CHECKS + 1):
                watch.check()
        self.assertEqual(self.sent, [])

    def test_address_survives_a_restart(self):
        self.watch().check()
        self.address = "192.168.50.20"
        watch = self.watch()
        for _ in range(pc_address.CONFIRM_CHECKS):
            watch.check()
        self.assertEqual(self.sent, ["192.168.50.20"])


if __name__ == "__main__":
    unittest.main()
