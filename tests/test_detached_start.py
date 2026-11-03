import unittest
from unittest import mock

import detached_start


class DetachedStartTests(unittest.TestCase):
    """The engine knows it belongs to an agent session via its parent chain, and does not mistake others."""

    TABLE = {
        10: (9, "pythonw.exe"), 9: (8, "pwsh.exe"), 8: (7, "cmd.exe"), 7: (6, "claude.exe"),
        6: (5, "Claude.exe"), 5: (1, "explorer.exe"),
        20: (21, "pythonw.exe"), 21: (5, "WmiPrvSE.exe"),
    }

    def test_agent_found_up_the_chain(self) -> None:
        with mock.patch.object(detached_start, "_processes", return_value=self.TABLE):
            self.assertEqual(detached_start.agent_ancestor(10), "claude.exe")

    def test_wmi_child_is_not_under_agent(self) -> None:
        with mock.patch.object(detached_start, "_processes", return_value=self.TABLE):
            self.assertEqual(detached_start.agent_ancestor(20), "")

    def test_quote_doubles_single_quotes(self) -> None:
        self.assertEqual(detached_start._quote("a'b"), "'a''b'")


if __name__ == "__main__":
    unittest.main()
