import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PrivateDataScanTests(unittest.TestCase):
    def test_tracked_files_and_new_commits_hold_no_personal_data(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "check_private_data.py")],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
