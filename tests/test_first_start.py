import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class FirstStartTests(unittest.TestCase):
    def test_engine_starts_when_the_data_folder_does_not_exist(self):
        with tempfile.TemporaryDirectory() as folder:
            data = Path(folder) / "not" / "made" / "yet"
            port = free_port()
            env = {**os.environ, "PRIVACY_PROTECTOR_DATA_DIR": str(data), "PYTHONUTF8": "1"}
            engine = subprocess.Popen([sys.executable, str(ROOT / "app.py"), "--attached", "--no-tray", "--dns-port", str(free_port()),
                                       "--web-port", str(port)], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                answer = None
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline and engine.poll() is None and answer is None:
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2) as reply:
                            answer = json.loads(reply.read().decode("utf-8"))
                    except OSError:
                        time.sleep(0.3)
                self.assertEqual(answer, {"ok": True})
            finally:
                engine.kill()
                engine.wait(10)


if __name__ == "__main__":
    unittest.main()
