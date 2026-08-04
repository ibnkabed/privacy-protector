import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    for _ in range(20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                datagram.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
    raise RuntimeError("Could not reserve a temporary TCP/UDP port")


def request_json(url: str, method: str = "GET") -> dict:
    request = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(request, timeout=2) as response:
        return json.loads(response.read().decode("utf-8"))


class CleanReleaseRuntimeTests(unittest.TestCase):
    def test_first_run_is_empty_healthy_and_writes_only_to_runtime_data(self):
        dns_port = free_port()
        web_port = free_port()
        before = sorted(path.relative_to(ROOT).as_posix() for path in ROOT.rglob("*") if path.is_file())

        with tempfile.TemporaryDirectory(prefix="privacy-protector-runtime-") as runtime:
            env = os.environ.copy()
            env["PRIVACY_PROTECTOR_DATA_DIR"] = runtime
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            env["PYTHONUTF8"] = "1"
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(ROOT / "app.py"),
                    "--dns-host",
                    "127.0.0.1",
                    "--dns-port",
                    str(dns_port),
                    "--web-host",
                    "127.0.0.1",
                    "--web-port",
                    str(web_port),
                    "--upstream-timeout",
                    "0.2",
                ],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            base = f"http://127.0.0.1:{web_port}"
            try:
                deadline = time.time() + 15
                while time.time() < deadline:
                    if process.poll() is not None:
                        stdout, stderr = process.communicate(timeout=2)
                        self.fail(f"Backend exited early: {stdout}\n{stderr}")
                    try:
                        if request_json(base + "/api/health").get("ok"):
                            break
                    except (OSError, urllib.error.URLError):
                        time.sleep(0.1)
                else:
                    self.fail("Backend did not become healthy")

                self.assertEqual(request_json(base + "/api/policy").get("domains"), {})
                apps = request_json(base + "/api/apps")
                self.assertEqual(apps.get("apps"), [])
                self.assertEqual(apps.get("detectedApps"), [])
                self.assertEqual(request_json(base + "/api/privacy-controls").get("apps"), {})
                status = request_json(base + "/api/status")
                self.assertEqual(status.get("dnsPort"), dns_port)
                self.assertTrue(status.get("ok"))
                self.assertTrue(request_json(base + "/api/dns/cache", "DELETE").get("ok"))

                runtime_root = Path(runtime).resolve()
                generated = [path.resolve() for path in runtime_root.rglob("*") if path.is_file()]
                self.assertTrue(generated)
                self.assertTrue(all(runtime_root in path.parents for path in generated))
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                process.communicate(timeout=2)

        after = sorted(path.relative_to(ROOT).as_posix() for path in ROOT.rglob("*") if path.is_file())
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
