import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import mail_images


class ContentHostsTests(unittest.TestCase):
    def test_content_image_is_kept_and_pixel_is_not(self):
        html = (
            '<img src="https://cdn.braze.eu/appboy/logo.png" width="200">'
            '<img src="https://open.example.com/o/abc" width="1" height="1">'
            '<img src="https://pixel.example.net/I0/0100-abc">'
            '<img src="https://track.example.org/banner.png">'
            '<img src="https://discover.amd.com/rs/885/images/banner.jpg?version=0">'
        )
        self.assertEqual(mail_images.content_hosts(html), {"cdn.braze.eu", "discover.amd.com"})

    def test_recorded_host_is_protected(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "hosts.json"
            with mock.patch.object(mail_images, "FILE", target):
                self.assertEqual(mail_images.record({"cdn.braze.eu"}), ["cdn.braze.eu"])
                self.assertEqual(mail_images.record({"cdn.braze.eu"}), [])
                self.assertEqual(mail_images.host_reason("cdn.braze.eu"), mail_images.REASON)
                self.assertEqual(mail_images.host_reason("braze.eu"), "")
                self.assertIn("cdn.braze.eu", json.loads(target.read_text(encoding="utf-8"))["hosts"])


if __name__ == "__main__":
    unittest.main()
