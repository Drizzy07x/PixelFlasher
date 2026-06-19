import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import runtime


class Android17SupportTests(unittest.TestCase):
    def test_android_17_maps_to_api_37(self):
        versions = json.loads(Path("android_versions.json").read_text(encoding="utf-8"))
        runtime.set_android_versions(versions)

        self.assertEqual(37, runtime.get_api_level("17"))
        self.assertEqual("Android 17", versions["37"]["Name"])
        self.assertEqual("CinnamonBun", versions["37"]["Codename"])

    def test_latest_android_version_accepts_relative_a17_links(self):
        versions_html = """
        <html><body>
          <a href="/about/versions/16">Android 16</a>
          <a href="/about/versions/17">Android 17</a>
          <a href="/about/versions/17/get"><span class="devsite-nav-text">Android Beta</span></a>
        </body></html>
        """
        version_page_html = """
        <html><body>
          <a href="/about/versions/17/qpr1/get">QPR1</a>
          <a href="/about/versions/17/qpr1/download">Factory images</a>
        </body></html>
        """

        def fake_request(method, url):
            if url == "https://developer.android.com/about/versions":
                return SimpleNamespace(status_code=200, text=versions_html)
            if url == "https://developer.android.com/about/versions/17":
                return SimpleNamespace(status_code=200, text=version_page_html)
            self.fail(f"unexpected URL: {url}")

        with patch("runtime.request_with_fallback", side_effect=fake_request):
            self.assertEqual(
                (17, "https://developer.android.com/about/versions/17/qpr1"),
                runtime.get_latest_android_version(),
            )

    def test_forced_android_17_version_accepts_relative_links(self):
        versions_html = """
        <html><body>
          <a href="/about/versions/17">Android 17</a>
          <a href="/about/versions/17/get"><span class="devsite-nav-text">Android Beta</span></a>
        </body></html>
        """
        version_page_html = "<html><body></body></html>"

        def fake_request(method, url):
            if url == "https://developer.android.com/about/versions":
                return SimpleNamespace(status_code=200, text=versions_html)
            if url == "https://developer.android.com/about/versions/17":
                return SimpleNamespace(status_code=200, text=version_page_html)
            self.fail(f"unexpected URL: {url}")

        with (
            patch("runtime.request_with_fallback", side_effect=fake_request),
            patch("runtime.resolve_url_redirects", side_effect=lambda url: url),
        ):
            self.assertEqual(
                (17, "https://developer.android.com/about/versions/17/get"),
                runtime.get_latest_android_version(17),
            )

    def test_android_beta_shortcuts_point_to_a17(self):
        source = Path("Main.py").read_text(encoding="utf-8")

        self.assertIn("Full OTA Images for Pixel Beta 17", source)
        self.assertIn("Factory Images for Pixel Beta 17", source)
        self.assertIn("https://developer.android.com/about/versions/17/download-ota", source)
        self.assertIn("https://developer.android.com/about/versions/17/download", source)
        self.assertNotIn("Full OTA Images for Pixel Beta 16", source)
        self.assertNotIn("Factory Images for Pixel Beta 16", source)


if __name__ == "__main__":
    unittest.main()
