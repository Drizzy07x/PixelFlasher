"""The hardware harness must judge host-path leakage, not arbitrary device text.

`scripts/hardware_gate.py` records the session document that the parity matrix
cites as hardware evidence. Its verdict therefore has to depend only on what the
product projected, never on whatever happened to sit in the device log buffer at
the moment the probe ran.
"""

from __future__ import annotations

import unittest

from scripts.hardware_gate import _route_free


class RouteFreeDeviceTextTest(unittest.TestCase):
    """Device-supplied text carries URLs; a URL is not a host path."""

    def test_logcat_url_is_route_free(self) -> None:
        # Verbatim shape of the APN line a real Pixel emits on Google Fi.
        payload = {
            "value": {
                "lines": [
                    "ApnSetting: [ApnSetting] Google Fi - Tm, 6, 310240, ims, , "
                    "http://localhost/mmsc, , null, null, 3, ims, IPV6, IPV4V6, true",
                ]
            }
        }
        self.assertTrue(_route_free(payload))

    def test_https_url_is_route_free(self) -> None:
        payload = {"value": {"lines": ["fetching https://dl.google.com/android/repository"]}}
        self.assertTrue(_route_free(payload))

    def test_android_absolute_path_is_route_free(self) -> None:
        payload = {"value": {"lines": ["opened /data/local/tmp/pf-runner"]}}
        self.assertTrue(_route_free(payload))


class RouteFreeHostPathTest(unittest.TestCase):
    """A genuine host path must still fail the projection closed."""

    def test_windows_drive_path_leaks(self) -> None:
        self.assertFalse(_route_free({"path": "C:\\Users\\someone\\PixelFlasher"}))

    def test_windows_forward_slash_drive_path_leaks(self) -> None:
        self.assertFalse(_route_free({"path": "C:/Users/someone/PixelFlasher"}))

    def test_unc_path_leaks(self) -> None:
        self.assertFalse(_route_free({"path": "\\\\fileserver\\share\\image.img"}))

    def test_posix_home_leaks(self) -> None:
        self.assertFalse(_route_free({"path": "/home/someone/platform-tools"}))

    def test_macos_home_leaks(self) -> None:
        self.assertFalse(_route_free({"path": "/Users/someone/platform-tools"}))

    def test_file_url_to_drive_leaks(self) -> None:
        self.assertFalse(_route_free({"path": "file:///C:/Users/someone/boot.img"}))

    def test_host_path_nested_in_device_text_leaks(self) -> None:
        payload = {
            "value": {
                "lines": [
                    "pushed https://example.test/artifact",
                    "staged at C:\\Users\\someone\\AppData\\Local\\Temp\\stage",
                ]
            }
        }
        self.assertFalse(_route_free(payload))


if __name__ == "__main__":
    unittest.main()
