from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest.mock import patch

from pixelflasher_core.path_compat import is_reserved_path


class ReservedPathCompatibilityTests(unittest.TestCase):
    def test_regular_filename_is_not_reserved(self) -> None:
        self.assertFalse(is_reserved_path(Path("pixel-firmware.img")))

    def test_windows_device_filename_follows_platform_policy(self) -> None:
        self.assertEqual(is_reserved_path(Path("CON.img")), os.name == "nt")

    def test_windows_stream_and_control_names_are_rejected(self) -> None:
        expected = os.name == "nt"
        self.assertEqual(is_reserved_path(Path("image.img:stream")), expected)
        self.assertEqual(is_reserved_path("unsafe\x01.img"), expected)

    def test_python_313_checker_is_used_when_available(self) -> None:
        with patch.object(os.path, "isreserved", return_value=True, create=True) as checker:
            self.assertTrue(is_reserved_path(Path("platform-specific.img")))
        checker.assert_called_once_with(Path("platform-specific.img"))

    def test_compatibility_fallback_matches_windows_reserved_name_boundaries(self) -> None:
        with (
            patch.object(os.path, "isreserved", None, create=True),
            patch("pixelflasher_core.path_compat.os.name", "nt"),
        ):
            self.assertFalse(is_reserved_path(""))
            self.assertTrue(is_reserved_path("factory.img."))
            self.assertTrue(is_reserved_path("factory.img "))
            self.assertTrue(is_reserved_path("factory?.img"))
            self.assertTrue(is_reserved_path("unsafe\x01.img"))
            self.assertTrue(is_reserved_path("nested/CON.img"))
            self.assertTrue(is_reserved_path("COM\u00b9.log"))
            self.assertFalse(is_reserved_path("COM0.img"))

    def test_compatibility_fallback_is_inactive_off_windows(self) -> None:
        with (
            patch.object(os.path, "isreserved", None, create=True),
            patch("pixelflasher_core.path_compat.os.name", "posix"),
        ):
            self.assertFalse(is_reserved_path("CON.img"))


if __name__ == "__main__":
    unittest.main()
