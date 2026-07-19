from __future__ import annotations

import os
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
