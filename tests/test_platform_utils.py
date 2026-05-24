import os
import tempfile
import unittest
from pathlib import Path

import platform_utils


class PlatformUtilsTests(unittest.TestCase):
    def test_current_platform_is_serializable(self):
        info = platform_utils.current_platform().to_dict()
        self.assertIn("system", info)
        self.assertIn("python", info)

    def test_executable_name_adds_exe_only_on_windows(self):
        name = platform_utils.executable_name("adb")
        if platform_utils.is_windows():
            self.assertEqual(name, "adb.exe")
        else:
            self.assertEqual(name, "adb")

    def test_ensure_directory_creates_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "nested" / "dir"
            created = platform_utils.ensure_directory(target)
            self.assertTrue(created.is_dir())

    def test_open_path_dry_run_is_safe(self):
        command = platform_utils.open_path(Path.cwd(), dry_run=True)
        self.assertTrue(command)
        self.assertIsInstance(command[0], str)

    def test_path_for_display_compacts_home(self):
        displayed = platform_utils.path_for_display(Path.home() / "PixelFlasher-test")
        self.assertTrue(displayed.startswith("~") or os.name == "nt")


if __name__ == "__main__":
    unittest.main()
