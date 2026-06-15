import tempfile
import unittest
import zipfile
from pathlib import Path

from ui.pages.platform_tools_setup import (
    PlatformToolsSetupError,
    install_platform_tools,
    platform_tools_binary_names,
    platform_tools_download_url,
    validate_platform_tools_path,
)


class PlatformToolsSetupTests(unittest.TestCase):
    def test_platform_urls_are_official_google_downloads(self):
        for platform in ("win32", "darwin", "linux"):
            with self.subTest(platform=platform):
                url = platform_tools_download_url(platform)
                self.assertTrue(url.startswith("https://dl.google.com/android/repository/platform-tools-latest-"))
                self.assertTrue(url.endswith(".zip"))

    def test_validate_platform_tools_path_requires_adb_and_fastboot(self):
        with tempfile.TemporaryDirectory(prefix="pf-tools-test-") as tmp:
            root = Path(tmp)
            adb_name, fastboot_name = platform_tools_binary_names()
            (root / adb_name).write_text("adb", encoding="utf-8")

            with self.assertRaises(PlatformToolsSetupError):
                validate_platform_tools_path(root)

            (root / fastboot_name).write_text("fastboot", encoding="utf-8")
            result = validate_platform_tools_path(root)

        self.assertTrue(result.adb_path.endswith(adb_name))
        self.assertTrue(result.fastboot_path.endswith(fastboot_name))

    def test_install_platform_tools_from_local_archive(self):
        with tempfile.TemporaryDirectory(prefix="pf-tools-install-") as tmp:
            tmp_root = Path(tmp)
            archive = tmp_root / "platform-tools.zip"
            install_root = tmp_root / "install"
            adb_name, fastboot_name = platform_tools_binary_names()
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(f"platform-tools/{adb_name}", "adb")
                zf.writestr(f"platform-tools/{fastboot_name}", "fastboot")

            result = install_platform_tools(install_root=install_root, download_url=archive.as_uri())

            self.assertEqual(str(install_root / "platform-tools"), result.platform_tools_path)
            self.assertTrue(Path(result.adb_path).is_file())
            self.assertTrue(Path(result.fastboot_path).is_file())

    def test_unsafe_archive_paths_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pf-tools-unsafe-") as tmp:
            tmp_root = Path(tmp)
            archive = tmp_root / "platform-tools.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../outside.txt", "bad")

            with self.assertRaises(PlatformToolsSetupError):
                install_platform_tools(install_root=tmp_root / "install", download_url=archive.as_uri())


if __name__ == "__main__":
    unittest.main()
