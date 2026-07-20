import json
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.release_version import ReleaseVersion, apply_version, check_version

ROOT = Path(__file__).resolve().parents[1]


class ReleaseVersionTests(unittest.TestCase):
    def fixture(self, directory):
        target = Path(directory)
        (target / "ui" / "web").mkdir(parents=True)
        for relative in (
            "constants.py",
            "build-on-mac.spec",
            "build-on-mac-intel-only.spec",
            "windows-version-info.txt",
            "ui/web/package.json",
        ):
            source = ROOT / relative
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        return target

    def test_semver_rc_parser_and_windows_numeric_projection(self):
        version = ReleaseVersion.parse("v10.0.0-rc.2")
        self.assertEqual("10.0.0-rc.2", version.text)
        self.assertEqual("(10,0,0,0)", version.windows_tuple)
        stable = ReleaseVersion.parse("v10.0.0")
        self.assertEqual("10.0.0", stable.text)
        self.assertEqual("(10,0,0,0)", stable.windows_tuple)
        for invalid in ("10", "10.0", "10.0.0-beta.1", "10.0.0-rc.0", "v01.0.0"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    ReleaseVersion.parse(invalid)

    def test_apply_updates_every_packaging_surface_and_check_is_exact(self):
        with TemporaryDirectory() as directory:
            root = self.fixture(directory)
            version = ReleaseVersion.parse("10.0.0-rc.1")

            apply_version(root, version)
            check_version(root, version)

            self.assertIn(
                "VERSION = '10.0.0-rc.1'",
                (root / "constants.py").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "filevers=(10,0,0,0)",
                (root / "windows-version-info.txt").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                "10.0.0-rc.1",
                json.loads((root / "ui/web/package.json").read_text(encoding="utf-8"))["version"],
            )
            with self.assertRaises(RuntimeError):
                check_version(root, ReleaseVersion.parse("10.0.0"))

    def test_checked_in_source_remains_at_9_2_2_until_rc(self):
        check_version(ROOT, ReleaseVersion.parse("9.2.2"))


if __name__ == "__main__":
    unittest.main()
