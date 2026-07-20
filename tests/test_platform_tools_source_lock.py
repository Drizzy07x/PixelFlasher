import json
import unittest
from pathlib import Path


class PlatformToolsSourceLockTests(unittest.TestCase):
    def test_stable_google_release_is_versioned_and_covers_the_release_matrix(self) -> None:
        path = Path("resources/platform-tools/source-lock.json")
        values = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(1, values["schemaVersion"])
        self.assertEqual("stable", values["releaseChannel"])
        self.assertEqual("37.0.0", values["version"])
        self.assertEqual("Android-SDK-License", values["license"])
        self.assertEqual(
            "https://dl.google.com/android/repository/repository2-1.xml",
            values["sourceMetadataUrl"],
        )
        targets = {
            (archive["platform"], architecture)
            for archive in values["archives"]
            for architecture in archive["hostArchitectures"]
        }
        self.assertEqual(
            {
                ("windows", "x86_64"),
                ("windows", "arm64"),
                ("darwin", "x86_64"),
                ("darwin", "arm64"),
                ("linux", "x86_64"),
            },
            targets,
        )
        for archive in values["archives"]:
            with self.subTest(platform=archive["platform"]):
                self.assertTrue(archive["url"].startswith("https://dl.google.com/android/repository/"))
                self.assertNotIn("latest", archive["url"])
                self.assertEqual(40, len(archive["sha1"]))
                self.assertEqual(64, len(archive["sha256"]))
                self.assertGreater(archive["size"], 1_000_000)


if __name__ == "__main__":
    unittest.main()
