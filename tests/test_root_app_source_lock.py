from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from scripts.audit_root_app_releases import RELEASES

ROOT = Path(__file__).resolve().parents[1]
SOURCE_LOCK = ROOT / "resources" / "root-apps" / "source-lock.json"


class RootAppSourceLockTests(unittest.TestCase):
    def test_stable_source_lock_covers_all_seven_non_spoofed_providers(self) -> None:
        document = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))

        self.assertEqual(
            {"schemaVersion", "channel", "license", "provenance", "apps"},
            set(document),
        )
        self.assertEqual(1, document["schemaVersion"])
        self.assertEqual("stable", document["channel"])
        self.assertEqual("GPL-3.0", document["license"])
        apps = document["apps"]
        self.assertEqual(7, len(apps))
        self.assertEqual(
            {"magisk", "apatch", "kernelsu", "kernelsu-next", "sukisu", "wild-ksu", "legacy"},
            {app["provider"] for app in apps},
        )
        self.assertTrue(all("spoofed" not in app["asset"].casefold() for app in apps))

    def test_audit_pins_match_source_lock_identity_and_release_assets(self) -> None:
        apps = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))["apps"]
        by_repository = {app["repository"]: app for app in apps}

        for release in RELEASES:
            with self.subTest(repository=release.repository):
                app = by_repository[release.repository]
                self.assertEqual(release.tag, app["tag"])
                self.assertEqual(release.asset, app["asset"])
                self.assertEqual(release.version, app["version"])
                self.assertEqual(release.url, app["url"])
                self.assertEqual(release.size, app["size"])
                self.assertEqual(release.sha256, app["sha256"])
                self.assertEqual(release.package_name, app["packageName"])

    def test_hashes_signers_architectures_and_urls_are_closed(self) -> None:
        apps = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))["apps"]
        allowed_architectures = {"universal", "arm64", "arm", "x86_64", "x86"}

        for app in apps:
            with self.subTest(provider=app["provider"]):
                self.assertRegex(app["sha256"], r"^[0-9a-f]{64}$")
                self.assertTrue(app["signerSha256"])
                self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", value) for value in app["signerSha256"]))
                self.assertTrue(set(app["schemes"]) <= {"v1", "v2", "v3"})
                self.assertTrue(set(app["architectures"]) <= allowed_architectures)
                self.assertEqual(len(app["architectures"]), len(set(app["architectures"])))
                self.assertTrue(app["url"].startswith(f"https://github.com/{app['repository']}/releases/download/"))


if __name__ == "__main__":
    unittest.main()
