import contextlib
import io
import re
import unittest
from pathlib import Path

from runtime import ROOT_APP_ASSET_PATTERNS, gh_asset_utility


class RootAppAssetPatternTests(unittest.TestCase):
    def test_wild_ksu_selector_skips_spoofed_asset_when_it_appears_first(self):
        release = {
            "assets": [
                {
                    "name": "Wild_KSU_Spoofed-v3.1.2_33208-release.apk",
                    "browser_download_url": "https://example.invalid/Wild_KSU_Spoofed.apk",
                },
                {
                    "name": "Wild_KSU_v3.1.2_33208-release.apk",
                    "browser_download_url": "https://example.invalid/Wild_KSU.apk",
                },
            ]
        }

        with contextlib.redirect_stdout(io.StringIO()):
            selected = gh_asset_utility(
                release_object=release,
                asset_name_pattern=ROOT_APP_ASSET_PATTERNS["wild_ksu"],
                download=False,
            )

        self.assertEqual("https://example.invalid/Wild_KSU.apk", selected)

    def test_root_app_patterns_reject_spoofed_variants_case_insensitively(self):
        cases = {
            "kernelsu": ("KernelSU_Spoofed_v1.apk", "KernelSU_v1.apk"),
            "kernelsu_next": ("KernelSU_Next_v3.2.0-Spoofed_33129-release.apk", "KernelSU_Next_v3.2.0_33129-release.apk"),
            "sukisu": ("SukiSU_Spoofed_v4.1.3.apk", "SukiSU_v4.1.3_40796-release.apk"),
            "wild_ksu": ("Wild_KSU_Spoofed-v3.1.2_33208-release.apk", "Wild_KSU_v3.1.2_33208-release.apk"),
        }

        for key, (spoofed, normal) in cases.items():
            pattern = re.compile(ROOT_APP_ASSET_PATTERNS[key])
            with self.subTest(key=key, asset=spoofed):
                self.assertIsNone(pattern.match(spoofed))
            with self.subTest(key=key, asset=normal):
                self.assertIsNotNone(pattern.match(normal))

    def test_root_installers_use_shared_asset_patterns(self):
        source = Path("pf_modules.py").read_text(encoding="utf-8")

        for key in ("kernelsu", "kernelsu_next", "sukisu", "wild_ksu", "apatch"):
            with self.subTest(key=key):
                self.assertIn(f'ROOT_APP_ASSET_PATTERNS["{key}"]', source)

        self.assertNotIn("Wild_KSU(?!.*spoofed)", source)
        self.assertNotIn("KernelSU_Next(?!.*spoofed)", source)


if __name__ == "__main__":
    unittest.main()
