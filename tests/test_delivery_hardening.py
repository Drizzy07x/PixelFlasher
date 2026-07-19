import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


class DeliveryHardeningTests(unittest.TestCase):
    def source(self, name):
        return (WORKFLOWS / name).read_text(encoding="utf-8")

    def parsed(self, name):
        return yaml.safe_load(self.source(name))

    def test_windows_release_artifacts_require_verified_authenticode(self):
        x64 = self.source("windows.yml")
        arm = self.source("windows-arm64.yml")
        self.assertIn("Get-AuthenticodeSignature", x64)
        self.assertIn("Get-AuthenticodeSignature", arm)
        self.assertIn("mandatory for v10 release tags", x64)
        self.assertIn("mandatory for v10 release tags", arm)
        self.assertIn("windows-11-arm", arm)
        self.assertIn("dumpbin.exe /headers", arm)
        self.assertIn("PixelFlasher-arm64.exe\" --self-test", arm)

    def test_macos_builds_native_signed_notarized_packages_for_both_arches(self):
        source = self.source("mac.yml")
        workflow = self.parsed("mac.yml")
        matrix = workflow["jobs"]["build-macos"]["strategy"]["matrix"]["include"]
        self.assertEqual({"arm64", "x86_64"}, {item["arch"] for item in matrix})
        for marker in (
            "macos-15-intel",
            "--options runtime",
            "notarytool submit",
            "stapler staple",
            "spctl --assess",
            "label: AppleSilicon",
            "label: Intel",
            "PixelFlasher_MacOS_${{ matrix.label }}.dmg",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)
        release_source = self.source("main.yml")
        self.assertIn("PixelFlasher_MacOS_AppleSilicon.dmg", release_source)
        self.assertIn("PixelFlasher_MacOS_Intel.dmg", release_source)
        self.assertIn("target_arch='arm64'", (ROOT / "build-on-mac.spec").read_text(encoding="utf-8"))

    def test_appimage_tool_is_hash_pinned_and_x11_wayland_clean_smokes_exist(self):
        source = self.source("appimage-x86_64.yml")
        for marker in (
            "releases/assets/324406882",
            "a6d71e2b6cd66f8e8d16c37ad164658985e0cf5fcaa950c90a482890cb9d13e0",
            "sha256sum --check --strict",
            "GDK_BACKEND=wayland",
            "backend=headless-backend.so",
            "smoke_clean_image",
            "ubuntu:22.04",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)
        runtime_hook = (ROOT / "pyi_runtime_linux_gtk.py").read_text(encoding="utf-8")
        self.assertNotIn('setdefault("NO_AT_BRIDGE"', runtime_hook)

    def test_codeql_covers_python_and_typescript_without_actor_filter(self):
        source = self.source("codeql-analysis.yml")
        self.assertIn("'python', 'javascript-typescript'", source)
        self.assertNotIn("github.actor ==", source)
        self.assertIn(
            "github/codeql-action/analyze@b7351df727350dca84cb9d725d57dcf5bc82ba26",
            source,
        )

    def test_every_external_github_action_is_pinned_to_a_full_commit(self):
        mutable = []
        pattern = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
        for path in WORKFLOWS.glob("*.yml"):
            for reference in pattern.findall(path.read_text(encoding="utf-8")):
                if reference.startswith("./") or reference.startswith("docker://"):
                    continue
                revision = reference.rpartition("@")[2]
                if not re.fullmatch(r"[0-9a-f]{40}", revision):
                    mutable.append((path.name, reference))
        self.assertEqual([], mutable)


if __name__ == "__main__":
    unittest.main()
