import ast
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
        self.assertIn("scripts/verify_binary_architecture.py", arm)
        self.assertIn("--architecture arm64", arm)
        self.assertIn("PixelFlasher-arm64.exe\" --self-test", arm)

    def test_windows_build_wrapper_propagates_failures_and_exposes_repo_modules(self):
        source = (ROOT / "build.bat").read_text(encoding="utf-8")
        self.assertIn('set "PYTHONPATH=%~dp0;%PYTHONPATH%"', source)
        self.assertGreaterEqual(source.count("if errorlevel 1 exit /b 1"), 4)
        self.assertNotIn("exit /b %errorlevel%", source)

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
        self.assertIn('ditto dist/PixelFlasher.app "${dmg_root}/PixelFlasher.app"', source)
        self.assertIn('"${dmg}" \\\n            "${dmg_root}"', source)
        self.assertNotIn("create-dmg dist/PixelFlasher.app", source)

    def test_appimage_tool_is_hash_pinned_and_x11_wayland_clean_smokes_exist(self):
        source = self.source("appimage-x86_64.yml")
        for marker in (
            "releases/assets/324406882",
            "a6d71e2b6cd66f8e8d16c37ad164658985e0cf5fcaa950c90a482890cb9d13e0",
            "sha256sum --check --strict",
            "GDK_BACKEND=x11",
            "backend=headless-backend.so",
            "--xwayland",
            "xserver listening on display",
            "smoke_clean_image",
            "ubuntu:22.04",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)
        runtime_hook = (ROOT / "pyi_runtime_linux_gtk.py").read_text(encoding="utf-8")
        self.assertNotIn('setdefault("NO_AT_BRIDGE"', runtime_hook)
        self.assertNotIn("python3-minimal", source)

    def test_clean_receipt_verifiers_remain_python310_runtime_independent(self):
        schema_path = ROOT / "smoke_receipt_schema.py"
        schema_source = schema_path.read_text(encoding="utf-8")
        ast.parse(schema_source, filename=str(schema_path), feature_version=(3, 10))
        self.assertNotIn("pixelflasher_core", schema_source)
        self.assertNotIn("from constants", schema_source)
        for verifier in ("verify_pty_smoke.py", "verify_legacy_raw_smoke.py"):
            with self.subTest(verifier=verifier):
                source = (ROOT / "scripts" / verifier).read_text(encoding="utf-8")
                self.assertIn("from smoke_receipt_schema import", source)

    def test_every_native_artifact_proves_react_bridge_and_clean_shutdown(self):
        expected_targets = {
            "windows.yml": ("windows", "x86_64"),
            "windows-arm64.yml": ("windows", "arm64"),
            "mac.yml": ("macos", '"${{ matrix.arch }}"'),
            "ubuntu_24_04.yml": ("linux", "x86_64"),
            "ubuntu_22_04.yml": ("linux", "x86_64"),
            "appimage-x86_64.yml": ("linux", "x86_64"),
        }
        for workflow, (platform, architecture) in expected_targets.items():
            source = self.source(workflow)
            with self.subTest(workflow=workflow):
                self.assertIn("--ui-smoke-report", source)
                self.assertIn("--ui-smoke-timeout", source)
                self.assertIn("scripts/verify_ui_smoke.py", source)
                self.assertIn(f"--expect-platform {platform}", source)
                self.assertIn(f"--expect-architecture {architecture}", source)

    def test_every_native_artifact_executes_the_isolated_legacy_raw_smoke(self):
        expected_targets = {
            "windows.yml": ("windows", "x86_64"),
            "windows-arm64.yml": ("windows", "arm64"),
            "mac.yml": ("macos", '"${{ matrix.arch }}"'),
            "ubuntu_24_04.yml": ("linux", "x86_64"),
            "ubuntu_22_04.yml": ("linux", "x86_64"),
            "appimage-x86_64.yml": ("linux", "x86_64"),
        }
        for workflow, (platform, architecture) in expected_targets.items():
            source = self.source(workflow)
            with self.subTest(workflow=workflow):
                self.assertIn("--legacy-raw-smoke-report", source)
                self.assertIn("scripts/verify_legacy_raw_smoke.py", source)
                self.assertIn(f"--expect-platform {platform}", source)
                self.assertIn(f"--expect-architecture {architecture}", source)

    def test_every_native_artifact_executes_the_closed_firmware_smoke(self):
        expected_targets = {
            "windows.yml": ("windows", "x86_64"),
            "windows-arm64.yml": ("windows", "arm64"),
            "mac.yml": ("macos", '"${{ matrix.arch }}"'),
            "ubuntu_24_04.yml": ("linux", "x86_64"),
            "ubuntu_22_04.yml": ("linux", "x86_64"),
            "appimage-x86_64.yml": ("linux", "x86_64"),
        }
        for workflow, (platform, architecture) in expected_targets.items():
            source = self.source(workflow)
            with self.subTest(workflow=workflow):
                self.assertIn("--firmware-smoke-report", source)
                self.assertIn("scripts/verify_firmware_smoke.py", source)
                self.assertIn(f"--expect-platform {platform}", source)
                self.assertIn(f"--expect-architecture {architecture}", source)

    def test_every_native_artifact_executes_the_closed_support_smoke(self):
        expected_targets = {
            "windows.yml": ("windows", "x86_64"),
            "windows-arm64.yml": ("windows", "arm64"),
            "mac.yml": ("macos", '"${{ matrix.arch }}"'),
            "ubuntu_24_04.yml": ("linux", "x86_64"),
            "ubuntu_22_04.yml": ("linux", "x86_64"),
            "appimage-x86_64.yml": ("linux", "x86_64"),
        }
        for workflow, (platform, architecture) in expected_targets.items():
            source = self.source(workflow)
            with self.subTest(workflow=workflow):
                self.assertIn("--support-smoke-report", source)
                self.assertIn("scripts/verify_support_smoke.py", source)
                self.assertIn(f"--expect-platform {platform}", source)
                self.assertIn(f"--expect-architecture {architecture}", source)

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
