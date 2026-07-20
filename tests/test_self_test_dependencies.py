import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from self_test import (
    CheckResult,
    _check_patch_resources,
    _check_platform_tools,
    _check_root_app_distribution,
    _write_frozen_self_test_log,
    format_results,
    run_checks,
)

WINDOWS_SPEC_SOURCE = Path("build-on-win.spec")
DESKTOP_SPEC_SOURCES = (
    WINDOWS_SPEC_SOURCE,
    Path("build-on-linux.spec"),
    Path("build-on-mac.spec"),
    Path("build-on-mac-intel-only.spec"),
)
RELEASE_METADATA_PATHS = (
    "images/icon-dark-256.png",
    "images/icon-dark-256.ico",
    "images/icon-dark-256.icns",
    "windows-version-info.txt",
)


class SelfTestDependencyTests(unittest.TestCase):
    def test_missing_root_app_distribution_is_visible_but_optional_during_migration(self):
        result = _check_root_app_distribution()

        self.assertFalse(result.required)
        self.assertFalse(result.ok)
        self.assertIn("not provisioned", result.message)

    def test_packaged_patch_runner_distribution_is_required_and_verified(self):
        result = _check_patch_resources()

        self.assertTrue(result.required)
        self.assertTrue(result.ok, result.message)
        self.assertIn("24 verified ABI runner bindings", result.message)

    def test_retired_wx_runtime_modules_are_not_modern_release_requirements(self):
        results = {result.name: result for result in run_checks()}

        for module in ("darkdetect", "json5"):
            with self.subTest(module=module):
                self.assertNotIn(f"module:{module}", results)

    def test_frozen_ui_foundation_is_validated_by_the_bundled_frontend_contract(self):
        with patch("self_test._is_frozen", return_value=True):
            results = {result.name: result for result in run_checks()}

        self.assertTrue(results["ui_theme_tokens"].ok)
        self.assertTrue(results["ui_asset_registry"].ok)
        self.assertIn("bundled frontend", results["ui_theme_tokens"].message)

    def test_release_metadata_is_checked(self):
        results = {result.name: result for result in run_checks()}

        for name in (
            "release_version",
            "file:icon-dark-256.png",
            "file:icon-dark-256.ico",
            "file:icon-dark-256.icns",
            "file:windows-version-info.txt",
        ):
            with self.subTest(name=name):
                self.assertIn(name, results)
                self.assertTrue(results[name].ok)

    def test_desktop_builds_package_self_test_release_metadata(self):
        for spec_path in DESKTOP_SPEC_SOURCES:
            source = spec_path.read_text(encoding="utf-8")
            for expected in RELEASE_METADATA_PATHS:
                with self.subTest(spec=str(spec_path), expected=expected):
                    self.assertIn(expected, source)

    def test_build_script_uses_current_release_version(self):
        source = Path("build.sh").read_text(encoding="utf-8")

        self.assertIn("from constants import VERSION", source)
        self.assertNotIn("VERSION=9.1.1.1", source)

    def test_self_test_checks_current_modern_primary_entrypoint(self):
        results = {result.name: result for result in run_checks()}

        self.assertIn("entrypoint:modern_primary_app", results)
        self.assertTrue(results["entrypoint:modern_primary_app"].ok)
        self.assertNotIn("entrypoint:main_integration", results)

    def test_format_results_uses_ascii_markers_when_stdout_needs_them(self):
        results = [
            CheckResult("pass", True, "ok"),
            CheckResult("fail", False, "missing"),
        ]

        with patch("self_test.sys.stdout", SimpleNamespace(encoding="cp1252")):
            output = format_results(results)

        self.assertIn("+ PASS", output)
        self.assertIn("x FAIL", output)

    def test_frozen_self_test_writes_diagnostic_log(self):
        with tempfile.TemporaryDirectory(prefix="pf-self-test-log-") as tmp:
            with patch("self_test._is_frozen", return_value=True), patch("self_test.tempfile.gettempdir", return_value=tmp):
                _write_frozen_self_test_log("self-test output")

            log_path = Path(tmp) / "PixelFlasher-self-test.log"
            self.assertEqual(log_path.read_text(encoding="utf-8").strip(), "self-test output")

    def test_platform_tools_check_uses_configured_path(self):
        with tempfile.TemporaryDirectory(prefix="pf-self-test-tools-") as tmp:
            root = Path(tmp)
            config_dir = root / "config"
            tools = root / "platform-tools"
            config_dir.mkdir()
            tools.mkdir()
            for name in ("adb.exe", "fastboot.exe", "adb", "fastboot"):
                tool_path = tools / name
                tool_path.write_text(name, encoding="utf-8")
                tool_path.chmod(0o755)
            (config_dir / "PixelFlasher.json").write_text(
                json.dumps({"platform_tools_path": str(tools)}),
                encoding="utf-8",
            )

            with patch("self_test._find_binary", return_value=None), patch("self_test.user_data_dir", return_value=str(config_dir)):
                results = {result.name: result for result in _check_platform_tools()}

        self.assertTrue(results["platform_tool:adb"].ok)
        self.assertTrue(results["platform_tool:fastboot"].ok)
        self.assertIn("platform-tools", results["platform_tool:adb"].message)


if __name__ == "__main__":
    unittest.main()
