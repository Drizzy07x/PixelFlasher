import unittest
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from self_test import CheckResult, _check_platform_tools, format_results, run_checks


class SelfTestDependencyTests(unittest.TestCase):
    def test_required_runtime_modules_are_checked(self):
        results = {result.name: result for result in run_checks()}

        for module in ("darkdetect", "json5"):
            with self.subTest(module=module):
                name = f"module:{module}"
                self.assertIn(name, results)
                self.assertTrue(results[name].required)

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

    def test_format_results_uses_ascii_markers_when_stdout_needs_them(self):
        results = [
            CheckResult("pass", True, "ok"),
            CheckResult("fail", False, "missing"),
        ]

        with patch("self_test.sys.stdout", SimpleNamespace(encoding="cp1252")):
            output = format_results(results)

        self.assertIn("+ PASS", output)
        self.assertIn("x FAIL", output)

    def test_platform_tools_check_uses_configured_path(self):
        with tempfile.TemporaryDirectory(prefix="pf-self-test-tools-") as tmp:
            root = Path(tmp)
            config_dir = root / "config"
            tools = root / "platform-tools"
            config_dir.mkdir()
            tools.mkdir()
            (tools / "adb.exe").write_text("adb", encoding="utf-8")
            (tools / "fastboot.exe").write_text("fastboot", encoding="utf-8")
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
