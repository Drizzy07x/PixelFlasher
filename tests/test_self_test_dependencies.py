import unittest
from types import SimpleNamespace
from unittest.mock import patch

from self_test import CheckResult, format_results, run_checks


class SelfTestDependencyTests(unittest.TestCase):
    def test_required_runtime_modules_are_checked(self):
        results = {result.name: result for result in run_checks()}

        for module in ("darkdetect", "json5"):
            with self.subTest(module=module):
                name = f"module:{module}"
                self.assertIn(name, results)
                self.assertTrue(results[name].required)

    def test_format_results_uses_ascii_markers_when_stdout_needs_them(self):
        results = [
            CheckResult("pass", True, "ok"),
            CheckResult("fail", False, "missing"),
        ]

        with patch("self_test.sys.stdout", SimpleNamespace(encoding="cp1252")):
            output = format_results(results)

        self.assertIn("+ PASS", output)
        self.assertIn("x FAIL", output)


if __name__ == "__main__":
    unittest.main()
