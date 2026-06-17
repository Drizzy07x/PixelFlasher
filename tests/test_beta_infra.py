import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

import diagnostics
import self_test


class BetaInfraTests(unittest.TestCase):
    def test_self_test_has_no_required_failures_in_repo_context(self):
        results = self_test.run_checks()
        required_failures = [result for result in results if result.required and not result.ok]
        self.assertEqual(required_failures, [])

    def test_self_test_json_output_shape(self):
        results = self_test.run_checks()
        payload = json.loads(json.dumps([result.__dict__ | {"status": result.status} for result in results]))
        self.assertTrue(payload)
        self.assertIn("name", payload[0])
        self.assertIn("status", payload[0])

    def test_diagnostics_redacts_sensitive_values(self):
        sample = str(Path.home()) + " ABCDEF1234567890 user-secret"
        redacted = diagnostics.redact(sample)
        self.assertNotIn(str(Path.home()), redacted)
        self.assertIn("<home>", redacted)
        self.assertIn("ABCD…redacted", redacted)

    def test_runtime_imports_and_flushes_without_gui_console(self):
        env = os.environ.copy()
        env.pop("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", None)

        result = subprocess.run(
            [sys.executable, "-c", "import runtime; runtime.flush_output(); print('runtime import ok')"],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("runtime import ok", result.stdout)


if __name__ == "__main__":
    unittest.main()
