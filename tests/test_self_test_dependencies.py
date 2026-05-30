import unittest

from self_test import run_checks


class SelfTestDependencyTests(unittest.TestCase):
    def test_required_runtime_modules_are_checked(self):
        results = {result.name: result for result in run_checks()}

        for module in ("darkdetect", "json5"):
            with self.subTest(module=module):
                name = f"module:{module}"
                self.assertIn(name, results)
                self.assertTrue(results[name].required)


if __name__ == "__main__":
    unittest.main()
