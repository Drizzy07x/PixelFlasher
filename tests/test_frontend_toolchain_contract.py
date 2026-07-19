import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "ui" / "web"


class FrontendToolchainContractTests(unittest.TestCase):
    def test_modern_runtime_lines_are_exact_and_never_prereleases(self) -> None:
        package = json.loads((WEB / "package.json").read_text(encoding="utf-8"))
        dependencies = {**package["dependencies"], **package["devDependencies"]}
        expected = {
            "react": "19.2.7",
            "react-dom": "19.2.7",
            "vite": "8.1.5",
            "typescript": "6.0.3",
            # Vitest 5 has no stable release as of this checkpoint; prereleases
            # are forbidden, so the latest stable major remains authoritative.
            "vitest": "4.1.10",
            "@vitejs/plugin-react": "6.0.3",
            "@vitest/coverage-v8": "4.1.10",
        }
        self.assertEqual(expected, {name: dependencies[name] for name in expected})
        for name, version in dependencies.items():
            with self.subTest(package=name):
                self.assertRegex(version, r"^\d+\.\d+\.\d+$")
                self.assertNotRegex(version, r"(?i)(alpha|beta|rc|next|canary)")

    def test_node_and_pnpm_are_locked_across_package_and_builder(self) -> None:
        package = json.loads((WEB / "package.json").read_text(encoding="utf-8"))
        builder = (ROOT / "scripts" / "build_frontend.py").read_text(encoding="utf-8")

        self.assertEqual("pnpm@11.9.0", package["packageManager"])
        self.assertEqual(">=24.0.0 <25", package["engines"]["node"])
        self.assertIn('EXPECTED_NODE_VERSION = "v24.14.0"', builder)
        self.assertIn('EXPECTED_PNPM_VERSION = "11.9.0"', builder)
        self.assertIn('"install", "--frozen-lockfile"', re.sub(r"\s+", " ", builder))

    def test_production_webview_disables_browser_networking(self) -> None:
        index = (WEB / "index.html").read_text(encoding="utf-8")
        vite = (WEB / "vite.config.ts").read_text(encoding="utf-8")
        verifier = (WEB / "scripts" / "verify-dist.mjs").read_text(encoding="utf-8")

        for text in (index, vite):
            self.assertIn("connect-src 'none'", text)
            self.assertNotIn("connect-src 'self'", text)
        self.assertIn("Production WebView CSP must disable browser networking", verifier)


if __name__ == "__main__":
    unittest.main()
