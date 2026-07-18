import ast
from pathlib import Path
import unittest

from ui.bridge_contract import ALLOWED_COMMANDS, BRIDGE_CHANNEL, BRIDGE_VERSION


ROOT = Path(__file__).resolve().parents[1]
PIXELFLASHER_SOURCE = ROOT / "PixelFlasher.py"
PRIMARY_SOURCE = ROOT / "ui" / "pages" / "modern_primary_app.py"
HOST_SOURCE = ROOT / "ui" / "pages" / "modern_webview_host.py"
CORE_ROOT = ROOT / "pixelflasher_core"
DESKTOP_SPECS = (
    ROOT / "build-on-win.spec",
    ROOT / "build-on-win-arm64.spec",
    ROOT / "build-on-linux.spec",
    ROOT / "build-on-mac.spec",
    ROOT / "build-on-mac-intel-only.spec",
)


class ModernPrimaryExperienceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entry_source = PIXELFLASHER_SOURCE.read_text(encoding="utf-8")
        cls.primary_source = PRIMARY_SOURCE.read_text(encoding="utf-8")
        cls.host_source = HOST_SOURCE.read_text(encoding="utf-8")

    def test_default_startup_uses_the_headless_modern_runtime(self):
        self.assertIn("launch_modern_primary", self.entry_source)
        self.assertIn("_run_modern_primary(sys.argv)", self.entry_source)
        self.assertIn("ApplicationRuntime.open", self.primary_source)
        self.assertIn("create_modern_webview_frame", self.primary_source)

        forbidden = (
            "import Main",
            "Main.PixelFlasher",
            "PIXELFLASHER_MODERN_ENGINE",
            "state_host",
            "_create_hidden_engine",
            "SimpleNamespace",
        )
        for snippet in forbidden:
            with self.subTest(snippet=snippet):
                self.assertNotIn(snippet, self.primary_source)

    def test_webview_keeps_one_persistent_local_document(self):
        self.assertIn("wx.DEFAULT_FRAME_STYLE", self.host_source)
        self.assertIn("LoadURL(self._index_path.as_uri())", self.host_source)
        self.assertIn("AddScriptMessageHandler(BRIDGE_CHANNEL)", self.host_source)
        self.assertIn("EVT_WEBVIEW_SCRIPT_MESSAGE_RECEIVED", self.host_source)
        self.assertIn("RunScriptAsync", self.host_source)
        self.assertNotIn("SetPage(", self.host_source)
        self.assertNotIn("wx.NO_BORDER", self.host_source)
        self.assertNotIn("wx.MessageDialog", self.host_source)

    def test_bridge_is_versioned_single_channel_and_allow_listed(self):
        self.assertEqual(1, BRIDGE_VERSION)
        self.assertEqual("pixelflasher", BRIDGE_CHANNEL)
        self.assertIn("snapshot.get", ALLOWED_COMMANDS)
        self.assertIn("device.scan", ALLOWED_COMMANDS)
        self.assertIn("flash.execute", ALLOWED_COMMANDS)
        self.assertIn("interaction.respond", ALLOWED_COMMANDS)
        self.assertNotIn("python.eval", ALLOWED_COMMANDS)

    def test_core_has_no_presentation_or_legacy_imports(self):
        forbidden_roots = {"wx", "Main", "ui", "runtime", "pf_modules"}
        violations = []
        for path in CORE_ROOT.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    roots = {alias.name.split(".", 1)[0] for alias in node.names}
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    roots = {node.module.split(".", 1)[0]}
                else:
                    continue
                for root in roots & forbidden_roots:
                    violations.append(f"{path.name}:{node.lineno}:{root}")
        self.assertEqual([], violations)

    def test_every_desktop_artifact_bundles_the_react_build(self):
        for spec in DESKTOP_SPECS:
            with self.subTest(spec=spec.name):
                self.assertIn("ui/web/dist", spec.read_text(encoding="utf-8"))

    def test_frontend_contract_is_buildable_without_a_runtime_server(self):
        package = (ROOT / "ui" / "web" / "package.json").read_text(encoding="utf-8")
        vite = (ROOT / "ui" / "web" / "vite.config.ts").read_text(encoding="utf-8")
        self.assertIn('"build"', package)
        self.assertIn("base: './'", vite)
        self.assertIn("outDir: 'dist'", vite)


if __name__ == "__main__":
    unittest.main()
