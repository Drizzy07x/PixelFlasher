from pathlib import Path
import unittest


MODERN_SHELL_SOURCE = Path("ui/pages/modern_shell_app.py")
FLASH_WIZARD_SOURCE = Path("ui/pages/flash_wizard.py")


class ModernShellPreviewSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shell_source = MODERN_SHELL_SOURCE.read_text(encoding="utf-8")
        cls.wizard_source = FLASH_WIZARD_SOURCE.read_text(encoding="utf-8")

    def test_tools_page_has_explicit_renderer(self):
        self.assertIn('"tools": self._render_tools', self.shell_source)
        self.assertIn("def _render_tools(self)", self.shell_source)
        self.assertIn("Preview only · tool execution disabled", self.shell_source)

    def test_preview_pages_show_disabled_safety_banners(self):
        expected = (
            "Preview only · patch execution disabled",
            "Preview only · scan/refresh disabled",
            "Preview only · tool execution disabled",
            "Preview only · live log capture disabled",
            "No Flash Execution",
        )
        for label in expected:
            with self.subTest(label=label):
                self.assertIn(label, self.shell_source)

    def test_modern_shell_source_does_not_call_device_execution_helpers(self):
        forbidden_snippets = (
            "subprocess.run",
            "subprocess.Popen",
            "os.system",
            "fastboot ",
            "adb shell",
            "delete_all",
            "wipe_data",
        )
        for snippet in forbidden_snippets:
            with self.subTest(snippet=snippet):
                self.assertNotIn(snippet, self.shell_source)

    def test_flash_wizard_final_footer_action_is_hidden_in_preview(self):
        self.assertIn("self._next.Hide()", self.wizard_source)
        self.assertIn("Preview only · flash execution disabled", self.wizard_source)
        self.assertNotIn('wx.Button(self._content_panel, label="Flash disabled"', self.wizard_source)
        self.assertNotIn('wx.Button(self._content_panel, label="Flash Device"', self.wizard_source)


if __name__ == "__main__":
    unittest.main()
