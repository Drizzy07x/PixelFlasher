import importlib
from pathlib import Path
import unittest

from ui.pages.modern_preview_copy import (
    MODERN_PREVIEW_FOOTER,
    MODERN_PREVIEW_SUBTITLE,
    MODERN_PREVIEW_TITLE,
    NAV_ITEMS,
    PREVIEW_BADGES,
    SAFETY_BOUNDARY_LINES,
)


MODERN_DASHBOARD_APP_SOURCE = Path("ui/pages/dashboard_app.py")
MODERN_SHELL_SOURCE = Path("ui/pages/modern_shell_app.py")
FLASH_WIZARD_SOURCE = Path("ui/pages/flash_wizard.py")
MODERN_STYLE_SOURCE = Path("ui/pages/modern_preview_style.py")


class ModernShellPreviewSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dashboard_app_source = MODERN_DASHBOARD_APP_SOURCE.read_text(encoding="utf-8")
        cls.shell_source = MODERN_SHELL_SOURCE.read_text(encoding="utf-8")
        cls.wizard_source = FLASH_WIZARD_SOURCE.read_text(encoding="utf-8")
        cls.style_source = MODERN_STYLE_SOURCE.read_text(encoding="utf-8")

    def require_wx(self):
        try:
            import wx  # noqa: F401
        except ModuleNotFoundError:
            self.skipTest("wxPython is not available")

    def test_preview_launcher_entrypoints_are_importable(self):
        self.require_wx()
        for module_name in (
            "ui.pages.dashboard_app",
            "ui.pages.modern_shell_app",
            "ui.pages.flash_wizard",
        ):
            with self.subTest(module_name=module_name):
                module = importlib.import_module(module_name)
                self.assertTrue(callable(getattr(module, "main", None)))

    def test_modern_preview_style_helpers_are_importable(self):
        self.require_wx()
        module = importlib.import_module("ui.pages.modern_preview_style")

        for helper in ("action_tile", "badge", "button_panel", "card", "sidebar_row"):
            with self.subTest(helper=helper):
                self.assertTrue(callable(getattr(module, helper, None)))

    def test_preview_launchers_have_module_entrypoints(self):
        for name, source in (
            ("dashboard_app", self.dashboard_app_source),
            ("modern_shell_app", self.shell_source),
            ("flash_wizard", self.wizard_source),
        ):
            with self.subTest(name=name):
                self.assertIn('if __name__ == "__main__":', source)
                self.assertIn("raise SystemExit(main())", source)

    def test_modern_shell_sidebar_uses_dark_preview_rows_not_native_buttons(self):
        self.assertIn("preview_style.sidebar_row", self.shell_source)
        self.assertIn("bind_click_recursive", self.shell_source)
        self.assertNotIn("wx.Button(panel, label=nav_label", self.shell_source)
        self.assertIn("def sidebar_row", self.style_source)
        self.assertIn("SetMinSize((-1, 54))", self.style_source)

    def test_modern_shell_sidebar_uses_unique_preview_destinations(self):
        self.assertIn('("dashboard", "devices", "flash", "backups", "downloads", "tools", "settings")', self.shell_source)
        self.assertNotIn('("dashboard", "flash", "patch", "devices", "tools", "logs", "settings")', self.shell_source)
        nav_titles = [title for _key, title, _detail in NAV_ITEMS]
        self.assertEqual(len(nav_titles), len(set(nav_titles)))

    def test_modern_shell_devices_page_is_readonly_state_explorer(self):
        self.assertIn('self.active_page = "devices"', self.shell_source)
        self.assertIn('"devices": self._render_devices', self.shell_source)
        for label in ("Loaded Device State", "Connection Readiness", "Firmware Context", "Safety Boundary"):
            with self.subTest(label=label):
                self.assertIn(label, self.shell_source)

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
        self.assertEqual("Modern UI - Preview (Read-Only)", MODERN_PREVIEW_TITLE)
        self.assertEqual("Safe by default. No device changes. No flashing. No patches.", MODERN_PREVIEW_SUBTITLE)
        self.assertIn("PREVIEW ONLY", PREVIEW_BADGES)
        self.assertIn("Read-Only", PREVIEW_BADGES)
        self.assertEqual("No device changes will be made.", MODERN_PREVIEW_FOOTER)

    def test_safety_boundary_copy_is_shared_across_shell_and_wizard(self):
        for label in (
            "No flashing, patching, or firmware writing.",
            "No ADB or Fastboot command execution.",
            "No reboot, wipe, slot switching, or device changes.",
            "Preview-only. Read-only state. Legacy flows guarded.",
        ):
            with self.subTest(label=label):
                self.assertIn(label, SAFETY_BOUNDARY_LINES)
        self.assertIn("SAFETY_BOUNDARY_LINES", self.shell_source)
        self.assertIn("Flash Wizard – Preview & Plan Only", self.wizard_source)
        self.assertIn('FLASH_WIZARD_PREVIEW_TITLE = "Flash Wizard – Preview & Plan Only"', self.wizard_source)
        self.assertIn("_wx_static_label(FLASH_WIZARD_PREVIEW_TITLE)", self.wizard_source)
        self.assertNotIn("Preview _Plan Only", self.wizard_source)
        self.assertIn("MODERN_PREVIEW_FOOTER", self.wizard_source)

    def test_modern_shell_source_does_not_call_device_execution_helpers(self):
        forbidden_snippets = (
            "subprocess.run",
            "subprocess.Popen",
            "os.system",
            "from runtime import",
            "get_phone(",
            "fastboot ",
            "adb shell",
            "delete_all",
            "wipe_data",
        )
        for source_name, source in (
            ("dashboard_app", self.dashboard_app_source),
            ("modern_shell_app", self.shell_source),
            ("flash_wizard", self.wizard_source),
            ("modern_preview_style", self.style_source),
        ):
            for snippet in forbidden_snippets:
                with self.subTest(source_name=source_name, snippet=snippet):
                    self.assertNotIn(snippet, source)

    def test_flash_wizard_preview_launcher_uses_default_readonly_session(self):
        self.assertIn("FlashWizardPanel(self, session=WizardSession())", self.wizard_source)
        self.assertNotIn("demo_session", self.wizard_source)

    def test_flash_wizard_final_footer_action_is_hidden_in_preview(self):
        self.assertIn("self._next.Hide()", self.wizard_source)
        self.assertIn("Preview only · flash execution disabled", self.wizard_source)
        self.assertIn("Blocked Execution", self.wizard_source)
        self.assertIn("Preview-only planning is visible. No flash, patch, reboot, or device changes are available here.", self.wizard_source)
        self.assertIn("preview_style.button_panel(panel, self.theme, \"Back\", \"info\")", self.wizard_source)
        self.assertIn("preview_style.button_panel(panel, self.theme, \"Next\", \"info\")", self.wizard_source)
        self.assertNotIn('wx.Button(panel, label="Back")', self.wizard_source)
        self.assertNotIn('wx.Button(panel, label="Next")', self.wizard_source)
        self.assertNotIn('wx.Button(self._content_panel, label="Flash disabled"', self.wizard_source)
        self.assertNotIn('wx.Button(self._content_panel, label="Flash Device"', self.wizard_source)

    def test_flash_wizard_device_step_has_structured_readonly_preview_cards(self):
        for label in (
            "Device Readiness Checklist",
            "Firmware Readiness Checklist",
            "Execution Blocked Checklist",
            "Preview Limitations",
            "No scan, reboot, or slot action runs here.",
            "No archive parsing or file access starts here.",
            "Device mutation is blocked in preview.",
        ):
            with self.subTest(label=label):
                self.assertIn(label, self.wizard_source)


if __name__ == "__main__":
    unittest.main()
