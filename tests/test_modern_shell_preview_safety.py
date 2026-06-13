import importlib
from pathlib import Path
import unittest

from ui.pages.modern_preview_copy import (
    MODERN_PREVIEW_FOOTER,
    MODERN_PREVIEW_SUBTITLE,
    MODERN_PREVIEW_TITLE,
    NAV_ICONS,
    NAV_ITEMS,
    PREVIEW_BADGES,
    SAFETY_BOUNDARY_LINES,
)


MODERN_DASHBOARD_APP_SOURCE = Path("ui/pages/dashboard_app.py")
MODERN_SHELL_SOURCE = Path("ui/pages/modern_shell_app.py")
FLASH_WIZARD_SOURCE = Path("ui/pages/flash_wizard.py")
MODERN_STYLE_SOURCE = Path("ui/pages/modern_preview_style.py")
MODERN_WEB_SOURCE = Path("ui/pages/modern_preview_web.py")
MODERN_TEMPLATE_SOURCE = Path("ui/pages/modern_preview_templates.py")
MAIN_SOURCE = Path("Main.py")


class ModernShellPreviewSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dashboard_app_source = MODERN_DASHBOARD_APP_SOURCE.read_text(encoding="utf-8")
        cls.shell_source = MODERN_SHELL_SOURCE.read_text(encoding="utf-8")
        cls.wizard_source = FLASH_WIZARD_SOURCE.read_text(encoding="utf-8")
        cls.style_source = MODERN_STYLE_SOURCE.read_text(encoding="utf-8")
        cls.web_source = MODERN_WEB_SOURCE.read_text(encoding="utf-8")
        cls.template_source = MODERN_TEMPLATE_SOURCE.read_text(encoding="utf-8")
        cls.main_source = MAIN_SOURCE.read_text(encoding="utf-8")

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

    def test_webview_preview_module_is_importable(self):
        self.require_wx()
        module = importlib.import_module("ui.pages.modern_preview_web")

        self.assertTrue(callable(getattr(module, "create_modern_preview_frame", None)))
        self.assertTrue(callable(getattr(module, "is_webview_available", None)))

    def test_modern_preview_style_helpers_are_importable(self):
        self.require_wx()
        module = importlib.import_module("ui.pages.modern_preview_style")

        for helper in (
            "action_tile",
            "apply_window_theme",
            "app_panel",
            "badge",
            "badge_row",
            "bottom_status_bar",
            "button_panel",
            "card",
            "checklist_card",
            "device_glyph_panel",
            "footer_button",
            "hero_device_card",
            "icon_action_tile",
            "info_column",
            "info_row",
            "info_strip",
            "metric_card",
            "notice_card",
            "page_header",
            "safety_boundary_card",
            "sidebar",
            "sidebar_brand",
            "sidebar_container",
            "sidebar_row",
            "status_card",
            "stepper_cell",
        ):
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

    def test_legacy_menu_exposes_modern_ui_preview_entrypoint(self):
        self.assertIn('_("Modern UI Preview")', self.main_source)
        self.assertIn('_("Preview-only · Read-only · No device changes")', self.main_source)
        self.assertIn("self.modern_ui_preview_item", self.main_source)
        self.assertIn("self._on_modern_ui_preview", self.main_source)

    def test_legacy_preview_entrypoint_opens_dashboard_preview_only(self):
        handler = _source_block(self.main_source, "def _on_modern_ui_preview", "def _on_advanced_config")

        self.assertIn("from ui.pages.dashboard_app import show_dashboard_preview", handler)
        self.assertIn("show_dashboard_preview(self)", handler)
        self.assertNotIn("modern_shell_app", handler)
        self.assertNotIn("flash_wizard", handler)
        self.assertIn("class DashboardPreviewFrame", self.dashboard_app_source)
        self.assertIn("def show_dashboard_preview", self.dashboard_app_source)
        self.assertIn('create_modern_preview_frame(page="dashboard"', self.dashboard_app_source)

    def test_legacy_preview_entrypoint_does_not_call_execution_helpers(self):
        handler = _source_block(self.main_source, "def _on_modern_ui_preview", "def _on_advanced_config")
        forbidden_snippets = (
            "subprocess",
            "os.system",
            "from runtime import",
            "get_phone(",
            "fastboot ",
            "adb shell",
            "delete_all",
            "wipe_data",
            "firmware_parser",
        )

        for snippet in forbidden_snippets:
            with self.subTest(snippet=snippet):
                self.assertNotIn(snippet, handler)

    def test_modern_shell_sidebar_uses_dark_preview_rows_not_native_buttons(self):
        self.assertIn("preview_style.sidebar_row", self.shell_source)
        self.assertIn("NAV_ICONS", self.shell_source)
        self.assertIn("bind_click_recursive", self.shell_source)
        self.assertNotIn("wx.Button(panel, label=nav_label", self.shell_source)
        self.assertIn("def sidebar_row", self.style_source)
        self.assertIn("SetMinSize((-1, 62))", self.style_source)

    def test_modern_preview_safe_nav_glyphs_are_defined(self):
        for key in ("dashboard", "shell", "wizard", "backups", "downloads", "settings", "tools", "safety", "about"):
            with self.subTest(key=key):
                self.assertIn(key, NAV_ICONS)
                self.assertTrue(NAV_ICONS[key])

    def test_webview_preview_template_contains_required_dashboard_structure(self):
        from ui.pages.modern_preview_templates import render_preview_html
        from ui.pages.modern_readonly_state import ModernDeviceState, ModernFirmwareState, ModernReadonlyState, ModernToolState

        html = render_preview_html(
            "dashboard",
            ModernReadonlyState(
                device=ModernDeviceState(display_name="Google Pixel 8 Pro", android_version="14"),
                firmware=ModernFirmwareState(),
                tools=ModernToolState(),
                warnings=(),
            ),
        )

        for label in (
            "Modern UI · Safe by Default",
            "Connected Device",
            "Quick Actions",
            "Safety Boundary",
            "Device Slots",
            "Partitions",
            "Last Backup",
            "Safe-by-Default Mode",
            "Open Classic PixelFlasher",
            "No direct device execution from Modern UI",
            "PixelFlasher 9.2.0-beta",
        ):
            with self.subTest(label=label):
                self.assertIn(label, html)

    def test_webview_preview_template_contains_navigation_inventory(self):
        from ui.pages.modern_preview_templates import render_preview_html
        from ui.pages.modern_readonly_state import ModernDeviceState, ModernFirmwareState, ModernReadonlyState, ModernToolState

        html = render_preview_html(
            "shell",
            ModernReadonlyState(
                device=ModernDeviceState(),
                firmware=ModernFirmwareState(),
                tools=ModernToolState(),
                warnings=(),
            ),
        )

        for label in ("Dashboard", "Modern Shell", "Flash Wizard", "Backups", "Downloads", "Settings", "Tools", "Safety", "About"):
            with self.subTest(label=label):
                self.assertIn(label, html)

        for action in (
            "pixelflasher://action/open_modern_dashboard",
            "pixelflasher://action/open_modern_shell",
            "pixelflasher://action/open_modern_flash_wizard",
            "pixelflasher://action/open_backups_preview",
            "pixelflasher://action/open_downloads_preview",
            "pixelflasher://action/open_settings_preview",
            "pixelflasher://action/open_tools_preview",
            "pixelflasher://action/open_safety_preview",
            "pixelflasher://action/open_about_preview",
        ):
            with self.subTest(action=action):
                self.assertIn(action, html)

    def test_webview_preview_template_contains_shell_and_wizard_structure(self):
        from ui.pages.modern_preview_templates import render_preview_html
        from ui.pages.modern_readonly_state import ModernDeviceState, ModernFirmwareState, ModernReadonlyState, ModernToolState

        state = ModernReadonlyState(
            device=ModernDeviceState(),
            firmware=ModernFirmwareState(),
            tools=ModernToolState(),
            warnings=("No target device selected.",),
        )
        shell_html = render_preview_html("shell", state)
        wizard_html = render_preview_html("wizard", state)

        for label in ("Device State Overview", "Connection Readiness", "Device Information", "Firmware Context", "Preview Limitations"):
            with self.subTest(label=label):
                self.assertIn(label, shell_html)
        for label in (
            "Step 1: Device Selection",
            "Device Readiness",
            "Firmware Readiness",
            "Execution Blocked",
            "Blocked Execution",
            "Firmware Step Preview",
            "Options Step Preview",
            "Plan Step Preview",
            "Review Step Preview",
            "Can flash",
        ):
            with self.subTest(label=label):
                self.assertIn(label, wizard_html)

    def test_webview_preview_template_contains_remaining_concept_pages(self):
        from ui.pages.modern_preview_templates import render_preview_html
        from ui.pages.modern_readonly_state import ModernDeviceState, ModernFirmwareState, ModernReadonlyState, ModernToolState

        state = ModernReadonlyState(
            device=ModernDeviceState(),
            firmware=ModernFirmwareState(),
            tools=ModernToolState(),
            warnings=(),
        )

        expected_by_page = {
            "backups": ("Backups (Preview)", "Backup Actions (Guarded)", "No backups loaded", "File changes"),
            "downloads": ("Downloads (Preview)", "Firmware Downloads (Preview)", "Network access", "Device apply"),
            "settings": ("Settings (Preview)", "General Settings", "Saved changes", "No settings are saved"),
            "tools": ("Tools (Preview)", "Tool Catalog", "Command Runner", "Unknown actions"),
            "safety": ("Safety (Read-Only)", "Safety Boundary", "Disabled in Modern UI", "Allow-listed"),
            "about": ("About PixelFlasher", "Application", "Modern UI Status", "Legacy UI"),
        }

        for page, labels in expected_by_page.items():
            html = render_preview_html(page, state)
            for label in labels:
                with self.subTest(page=page, label=label):
                    self.assertIn(label, html)

    def test_webview_preview_html_is_static_and_local(self):
        forbidden_snippets = (
            "http://",
            "https://",
            "cdn",
            "script src",
            "wx.CallAfter",
            "AddScriptMessageHandler",
            "RunScript",
            "javascript:",
            "onclick=",
        )

        for source_name, source in (
            ("modern_preview_templates", self.template_source),
            ("modern_preview_web", self.web_source),
        ):
            for snippet in forbidden_snippets:
                with self.subTest(source_name=source_name, snippet=snippet):
                    self.assertNotIn(snippet, source)

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
        self.assertEqual("Modern UI – Preview", MODERN_PREVIEW_TITLE)
        self.assertEqual("Safe by default. No device changes. No flashing. No patches.", MODERN_PREVIEW_SUBTITLE)
        self.assertIn("PREVIEW ONLY", PREVIEW_BADGES)
        self.assertIn("Read-Only", PREVIEW_BADGES)
        self.assertIn("No Device Changes", PREVIEW_BADGES)
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
            ("modern_preview_web", self.web_source),
            ("modern_preview_templates", self.template_source),
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
        self.assertIn("preview_style.stepper_cell", self.wizard_source)
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
            "Patch Plan",
            "Safe Defaults",
            "Review Summary",
            "Final Step",
            "No scan, reboot, or slot action runs here.",
            "No archive parsing or file access starts here.",
            "Device mutation is blocked in preview.",
        ):
            with self.subTest(label=label):
                self.assertIn(label, self.wizard_source)


def _source_block(source: str, start: str, end: str) -> str:
    start_index = source.index(start)
    end_index = source.index(end, start_index)
    return source[start_index:end_index]


if __name__ == "__main__":
    unittest.main()
