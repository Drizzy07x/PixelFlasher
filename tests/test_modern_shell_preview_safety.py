import importlib
from pathlib import Path
import re
from types import SimpleNamespace
import unittest

from ui.pages.modern_preview_copy import NAV_ICONS, NAV_ITEMS, PREVIEW_BADGES, SAFETY_BOUNDARY_LINES


MODERN_DASHBOARD_APP_SOURCE = Path("ui/pages/dashboard_app.py")
MODERN_SHELL_SOURCE = Path("ui/pages/modern_shell_app.py")
FLASH_WIZARD_SOURCE = Path("ui/pages/flash_wizard.py")
MODERN_STYLE_SOURCE = Path("ui/pages/modern_preview_style.py")
MODERN_WEB_SOURCE = Path("ui/pages/modern_preview_web.py")
MODERN_TEMPLATE_SOURCE = Path("ui/pages/modern_preview_templates.py")
MAIN_SOURCE = Path("Main.py")
PIXELFLASHER_SOURCE = Path("PixelFlasher.py")
WINDOWS_SPEC_SOURCE = Path("build-on-win.spec")


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
        cls.pixelflasher_source = PIXELFLASHER_SOURCE.read_text(encoding="utf-8")
        cls.windows_spec_source = WINDOWS_SPEC_SOURCE.read_text(encoding="utf-8")

    def require_wx(self):
        try:
            import wx  # noqa: F401
        except ModuleNotFoundError:
            self.skipTest("wxPython is not available")

    def test_launcher_entrypoints_are_importable(self):
        self.require_wx()
        for module_name in (
            "ui.pages.dashboard_app",
            "ui.pages.modern_shell_app",
            "ui.pages.flash_wizard",
        ):
            with self.subTest(module_name=module_name):
                module = importlib.import_module(module_name)
                self.assertTrue(callable(getattr(module, "main", None)))

    def test_webview_module_is_importable(self):
        self.require_wx()
        module = importlib.import_module("ui.pages.modern_preview_web")

        self.assertTrue(callable(getattr(module, "create_modern_preview_frame", None)))
        self.assertTrue(callable(getattr(module, "is_webview_available", None)))

    def test_flash_device_contextual_action_uses_current_mode_label(self):
        self.require_wx()
        module = importlib.import_module("ui.pages.modern_preview_web")
        from ui.pages.modern_action_bridge import action_by_id

        frame = module.ModernPreviewWebFrame.__new__(module.ModernPreviewWebFrame)
        base_action = action_by_id("flash_device")
        expected_by_mode = {
            "dryRun": ("Run Dry Run", "Run Dry Run?", False),
            "OTA": ("Sideload OTA", "Sideload OTA?", True),
            "keepData": ("Flash Device", "Flash Device?", True),
        }

        for mode, (label, title, dangerous) in expected_by_mode.items():
            with self.subTest(mode=mode):
                frame._state_host = SimpleNamespace(config=SimpleNamespace(flash_mode=mode))
                action = frame._contextual_action(base_action)

                self.assertEqual(label, action.label)
                self.assertEqual(title, action.confirmation_title)
                self.assertEqual(dangerous, action.dangerous)

    def test_windows_build_packages_webview_loader(self):
        for expected in (
            "import wx",
            "wx_dir = Path(wx.__file__).resolve().parent",
            "WebView2Loader.dll",
            "'wx'",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.windows_spec_source)

    def test_webview_prefers_modern_windows_backend_when_available(self):
        self.assertIn("_preferred_webview_backend", self.web_source)
        self.assertIn("WebViewBackendEdge", self.web_source)
        self.assertIn("IsBackendAvailable", self.web_source)
        self.assertIn("return None", self.web_source)
        self.assertNotIn("except Exception:\n        return None", self.web_source)

    def test_webview_allows_only_initial_document_and_action_urls(self):
        for expected in (
            "EVT_WEBVIEW_LOADED",
            "_loading_document",
            "_is_safe_document_load_url",
            "event.Veto()",
            "blocked_navigation_feedback",
            "action_from_url",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.web_source)

    def test_webview_uses_custom_frameless_window_chrome(self):
        for expected in (
            "FRAME_STYLE = wx.NO_BORDER",
            "wx.CLIP_CHILDREN",
            "wx.NO_FULL_REPAINT_ON_RESIZE",
            "ModernWindowChrome",
            "Iconize(True)",
            "Close(True)",
            "Maximize(not self._frame.IsMaximized())",
            "EVT_LEFT_DOWN",
            "EVT_MOTION",
            "ClientToScreen",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.web_source)

    def test_window_chrome_is_owner_drawn_to_reduce_flicker(self):
        for expected in (
            "wx.AutoBufferedPaintDC",
            "wx.BG_STYLE_PAINT",
            "EVT_PAINT",
            "EVT_ERASE_BACKGROUND",
            "_button_rects",
            "_button_at",
            "_run_button_action",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.web_source)
        self.assertNotIn("wx.Button(self, label=", self.web_source)
        self.assertNotIn("wx.StaticText(self, label=", self.web_source)

    def test_webview_soft_refresh_keeps_current_document_visible(self):
        for expected in (
            "self._has_rendered_document = False",
            "show_loader: bool | None = None",
            "show_loader = not self._has_rendered_document",
            "if show_loader:",
            "self._show_page(self._page, message, tone, show_loader=False)",
            "self._has_rendered_document = True",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.web_source)

    def test_webview_frame_uses_application_icon(self):
        for expected in (
            "_apply_frame_icon(self)",
            "images.Icon_dark_256.GetIcon()",
            "frame.SetIcon(icon)",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.web_source)

    def test_webview_uses_dark_borderless_edges(self):
        for expected in (
            "APP_BACKGROUND = \"#070b12\"",
            "self.SetBackgroundColour(_colour(APP_BACKGROUND))",
            "wx.Panel(self, style=wx.BORDER_NONE | wx.CLIP_CHILDREN)",
            "wx.Simplebook(shell, style=wx.BORDER_NONE)",
            "html2.WebView.New(content, backend=backend, style=wx.BORDER_NONE)",
            "view.SetBackgroundColour(_colour(APP_BACKGROUND))",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.web_source)
        for expected in (
            "padding: 0;",
            "border: 0;",
            "outline: 0;",
            "background: var(--bg);",
            "width: 100vw;",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.template_source)

    def test_webview_blocks_duplicate_engine_actions(self):
        for expected in (
            "_action_running",
            "another operation is already running",
            "finally:",
            "self._action_running = False",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.web_source)

    def test_platform_tools_setup_does_not_block_ui_thread(self):
        for expected in (
            "import threading",
            "threading.Thread",
            "_install_platform_tools_worker",
            "_finish_platform_tools_setup",
            "daemon=True",
            "wx.CallAfter(self._finish_platform_tools_setup",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.web_source)

    def test_modern_style_helpers_are_importable(self):
        self.require_wx()
        module = importlib.import_module("ui.pages.modern_preview_style")

        for helper in (
            "action_tile",
            "apply_window_theme",
            "app_panel",
            "badge",
            "bottom_status_bar",
            "card",
            "icon_action_tile",
            "safety_boundary_card",
            "sidebar_row",
        ):
            with self.subTest(helper=helper):
                self.assertTrue(callable(getattr(module, helper, None)))

    def test_launchers_keep_module_entrypoints(self):
        for name, source in (
            ("dashboard_app", self.dashboard_app_source),
            ("modern_shell_app", self.shell_source),
            ("flash_wizard", self.wizard_source),
        ):
            with self.subTest(name=name):
                self.assertIn('if __name__ == "__main__":', source)
                self.assertIn("raise SystemExit(main())", source)

    def test_default_startup_uses_modern_primary_ui(self):
        self.assertIn("launch_modern_primary", self.pixelflasher_source)
        self.assertIn("_run_modern_primary(sys.argv)", self.pixelflasher_source)
        self.assertNotIn("Main.main()", self.pixelflasher_source)
        self.assertNotIn("--legacy-ui", self.pixelflasher_source)

    def test_main_frame_supports_hidden_engine_mode(self):
        self.assertIn("PIXELFLASHER_MODERN_ENGINE", self.main_source)
        self.assertIn("set_window_shown(not self._modern_engine_mode)", self.main_source)
        self.assertIn("self.Hide()", self.main_source)
        self.assertIn("if self._modern_engine_mode:", self.main_source)
        self.assertIn("self.device_choice.Count == 1", self.main_source)
        self.assertIn("self.device_choice.SetSelection(0)", self.main_source)

    def test_shared_nav_glyphs_are_defined(self):
        for key in ("dashboard", "shell", "wizard", "backups", "downloads", "settings", "tools", "safety", "about"):
            with self.subTest(key=key):
                self.assertIn(key, NAV_ICONS)
                self.assertTrue(NAV_ICONS[key])

    def test_webview_template_contains_dashboard_structure(self):
        from ui.pages.modern_preview_templates import render_preview_html
        from ui.pages.modern_readonly_state import ModernDeviceState, ModernFirmwareState, ModernReadonlyState, ModernToolState
        from constants import VERSION

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
            "Modern UI",
            "Connected Device",
            "Quick Actions",
            "Device Slots",
            "Partitions",
            "Last Backup",
            "Flash Device",
            "Patch Boot",
            "Scan Devices",
            "Platform Tools need setup",
            "Set Up Platform Tools",
            f"PixelFlasher {VERSION}",
        ):
            with self.subTest(label=label):
                self.assertIn(label, html)

    def test_webview_template_contains_navigation_inventory(self):
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

        for label in ("Dashboard", "Device", "Flash Wizard", "Backups", "Downloads", "Settings", "Tools", "Safety", "About"):
            with self.subTest(label=label):
                self.assertIn(label, html)

        for action in (
            "pixelflasher://action/open_modern_dashboard",
            "pixelflasher://action/open_modern_shell",
            "pixelflasher://action/open_modern_flash_wizard",
            "pixelflasher://action/open_backups",
            "pixelflasher://action/open_downloads",
            "pixelflasher://action/open_settings",
            "pixelflasher://action/open_tools",
            "pixelflasher://action/open_safety",
            "pixelflasher://action/open_about",
        ):
            with self.subTest(action=action):
                self.assertIn(action, html)

    def test_webview_navigation_marks_exactly_one_active_page(self):
        from ui.pages.modern_preview_templates import render_preview_html
        from ui.pages.modern_readonly_state import ModernDeviceState, ModernFirmwareState, ModernReadonlyState, ModernToolState

        state = ModernReadonlyState(
            device=ModernDeviceState(),
            firmware=ModernFirmwareState(),
            tools=ModernToolState(),
            warnings=(),
        )

        for page, _title, _detail in NAV_ITEMS:
            with self.subTest(page=page):
                html = render_preview_html(page, state)
                self.assertIn('aria-label="Modern UI surfaces"', html)
                self.assertIn(f'data-active-page="{page}"', html)
                self.assertEqual(1, html.count('aria-current="page"'))
                self.assertRegex(
                    html,
                    rf'<a class="nav-item active" data-page="{re.escape(page)}" [^>]*aria-current="page">',
                )

        unknown_html = render_preview_html("not-a-page", state)
        self.assertIn('data-active-page="dashboard"', unknown_html)
        self.assertEqual(1, unknown_html.count('aria-current="page"'))

    def test_webview_template_contains_shell_and_wizard_structure(self):
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

        for label in ("Device", "Firmware"):
            with self.subTest(label=label):
                self.assertIn(label, shell_html)
        for removed in ("Device Actions", "Scan Devices", "Patch Boot"):
            with self.subTest(removed=removed):
                self.assertNotIn(removed, shell_html)
        for label in (
            "Step 1: Device &amp; Firmware",
            "Device Readiness",
            "Firmware Readiness",
            "Final Flash",
            "Flash Plan",
            "Flash Summary",
            "Firmware",
            "Options",
            "Plan",
            "Review",
            "Official / OTA",
            "Process Package",
            "Official / OTA",
            "Custom ROM",
            "Run Dry Run",
            "Dry Run does not flash partitions",
        ):
            with self.subTest(label=label):
                self.assertIn(label, wizard_html)
        self.assertNotIn("Execution Blocked", wizard_html)

    def test_webview_template_contains_remaining_pages(self):
        from ui.pages.modern_preview_templates import render_preview_html
        from ui.pages.modern_readonly_state import ModernDeviceState, ModernFirmwareState, ModernReadonlyState, ModernToolState

        state = ModernReadonlyState(
            device=ModernDeviceState(),
            firmware=ModernFirmwareState(),
            tools=ModernToolState(),
            warnings=(),
        )

        expected_by_page = {
            "backups": ("Backups", "Backup Actions", "Backup State", "No backups loaded"),
            "downloads": ("Downloads", "Firmware Source", "Official Android Release", "Custom ROM"),
            "settings": ("Settings", "Preferences", "Open Settings"),
            "tools": ("Tools", "Tool Catalog", "Partition Manager"),
            "safety": ("Safety", "Confirmations"),
            "about": ("PixelFlasher", "Application"),
        }

        for page, labels in expected_by_page.items():
            html = render_preview_html(page, state)
            for label in labels:
                with self.subTest(page=page, label=label):
                    self.assertIn(label, html)

        downloads_html = render_preview_html("downloads", state)
        for removed in ("Rooting App", "Process Firmware"):
            with self.subTest(page="downloads", removed=removed):
                self.assertNotIn(removed, downloads_html)

        tools_html = render_preview_html("tools", state)
        self.assertNotIn("Device Scan", tools_html)

    def test_webview_html_is_static_and_local(self):
        forbidden_snippets = (
            "http://",
            "https://",
            "cdn",
            "script src",
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

    def test_shared_copy_uses_modern_product_language(self):
        self.assertEqual(("Ready", "Modern UI", "Protected"), PREVIEW_BADGES)
        self.assertIn("Sensitive operations require existing PixelFlasher confirmation.", SAFETY_BOUNDARY_LINES)
        self.assertNotIn("Read-Only", PREVIEW_BADGES)

    def test_modern_sources_do_not_call_raw_execution_helpers(self):
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


if __name__ == "__main__":
    unittest.main()
