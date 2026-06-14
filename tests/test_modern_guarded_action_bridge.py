import unittest
from pathlib import Path

from ui.pages.modern_action_bridge import (
    DISABLED,
    GUARDED_LEGACY_FLOW,
    LEGACY_UI_DELEGATE,
    action_by_id,
    action_from_url,
    action_url,
    is_legacy_handoff,
    modern_actions,
)
from ui.pages.modern_preview_templates import render_preview_html
from ui.pages.modern_readonly_state import (
    ModernBackupState,
    ModernDeviceState,
    ModernDownloadState,
    ModernFirmwareState,
    ModernFlashOptionsState,
    ModernReadonlyState,
    ModernSettingsState,
    ModernToolState,
)


MODERN_BRIDGE_SOURCE = Path("ui/pages/modern_action_bridge.py")
MODERN_FEEDBACK_SOURCE = Path("ui/pages/modern_action_feedback.py")
MODERN_WEB_SOURCE = Path("ui/pages/modern_preview_web.py")
MODERN_TEMPLATE_SOURCE = Path("ui/pages/modern_preview_templates.py")


class ModernGuardedActionBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bridge_source = MODERN_BRIDGE_SOURCE.read_text(encoding="utf-8")
        cls.feedback_source = MODERN_FEEDBACK_SOURCE.read_text(encoding="utf-8")
        cls.web_source = MODERN_WEB_SOURCE.read_text(encoding="utf-8")
        cls.template_source = MODERN_TEMPLATE_SOURCE.read_text(encoding="utf-8")

    def test_action_urls_use_local_custom_scheme_only(self):
        self.assertEqual(
            "pixelflasher://action/guarded_legacy_flash_flow",
            action_url("guarded_legacy_flash_flow"),
        )
        self.assertIs(action_by_id("guarded_legacy_flash_flow"), action_from_url(action_url("guarded_legacy_flash_flow")))

    def test_unknown_and_external_action_urls_are_rejected(self):
        for url in (
            "pixelflasher://action/unknown_action",
            "pixelflasher://other/guarded_legacy_flash_flow",
            "https://example.invalid/action/guarded_legacy_flash_flow",
            "http://example.invalid/action/guarded_legacy_flash_flow",
            "file:///tmp/guarded_legacy_flash_flow",
            "javascript:guarded_legacy_flash_flow",
        ):
            with self.subTest(url=url):
                self.assertIsNone(action_from_url(url))

    def test_required_actions_are_allow_listed(self):
        actions = {action.id for action in modern_actions()}

        self.assertEqual(
            {
                "open_legacy_ui",
                "open_modern_dashboard",
                "open_modern_flash_wizard",
                "open_modern_shell",
                "open_backups_preview",
                "open_downloads_preview",
                "open_settings_preview",
                "open_tools_preview",
                "open_safety_preview",
                "open_about_preview",
                "guarded_legacy_flash_flow",
                "guarded_legacy_patch_flow",
                "guarded_legacy_support_zip",
                "disabled_reboot",
                "disabled_wipe",
                "disabled_slot_switch",
            },
            actions,
        )

    def test_all_modern_preview_pages_render_static_local_content(self):
        state = ModernReadonlyState(
            device=ModernDeviceState(),
            firmware=ModernFirmwareState(),
            tools=ModernToolState(),
            warnings=(),
        )

        expected_by_page = {
            "dashboard": ("Modern UI · Safe by Default", "pixelflasher://action/open_modern_dashboard"),
            "shell": ("Modern Shell – Read-Only State", "pixelflasher://action/open_modern_shell"),
            "wizard": ("Flash Wizard (Preview)", "pixelflasher://action/open_modern_flash_wizard", "Review Step Preview"),
            "backups": ("Backups (Preview)", "Backup Summary (Read-Only)", "No backups loaded"),
            "downloads": ("Downloads (Preview)", "Firmware Downloads (Preview)", "Network"),
            "settings": ("Settings (Preview)", "General Settings", "Saved changes"),
            "tools": ("Tools (Preview)", "Tool Catalog", "Direct commands"),
            "safety": ("Safety (Read-Only)", "Guarded Handoffs", "Unknown URLs"),
            "about": ("About PixelFlasher", "Modern UI Status", "Legacy UI"),
        }

        for page, labels in expected_by_page.items():
            html = render_preview_html(page, state)
            for label in labels:
                with self.subTest(page=page, label=label):
                    self.assertIn(label, html)
            self.assertIn("Safety", html)
            self.assertIn("No direct device execution from Modern UI", html)

    def test_guarded_flash_handoff_requires_confirmation_and_delegates_to_legacy_only(self):
        action = action_by_id("guarded_legacy_flash_flow")

        self.assertIsNotNone(action)
        self.assertEqual(GUARDED_LEGACY_FLOW, action.safety_level)
        self.assertTrue(action.enabled)
        self.assertTrue(action.requires_confirmation)
        self.assertTrue(action.dangerous)
        self.assertEqual(LEGACY_UI_DELEGATE, action.delegate)
        self.assertTrue(is_legacy_handoff(action))
        self.assertIn("Existing guarded legacy flow", action.confirmation_body)
        self.assertIn("Modern UI does not execute device commands directly", action.confirmation_body)
        self.assertIn("No flash command is run from Modern UI.", action.confirmation_body)

    def test_disabled_mutating_actions_remain_disabled(self):
        for action_id in ("disabled_reboot", "disabled_wipe", "disabled_slot_switch"):
            with self.subTest(action_id=action_id):
                action = action_by_id(action_id)
                self.assertIsNotNone(action)
                self.assertEqual(DISABLED, action.safety_level)
                self.assertFalse(action.enabled)
                self.assertFalse(action.requires_confirmation)
                self.assertFalse(action.delegate)

    def test_webview_bridge_intercepts_navigation_without_script_bridge(self):
        for expected in (
            "EVT_WEBVIEW_NAVIGATING",
            "action_from_url",
            "event.Veto()",
            "wx.MessageDialog",
            "wx.NO_DEFAULT",
            "_confirm_guarded_action",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.web_source)

        for forbidden in ("AddScriptMessageHandler", "RunScript", "javascript:", "onclick="):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.web_source)

    def test_wizard_template_exposes_guarded_handoff_copy(self):
        state = ModernReadonlyState(
            device=ModernDeviceState(),
            firmware=ModernFirmwareState(),
            tools=ModernToolState(),
            warnings=(),
        )
        html = render_preview_html("wizard", state)

        for expected in (
            "Guarded legacy flow · confirmation required",
            "Modern UI prepares the plan; execution is delegated to existing guarded PixelFlasher flow.",
            "No flash command is run from Modern UI.",
            "Continue to Guarded Legacy Flash Flow",
            "pixelflasher://action/guarded_legacy_flash_flow",
            "no direct execution",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, html)

    def test_templates_render_loaded_readonly_state(self):
        state = ModernReadonlyState(
            device=ModernDeviceState(
                display_name="Pixel 6",
                serial="abc123",
                codename="oriole",
                product="oriole_beta",
                android_version="15",
                build_id="AP2A.240605.024",
                security_patch="2024-06-05",
                active_slot="b",
            ),
            firmware=ModernFirmwareState(path="oriole-factory-ap2a.zip", package_type="factory", build_id="oriole-factory", verified=True),
            tools=ModernToolState(platform_tools_path="/opt/platform-tools"),
            warnings=("Loaded state warning.",),
            flash=ModernFlashOptionsState(flash_mode="keepData", data_behavior="Keep data", slot_behavior="Inactive slot", no_reboot=True),
            backups=ModernBackupState(total_count=2, latest_label="2024-06-01 · AP2A", location="/storage/emulated/0/Download"),
            downloads=ModernDownloadState(update_check=True, image_catalog_status="loaded", update_frequency="every 7 days", last_checked="1700000000"),
            settings=ModernSettingsState(language="es", advanced_options=True, verbose=True, phone_path="/storage/emulated/0/Download"),
        )

        dashboard_html = render_preview_html("dashboard", state)
        shell_html = render_preview_html("shell", state)
        wizard_html = render_preview_html("wizard", state)
        backups_html = render_preview_html("backups", state)
        downloads_html = render_preview_html("downloads", state)
        settings_html = render_preview_html("settings", state)

        for expected in ("AP2A.240605.024", "2024-06-05", "Inactive slot", "2024-06-01 · AP2A"):
            with self.subTest(expected=expected):
                self.assertIn(expected, dashboard_html)
        for expected in ("oriole", "oriole_beta", "Loaded Flash Options", "Keep data"):
            with self.subTest(expected=expected):
                self.assertIn(expected, shell_html)
        self.assertIn("Loaded Plan Inputs", wizard_html)
        self.assertIn("keepData", wizard_html)
        self.assertIn("2", backups_html)
        self.assertIn("/storage/emulated/0/Download", backups_html)
        self.assertIn("every 7 days", downloads_html)
        self.assertIn("es", settings_html)

    def test_template_status_bar_renders_safe_action_feedback(self):
        state = ModernReadonlyState(
            device=ModernDeviceState(),
            firmware=ModernFirmwareState(),
            tools=ModernToolState(),
            warnings=(),
        )

        html = render_preview_html(
            "dashboard",
            state,
            status_message="Guarded handoff canceled. No legacy flow opened.",
            status_tone="warning",
        )
        escaped_html = render_preview_html(
            "dashboard",
            state,
            status_message="<blocked action>",
            status_tone="blocked",
        )

        self.assertIn("Guarded handoff canceled. No legacy flow opened.", html)
        self.assertIn('class="statusbar warning"', html)
        self.assertIn("Modern UI · Safe by Default", html)
        self.assertIn("&lt;blocked action&gt;", escaped_html)
        self.assertNotIn("<blocked action>", escaped_html)
        self.assertIn('class="statusbar blocked"', escaped_html)

    def test_modern_preview_sources_avoid_execution_patterns(self):
        forbidden = (
            "subprocess.run",
            "subprocess.Popen",
            "os.system",
            "adb ",
            "fastboot",
            "flash_all",
            "wipe_data",
            "delete_all",
            "reboot_",
            "set_active_slot",
            "get_phone(",
        )

        for source_name, source in (
            ("modern_action_bridge", self.bridge_source),
            ("modern_action_feedback", self.feedback_source),
            ("modern_preview_web", self.web_source),
            ("modern_preview_templates", self.template_source),
        ):
            for snippet in forbidden:
                with self.subTest(source_name=source_name, snippet=snippet):
                    self.assertNotIn(snippet, source)


if __name__ == "__main__":
    unittest.main()
