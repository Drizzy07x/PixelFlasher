import re
import unittest
from pathlib import Path

from ui.pages.modern_action_bridge import (
    DISABLED,
    GUARDED_FLOW,
    action_by_id,
    action_from_url,
    action_url,
    is_engine_action,
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
        self.assertEqual("pixelflasher://action/flash_device", action_url("flash_device"))
        self.assertIs(action_by_id("flash_device"), action_from_url(action_url("flash_device")))

    def test_unknown_and_external_action_urls_are_rejected(self):
        for url in (
            "pixelflasher://action/unknown_action",
            "pixelflasher://other/flash_device",
            "https://example.invalid/action/flash_device",
            "http://example.invalid/action/flash_device",
            "file:///tmp/flash_device",
            "javascript:flash_device",
            "pixelflasher://action/flash_device?confirm=yes",
            "pixelflasher://action/flash_device#confirm",
            "pixelflasher://action/flash_device;run",
        ):
            with self.subTest(url=url):
                self.assertIsNone(action_from_url(url))

    def test_required_actions_are_allow_listed(self):
        actions = {action.id for action in modern_actions()}

        self.assertEqual(
            {
                "open_modern_dashboard",
                "open_modern_flash_wizard",
                "open_modern_shell",
                "open_backups",
                "open_downloads",
                "open_settings",
                "open_tools",
                "open_safety",
                "open_about",
                "scan_devices",
                "setup_platform_tools",
                "select_firmware",
                "process_firmware",
                "flash_device",
                "patch_boot",
                "create_support_package",
                "backup_manager",
                "firmware_downloads",
                "settings_dialog",
                "rooting_app",
                "magisk_modules",
                "partition_manager",
                "disabled_reboot",
                "disabled_wipe",
                "disabled_slot_switch",
            },
            actions,
        )

        self.assertEqual(len(actions), len(modern_actions()))

    def test_platform_tools_setup_action_is_confirmed_internal_setup(self):
        action = action_by_id("setup_platform_tools")

        self.assertIsNotNone(action)
        self.assertTrue(action.enabled)
        self.assertTrue(action.requires_confirmation)
        self.assertFalse(action.dangerous)
        self.assertEqual("_setup_platform_tools", action.delegate)
        self.assertIn("Android Platform Tools", action.description)
        self.assertIn("No flash", action.confirmation_body)

    def test_all_modern_pages_render_static_local_content(self):
        state = ModernReadonlyState(
            device=ModernDeviceState(),
            firmware=ModernFirmwareState(),
            tools=ModernToolState(),
            warnings=(),
        )

        expected_by_page = {
            "dashboard": ("Modern UI", "Connected Device", "Quick Actions", "Flash Device"),
            "shell": ("Modern Shell", "Device State Overview", "Firmware Context", "Available Actions"),
            "wizard": ("Flash Wizard", "Step 1: Device &amp; Firmware", "Flash Summary", "Process Firmware"),
            "backups": ("Backups", "Backup Summary", "Backup Actions", "No backups loaded"),
            "downloads": ("Downloads", "Firmware Downloads", "Download Actions", "Rooting App"),
            "settings": ("Settings", "General Settings", "Settings Actions", "Open Settings"),
            "tools": ("Tools", "Tool Catalog", "Advanced Operations", "Partition Manager"),
            "safety": ("Safety", "Safety Boundary", "Operation Policy", "Confirmations"),
            "about": ("About PixelFlasher", "Modern UI Status", "Application Engine", "PixelFlasher"),
        }

        for page, labels in expected_by_page.items():
            html = render_preview_html(page, state)
            for label in labels:
                with self.subTest(page=page, label=label):
                    self.assertIn(label, html)
            self.assertIn("pixelflasher://action/", html)

    def test_flash_action_requires_confirmation_and_delegates_to_engine_only(self):
        action = action_by_id("flash_device")

        self.assertIsNotNone(action)
        self.assertEqual(GUARDED_FLOW, action.safety_level)
        self.assertTrue(action.enabled)
        self.assertTrue(action.requires_confirmation)
        self.assertTrue(action.dangerous)
        self.assertEqual("_on_flash", action.delegate)
        self.assertTrue(is_engine_action(action))
        self.assertIn("PixelFlasher will run", action.confirmation_body)
        self.assertIn("Review every prompt", action.confirmation_body)

    def test_disabled_mutating_shortcuts_remain_disabled_until_state_exists(self):
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

    def test_wizard_template_exposes_real_workflow_actions(self):
        state = ModernReadonlyState(
            device=ModernDeviceState(),
            firmware=ModernFirmwareState(),
            tools=ModernToolState(),
            warnings=(),
        )
        html = render_preview_html("wizard", state)

        for expected in (
            "Select Firmware",
            "Process Firmware",
            "Flash Device",
            "Set Up Platform Tools",
            "pixelflasher://action/select_firmware",
            "pixelflasher://action/process_firmware",
            "pixelflasher://action/flash_device",
            "pixelflasher://action/setup_platform_tools",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, html)

    def test_rendered_action_urls_are_allow_listed(self):
        state = ModernReadonlyState(
            device=ModernDeviceState(),
            firmware=ModernFirmwareState(),
            tools=ModernToolState(),
            warnings=(),
        )

        for page in ("dashboard", "shell", "wizard", "backups", "downloads", "settings", "tools", "safety", "about"):
            html = render_preview_html(page, state)
            action_ids = re.findall(r"pixelflasher://action/([a-z0-9_]+)", html)
            self.assertTrue(action_ids, page)
            for action_id in action_ids:
                with self.subTest(page=page, action_id=action_id):
                    self.assertIsNotNone(action_by_id(action_id))

    def test_templates_render_loaded_state(self):
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
            tools=ModernToolState(adb_path="/opt/platform-tools/adb", fastboot_path="/opt/platform-tools/fastboot", platform_tools_path="/opt/platform-tools"),
            warnings=("Loaded state warning.",),
            flash=ModernFlashOptionsState(flash_mode="keepData", data_behavior="Keep data", slot_behavior="Inactive slot", no_reboot=True),
            backups=ModernBackupState(total_count=2, latest_label="2024-06-01 - AP2A", location="/storage/emulated/0/Download"),
            downloads=ModernDownloadState(update_check=True, image_catalog_status="loaded", update_frequency="every 7 days", last_checked="1700000000"),
            settings=ModernSettingsState(language="es", advanced_options=True, verbose=True, custom_rom_options=True, phone_path="/storage/emulated/0/Download"),
        )

        dashboard_html = render_preview_html("dashboard", state)
        shell_html = render_preview_html("shell", state)
        wizard_html = render_preview_html("wizard", state)
        backups_html = render_preview_html("backups", state)
        downloads_html = render_preview_html("downloads", state)
        settings_html = render_preview_html("settings", state)

        for expected in ("AP2A.240605.024", "2024-06-05", "Inactive slot", "2024-06-01 - AP2A"):
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

    def test_template_status_bar_escapes_feedback(self):
        state = ModernReadonlyState(
            device=ModernDeviceState(),
            firmware=ModernFirmwareState(),
            tools=ModernToolState(),
            warnings=(),
        )

        html = render_preview_html("dashboard", state, status_message="Flash Device: canceled.", status_tone="warning")
        escaped_html = render_preview_html("dashboard", state, status_message="<blocked action>", status_tone="blocked")

        self.assertIn("Flash Device: canceled.", html)
        self.assertIn('class="statusbar warning"', html)
        self.assertIn("Modern UI", html)
        self.assertIn("&lt;blocked action&gt;", escaped_html)
        self.assertNotIn("<blocked action>", escaped_html)
        self.assertIn('class="statusbar blocked"', escaped_html)

    def test_modern_sources_avoid_raw_execution_patterns(self):
        forbidden = (
            "subprocess.run",
            "subprocess.Popen",
            "os.system",
            "adb shell",
            "fastboot ",
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
