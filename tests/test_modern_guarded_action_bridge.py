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
MAIN_SOURCE = Path("Main.py")
MAGISK_DOWNLOADS_SOURCE = Path("magisk_downloads.py")


class ModernGuardedActionBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bridge_source = MODERN_BRIDGE_SOURCE.read_text(encoding="utf-8")
        cls.feedback_source = MODERN_FEEDBACK_SOURCE.read_text(encoding="utf-8")
        cls.web_source = MODERN_WEB_SOURCE.read_text(encoding="utf-8")
        cls.template_source = MODERN_TEMPLATE_SOURCE.read_text(encoding="utf-8")
        cls.main_source = MAIN_SOURCE.read_text(encoding="utf-8")
        cls.magisk_downloads_source = MAGISK_DOWNLOADS_SOURCE.read_text(encoding="utf-8")

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
                "select_custom_rom",
                "process_firmware",
                "process_custom_rom",
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
            "shell": ("Device", "Firmware"),
            "wizard": ("Flash Wizard", "Step 1: Device &amp; Firmware", "Flash Summary", "Process Package", "Custom ROM"),
            "backups": ("Backups", "Backup State", "Backup Actions", "No backups loaded"),
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
        self.assertIn("Review every confirmation", action.confirmation_body)

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
            "action_started_feedback",
            "wx.CallLater",
            "_invoke_engine_action",
            "_preflight_action",
            "_align_state_host_for_dialogs",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.web_source)

        for forbidden in ("AddScriptMessageHandler", "RunScript", "javascript:", "onclick="):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.web_source)

    def test_tools_catalog_exposes_actionable_allow_listed_tiles(self):
        state = ModernReadonlyState(
            device=ModernDeviceState(),
            firmware=ModernFirmwareState(),
            tools=ModernToolState(),
            warnings=(),
        )
        html = render_preview_html("tools", state)

        expected_actions = (
            "patch_boot",
            "create_support_package",
            "rooting_app",
            "magisk_modules",
            "partition_manager",
        )
        for action_id in expected_actions:
            with self.subTest(action_id=action_id):
                self.assertIn(action_url(action_id), html)
                self.assertIsNotNone(action_by_id(action_id))
        self.assertIn('class="tile action-tile"', html)
        self.assertIn('class="tile-chevron"', html)
        self.assertNotIn(action_url("scan_devices"), html)
        self.assertNotIn("Device Scan", html)

    def test_tools_page_avoids_non_actionable_header_noise(self):
        state = ModernReadonlyState(
            device=ModernDeviceState(display_name="Pixel 9 Pro XL"),
            firmware=ModernFirmwareState(),
            tools=ModernToolState(adb_path="adb", fastboot_path="fastboot", platform_tools_path="platform-tools"),
            warnings=(),
        )
        html = render_preview_html("tools", state)

        for removed in (
            "Tool groups",
            "Navigation",
            "Workspace",
            "Loaded Tool State",
            "Tool Availability Summary",
            "Device Context",
            "Platform Tools</h2>",
            "Configured path",
            "<h2>Status</h2>",
            "Advanced Operations",
            "Open PixelFlasher tools from the modern workspace.",
        ):
            with self.subTest(removed=removed):
                self.assertNotIn(removed, html)
        self.assertIn("Root, support, and partition utilities.", html)

    def test_tool_actions_use_preflight_without_new_command_paths(self):
        for expected in (
            "DEVICE_REQUIRED_ACTIONS",
            "FIRMWARE_REQUIRED_ACTIONS",
            "CUSTOM_ROM_REQUIRED_ACTIONS",
            "BOOT_IMAGE_REQUIRED_ACTIONS",
            "PLATFORM_TOOLS_REQUIRED_ACTIONS",
            "Connect and scan a device first.",
            "Select and process a firmware or boot image first.",
            "Select a custom ROM archive first.",
            "Select a boot image first.",
            "Set up Android Platform Tools first.",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.web_source)

    def test_legacy_tool_dialogs_can_use_modern_dialog_parent(self):
        for expected in (
            "def _dialog_parent(self):",
            "def _ensure_runtime_device_loaded(self):",
            "def _select_runtime_phone(self, device_id):",
            "def update_custom_rom_selection(self, path):",
            'getattr(self, "_modern_dialog_parent", self)',
            "wx.FileDialog(self._dialog_parent()",
            "MagiskModules(parent=self._dialog_parent(), config=self.config)",
            "MagiskDownloads(self._dialog_parent())",
            "BackupManager(self._dialog_parent())",
            "PartitionManager(self._dialog_parent())",
            "GoogleImagesPopupMenu(parent",
            "parent.PopupMenu(menu)",
            "self._ensure_runtime_device_loaded()",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.main_source)

        for expected in (
            "_modern_dialog_parent",
            "def config(self):",
            "def get_progress_window(self):",
            "def toast(self, title: str, message: str)",
            "def clear_device_selection(self)",
            "select_custom_rom_file",
            "def _on_spin(self, state",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.web_source)

    def test_rooting_app_dialog_keeps_device_selection_and_selects_first_row(self):
        for expected in (
            "if self.list.ItemCount:",
            "self._select_apk_row(0)",
            "def _select_apk_row(self, row):",
            "self.currentItem = row",
            "self.install_button.Enable(True)",
            "self.download_button.Enable(True)",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.magisk_downloads_source)

        self.assertNotIn("self.Parent.clear_device_selection()", self.magisk_downloads_source)

    def test_wizard_template_exposes_real_workflow_actions(self):
        state = ModernReadonlyState(
            device=ModernDeviceState(),
            firmware=ModernFirmwareState(),
            tools=ModernToolState(),
            warnings=(),
        )
        html = render_preview_html("wizard", state)

        for expected in (
            "Official / OTA",
            "Custom ROM",
            "Process Package",
            "Flash Device",
            "Set Up Platform Tools",
            "pixelflasher://action/select_firmware",
            "pixelflasher://action/select_custom_rom",
            "pixelflasher://action/process_firmware",
            "pixelflasher://action/flash_device",
            "pixelflasher://action/setup_platform_tools",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, html)

        custom_state = ModernReadonlyState(
            device=ModernDeviceState(),
            firmware=ModernFirmwareState(path="raven-custom-rom.zip", package_type="custom_rom"),
            tools=ModernToolState(),
            warnings=(),
        )
        custom_html = render_preview_html("wizard", custom_state)
        self.assertIn("Process ROM", custom_html)
        self.assertIn("pixelflasher://action/process_custom_rom", custom_html)

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
            warnings=("State warning.",),
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
        for expected in ("Pixel 6", "oriole-factory-ap2a.zip", "factory", "b"):
            with self.subTest(expected=expected):
                self.assertIn(expected, shell_html)
        self.assertIn("Flash Plan", wizard_html)
        self.assertIn("keepData", wizard_html)
        self.assertIn("2", backups_html)
        self.assertIn("/storage/emulated/0/Download", backups_html)
        self.assertIn("oriole-factory-ap2a.zip", downloads_html)
        self.assertIn("Official Android", downloads_html)
        self.assertIn("verified", downloads_html)
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
