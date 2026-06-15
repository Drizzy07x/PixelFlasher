import unittest
from pathlib import Path

from ui.pages.modern_action_bridge import (
    DISABLED,
    GUARDED_FLOW,
    INTERNAL_FLOW,
    NAVIGATION,
    action_by_id,
    action_from_url,
    action_url,
    is_engine_action,
    modern_actions,
)


PIXELFLASHER_SOURCE = Path("PixelFlasher.py")
MODERN_PRIMARY_SOURCE = Path("ui/pages/modern_primary_app.py")
MODERN_BRIDGE_SOURCE = Path("ui/pages/modern_action_bridge.py")
MODERN_FEEDBACK_SOURCE = Path("ui/pages/modern_action_feedback.py")
MODERN_WEB_SOURCE = Path("ui/pages/modern_preview_web.py")
MODERN_TEMPLATE_SOURCE = Path("ui/pages/modern_preview_templates.py")


class ModernPrimaryExperienceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pixelflasher_source = PIXELFLASHER_SOURCE.read_text(encoding="utf-8")
        cls.primary_source = MODERN_PRIMARY_SOURCE.read_text(encoding="utf-8")
        cls.bridge_source = MODERN_BRIDGE_SOURCE.read_text(encoding="utf-8")
        cls.feedback_source = MODERN_FEEDBACK_SOURCE.read_text(encoding="utf-8")
        cls.web_source = MODERN_WEB_SOURCE.read_text(encoding="utf-8")
        cls.template_source = MODERN_TEMPLATE_SOURCE.read_text(encoding="utf-8")

    def test_startup_uses_modern_ui_as_primary_experience(self):
        self.assertIn("launch_modern_primary", self.pixelflasher_source)
        self.assertIn("_run_modern_primary(sys.argv)", self.pixelflasher_source)
        self.assertNotIn("Main.main()", self.pixelflasher_source)
        self.assertNotIn("--legacy-ui", self.pixelflasher_source)
        self.assertNotIn("PIXELFLASHER_LEGACY_UI", self.pixelflasher_source)

    def test_primary_wrapper_opens_dashboard_with_hidden_engine(self):
        self.assertIn('create_modern_preview_frame(page="dashboard"', self.primary_source)
        self.assertIn("state_host=engine", self.primary_source)
        self.assertIn("PIXELFLASHER_MODERN_ENGINE", self.primary_source)
        self.assertIn("Main.PixelFlasher", self.primary_source)
        self.assertNotIn("OPEN_LEGACY_EXIT_CODE", self.primary_source)

    def test_webview_has_no_classic_menu_or_script_bridge(self):
        self.assertNotIn("Open Classic PixelFlasher", self.web_source)
        self.assertNotIn("wx.EVT_MENU", self.web_source)
        self.assertNotIn("on_open_legacy", self.web_source)
        self.assertIn("EVT_WEBVIEW_NAVIGATING", self.web_source)
        self.assertIn("action_from_url", self.web_source)
        self.assertIn("wx.MessageDialog", self.web_source)
        self.assertIn("wx.NO_DEFAULT", self.web_source)
        self.assertNotIn("AddScriptMessageHandler", self.web_source)
        self.assertNotIn("RunScript", self.web_source)

    def test_action_bridge_classifies_navigation_and_engine_actions(self):
        actions = {action.id: action for action in modern_actions()}
        action_ids = [action.id for action in modern_actions()]

        self.assertEqual(len(action_ids), len(set(action_ids)))

        for action_id in (
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
        ):
            with self.subTest(action_id=action_id):
                self.assertIn(action_id, actions)
                self.assertIs(action_by_id(action_id), actions[action_id])

        levels = {action.safety_level for action in actions.values()}
        self.assertEqual({NAVIGATION, INTERNAL_FLOW, GUARDED_FLOW, DISABLED}, levels)

        setup = actions["setup_platform_tools"]
        self.assertEqual(INTERNAL_FLOW, setup.safety_level)
        self.assertTrue(setup.requires_confirmation)
        self.assertEqual("_setup_platform_tools", setup.delegate)

    def test_dangerous_actions_require_confirmation_and_delegate_to_engine(self):
        actions = {action.id: action for action in modern_actions()}

        expected_delegates = {
            "flash_device": "_on_flash",
            "patch_boot": "_on_magisk_patch_boot",
            "create_support_package": "_on_support_zip",
            "partition_manager": "_on_partition_manager",
        }
        for action_id, delegate in expected_delegates.items():
            with self.subTest(action_id=action_id):
                action = actions[action_id]
                self.assertEqual(GUARDED_FLOW, action.safety_level)
                self.assertTrue(action.enabled)
                self.assertTrue(action.requires_confirmation)
                self.assertTrue(action.dangerous)
                self.assertEqual(delegate, action.delegate)
                self.assertTrue(is_engine_action(action))
                self.assertIn("Review every prompt", action.confirmation_body)

        for action_id in ("disabled_reboot", "disabled_wipe", "disabled_slot_switch"):
            with self.subTest(action_id=action_id):
                action = actions[action_id]
                self.assertEqual(DISABLED, action.safety_level)
                self.assertFalse(action.enabled)
                self.assertFalse(action.delegate)

    def test_custom_action_urls_are_allow_listed(self):
        action = action_from_url(action_url("flash_device"))

        self.assertIsNotNone(action)
        self.assertEqual("flash_device", action.id)
        self.assertIsNone(action_from_url("pixelflasher://action/not_allowed"))
        self.assertIsNone(action_from_url("file:///tmp/not_allowed"))
        self.assertIsNone(action_from_url("mailto:test@example.invalid"))
        self.assertIsNone(action_from_url("pixelflasher://action/flash_device?confirm=yes"))
        self.assertIsNone(action_from_url("pixelflasher://action/flash_device#run"))

    def test_modern_primary_sources_avoid_raw_execution_patterns(self):
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
            ("modern_primary_app", self.primary_source),
            ("modern_action_bridge", self.bridge_source),
            ("modern_action_feedback", self.feedback_source),
            ("modern_preview_web", self.web_source),
            ("modern_preview_templates", self.template_source),
        ):
            for snippet in forbidden:
                with self.subTest(source_name=source_name, snippet=snippet):
                    self.assertNotIn(snippet, source)

    def test_templates_expose_modern_product_actions(self):
        for label in (
            "Modern UI",
            "Flash Device",
            "Patch Boot",
            "Select Firmware",
            "Process Firmware",
            "action_url(\"flash_device\")",
            "patch_boot",
        ):
            with self.subTest(label=label):
                self.assertIn(label, self.template_source)


if __name__ == "__main__":
    unittest.main()
