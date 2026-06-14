import unittest
from pathlib import Path

from ui.pages.modern_action_bridge import (
    DISABLED,
    GUARDED_LEGACY_FLOW,
    LEGACY_UI_DELEGATE,
    OPEN_LEGACY,
    PREVIEW_ONLY,
    action_by_id,
    action_from_url,
    action_url,
    is_legacy_handoff,
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

    def test_startup_prefers_modern_with_legacy_fallback(self):
        self.assertIn("launch_modern_primary", self.pixelflasher_source)
        self.assertIn("OPEN_LEGACY_EXIT_CODE", self.pixelflasher_source)
        self.assertIn("Main.main()", self.pixelflasher_source)
        self.assertIn("--legacy-ui", self.pixelflasher_source)
        self.assertIn("PIXELFLASHER_LEGACY_UI", self.pixelflasher_source)

    def test_primary_wrapper_opens_dashboard_webview_only(self):
        self.assertIn('create_modern_preview_frame(page="dashboard"', self.primary_source)
        self.assertIn("is_webview_available()", self.primary_source)
        self.assertIn("OPEN_LEGACY_EXIT_CODE", self.primary_source)
        self.assertNotIn("Main.main()", self.primary_source)

    def test_webview_exposes_classic_legacy_menu_without_script_bridge(self):
        self.assertIn("Open Classic PixelFlasher", self.web_source)
        self.assertIn("Open existing guarded legacy flow", self.web_source)
        self.assertIn("wx.EVT_MENU", self.web_source)
        self.assertIn("EVT_WEBVIEW_NAVIGATING", self.web_source)
        self.assertIn("action_from_url", self.web_source)
        self.assertIn("wx.MessageDialog", self.web_source)
        self.assertIn("wx.NO_DEFAULT", self.web_source)
        self.assertNotIn("AddScriptMessageHandler", self.web_source)
        self.assertNotIn("RunScript", self.web_source)

    def test_webview_reports_safe_action_feedback(self):
        for helper in (
            "blocked_navigation_feedback",
            "disabled_action_feedback",
            "guarded_action_canceled_feedback",
            "guarded_action_opening_feedback",
            "preview_action_feedback",
        ):
            with self.subTest(helper=helper):
                self.assertIn(helper, self.web_source)

        for message in (
            "Blocked unknown or external navigation. No action was run.",
            "disabled in Modern UI. No device changes.",
            "canceled. No legacy flow opened.",
            "opening existing guarded legacy flow.",
            "preview page opened. No device changes.",
        ):
            with self.subTest(message=message):
                self.assertIn(message, self.feedback_source)

    def test_action_bridge_classifies_all_expected_actions(self):
        actions = {action.id: action for action in modern_actions()}

        for action_id in (
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
        ):
            with self.subTest(action_id=action_id):
                self.assertIn(action_id, actions)
                self.assertIs(action_by_id(action_id), actions[action_id])

        levels = {action.safety_level for action in actions.values()}
        self.assertEqual({PREVIEW_ONLY, OPEN_LEGACY, GUARDED_LEGACY_FLOW, DISABLED}, levels)

    def test_dangerous_actions_are_disabled_or_guarded(self):
        actions = {action.id: action for action in modern_actions()}

        for action_id in ("guarded_legacy_flash_flow", "guarded_legacy_patch_flow", "guarded_legacy_support_zip"):
            with self.subTest(action_id=action_id):
                action = actions[action_id]
                self.assertEqual(GUARDED_LEGACY_FLOW, action.safety_level)
                self.assertTrue(action.enabled)
                self.assertTrue(action.requires_confirmation)
                self.assertTrue(action.dangerous)
                self.assertEqual(LEGACY_UI_DELEGATE, action.delegate)
                self.assertTrue(is_legacy_handoff(action))
                self.assertIn("Existing guarded legacy flow", action.confirmation_body)
                self.assertIn("Modern UI does not execute device commands directly", action.confirmation_body)

        for action_id in ("disabled_reboot", "disabled_wipe", "disabled_slot_switch"):
            with self.subTest(action_id=action_id):
                action = actions[action_id]
                self.assertEqual(DISABLED, action.safety_level)
                self.assertFalse(action.enabled)
                self.assertFalse(action.delegate)

    def test_custom_action_urls_are_allow_listed(self):
        action = action_from_url(action_url("guarded_legacy_flash_flow"))

        self.assertIsNotNone(action)
        self.assertEqual("guarded_legacy_flash_flow", action.id)
        self.assertIsNone(action_from_url("pixelflasher://action/not_allowed"))
        self.assertIsNone(action_from_url("file:///tmp/not_allowed"))
        self.assertIsNone(action_from_url("mailto:test@example.invalid"))

    def test_modern_primary_sources_avoid_execution_patterns(self):
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
            ("modern_primary_app", self.primary_source),
            ("modern_action_bridge", self.bridge_source),
            ("modern_action_feedback", self.feedback_source),
            ("modern_preview_web", self.web_source),
            ("modern_preview_templates", self.template_source),
        ):
            for snippet in forbidden:
                with self.subTest(source_name=source_name, snippet=snippet):
                    self.assertNotIn(snippet, source)

    def test_modern_templates_describe_guarded_and_blocked_execution(self):
        for label in (
            "Modern UI · Safe by Default",
            "Open Classic PixelFlasher",
            "Existing guarded legacy flow",
            "open_modern_dashboard",
            "open_backups_preview",
            "open_safety_preview",
            "action_url(\"guarded_legacy_flash_flow\")",
            "Continue to Guarded Legacy Flash Flow",
            "Guarded legacy flow · confirmation required",
            "No flash command is run from Modern UI.",
            "Planning preview · execution delegated to guarded legacy flow.",
            "Guarded Legacy Handoff",
            "No direct device execution from Modern UI",
        ):
            with self.subTest(label=label):
                self.assertIn(label, self.template_source)


if __name__ == "__main__":
    unittest.main()
