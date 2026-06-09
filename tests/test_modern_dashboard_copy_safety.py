import unittest
from pathlib import Path

try:
    from ui.pages.dashboard import (
        _dashboard_action_icon,
        _dashboard_action_button_label,
        _dashboard_backup_rows,
        _dashboard_preview_context_rows,
        _dashboard_partition_rows,
        _dashboard_quick_actions,
        _dashboard_slot_rows,
    )
except ModuleNotFoundError as exc:
    if exc.name == "wx":
        _dashboard_action_icon = None
        _dashboard_action_button_label = None
        _dashboard_backup_rows = None
        _dashboard_preview_context_rows = None
        _dashboard_partition_rows = None
        _dashboard_quick_actions = None
        _dashboard_slot_rows = None
    else:
        raise

from ui.pages.modern_preview_copy import (
    DASHBOARD_PREVIEW_ACTIONS,
    MODERN_PREVIEW_FOOTER,
    MODERN_PREVIEW_STATUS,
    MODERN_PREVIEW_SUBTITLE,
    MODERN_PREVIEW_TITLE,
    NAV_ICONS,
    NAV_ITEMS,
    PREVIEW_BADGES,
    SAFETY_BOUNDARY_LINES,
)
from ui.pages.modern_readonly_state import ModernDeviceState, ModernFirmwareState, ModernReadonlyState, ModernToolState


DASHBOARD_SOURCE = Path("ui/pages/dashboard.py")
TEMPLATE_SOURCE = Path("ui/pages/modern_preview_templates.py")


class ModernDashboardCopySafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dashboard_source = DASHBOARD_SOURCE.read_text(encoding="utf-8")
        cls.template_source = TEMPLATE_SOURCE.read_text(encoding="utf-8")

    def test_shared_preview_header_copy_is_explicit(self):
        self.assertEqual("Modern UI – Preview", MODERN_PREVIEW_TITLE)
        self.assertIn("No device changes", MODERN_PREVIEW_SUBTITLE)
        self.assertIn("No flashing", MODERN_PREVIEW_SUBTITLE)
        self.assertIn("No patches", MODERN_PREVIEW_SUBTITLE)
        self.assertIn("PREVIEW ONLY", PREVIEW_BADGES)
        self.assertIn("Read-Only", PREVIEW_BADGES)
        self.assertIn("No Device Changes", PREVIEW_BADGES)
        self.assertEqual("Modern UI: Preview-Only Mode", MODERN_PREVIEW_STATUS)
        self.assertEqual("No device changes will be made.", MODERN_PREVIEW_FOOTER)

    def test_safety_boundary_copy_covers_preview_limits(self):
        safety_text = "\n".join(SAFETY_BOUNDARY_LINES)

        for expected in (
            "No flashing, patching, or firmware writing.",
            "No ADB or Fastboot command execution.",
            "No reboot, wipe, slot switching, or device changes.",
            "Preview-only. Read-only state. Legacy flows guarded.",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, safety_text)

    def test_navigation_copy_marks_preview_and_readonly_sections(self):
        labels = {key: f"{title} {detail}" for key, title, detail in NAV_ITEMS}

        self.assertIn("Overview & device summary", labels["dashboard"])
        self.assertIn("Read-only device state", labels["shell"])
        self.assertIn("Preview & plan only", labels["wizard"])
        self.assertIn("Browse restore preview", labels["backups"])
        self.assertIn("Firmware updates", labels["downloads"])
        self.assertIn("Utilities preview", labels["tools"])
        self.assertNotIn("Browse & restore", labels["backups"])
        self.assertNotIn("Firmware & updates", labels["downloads"])
        self.assertIn("dashboard", NAV_ICONS)
        self.assertIn("wizard", NAV_ICONS)
        self.assertIn("about", NAV_ICONS)
        self.assertIn("Version & info", labels["about"])

    def test_preview_action_cards_do_not_claim_execution(self):
        text = "\n".join(f"{title}: {body}" for title, body in DASHBOARD_PREVIEW_ACTIONS)

        self.assertIn("Flash Wizard (Preview)", text)
        self.assertIn("Modern Shell (Read-Only)", text)
        self.assertIn("Downloads", text)
        self.assertNotIn("Flash Device", text)
        self.assertNotIn("Patch Boot", text)

    def test_dashboard_layout_badges_reinforce_readonly_boundaries(self):
        for expected in (
            "No slot switching",
            "No partition writes",
            "Restore stays guarded",
            "Preview-Only Mode",
            "Use legacy selector",
            "No file is opened by Modern UI.",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.dashboard_source)

    def test_dashboard_uses_shared_mockup_visual_helpers(self):
        for expected in (
            "preview_style.sidebar_container",
            "preview_style.sidebar_brand",
            "preview_style.sidebar_row",
            "preview_style.hero_device_card",
            "preview_style.device_glyph_panel",
            "preview_style.icon_action_tile",
            "preview_style.safety_boundary_card",
            "preview_style.notice_card",
            "preview_style.info_row",
            "preview_style.badge",
            "preview_style.bottom_status_bar",
            "NAV_ICONS",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.dashboard_source)

    def test_webview_dashboard_template_matches_preview_copy_boundaries(self):
        from ui.pages.modern_preview_templates import render_preview_html
        from ui.pages.modern_readonly_state import ModernDeviceState, ModernFirmwareState, ModernReadonlyState, ModernToolState

        html = render_preview_html(
            "dashboard",
            ModernReadonlyState(
                device=ModernDeviceState(),
                firmware=ModernFirmwareState(),
                tools=ModernToolState(),
                warnings=(),
            ),
        )

        for expected in (
            "Modern UI – Preview (Read-Only)",
            "Safe by default. No device changes. No flashing. No patches.",
            "PREVIEW ONLY",
            "Read-Only",
            "No Device Changes",
            "Connected Device (Read-Only)",
            "Quick Actions",
            "Safety Boundary",
            "No flashing, patching, or firmware writing.",
            "No ADB or Fastboot command execution.",
            "No reboot, wipe, slot switching, or device changes.",
            "Preview-only. Read-only state. Legacy flows guarded.",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, html)

    @unittest.skipIf(_dashboard_preview_context_rows is None, "wxPython is not available")
    def test_dashboard_preview_selector_context_is_readonly(self):
        rows = dict(_dashboard_preview_context_rows())

        self.assertEqual("already-loaded state", rows["Preview source"])
        self.assertEqual("legacy UI remains source", rows["State updates"])
        self.assertEqual("guarded or disabled", rows["Actions"])

    @unittest.skipIf(_dashboard_quick_actions is None, "wxPython is not available")
    def test_quick_action_titles_are_legacy_explicit(self):
        titles = {action.key: action.title for action in _dashboard_quick_actions()}

        self.assertEqual("Patch (Guarded Legacy)", titles["patch"])
        self.assertEqual("Flash (Guarded Legacy)", titles["flash"])
        self.assertEqual("Device Scan (Guarded Legacy)", titles["scan"])
        self.assertEqual("Diagnostics (Guarded Legacy)", titles["support"])

    @unittest.skipIf(_dashboard_quick_actions is None, "wxPython is not available")
    def test_button_labels_do_not_use_generic_run(self):
        labels = [_dashboard_action_button_label(action.key) for action in _dashboard_quick_actions()]

        self.assertNotIn("Run", labels)
        self.assertIn("Guarded legacy", labels)
        self.assertIn("Open guarded flow", labels)

    @unittest.skipIf(_dashboard_action_icon is None, "wxPython is not available")
    def test_quick_action_icons_are_visual_only(self):
        icons = [_dashboard_action_icon(action.key) for action in _dashboard_quick_actions()]

        self.assertEqual(len(icons), len(_dashboard_quick_actions()))
        self.assertNotIn("", icons)
        self.assertNotIn("Run", icons)

    @unittest.skipIf(_dashboard_quick_actions is None, "wxPython is not available")
    def test_flash_action_stays_marked_dangerous(self):
        actions = {action.key: action for action in _dashboard_quick_actions()}

        self.assertTrue(actions["flash"].dangerous)
        self.assertTrue(actions["flash"].requires_confirmation())

    @unittest.skipIf(_dashboard_slot_rows is None, "wxPython is not available")
    def test_dashboard_readonly_cards_report_disabled_mutation_paths(self):
        state = ModernReadonlyState(
            device=ModernDeviceState(active_slot="b"),
            firmware=ModernFirmwareState(has_boot_image=True),
            tools=ModernToolState(),
            warnings=(),
        )

        self.assertIn(("Slot changes", "disabled in preview"), _dashboard_slot_rows(state))
        self.assertIn(("Partition writes", "disabled in preview"), _dashboard_partition_rows(state))
        self.assertIn(("Restore", "guarded legacy flow only"), _dashboard_backup_rows())


if __name__ == "__main__":
    unittest.main()
