import unittest
from pathlib import Path

try:
    from ui.pages.dashboard import (
        _dashboard_action_button_label,
        _dashboard_backup_rows,
        _dashboard_partition_rows,
        _dashboard_quick_actions,
        _dashboard_slot_rows,
    )
except ModuleNotFoundError as exc:
    if exc.name == "wx":
        _dashboard_action_button_label = None
        _dashboard_backup_rows = None
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
    NAV_ITEMS,
    PREVIEW_BADGES,
    SAFETY_BOUNDARY_LINES,
)
from ui.pages.modern_readonly_state import ModernDeviceState, ModernFirmwareState, ModernReadonlyState, ModernToolState


DASHBOARD_SOURCE = Path("ui/pages/dashboard.py")


class ModernDashboardCopySafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dashboard_source = DASHBOARD_SOURCE.read_text(encoding="utf-8")

    def test_shared_preview_header_copy_is_explicit(self):
        self.assertEqual("Modern UI - Preview (Read-Only)", MODERN_PREVIEW_TITLE)
        self.assertIn("No device changes", MODERN_PREVIEW_SUBTITLE)
        self.assertIn("No flashing", MODERN_PREVIEW_SUBTITLE)
        self.assertIn("No patches", MODERN_PREVIEW_SUBTITLE)
        self.assertIn("PREVIEW ONLY", PREVIEW_BADGES)
        self.assertIn("Read-Only", PREVIEW_BADGES)
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

    def test_preview_action_cards_do_not_claim_execution(self):
        text = "\n".join(f"{title}: {body}" for title, body in DASHBOARD_PREVIEW_ACTIONS)

        self.assertIn("Flash Wizard (Preview)", text)
        self.assertIn("Modern Shell (Read-Only)", text)
        self.assertIn("Downloads", text)
        self.assertNotIn("Flash Device", text)
        self.assertNotIn("Patch Boot", text)

    def test_dashboard_layout_badges_reinforce_readonly_boundaries(self):
        for expected in (
            "No execution from this preview",
            "No slot switching",
            "No partition writes",
            "Restore stays guarded",
            "Preview boundary",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.dashboard_source)

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
