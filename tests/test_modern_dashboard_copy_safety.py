import unittest
from pathlib import Path

try:
    from ui.pages.dashboard import (
        _dashboard_action_icon,
        _dashboard_action_button_label,
        _dashboard_backup_rows,
        _dashboard_partition_rows,
        _dashboard_quick_actions,
        _dashboard_slot_rows,
    )
except ModuleNotFoundError as exc:
    if exc.name == "wx":
        _dashboard_action_icon = None
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

    def test_shared_header_copy_is_product_ready(self):
        self.assertEqual("Modern UI", MODERN_PREVIEW_TITLE)
        self.assertIn("modern workspace", MODERN_PREVIEW_SUBTITLE)
        self.assertEqual(("Ready", "Modern UI", "Protected"), PREVIEW_BADGES)
        self.assertEqual("Modern UI", MODERN_PREVIEW_STATUS)
        self.assertEqual("Ready", MODERN_PREVIEW_FOOTER)

    def test_safety_boundary_copy_covers_confirmations_without_demo_language(self):
        safety_text = "\n".join(SAFETY_BOUNDARY_LINES)

        for expected in (
            "Sensitive operations require existing PixelFlasher confirmation.",
            "ADB and Fastboot actions use PixelFlasher confirmations.",
            "Reboot, wipe, and slot changes are not launched from this screen.",
            "Unknown actions and external navigation are blocked.",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, safety_text)
        self.assertNotIn("Read-only", safety_text)
        self.assertNotIn("Preview-only", safety_text)

    def test_navigation_copy_matches_modern_sections(self):
        labels = {key: f"{title} {detail}" for key, title, detail in NAV_ITEMS}

        self.assertIn("Overview & device summary", labels["dashboard"])
        self.assertIn("Device state explorer", labels["shell"])
        self.assertIn("Plan and continue safely", labels["wizard"])
        self.assertIn("Backup context", labels["backups"])
        self.assertIn("Firmware updates", labels["downloads"])
        self.assertIn("Utilities", labels["tools"])
        self.assertIn("Boundaries & policy", labels["safety"])
        self.assertIn("Version & info", labels["about"])
        for key in labels:
            with self.subTest(key=key):
                self.assertIn(key, NAV_ICONS)

    def test_dashboard_action_cards_describe_modern_workflows(self):
        text = "\n".join(f"{title}: {body}" for title, body in DASHBOARD_PREVIEW_ACTIONS)

        self.assertIn("Flash Wizard", text)
        self.assertIn("Modern Shell", text)
        self.assertIn("Downloads", text)
        self.assertNotIn("Read-Only", text)
        self.assertNotIn("Preview-only", text)

    def test_webview_dashboard_template_matches_modern_structure(self):
        from ui.pages.modern_preview_templates import render_preview_html

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
            "Modern UI",
            "Connected Device",
            "Quick Actions",
            "Flash Wizard",
            "Patch Boot",
            "Scan Devices",
            "Platform Tools need setup",
            "Set Up Platform Tools",
            "Workflow Status",
            "Device Slots",
            "Partitions",
            "Last Backup",
            "pixelflasher://action/flash_device",
            "pixelflasher://action/patch_boot",
            "pixelflasher://action/scan_devices",
            "pixelflasher://action/setup_platform_tools",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, html)
        self.assertNotIn("Open Classic PixelFlasher", html)
        self.assertNotIn("Execution Blocked", html)

    def test_webview_dashboard_deduplicates_device_subtitle(self):
        from ui.pages.modern_preview_templates import render_preview_html

        html = render_preview_html(
            "dashboard",
            ModernReadonlyState(
                device=ModernDeviceState(
                    display_name="Pixel 9 Pro XL",
                    serial="45241FDAS0097U",
                    codename="komodo",
                    product="komodo",
                    adb_ready=True,
                ),
                firmware=ModernFirmwareState(),
                tools=ModernToolState(),
                warnings=(),
            ),
        )

        self.assertIn("45241FDAS0097U · komodo", html)
        self.assertNotIn("45241FDAS0097U · komodo · komodo", html)

    def test_webview_surfaces_show_firmware_metadata(self):
        from ui.pages.modern_preview_templates import render_preview_html

        state = ModernReadonlyState(
            device=ModernDeviceState(display_name="Pixel 9 Pro XL"),
            firmware=ModernFirmwareState(
                path="komodo-ota-cp1a.zip",
                package_type="ota",
                build_id="komodo-ota",
                file_size_bytes=1536,
                extension=".zip",
            ),
            tools=ModernToolState(),
            warnings=(),
        )
        dashboard_html = render_preview_html("dashboard", state)
        wizard_html = render_preview_html("wizard", state)

        for expected in ("komodo-ota-cp1a.zip", "OTA package", "1.5 KB"):
            with self.subTest(expected=expected):
                self.assertIn(expected, dashboard_html)
                self.assertIn(expected, wizard_html)

    def test_webview_template_does_not_load_remote_assets(self):
        for forbidden in ("http://", "https://", "cdn", "script src", "javascript:", "onclick="):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.template_source)

    @unittest.skipIf(_dashboard_quick_actions is None, "wxPython is not available")
    def test_existing_wx_dashboard_quick_actions_remain_guarded(self):
        titles = {action.key: action.title for action in _dashboard_quick_actions()}

        self.assertEqual("Patch (Guarded Legacy)", titles["patch"])
        self.assertEqual("Flash (Guarded Legacy)", titles["flash"])
        self.assertEqual("Device Scan (Guarded Legacy)", titles["scan"])
        self.assertEqual("Diagnostics (Guarded Legacy)", titles["support"])

    @unittest.skipIf(_dashboard_quick_actions is None, "wxPython is not available")
    def test_existing_wx_dashboard_buttons_do_not_use_generic_run(self):
        labels = [_dashboard_action_button_label(action.key) for action in _dashboard_quick_actions()]

        self.assertNotIn("Run", labels)
        self.assertIn("Guarded legacy", labels)
        self.assertIn("Open guarded flow", labels)

    @unittest.skipIf(_dashboard_action_icon is None, "wxPython is not available")
    def test_existing_wx_dashboard_quick_action_icons_are_visual_only(self):
        icons = [_dashboard_action_icon(action.key) for action in _dashboard_quick_actions()]

        self.assertEqual(len(icons), len(_dashboard_quick_actions()))
        self.assertNotIn("", icons)
        self.assertNotIn("Run", icons)

    @unittest.skipIf(_dashboard_quick_actions is None, "wxPython is not available")
    def test_existing_wx_flash_action_stays_marked_dangerous(self):
        actions = {action.key: action for action in _dashboard_quick_actions()}

        self.assertTrue(actions["flash"].dangerous)
        self.assertTrue(actions["flash"].requires_confirmation())

    @unittest.skipIf(_dashboard_slot_rows is None, "wxPython is not available")
    def test_existing_wx_dashboard_mutation_rows_remain_guarded(self):
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
