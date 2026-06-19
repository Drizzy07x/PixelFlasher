import unittest

try:
    from ui.pages.modern_shell_app import (
        _shell_bottom_rows,
        _shell_device_info_rows,
        _shell_device_subtitle,
        _shell_device_title,
        _shell_firmware_rows,
        _shell_firmware_subtitle,
        _shell_flash_summary_rows,
        _shell_preview_action_rows,
        _shell_recommended_body,
        _shell_recommended_title,
        _shell_status_rows,
        _shell_tool_rows,
    )
except ModuleNotFoundError as exc:
    if exc.name == "wx":
        _shell_bottom_rows = None
        _shell_device_info_rows = None
        _shell_device_subtitle = None
        _shell_device_title = None
        _shell_firmware_rows = None
        _shell_firmware_subtitle = None
        _shell_flash_summary_rows = None
        _shell_preview_action_rows = None
        _shell_recommended_body = None
        _shell_recommended_title = None
        _shell_status_rows = None
        _shell_tool_rows = None
    else:
        raise

from ui.pages.modern_readonly_state import (
    ModernDeviceState,
    ModernFirmwareState,
    ModernReadonlyState,
    ModernToolState,
)


def _state(device=None, firmware=None, tools=None):
    return ModernReadonlyState(
        device=device or ModernDeviceState(),
        firmware=firmware or ModernFirmwareState(),
        tools=tools or ModernToolState(),
        warnings=(),
    )


class ModernShellReadonlyStateTests(unittest.TestCase):
    @unittest.skipIf(_shell_device_title is None, "wxPython is not available")
    def test_empty_state_uses_safe_preview_defaults(self):
        state = _state()

        self.assertEqual("No device connected", _shell_device_title(state))
        self.assertEqual("Connect a device and use the legacy scan flow.", _shell_device_subtitle(state))
        self.assertIn(("Selected device", "none"), _shell_device_info_rows(state))
        self.assertIn(("Type", "not selected"), _shell_firmware_rows(state))
        self.assertEqual("Select Firmware", _shell_recommended_title(state))
        self.assertIn(("Flash", "requires confirmation"), _shell_flash_summary_rows(state))

    @unittest.skipIf(_shell_device_title is None, "wxPython is not available")
    def test_device_state_maps_to_shell_labels(self):
        state = _state(
            device=ModernDeviceState(
                display_name="Pixel 7 Pro",
                serial="abc123",
                adb_ready=True,
                bootloader_state="unlocked",
                active_slot="b",
                root_status="rooted",
                android_version="14",
            )
        )

        self.assertEqual("Pixel 7 Pro", _shell_device_title(state))
        self.assertEqual("ADB ready", _shell_device_subtitle(state))
        self.assertIn(("ADB", "Ready"), _shell_status_rows(state))
        self.assertIn(("Bootloader", "Unlocked"), _shell_status_rows(state))
        self.assertIn(("Root", "Rooted"), _shell_status_rows(state))
        self.assertIn(("Slot", "b"), _shell_status_rows(state))
        self.assertIn(("Current slot", "b"), _shell_device_info_rows(state))

    @unittest.skipIf(_shell_firmware_rows is None, "wxPython is not available")
    def test_firmware_state_maps_to_shell_labels(self):
        state = _state(
            firmware=ModernFirmwareState(
                path="cheetah-factory-ap1a.zip",
                package_type="factory",
                target_device="cheetah",
                build_id="cheetah-factory",
                sha256_available=True,
                verified=True,
                has_boot_image=True,
            )
        )

        self.assertEqual("Review Firmware", _shell_recommended_title(state))
        self.assertIn("cheetah-factory-ap1a.zip", _shell_recommended_body(state))
        self.assertEqual("cheetah-factory-ap1a.zip", _shell_firmware_subtitle(state))
        self.assertIn(("Type", "Factory image"), _shell_firmware_rows(state))
        self.assertIn(("Validation", "verified"), _shell_firmware_rows(state))
        self.assertIn(("Patch", "image available"), _shell_flash_summary_rows(state))
        self.assertIn(("Device Changes", "none"), _shell_bottom_rows(state))

    @unittest.skipIf(_shell_tool_rows is None, "wxPython is not available")
    def test_tool_state_reports_availability_without_execution(self):
        state = _state(tools=ModernToolState(adb_path="/tools/adb", fastboot_path="/tools/fastboot"))

        self.assertIn(("Platform Tools", "ADB/Fastboot available"), _shell_tool_rows(state))
        self.assertIn(("ADB shell", "requires confirmation"), _shell_tool_rows(state))
        self.assertIn(("Fastboot commands", "requires confirmation"), _shell_tool_rows(state))

    @unittest.skipIf(_shell_preview_action_rows is None, "wxPython is not available")
    def test_preview_actions_are_plan_and_readonly_copy(self):
        text = "\n".join(f"{title}: {body}" for title, body in _shell_preview_action_rows())

        self.assertIn("Flash Wizard", text)
        self.assertIn("Modern Shell", text)
        self.assertIn("confirmation", text)
        self.assertNotIn("Flash Device", text)


if __name__ == "__main__":
    unittest.main()
