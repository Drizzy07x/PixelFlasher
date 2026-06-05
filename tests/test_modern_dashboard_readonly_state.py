import unittest

try:
    from ui.pages.dashboard import _device_status_from_readonly, _firmware_info_from_readonly
except ModuleNotFoundError as exc:
    if exc.name == "wx":
        _device_status_from_readonly = None
        _firmware_info_from_readonly = None
    else:
        raise

from ui.pages.modern_readonly_state import (
    ModernDeviceState,
    ModernFirmwareState,
    ModernReadonlyState,
    ModernToolState,
)


def _state(device=None, firmware=None):
    return ModernReadonlyState(
        device=device or ModernDeviceState(),
        firmware=firmware or ModernFirmwareState(),
        tools=ModernToolState(),
        warnings=(),
    )


class ModernDashboardReadonlyStateTests(unittest.TestCase):
    @unittest.skipIf(_device_status_from_readonly is None, "wxPython is not available")
    def test_device_status_uses_shared_readonly_state(self):
        state = _state(
            device=ModernDeviceState(
                display_name="Pixel 7 Pro",
                serial="abc123456",
                adb_ready=True,
                bootloader_state="unlocked",
                active_slot="b",
                root_status="rooted",
                android_version="14",
            )
        )

        status = _device_status_from_readonly(state)

        self.assertEqual("Pixel 7 Pro", status.display_name)
        self.assertEqual("", status.codename)
        self.assertEqual("abc123456", status.serial)
        self.assertTrue(status.adb_ready)
        self.assertEqual("unlocked", status.bootloader_state)
        self.assertEqual("b", status.active_slot)
        self.assertEqual("rooted", status.root_status)
        self.assertEqual("14", status.android_version)

    @unittest.skipIf(_device_status_from_readonly is None, "wxPython is not available")
    def test_device_status_handles_empty_state(self):
        status = _device_status_from_readonly(_state())

        self.assertEqual("No device", status.display_name)
        self.assertFalse(status.adb_ready)
        self.assertEqual("", status.serial)

    @unittest.skipIf(_firmware_info_from_readonly is None, "wxPython is not available")
    def test_firmware_info_uses_shared_readonly_state(self):
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

        firmware = _firmware_info_from_readonly(state)

        self.assertEqual("cheetah-factory-ap1a.zip", firmware.filename)
        self.assertEqual("Factory image", firmware.package_type)
        self.assertEqual("cheetah", firmware.device)
        self.assertEqual("cheetah-factory", firmware.build)
        self.assertTrue(firmware.verified)

    @unittest.skipIf(_firmware_info_from_readonly is None, "wxPython is not available")
    def test_firmware_info_handles_empty_state(self):
        firmware = _firmware_info_from_readonly(_state())

        self.assertEqual("", firmware.path)
        self.assertEqual("unknown", firmware.package_type)
        self.assertFalse(firmware.verified)


if __name__ == "__main__":
    unittest.main()
