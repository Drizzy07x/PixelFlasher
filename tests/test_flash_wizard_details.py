import unittest

from ui.pages.flash_wizard_details import step_detail_lines, warning_lines
from ui.pages.flash_wizard_model import (
    DataBehavior,
    PatchChoice,
    SlotBehavior,
    WizardDevice,
    WizardFirmware,
    WizardOptions,
    WizardSession,
    WizardStepKey,
)


class FlashWizardDetailsTests(unittest.TestCase):
    def test_device_details_show_connection_state(self):
        session = WizardSession(
            device=WizardDevice(display_name="Pixel", serial="abc", adb_ready=True, bootloader_unlocked=True, active_slot="a")
        )
        lines = step_detail_lines(session, WizardStepKey.DEVICE)
        self.assertIn("Device: Pixel", lines)
        self.assertIn("Connection: ADB ready", lines)
        self.assertIn("Active slot: a", lines)

    def test_firmware_details_show_package_state(self):
        session = WizardSession(
            firmware=WizardFirmware(path="factory.zip", package_type="factory", target_device="husky", build_id="AP1A", sha256="hash", verified=True)
        )
        lines = step_detail_lines(session, "firmware")
        self.assertIn("Firmware: factory.zip", lines)
        self.assertIn("Package type: factory", lines)
        self.assertIn("Verified: yes", lines)

    def test_options_details_show_dangerous_state(self):
        session = WizardSession(
            options=WizardOptions(
                data_behavior=DataBehavior.WIPE,
                slot_behavior=SlotBehavior.BOTH,
                disable_verity=True,
                fastboot_force=True,
            )
        )
        lines = step_detail_lines(session, WizardStepKey.OPTIONS)
        self.assertIn("Data behavior: wipe", lines)
        self.assertIn("Slot behavior: both", lines)
        self.assertIn("Dangerous options: enabled", lines)

    def test_warning_lines_are_prefixed(self):
        session = WizardSession()
        lines = warning_lines(session)
        self.assertTrue(lines)
        self.assertTrue(lines[0].startswith("Warning:"))

    def test_flash_details_remain_disabled_by_default(self):
        session = WizardSession(
            device=WizardDevice(display_name="Pixel", serial="abc", adb_ready=True, bootloader_unlocked=True),
            firmware=WizardFirmware(path="ota.zip", verified=True),
            patch_choice=PatchChoice.SKIP,
            preflight_passed=True,
            flash_connected=False,
        )
        lines = step_detail_lines(session, WizardStepKey.FLASH)
        self.assertIn("Can flash: no", lines)
        self.assertIn("Flash execution connected: no", lines)


if __name__ == "__main__":
    unittest.main()
