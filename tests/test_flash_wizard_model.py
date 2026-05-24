import unittest

from ui.pages.flash_wizard_model import (
    PatchChoice,
    WizardDevice,
    WizardFirmware,
    WizardOptions,
    WizardSession,
    WizardStepKey,
    completed_step_titles,
)


class FlashWizardModelTests(unittest.TestCase):
    def test_default_session_is_not_flashable(self):
        session = WizardSession()
        self.assertFalse(session.can_flash)
        self.assertFalse(session.step_complete(WizardStepKey.DEVICE))
        self.assertFalse(session.step_complete(WizardStepKey.FIRMWARE))
        self.assertIn("No target device selected.", session.warnings())

    def test_ready_session_is_flashable_when_flash_is_connected(self):
        session = WizardSession(
            device=WizardDevice(display_name="Pixel", serial="abc123", adb_ready=True, bootloader_unlocked=True),
            firmware=WizardFirmware(path="factory.zip", package_type="factory", has_boot_image=True, verified=True),
            patch_choice=PatchChoice.SKIP,
            options=WizardOptions(),
            preflight_passed=True,
            flash_connected=True,
        )
        self.assertTrue(session.step_complete(WizardStepKey.DEVICE))
        self.assertTrue(session.step_complete(WizardStepKey.FIRMWARE))
        self.assertTrue(session.step_complete(WizardStepKey.REVIEW))
        self.assertTrue(session.can_flash)
        self.assertEqual((), session.warnings())

    def test_patch_warning_when_no_patchable_image_exists(self):
        session = WizardSession(
            device=WizardDevice(display_name="Pixel", serial="abc", adb_ready=True, bootloader_unlocked=True),
            firmware=WizardFirmware(path="rom.zip", package_type="custom", verified=True),
            patch_choice=PatchChoice.USE_EXISTING,
            preflight_passed=True,
            flash_connected=True,
        )
        self.assertIn("Patch requested but boot/init_boot image is not available.", session.warnings())
        self.assertFalse(session.can_flash)

    def test_completed_step_titles_include_safe_completed_steps(self):
        session = WizardSession(
            device=WizardDevice(display_name="Pixel", serial="abc", adb_ready=True, bootloader_unlocked=True),
            firmware=WizardFirmware(path="ota.zip", package_type="ota", verified=True),
        )
        completed = completed_step_titles(session)
        self.assertIn("Device", completed)
        self.assertIn("Firmware", completed)
        self.assertIn("Patch Boot", completed)
        self.assertIn("Options", completed)
        self.assertNotIn("Review", completed)


if __name__ == "__main__":
    unittest.main()
