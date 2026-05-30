import unittest
from types import SimpleNamespace

from ui.pages.flash_wizard_model import DataBehavior, PatchChoice, SlotBehavior
from ui.pages.flash_wizard_state_adapter import build_wizard_session


class _Picker:
    def __init__(self, path=""):
        self.path = path

    def GetPath(self):
        return self.path


class _Choice:
    def __init__(self, selected=""):
        self.selected = selected

    def GetStringSelection(self):
        return self.selected


class FlashWizardStateAdapterTests(unittest.TestCase):
    def test_empty_frame_builds_safe_blocked_session(self):
        frame = SimpleNamespace(config=SimpleNamespace())
        session = build_wizard_session(frame)

        self.assertFalse(session.can_flash)
        self.assertFalse(session.device.selected)
        self.assertFalse(session.firmware.selected)
        self.assertIn("No target device selected.", session.warnings())

    def test_reads_device_and_firmware_from_legacy_state(self):
        config = SimpleNamespace(
            device="redfin",
            firmware_path="",
            firmware_is_ota=True,
            custom_rom=False,
            firmware_sha256="abc123",
            boot_id="boot-1",
            selected_boot_md5="",
            firmware_has_init_boot=True,
            rom_has_init_boot=False,
            flash_both_slots=False,
            flash_to_inactive_slot=True,
            disable_verity=False,
            disable_verification=False,
            fastboot_force=False,
            no_reboot=True,
        )
        frame = SimpleNamespace(
            config=config,
            device_choice=_Choice("Pixel 5"),
            firmware_picker=_Picker("redfin-ota-ap1a.zip"),
            wipe=False,
        )

        session = build_wizard_session(frame)

        self.assertEqual("Pixel 5", session.device.display_name)
        self.assertEqual("redfin-ota-ap1a.zip", session.firmware.filename)
        self.assertEqual("ota", session.firmware.package_type)
        self.assertTrue(session.firmware.verified)
        self.assertTrue(session.firmware.has_boot_image)
        self.assertTrue(session.firmware.has_init_boot_image)
        self.assertEqual(PatchChoice.USE_EXISTING, session.patch_choice)
        self.assertEqual(DataBehavior.KEEP, session.options.data_behavior)
        self.assertEqual(SlotBehavior.INACTIVE, session.options.slot_behavior)
        self.assertTrue(session.options.no_reboot)
        self.assertFalse(session.can_flash)

    def test_reuses_shared_readonly_state_mapping(self):
        config = SimpleNamespace(
            device="cheetah",
            firmware_path="",
            firmware_is_ota=False,
            custom_rom=False,
            firmware_sha256="hash",
            boot_id=None,
            selected_boot_md5=None,
            firmware_has_init_boot=False,
            rom_has_init_boot=True,
            bootloader_state="unlocked",
            active_slot="b",
            flash_both_slots=False,
            flash_to_inactive_slot=False,
            disable_verity=False,
            disable_verification=False,
            fastboot_force=False,
            no_reboot=False,
        )
        frame = SimpleNamespace(
            config=config,
            device_choice=_Choice("Pixel 7 Pro"),
            firmware_picker=_Picker("cheetah-factory-ap1a.zip"),
            wipe=False,
        )

        session = build_wizard_session(frame)

        self.assertEqual("Pixel 7 Pro", session.device.display_name)
        self.assertTrue(session.device.adb_ready)
        self.assertTrue(session.device.bootloader_unlocked)
        self.assertEqual("b", session.device.active_slot)
        self.assertEqual("cheetah-factory-ap1a.zip", session.firmware.filename)
        self.assertEqual("factory", session.firmware.package_type)
        self.assertEqual("hash", session.firmware.sha256)
        self.assertTrue(session.firmware.has_init_boot_image)
        self.assertTrue(session.firmware.verified)
        self.assertFalse(session.can_flash)

    def test_reads_dangerous_options(self):
        config = SimpleNamespace(
            device="oriole",
            firmware_path="oriole-factory.zip",
            firmware_is_ota=False,
            custom_rom=False,
            firmware_sha256="hash",
            boot_id=None,
            selected_boot_md5=None,
            firmware_has_init_boot=False,
            rom_has_init_boot=False,
            flash_both_slots=True,
            flash_to_inactive_slot=False,
            disable_verity=True,
            disable_verification=True,
            fastboot_force=True,
            no_reboot=False,
        )
        frame = SimpleNamespace(config=config, wipe=True)
        session = build_wizard_session(frame)

        self.assertEqual(DataBehavior.WIPE, session.options.data_behavior)
        self.assertEqual(SlotBehavior.BOTH, session.options.slot_behavior)
        self.assertTrue(session.options.dangerous_enabled)
        self.assertIn("Dangerous options are enabled and require explicit confirmation.", session.warnings())


if __name__ == "__main__":
    unittest.main()
