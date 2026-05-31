import unittest
from types import SimpleNamespace

from ui.pages.modern_readonly_state import build_readonly_state


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


class ModernReadonlyStateTests(unittest.TestCase):
    def test_empty_frame_builds_safe_state(self):
        state = build_readonly_state(SimpleNamespace(config=SimpleNamespace()), tool_resolver=lambda name: None)

        self.assertFalse(state.device.selected)
        self.assertFalse(state.firmware.selected)
        self.assertFalse(state.ready_for_review)
        self.assertIn("No target device selected.", state.warnings)
        self.assertIn("No firmware package selected.", state.warnings)

    def test_reads_device_and_firmware_from_loaded_legacy_state(self):
        config = SimpleNamespace(
            device="redfin",
            firmware_path="",
            firmware_is_ota=True,
            custom_rom=False,
            firmware_sha256="hash",
            boot_id="boot-1",
            selected_boot_md5="",
            firmware_has_init_boot=True,
            rom_has_init_boot=False,
            bootloader_state="unlocked",
            active_slot="a",
            root_status="rooted",
            android_version="14",
        )
        frame = SimpleNamespace(
            config=config,
            device_choice=_Choice("Pixel 5"),
            firmware_picker=_Picker("redfin-ota-ap1a.zip"),
        )

        state = build_readonly_state(frame, tool_resolver=lambda name: f"/tools/{name}")

        self.assertEqual("Pixel 5", state.device.display_name)
        self.assertEqual("ADB ready", state.device.connection_label)
        self.assertEqual("unlocked", state.device.bootloader_state)
        self.assertEqual("a", state.device.active_slot)
        self.assertEqual("redfin-ota-ap1a.zip", state.firmware.filename)
        self.assertEqual("ota", state.firmware.package_type)
        self.assertTrue(state.firmware.verified)
        self.assertTrue(state.firmware.has_patchable_image)
        self.assertTrue(state.tools.adb_available)
        self.assertTrue(state.tools.fastboot_available)
        self.assertTrue(state.ready_for_review)

    def test_custom_rom_path_is_preferred_for_custom_rom_state(self):
        config = SimpleNamespace(
            device="raven",
            firmware_path="raven-factory.zip",
            custom_rom=True,
            custom_rom_path="raven-custom-rom.zip",
            firmware_is_ota=False,
            firmware_sha256="",
            rom_sha256="rom-hash",
        )
        frame = SimpleNamespace(config=config, firmware_picker=_Picker(""))

        state = build_readonly_state(frame, tool_resolver=lambda name: None)

        self.assertEqual("raven-custom-rom.zip", state.firmware.filename)
        self.assertEqual("custom_rom", state.firmware.package_type)
        self.assertTrue(state.firmware.verified)

    def test_unverified_firmware_is_reported(self):
        config = SimpleNamespace(
            device="oriole",
            firmware_path="oriole-factory.zip",
            firmware_is_ota=False,
            custom_rom=False,
            firmware_sha256="",
        )
        frame = SimpleNamespace(config=config)

        state = build_readonly_state(frame, tool_resolver=lambda name: None)

        self.assertTrue(state.firmware.selected)
        self.assertFalse(state.firmware.verified)
        self.assertFalse(state.ready_for_review)
        self.assertIn("Firmware package has not been verified.", state.warnings)

    def test_reader_suppresses_bad_legacy_controls(self):
        class BadPicker:
            def GetPath(self):
                raise RuntimeError("legacy control failed")

        frame = SimpleNamespace(config=SimpleNamespace(), firmware_picker=BadPicker())
        state = build_readonly_state(frame, tool_resolver=lambda name: None)

        self.assertEqual("", state.firmware.path)
        self.assertFalse(state.ready_for_review)


if __name__ == "__main__":
    unittest.main()
