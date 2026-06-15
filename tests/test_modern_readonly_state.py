import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ui.pages.modern_readonly_state import build_readonly_state


READONLY_STATE_SOURCE = Path("ui/pages/modern_readonly_state.py")


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
    @classmethod
    def setUpClass(cls):
        cls.source = READONLY_STATE_SOURCE.read_text(encoding="utf-8")

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

    def test_reads_extended_loaded_state_without_device_access(self):
        config = SimpleNamespace(
            device="abc123",
            firmware_path="oriole-factory-ap1a.zip",
            firmware_is_ota=False,
            custom_rom=False,
            firmware_sha256="hash",
            platform_tools_path="/opt/platform-tools",
            flash_mode="keepData",
            flash_both_slots=False,
            flash_to_inactive_slot=True,
            disable_verification=True,
            disable_verity=False,
            fastboot_force=True,
            no_reboot=True,
            temporary_root=False,
            phone_path="/storage/emulated/0/Download",
            google_images_update_frequency=7,
            google_images_last_checked=1700000000,
            update_check=True,
            check_module_updates=True,
            language="es",
            advanced_options=True,
            verbose=True,
            low_mem=True,
            show_notifications=True,
            show_custom_rom_options=True,
        )
        phone = SimpleNamespace(
            id="abc123",
            true_mode="adb",
            _rooted=True,
            backups={
                "backup-1": SimpleNamespace(date="2024-05-01", firmware="AP1A"),
                "backup-2": SimpleNamespace(date="2024-06-01", firmware="AP2A"),
            },
            props=SimpleNamespace(
                property={
                    "ro.product.model": "Pixel 6",
                    "ro.product.device": "oriole",
                    "ro.product.name": "oriole_beta",
                    "ro.build.version.release": "15",
                    "ro.build.id": "AP2A.240605.024",
                    "ro.build.version.security_patch": "2024-06-05",
                    "ro.boot.slot_suffix": "_b",
                    "ro.boot.vbmeta.device_state": "unlocked",
                }
            ),
        )
        frame = SimpleNamespace(config=config, phone=phone)

        state = build_readonly_state(frame, tool_resolver=lambda name: None)

        self.assertEqual("Pixel 6", state.device.display_name)
        self.assertEqual("abc123", state.device.serial)
        self.assertEqual("oriole", state.device.codename)
        self.assertEqual("oriole_beta", state.device.product)
        self.assertEqual("15", state.device.android_version)
        self.assertEqual("AP2A.240605.024", state.device.build_id)
        self.assertEqual("2024-06-05", state.device.security_patch)
        self.assertEqual("b", state.device.active_slot)
        self.assertEqual("rooted", state.device.root_status)
        self.assertEqual("Inactive slot", state.flash.slot_behavior)
        self.assertEqual("Keep data", state.flash.data_behavior)
        self.assertEqual("disabled", state.flash.verification)
        self.assertTrue(state.flash.force)
        self.assertTrue(state.flash.no_reboot)
        self.assertEqual(2, state.backups.total_count)
        self.assertIn("AP2A", state.backups.latest_label)
        self.assertEqual("/storage/emulated/0/Download", state.backups.location)
        self.assertEqual("loaded", state.downloads.image_catalog_status)
        self.assertEqual("every 7 days", state.downloads.update_frequency)
        self.assertEqual("1700000000", state.downloads.last_checked)
        self.assertEqual("es", state.settings.language)
        self.assertTrue(state.settings.advanced_options)
        self.assertEqual("/opt/platform-tools", state.tools.platform_tools_path)

    def test_reads_platform_tools_from_configured_path(self):
        import tempfile

        with tempfile.TemporaryDirectory(prefix="pf-readonly-tools-") as tmp:
            root = Path(tmp)
            (root / "adb.exe").write_text("adb", encoding="utf-8")
            (root / "fastboot.exe").write_text("fastboot", encoding="utf-8")
            config = SimpleNamespace(platform_tools_path=str(root))
            frame = SimpleNamespace(config=config)

            state = build_readonly_state(frame, tool_resolver=lambda name: None)

        self.assertTrue(state.tools.adb_available)
        self.assertTrue(state.tools.fastboot_available)
        self.assertTrue(state.tools.adb_path.endswith("adb.exe"))
        self.assertTrue(state.tools.fastboot_path.endswith("fastboot.exe"))

    def test_fastboot_selection_preserves_connection_mode(self):
        config = SimpleNamespace(device="abc123456")
        frame = SimpleNamespace(
            config=config,
            device_choice=_Choice("Pixel 7 Pro [fastboot]"),
        )

        state = build_readonly_state(frame, tool_resolver=lambda name: None)

        self.assertTrue(state.device.selected)
        self.assertFalse(state.device.adb_ready)
        self.assertTrue(state.device.fastboot_ready)
        self.assertEqual("Fastboot ready", state.device.connection_label)

    def test_loaded_phone_mode_overrides_selection_text(self):
        config = SimpleNamespace(device="abc123456")
        frame = SimpleNamespace(
            config=config,
            phone=SimpleNamespace(true_mode="fastboot"),
            device_choice=_Choice("Pixel 7 Pro"),
        )

        state = build_readonly_state(frame, tool_resolver=lambda name: None)

        self.assertFalse(state.device.adb_ready)
        self.assertTrue(state.device.fastboot_ready)
        self.assertEqual("Fastboot ready", state.device.connection_label)

    def test_device_choice_text_is_humanized_for_modern_display(self):
        config = SimpleNamespace(device="45241FDAS0097U")
        frame = SimpleNamespace(
            config=config,
            device_choice=_Choice("X (adb) 45241FDAS0097U komodo CP1A.260505.005"),
        )

        state = build_readonly_state(frame, tool_resolver=lambda name: None)

        self.assertEqual("Pixel 9 Pro XL", state.device.display_name)
        self.assertEqual("45241FDAS0097U", state.device.serial)
        self.assertEqual("komodo", state.device.codename)
        self.assertEqual("ADB ready", state.device.connection_label)

    def test_adb_model_text_is_humanized_for_modern_display(self):
        config = SimpleNamespace(device="")
        frame = SimpleNamespace(
            config=config,
            device_choice=_Choice("45241FDAS0097U device product:komodo model:Pixel_9_Pro_XL device:komodo"),
        )

        state = build_readonly_state(frame, tool_resolver=lambda name: None)

        self.assertEqual("Pixel 9 Pro XL", state.device.display_name)
        self.assertEqual("45241FDAS0097U", state.device.serial)
        self.assertEqual("komodo", state.device.codename)

    def test_reads_cached_scan_phone_props_without_frame_phone(self):
        cached_phone = SimpleNamespace(
            id="45241FDAS0097U",
            true_mode="adb",
            _rooted=False,
            props=SimpleNamespace(
                property={
                    "ro.product.model": "Pixel 9 Pro XL",
                    "ro.product.device": "komodo",
                    "ro.product.name": "komodo_beta",
                    "ro.build.version.release": "16",
                    "ro.build.id": "CP1A.260505.005",
                    "ro.build.version.security_patch": "2026-05-05",
                    "ro.boot.slot_suffix": "_a",
                    "ro.boot.vbmeta.device_state": "locked",
                }
            ),
        )
        runtime = SimpleNamespace(
            get_phones=lambda: [cached_phone],
            get_phone_id=lambda: "45241FDAS0097U",
        )
        frame = SimpleNamespace(
            config=SimpleNamespace(device="45241FDAS0097U"),
            device_choice=_Choice("X (adb) 45241FDAS0097U komodo CP1A.260505.005"),
        )

        with patch("ui.pages.modern_readonly_state.importlib.import_module", return_value=runtime):
            state = build_readonly_state(frame, tool_resolver=lambda name: None)

        self.assertEqual("Pixel 9 Pro XL", state.device.display_name)
        self.assertEqual("45241FDAS0097U", state.device.serial)
        self.assertEqual("komodo", state.device.codename)
        self.assertEqual("16", state.device.android_version)
        self.assertEqual("CP1A.260505.005", state.device.build_id)
        self.assertEqual("2026-05-05", state.device.security_patch)
        self.assertEqual("locked", state.device.bootloader_state)
        self.assertEqual("a", state.device.active_slot)
        self.assertEqual("not rooted", state.device.root_status)

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

    def test_custom_rom_requires_rom_hash_for_verification(self):
        config = SimpleNamespace(
            device="raven",
            firmware_path="raven-factory.zip",
            custom_rom=True,
            custom_rom_path="raven-custom-rom.zip",
            firmware_is_ota=False,
            firmware_sha256="factory-hash",
            rom_sha256="",
        )
        frame = SimpleNamespace(config=config, firmware_picker=_Picker(""))

        state = build_readonly_state(frame, tool_resolver=lambda name: None)

        self.assertEqual("raven-custom-rom.zip", state.firmware.filename)
        self.assertEqual("custom_rom", state.firmware.package_type)
        self.assertFalse(state.firmware.verified)
        self.assertFalse(state.ready_for_review)

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

    def test_firmware_metadata_is_inferred_from_selected_file(self):
        import tempfile

        with tempfile.TemporaryDirectory(prefix="pf-modern-fw-") as tmp:
            ota_path = Path(tmp) / "komodo-ota-cp1a.zip"
            ota_path.write_bytes(b"0" * 1536)
            image_path = Path(tmp) / "init_boot.img"
            image_path.write_bytes(b"1" * 2048)

            ota_state = build_readonly_state(
                SimpleNamespace(
                    config=SimpleNamespace(firmware_path=str(ota_path), firmware_is_ota=False),
                    firmware_picker=_Picker(""),
                ),
                tool_resolver=lambda name: None,
            )
            image_state = build_readonly_state(
                SimpleNamespace(
                    config=SimpleNamespace(firmware_path=str(image_path), firmware_is_ota=False),
                    firmware_picker=_Picker(""),
                ),
                tool_resolver=lambda name: None,
            )

        self.assertEqual("ota", ota_state.firmware.package_type)
        self.assertEqual(".zip", ota_state.firmware.extension)
        self.assertEqual(1536, ota_state.firmware.file_size_bytes)
        self.assertEqual("1.5 KB", ota_state.firmware.size_label)
        self.assertEqual("image", image_state.firmware.package_type)
        self.assertEqual(".img", image_state.firmware.extension)
        self.assertEqual("2.0 KB", image_state.firmware.size_label)

    def test_reader_suppresses_bad_legacy_controls(self):
        class BadPicker:
            def GetPath(self):
                raise RuntimeError("legacy control failed")

        frame = SimpleNamespace(config=SimpleNamespace(), firmware_picker=BadPicker())
        state = build_readonly_state(frame, tool_resolver=lambda name: None)

        self.assertEqual("", state.firmware.path)
        self.assertFalse(state.ready_for_review)

    def test_reader_source_stays_readonly_and_frame_scoped(self):
        forbidden_snippets = (
            "from runtime import",
            "get_phone(",
            "subprocess.",
            "os.system",
            "adb shell",
            "fastboot -",
            "fastboot flash",
            "wipe_data",
            "delete_all",
            "reboot_",
        )

        for snippet in forbidden_snippets:
            with self.subTest(snippet=snippet):
                self.assertNotIn(snippet, self.source)


if __name__ == "__main__":
    unittest.main()
