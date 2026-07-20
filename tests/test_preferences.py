import json
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from hypothesis import given, settings
from hypothesis import strategies as st

from pixelflasher_core.config_store import ConfigStore
from pixelflasher_core.preferences import (
    MAX_ZOOM,
    MIN_ZOOM,
    PREFERENCES_KEY,
    PREFERENCES_SCHEMA_VERSION,
    SUPPORTED_LOCALES,
    ModernPreferences,
    PreferencesError,
    load_preferences,
    save_preferences,
)


class ModernPreferencesValidationTests(unittest.TestCase):
    def test_safe_defaults_and_all_supported_values(self):
        defaults = ModernPreferences()
        self.assertEqual(("en", "es", "fr", "it", "zh_CN", "zh_TW"), SUPPORTED_LOCALES)
        self.assertEqual("dark", defaults.theme)
        self.assertEqual("en", defaults.locale)
        self.assertFalse(defaults.high_contrast)
        self.assertFalse(defaults.reduced_motion)
        self.assertEqual(100, defaults.zoom)
        self.assertFalse(defaults.expert_mode)
        self.assertFalse(defaults.automatic_update_check)
        self.assertTrue(defaults.check_disk_space)
        self.assertTrue(defaults.check_bootloader_unlocked)
        self.assertTrue(defaults.check_firmware_hash)
        self.assertFalse(defaults.check_module_updates)
        self.assertFalse(defaults.show_notifications)
        self.assertEqual(90, defaults.reboot_timeout_seconds)
        self.assertFalse(defaults.customize_font)
        self.assertEqual("Courier", defaults.font_face)
        self.assertEqual(12, defaults.font_size)
        self.assertEqual("top", defaults.toolbar_position)
        self.assertTrue(defaults.toolbar_show_device)
        self.assertTrue(defaults.toolbar_show_theme)
        self.assertTrue(defaults.toolbar_show_language)
        self.assertFalse(defaults.create_boot_tar)
        self.assertEqual(80, MIN_ZOOM)
        self.assertEqual(200, MAX_ZOOM)

        for theme in ("dark", "light"):
            for locale in SUPPORTED_LOCALES:
                with self.subTest(theme=theme, locale=locale):
                    value = ModernPreferences(
                        theme,
                        locale,
                        high_contrast=True,
                        reduced_motion=True,
                        zoom=MIN_ZOOM if theme == "dark" else MAX_ZOOM,
                    )
                    self.assertEqual(theme, value.theme)
                    self.assertEqual(locale, value.locale)

    def test_unknown_fields_and_unsupported_schema_fail_closed(self):
        for raw in (
            {"theme": "dark", "command": "shell id"},
            {"theme": "dark", 7: "not-a-field"},
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(PreferencesError) as raised:
                    ModernPreferences.from_mapping(
                        cast(Mapping[str, Any], raw)
                    )
                self.assertEqual("unknown_preference_field", raised.exception.code)

        for schema in (True, "1", 0, 2):
            with self.subTest(schema=schema):
                with self.assertRaises(PreferencesError) as raised:
                    ModernPreferences.from_mapping({"schemaVersion": schema})
                self.assertIn(
                    raised.exception.code,
                    {"preferences_schema_invalid", "preferences_schema_unsupported"},
                )

    def test_invalid_types_values_and_zoom_bounds_are_rejected(self):
        cases = (
            ({"theme": "system"}, "theme_invalid"),
            ({"theme": 1}, "theme_invalid"),
            ({"locale": "de"}, "locale_invalid"),
            ({"locale": None}, "locale_invalid"),
            ({"highContrast": 1}, "high_contrast_invalid"),
            ({"reducedMotion": "false"}, "reduced_motion_invalid"),
            ({"zoom": True}, "zoom_invalid"),
            ({"zoom": 100.0}, "zoom_invalid"),
            ({"zoom": MIN_ZOOM - 1}, "zoom_invalid"),
            ({"zoom": MAX_ZOOM + 1}, "zoom_invalid"),
            ({"expertMode": 1}, "expert_mode_invalid"),
            ({"automaticUpdateCheck": 1}, "maintenance_preference_invalid"),
            ({"checkDiskSpace": "yes"}, "maintenance_preference_invalid"),
            ({"checkBootloaderUnlocked": 0}, "maintenance_preference_invalid"),
            ({"checkFirmwareHash": None}, "maintenance_preference_invalid"),
            ({"checkModuleUpdates": 1}, "maintenance_preference_invalid"),
            ({"showNotifications": "no"}, "maintenance_preference_invalid"),
            ({"rebootTimeoutSeconds": True}, "reboot_timeout_invalid"),
            ({"rebootTimeoutSeconds": 0}, "reboot_timeout_invalid"),
            ({"rebootTimeoutSeconds": 3601}, "reboot_timeout_invalid"),
            ({"customizeFont": 1}, "maintenance_preference_invalid"),
            ({"fontFace": ""}, "font_face_invalid"),
            ({"fontFace": "Font; color: red"}, "font_face_invalid"),
            ({"fontFace": "A" * 97}, "font_face_invalid"),
            ({"fontSize": True}, "font_size_invalid"),
            ({"fontSize": 5}, "font_size_invalid"),
            ({"fontSize": 51}, "font_size_invalid"),
            ({"toolbarPosition": "floating"}, "toolbar_position_invalid"),
            ({"toolbarPosition": 1}, "toolbar_position_invalid"),
            ({"toolbarShowDevice": 1}, "maintenance_preference_invalid"),
            ({"toolbarShowTheme": "yes"}, "maintenance_preference_invalid"),
            ({"toolbarShowLanguage": None}, "maintenance_preference_invalid"),
            ({"createBootTar": 1}, "maintenance_preference_invalid"),
        )
        for values, code in cases:
            with self.subTest(values=values):
                with self.assertRaises(PreferencesError) as raised:
                    ModernPreferences.from_mapping(values)
                self.assertEqual(code, raised.exception.code)

    @settings(max_examples=100, deadline=None)
    @given(
        theme=st.sampled_from(("dark", "light")),
        locale=st.sampled_from(SUPPORTED_LOCALES),
        flags=st.lists(st.booleans(), min_size=20, max_size=20),
        zoom=st.integers(min_value=MIN_ZOOM, max_value=MAX_ZOOM),
        reboot_timeout=st.integers(min_value=1, max_value=3600),
        font_face=st.sampled_from(("Courier", "Cascadia Code", "Noto Sans Mono")),
        font_size=st.integers(min_value=6, max_value=50),
        toolbar_position=st.sampled_from(("top", "right", "bottom", "left")),
    )
    def test_property_every_valid_preference_round_trips_without_loss(
        self,
        theme: str,
        locale: str,
        flags: list[bool],
        zoom: int,
        reboot_timeout: int,
        font_face: str,
        font_size: int,
        toolbar_position: str,
    ) -> None:
        value = ModernPreferences(
            theme=theme,
            locale=locale,
            high_contrast=flags[0],
            reduced_motion=flags[1],
            zoom=zoom,
            expert_mode=flags[2],
            automatic_update_check=flags[3],
            check_disk_space=flags[4],
            check_bootloader_unlocked=flags[5],
            check_firmware_hash=flags[6],
            check_module_updates=flags[7],
            show_notifications=flags[8],
            reboot_timeout_seconds=reboot_timeout,
            offer_patch_methods=flags[9],
            show_recovery_patching=flags[10],
            keep_patch_temporary_files=flags[11],
            use_busybox_shell=flags[12],
            low_memory_mode=flags[13],
            extra_image_extracts=flags[14],
            show_custom_rom_options=flags[15],
            keybox_index=flags[16],
            customize_font=flags[17],
            font_face=font_face,
            font_size=font_size,
            toolbar_position=toolbar_position,
            toolbar_show_device=flags[18],
            toolbar_show_theme=flags[19],
            toolbar_show_language=flags[0],
            create_boot_tar=flags[1],
        )

        encoded = value.to_dict()
        self.assertEqual(value, ModernPreferences.from_mapping(encoded, require_schema=True))
        self.assertEqual(PREFERENCES_SCHEMA_VERSION, encoded["schemaVersion"])
        self.assertEqual(value.create_boot_tar, encoded["createBootTar"])

    @settings(max_examples=100, deadline=None)
    @given(
        field=st.sampled_from(
            (
                "automaticUpdateCheck",
                "checkDiskSpace",
                "checkBootloaderUnlocked",
                "checkFirmwareHash",
                "checkModuleUpdates",
                "showNotifications",
                "offerPatchMethods",
                "showRecoveryPatching",
                "keepPatchTemporaryFiles",
                "useBusyboxShell",
                "lowMemoryMode",
                "extraImageExtracts",
                "showCustomRomOptions",
                "keyboxIndex",
                "customizeFont",
                "toolbarShowDevice",
                "toolbarShowTheme",
                "toolbarShowLanguage",
                "createBootTar",
            )
        ),
        invalid=st.one_of(st.none(), st.integers(), st.text(max_size=12), st.lists(st.booleans(), max_size=2)),
    )
    def test_property_boolean_preferences_reject_non_booleans(self, field: str, invalid: object) -> None:
        if isinstance(invalid, bool):
            return
        with self.assertRaises(PreferencesError) as raised:
            ModernPreferences.from_mapping({field: invalid})
        self.assertEqual("maintenance_preference_invalid", raised.exception.code)


class PreferencePersistenceTests(unittest.TestCase):
    def test_missing_file_and_partial_schema_use_safe_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            self.assertEqual(ModernPreferences(), load_preferences(path))
            self.assertFalse(path.exists())

            path.write_text(
                json.dumps(
                    {
                        "_pixelflasher_core_schema": 1,
                        PREFERENCES_KEY: {
                            "schemaVersion": PREFERENCES_SCHEMA_VERSION,
                            "theme": "light",
                        },
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                ModernPreferences(theme="light"),
                load_preferences(ConfigStore(path)),
            )

    def test_reads_recognized_9x_flat_values_and_ignores_unrelated_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "device": "SERIAL",
                        "firmware_path": "factory.zip",
                        "theme": "light",
                        "language": "zh_TW",
                        "high_contrast": True,
                        "reduced_motion": True,
                        "ui_zoom": 130,
                        "advanced_options": True,
                        "update_check": True,
                        "check_for_disk_space": False,
                        "check_for_bootloader_unlocked": False,
                        "check_for_firmware_hash_validity": False,
                        "check_module_updates": True,
                        "show_notifications": True,
                        "reboot_to_system_timeout": 180,
                        "offer_patch_methods": True,
                        "show_recovery_patching_option": True,
                        "keep_patch_temporary_files": True,
                        "use_busybox_shell": True,
                        "low_mem": True,
                        "extra_img_extracts": True,
                        "show_custom_rom_options": True,
                        "kb_index": True,
                        "customize_font": True,
                        "pf_font_face": "Cascadia Code",
                        "pf_font_size": 18,
                        "toolbar": {
                            "tb_position": "right",
                            "tb_show_text": True,
                            "visible": {"partition_manager": True},
                        },
                    }
                ),
                encoding="utf-8",
            )

            preferences = load_preferences(path)

            self.assertEqual(
                ModernPreferences(
                    "light",
                    "zh_TW",
                    True,
                    True,
                    130,
                    True,
                    automatic_update_check=True,
                    check_disk_space=False,
                    check_bootloader_unlocked=False,
                    check_firmware_hash=False,
                    check_module_updates=True,
                    show_notifications=True,
                    reboot_timeout_seconds=180,
                    offer_patch_methods=True,
                    show_recovery_patching=True,
                    keep_patch_temporary_files=True,
                    use_busybox_shell=True,
                    low_memory_mode=True,
                    extra_image_extracts=True,
                    show_custom_rom_options=True,
                    keybox_index=True,
                    customize_font=True,
                    font_face="Cascadia Code",
                    font_size=18,
                    toolbar_position="right",
                ),
                preferences,
            )
            # Loading a schema-0 9.x file migrates only after exact backups.
            migrated = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(2, migrated["_pixelflasher_core_schema"])
            self.assertEqual(
                {
                    "tb_position": "right",
                    "tb_show_text": True,
                    "visible": {"partition_manager": True},
                },
                migrated["toolbar"],
            )
            original = {
                key: value
                for key, value in migrated.items()
                if key not in {"_pixelflasher_core_schema", "modern"}
            }
            self.assertEqual(
                original,
                json.loads(path.with_name("config.json.bak").read_text(encoding="utf-8")),
            )
            self.assertEqual(
                original,
                json.loads(path.with_name("config.json.v9.bak").read_text(encoding="utf-8")),
            )

    def test_canonical_nested_preferences_take_precedence_over_legacy_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "theme": "light",
                        "language": "es",
                        PREFERENCES_KEY: ModernPreferences(
                            "dark",
                            "fr",
                            True,
                            False,
                            90,
                        ).to_dict(),
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                ModernPreferences("dark", "fr", True, False, 90),
                load_preferences(path),
            )

    def test_unknown_or_malformed_nested_fields_are_rejected(self):
        cases = (
            (None, "preferences_not_object"),
            ("not-an-object", "preferences_not_object"),
            ({"theme": "dark"}, "preferences_schema_invalid"),
            ({"theme": "dark", "extra": True}, "unknown_preference_field"),
            ({"schemaVersion": 1, "zoom": "100"}, "zoom_invalid"),
        )
        for modern, code in cases:
            with self.subTest(modern=modern):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "config.json"
                    path.write_text(
                        json.dumps({PREFERENCES_KEY: modern}),
                        encoding="utf-8",
                    )
                    with self.assertRaises(PreferencesError) as raised:
                        load_preferences(path)
                    self.assertEqual(code, raised.exception.code)

    def test_conflicting_legacy_aliases_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps({"language": "es", "locale": "fr"}),
                encoding="utf-8",
            )

            with self.assertRaises(PreferencesError) as raised:
                load_preferences(path)

            self.assertEqual("legacy_preference_ambiguous", raised.exception.code)

    def test_save_preserves_legacy_data_and_uses_atomic_backup_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = {
                "device": "SERIAL",
                "firmware_path": "factory.zip",
                "toolbar": {"visible": {"partition_manager": True}},
                "language": "en",
            }
            path.write_text(json.dumps(original), encoding="utf-8")
            store = ConfigStore(path)
            expected = ModernPreferences("light", "it", True, True, 120)

            saved = save_preferences(store, expected)

            self.assertEqual(expected, saved)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("SERIAL", payload["device"])
            self.assertEqual(original["toolbar"], payload["toolbar"])
            self.assertEqual(expected.to_dict(), payload[PREFERENCES_KEY])
            self.assertEqual("light", payload["theme"])
            self.assertEqual("it", payload["language"])
            self.assertEqual(2, payload["_pixelflasher_core_schema"])
            self.assertEqual(expected.to_dict(), payload["modern"][PREFERENCES_KEY])
            self.assertEqual(
                original,
                json.loads(store.migration_backup_path.read_text(encoding="utf-8")),
            )
            previous_schema_two = json.loads(
                store.backup_path.read_text(encoding="utf-8")
            )
            self.assertEqual(2, previous_schema_two["_pixelflasher_core_schema"])
            self.assertEqual(original["toolbar"], previous_schema_two["toolbar"])
            self.assertEqual([], list(path.parent.glob(".config.json.*.tmp")))

            previous = path.read_bytes()
            save_preferences(store, ModernPreferences(locale="fr"))
            self.assertEqual(previous, store.backup_path.read_bytes())
            self.assertEqual([], list(path.parent.glob(".config.json.*.tmp")))

    def test_save_accepts_strict_mapping_and_rejects_invalid_without_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps({"_pixelflasher_core_schema": 1, "device": "SERIAL"}),
                encoding="utf-8",
            )
            before = path.read_bytes()

            with self.assertRaises(PreferencesError) as raised:
                save_preferences(path, {"theme": "dark", "unknown": False})
            self.assertEqual("unknown_preference_field", raised.exception.code)
            self.assertEqual(before, path.read_bytes())
            self.assertFalse(path.with_name("config.json.bak").exists())

            saved = save_preferences(
                path,
                {
                    "theme": "dark",
                    "locale": "es",
                    "highContrast": False,
                    "reducedMotion": True,
                    "zoom": 110,
                },
            )
            self.assertEqual(ModernPreferences("dark", "es", False, True, 110), saved)

    def test_save_updates_all_existing_aliases_and_required_9x_mirrors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "uiTheme": "light",
                        "locale": "es",
                        "highContrast": False,
                        "reducedMotion": False,
                        "zoom": 90,
                        "unrelated": {"keep": True},
                    }
                ),
                encoding="utf-8",
            )
            expected = ModernPreferences(
                "dark",
                "fr",
                high_contrast=True,
                reduced_motion=True,
                zoom=175,
            )

            save_preferences(path, expected)
            payload = json.loads(path.read_text(encoding="utf-8"))

            self.assertEqual("dark", payload["theme"])
            self.assertEqual("dark", payload["uiTheme"])
            self.assertEqual("fr", payload["language"])
            self.assertEqual("fr", payload["locale"])
            self.assertTrue(payload["high_contrast"])
            self.assertTrue(payload["highContrast"])
            self.assertTrue(payload["reduced_motion"])
            self.assertTrue(payload["reducedMotion"])
            self.assertEqual(175, payload["ui_zoom"])
            self.assertEqual(175, payload["zoom"])
            self.assertEqual({"keep": True}, payload["unrelated"])
            self.assertEqual(expected.to_dict(), payload[PREFERENCES_KEY])

    def test_save_does_not_overwrite_unknown_future_preference_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "_pixelflasher_core_schema": 1,
                        PREFERENCES_KEY: {
                            "schemaVersion": 1,
                            "theme": "dark",
                            "futureField": "preserve-me",
                        },
                    }
                ),
                encoding="utf-8",
            )
            before = path.read_bytes()

            with self.assertRaises(PreferencesError) as raised:
                save_preferences(path, ModernPreferences(theme="light"))

            self.assertEqual("unknown_preference_field", raised.exception.code)
            migrated = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(2, migrated["_pixelflasher_core_schema"])
            self.assertEqual(
                "preserve-me",
                migrated[PREFERENCES_KEY]["futureField"],
            )
            self.assertEqual(
                before,
                path.with_name("config.json.v9.bak").read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
