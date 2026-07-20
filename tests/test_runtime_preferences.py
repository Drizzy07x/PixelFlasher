import json
import tempfile
import threading
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from pixelflasher_core import PixelFlasherEngine
from pixelflasher_core.config_store import ConfigStore
from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    OperationFinished,
    OperationStatus,
    SnapshotChanged,
)
from pixelflasher_core.engine import CommandEngine
from pixelflasher_core.preferences import PREFERENCES_KEY, ModernPreferences
from pixelflasher_core.runtime import ApplicationRuntime
from pixelflasher_core.store import StaleRevisionError


def versioned_config(path: Path, **values) -> None:
    path.write_text(
        json.dumps({"_pixelflasher_core_schema": 1, **values}),
        encoding="utf-8",
    )


class RuntimePreferencesTests(unittest.TestCase):
    def test_runtime_is_the_composition_root_for_the_public_engine_facade(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            versioned_config(path)

            runtime = ApplicationRuntime.open(path)

            self.assertIsInstance(runtime.command_engine, CommandEngine)
            self.assertIsInstance(runtime.engine, PixelFlasherEngine)
            self.assertFalse(hasattr(runtime.engine, "command_engine"))
            self.assertFalse(hasattr(runtime.engine, "register_support_destination"))
            self.assertIs(runtime.snapshot(), runtime.engine.snapshot())
            self.assertIs(
                runtime.command_engine.package_service.apk_inspector,
                runtime.command_engine.rooting_service.apk_inspector,
            )
            runtime.shutdown()

    def test_scrcpy_executable_is_loaded_only_from_backend_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "config.json"
            executable = root / "scrcpy.exe"
            versioned_config(path, scrcpy={"path": str(executable), "flags": "--unsafe"})

            runtime = ApplicationRuntime.open(path)

            self.assertEqual(
                executable,
                runtime.command_engine.device_tools_service.scrcpy_executable,
            )
            runtime.shutdown()

    def test_get_loads_host_preferences_without_requiring_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            expected = ModernPreferences("light", "fr", True, True, 120)
            versioned_config(path, **{PREFERENCES_KEY: expected.to_dict()})
            runtime = ApplicationRuntime.open(path)
            observed = []
            subscription = runtime.subscribe(observed.append)

            result = runtime.execute(AppCommand("settings.get"))

            self.assertEqual(OperationStatus.SUCCESS, result.status)
            self.assertEqual("settings_loaded", result.code)
            self.assertEqual(expected.to_dict(), result.value["preferences"])
            self.assertEqual(expected, runtime.snapshot().preferences)
            self.assertEqual(expected.to_dict(), runtime.snapshot().to_dict()["preferences"])
            self.assertEqual([OperationFinished(result)], observed)
            self.assertEqual(0, runtime.snapshot().revision)
            subscription()
            runtime.shutdown()

    def test_update_merges_partial_payload_persists_and_keeps_document_coherent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            versioned_config(
                path,
                device="SERIAL",
                unrelated={"preserve": True},
                **{PREFERENCES_KEY: ModernPreferences(reduced_motion=True).to_dict()},
            )
            runtime = ApplicationRuntime.open(path)

            result = runtime.execute(
                AppCommand(
                    "settings.update",
                    expected_revision=0,
                    payload={
                        "theme": "light",
                        "locale": "es",
                        "zoom": 200,
                        "expertMode": True,
                        "automaticUpdateCheck": True,
                        "checkDiskSpace": False,
                        "checkBootloaderUnlocked": False,
                        "checkFirmwareHash": False,
                        "checkModuleUpdates": True,
                        "showNotifications": True,
                        "rebootTimeoutSeconds": 240,
                        "offerPatchMethods": True,
                        "showRecoveryPatching": True,
                        "keepPatchTemporaryFiles": True,
                        "useBusyboxShell": True,
                        "lowMemoryMode": True,
                        "extraImageExtracts": True,
                        "showCustomRomOptions": True,
                        "keyboxIndex": True,
                        "customizeFont": True,
                        "fontFace": "Cascadia Code",
                        "fontSize": 18,
                    },
                )
            )

            expected = ModernPreferences(
                "light",
                "es",
                False,
                True,
                200,
                True,
                automatic_update_check=True,
                check_disk_space=False,
                check_bootloader_unlocked=False,
                check_firmware_hash=False,
                check_module_updates=True,
                show_notifications=True,
                reboot_timeout_seconds=240,
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
            )
            self.assertTrue(result.ok)
            self.assertEqual("settings_updated", result.code)
            self.assertEqual(expected.to_dict(), result.value["preferences"])
            self.assertEqual(1, runtime.snapshot().revision)
            self.assertEqual(expected, runtime.snapshot().preferences)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(expected.to_dict(), payload[PREFERENCES_KEY])
            self.assertEqual({"preserve": True}, payload["unrelated"])
            self.assertEqual("light", payload["theme"])
            self.assertEqual("es", payload["language"])
            self.assertTrue(payload["advanced_options"])
            self.assertTrue(payload["update_check"])
            self.assertFalse(payload["check_for_disk_space"])
            self.assertFalse(payload["check_for_bootloader_unlocked"])
            self.assertFalse(payload["check_for_firmware_hash_validity"])
            self.assertTrue(payload["check_module_updates"])
            self.assertTrue(payload["show_notifications"])
            self.assertEqual(240, payload["reboot_to_system_timeout"])
            self.assertTrue(payload["offer_patch_methods"])
            self.assertTrue(payload["show_recovery_patching_option"])
            self.assertTrue(payload["keep_patch_temporary_files"])
            self.assertTrue(payload["use_busybox_shell"])
            self.assertTrue(payload["low_mem"])
            self.assertTrue(payload["extra_img_extracts"])
            self.assertTrue(payload["show_custom_rom_options"])
            self.assertTrue(payload["kb_index"])
            self.assertTrue(payload["customize_font"])
            self.assertEqual("Cascadia Code", payload["pf_font_face"])
            self.assertEqual(18, payload["pf_font_size"])
            self.assertEqual(
                expected.to_dict(),
                runtime.config_document.values[PREFERENCES_KEY],
            )
            runtime.shutdown()

            reopened = ApplicationRuntime.open(path)
            self.assertEqual(expected, reopened.snapshot().preferences)
            loaded = reopened.execute(AppCommand("settings.get"))
            self.assertEqual(expected.to_dict(), loaded.value["preferences"])
            reopened.shutdown()

    def test_update_requires_current_snapshot_revision_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            versioned_config(path, **{PREFERENCES_KEY: ModernPreferences().to_dict()})
            runtime = ApplicationRuntime.open(path)
            runtime.store.update(expected_revision=0, selected_serials=("SERIAL",), selected_serial="SERIAL")
            before = path.read_bytes()

            missing = runtime.execute(AppCommand("settings.update", payload={"theme": "light"}))
            stale = runtime.execute(
                AppCommand(
                    "settings.update",
                    expected_revision=0,
                    payload={"theme": "light"},
                )
            )

            self.assertEqual("revision_required", missing.code)
            self.assertEqual("stale_revision", stale.code)
            self.assertEqual(before, path.read_bytes())
            runtime.shutdown()

    def test_reusing_one_settings_revision_succeeds_once_then_is_stale(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            versioned_config(path, **{PREFERENCES_KEY: ModernPreferences().to_dict()})
            runtime = ApplicationRuntime.open(path)

            first = runtime.execute(
                AppCommand(
                    "settings.update",
                    expected_revision=0,
                    payload={"theme": "light"},
                )
            )
            second = runtime.execute(
                AppCommand(
                    "settings.update",
                    expected_revision=0,
                    payload={"locale": "es"},
                )
            )

            self.assertEqual(OperationStatus.SUCCESS, first.status)
            self.assertEqual("settings_updated", first.code)
            self.assertEqual(OperationStatus.FAILED, second.status)
            self.assertEqual("stale_revision", second.code)
            self.assertEqual(1, runtime.snapshot().revision)
            self.assertEqual(
                ModernPreferences(theme="light"),
                runtime.snapshot().preferences,
            )
            runtime.shutdown()

    def test_invalid_fields_types_and_get_payload_fail_without_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            versioned_config(path, **{PREFERENCES_KEY: ModernPreferences().to_dict()})
            runtime = ApplicationRuntime.open(path)
            before = path.read_bytes()

            cases = (
                (
                    AppCommand(
                        "settings.update",
                        expected_revision=0,
                        payload={"unknown": True},
                    ),
                    "unknown_preference_field",
                ),
                (
                    AppCommand(
                        "settings.update",
                        expected_revision=0,
                        payload={"highContrast": 1},
                    ),
                    "high_contrast_invalid",
                ),
                (
                    AppCommand("settings.get", payload={"include": "theme"}),
                    "invalid_settings_payload",
                ),
            )
            for command, code in cases:
                with self.subTest(code=code):
                    result = runtime.execute(command)
                    self.assertEqual(OperationStatus.FAILED, result.status)
                    self.assertEqual(code, result.code)
                    self.assertEqual(before, path.read_bytes())
            runtime.shutdown()

    def test_concurrent_same_revision_updates_have_one_winner_and_one_stale_result(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            versioned_config(path, **{PREFERENCES_KEY: ModernPreferences().to_dict()})
            runtime = ApplicationRuntime.open(path)
            barrier = threading.Barrier(3)
            results = {}

            def update(name, payload):
                barrier.wait()
                results[name] = runtime.execute(
                    AppCommand(
                        "settings.update",
                        expected_revision=0,
                        payload=payload,
                    )
                )

            workers = [
                threading.Thread(
                    target=update,
                    args=("theme", {"theme": "light"}),
                ),
                threading.Thread(
                    target=update,
                    args=("locale", {"locale": "it"}),
                ),
            ]
            for worker in workers:
                worker.start()
            barrier.wait()
            for worker in workers:
                worker.join(2)

            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertEqual(2, len(results))
            self.assertEqual(
                [OperationStatus.FAILED, OperationStatus.SUCCESS],
                sorted(result.status for result in results.values()),
            )
            self.assertEqual(
                ["settings_updated", "stale_revision"],
                sorted(result.code for result in results.values()),
            )
            self.assertEqual(1, runtime.snapshot().revision)
            loaded = runtime.execute(AppCommand("settings.get"))
            if results["theme"].ok:
                self.assertEqual("light", loaded.value["preferences"]["theme"])
                self.assertEqual("en", loaded.value["preferences"]["locale"])
            else:
                self.assertEqual("dark", loaded.value["preferences"]["theme"])
                self.assertEqual("it", loaded.value["preferences"]["locale"])
            runtime.shutdown()

    def test_persistence_is_inside_the_revision_lock_until_promotion(self):
        class BlockingStore(ConfigStore):
            block = False
            entered = threading.Event()
            release = threading.Event()

            def save(self, document):
                if self.block:
                    self.entered.set()
                    if not self.release.wait(2):
                        raise OSError("test persistence release timed out")
                return super().save(document)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            versioned_config(path, **{PREFERENCES_KEY: ModernPreferences().to_dict()})
            store = BlockingStore(path)
            document = store.load()
            runtime = ApplicationRuntime(
                store,
                document,
                ApplicationRuntime._snapshot_from_config(document),
            )
            store.block = True
            setting_results = []
            competing_errors = []

            setting = threading.Thread(
                target=lambda: setting_results.append(
                    runtime.execute(
                        AppCommand(
                            "settings.update",
                            expected_revision=0,
                            payload={"theme": "light"},
                        )
                    )
                )
            )

            def competing_update():
                try:
                    runtime.store.update(
                        expected_revision=0,
                        selected_serial="SERIAL",
                        selected_serials=("SERIAL",),
                    )
                except StaleRevisionError as error:
                    competing_errors.append(error)

            setting.start()
            self.assertTrue(store.entered.wait(1))
            competing = threading.Thread(target=competing_update)
            competing.start()
            competing.join(0.05)
            self.assertTrue(competing.is_alive())

            store.release.set()
            setting.join(2)
            competing.join(2)

            self.assertTrue(setting_results[0].ok)
            self.assertEqual(1, runtime.snapshot().revision)
            self.assertEqual(1, len(competing_errors))
            self.assertEqual(1, competing_errors[0].actual)
            runtime.shutdown()

    def test_snapshot_preferences_are_immutable_and_settings_get_is_canonical(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            initial = ModernPreferences(theme="light", locale="fr")
            versioned_config(path, **{PREFERENCES_KEY: initial.to_dict()})
            runtime = ApplicationRuntime.open(path)
            snapshot = runtime.snapshot()

            with self.assertRaises(FrozenInstanceError):
                snapshot.preferences.theme = "dark"  # type: ignore[misc]

            external = ModernPreferences(locale="it")
            versioned_config(path, **{PREFERENCES_KEY: external.to_dict()})
            loaded = runtime.execute(AppCommand("settings.get"))

            self.assertEqual(initial.to_dict(), loaded.value["preferences"])
            self.assertIs(snapshot, runtime.snapshot())
            runtime.shutdown()

    def test_persistence_failure_and_post_shutdown_calls_are_explicit(self):
        class FailingStore(ConfigStore):
            fail = True

            def save(self, document):
                if self.fail:
                    raise OSError("disk unavailable")
                return super().save(document)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            versioned_config(path, **{PREFERENCES_KEY: ModernPreferences().to_dict()})
            store = FailingStore(path)
            runtime = ApplicationRuntime(store, store.load(), AppSnapshot())
            before_snapshot = runtime.snapshot()
            before_document = runtime.config_document
            observed = []
            unsubscribe = runtime.subscribe(observed.append)

            failed = runtime.execute(
                AppCommand(
                    "settings.update",
                    expected_revision=0,
                    payload={"theme": "light"},
                )
            )
            self.assertEqual(OperationStatus.FAILED, failed.status)
            self.assertEqual("settings_save_failed", failed.code)
            self.assertIs(before_snapshot, runtime.snapshot())
            self.assertIs(before_document, runtime.config_document)
            self.assertFalse(any(isinstance(event, SnapshotChanged) for event in observed))

            store.fail = False
            unsubscribe()
            runtime.shutdown()
            stopped = runtime.execute(AppCommand("settings.get"))
            self.assertEqual("engine_shutdown", stopped.code)


if __name__ == "__main__":
    unittest.main()
