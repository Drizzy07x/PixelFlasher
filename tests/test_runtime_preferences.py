import json
import tempfile
import threading
import unittest
from pathlib import Path

from pixelflasher_core.config_store import ConfigStore
from pixelflasher_core.contracts import AppCommand, AppSnapshot, OperationStatus
from pixelflasher_core.preferences import ModernPreferences, PREFERENCES_KEY
from pixelflasher_core.runtime import ApplicationRuntime


def versioned_config(path: Path, **values) -> None:
    path.write_text(
        json.dumps({"_pixelflasher_core_schema": 1, **values}),
        encoding="utf-8",
    )


class RuntimePreferencesTests(unittest.TestCase):
    def test_scrcpy_executable_is_loaded_only_from_backend_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "config.json"
            executable = root / "scrcpy.exe"
            versioned_config(path, scrcpy={"path": str(executable), "flags": "--unsafe"})

            runtime = ApplicationRuntime.open(path)

            self.assertEqual(
                executable,
                runtime.engine.device_tools_service.scrcpy_executable,
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
            self.assertEqual([result], observed)
            self.assertEqual(0, runtime.snapshot().revision)
            subscription.cancel()
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
                    payload={"theme": "light", "locale": "es", "zoom": 200},
                )
            )

            expected = ModernPreferences("light", "es", False, True, 200)
            self.assertTrue(result.ok)
            self.assertEqual("settings_updated", result.code)
            self.assertEqual(expected.to_dict(), result.value["preferences"])
            self.assertEqual(0, runtime.snapshot().revision)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(expected.to_dict(), payload[PREFERENCES_KEY])
            self.assertEqual({"preserve": True}, payload["unrelated"])
            self.assertEqual("light", payload["theme"])
            self.assertEqual("es", payload["language"])
            self.assertEqual(
                expected.to_dict(),
                runtime.config_document.values[PREFERENCES_KEY],
            )
            runtime.shutdown()

            reopened = ApplicationRuntime.open(path)
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

            missing = runtime.execute(
                AppCommand("settings.update", payload={"theme": "light"})
            )
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

    def test_concurrent_partial_updates_are_serialized_without_lost_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            versioned_config(path, **{PREFERENCES_KEY: ModernPreferences().to_dict()})
            runtime = ApplicationRuntime.open(path)
            barrier = threading.Barrier(3)
            results = []

            def update(payload):
                barrier.wait()
                results.append(
                    runtime.execute(
                        AppCommand(
                            "settings.update",
                            expected_revision=0,
                            payload=payload,
                        )
                    )
                )

            workers = [
                threading.Thread(target=update, args=({"theme": "light"},)),
                threading.Thread(target=update, args=({"locale": "it"},)),
            ]
            for worker in workers:
                worker.start()
            barrier.wait()
            for worker in workers:
                worker.join(2)

            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertEqual(2, len(results))
            self.assertTrue(all(result.ok for result in results))
            loaded = runtime.execute(AppCommand("settings.get"))
            self.assertEqual("light", loaded.value["preferences"]["theme"])
            self.assertEqual("it", loaded.value["preferences"]["locale"])
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

            failed = runtime.execute(
                AppCommand(
                    "settings.update",
                    expected_revision=0,
                    payload={"theme": "light"},
                )
            )
            self.assertEqual(OperationStatus.FAILED, failed.status)
            self.assertEqual("settings_save_failed", failed.code)

            store.fail = False
            runtime.shutdown()
            stopped = runtime.execute(AppCommand("settings.get"))
            self.assertEqual("engine_shutdown", stopped.code)


if __name__ == "__main__":
    unittest.main()
