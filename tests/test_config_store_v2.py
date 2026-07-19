import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pixelflasher_core.config_store import (
    CURRENT_SCHEMA_VERSION,
    MODERN_KEY,
    SCHEMA_KEY,
    ConfigDocument,
    ConfigError,
    ConfigStore,
)


class ConfigStoreV2Tests(unittest.TestCase):
    def test_schema_two_uses_nested_canonical_values_and_legacy_mirrors(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            store = ConfigStore(path)
            document = ConfigDocument(
                values={
                    "device": "SERIAL",
                    "theme": "dark",
                    "_pixelflasher_core_state": {"selected_serials": ["SERIAL"]},
                    "_pixelflasher_modern_preferences": {"schemaVersion": 1, "theme": "light"},
                }
            )

            store.save(document)
            raw = json.loads(path.read_text(encoding="utf-8"))

            self.assertEqual(CURRENT_SCHEMA_VERSION, raw[SCHEMA_KEY])
            self.assertEqual("SERIAL", raw["device"])
            self.assertEqual(document.values["_pixelflasher_core_state"], raw[MODERN_KEY]["_pixelflasher_core_state"])
            self.assertEqual(document.values["_pixelflasher_modern_preferences"], raw[MODERN_KEY]["_pixelflasher_modern_preferences"])

    def test_nested_values_take_precedence_over_stale_legacy_mirror(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        SCHEMA_KEY: 2,
                        "_pixelflasher_core_state": {"selected_serials": ["OLD"]},
                        MODERN_KEY: {
                            "_pixelflasher_core_state": {"selected_serials": ["NEW"]},
                        },
                    }
                ),
                encoding="utf-8",
            )

            loaded = ConfigStore(path).load()

            state = loaded.values["_pixelflasher_core_state"]
            self.assertIsInstance(state, dict)
            if not isinstance(state, dict):
                self.fail("canonical core state is not an object")
            self.assertEqual(["NEW"], state["selected_serials"])

    def test_schema_one_is_migrated_after_immutable_backup_and_extras_round_trip(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = {SCHEMA_KEY: 1, "device": "SERIAL"}
            path.write_text(json.dumps(original), encoding="utf-8")
            store = ConfigStore(path)

            store.load()

            self.assertEqual(original, json.loads(store.backup_path.read_text(encoding="utf-8")))
            self.assertEqual(
                original,
                json.loads(store.migration_backup_path.read_text(encoding="utf-8")),
            )
            self.assertEqual(2, json.loads(path.read_text(encoding="utf-8"))[SCHEMA_KEY])

            extras_path = Path(directory) / "extras.json"
            extras_path.write_text(
                json.dumps({SCHEMA_KEY: 2, MODERN_KEY: {"arbitrary": True}}),
                encoding="utf-8",
            )
            extras = ConfigStore(extras_path).load()
            self.assertEqual({"arbitrary": True}, dict(extras.modern_extras))
            ConfigStore(extras_path).save(extras)
            self.assertTrue(
                json.loads(extras_path.read_text(encoding="utf-8"))[MODERN_KEY]["arbitrary"]
            )

    def test_malformed_namespace_without_backup_fails(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps({SCHEMA_KEY: 2, MODERN_KEY: "not-an-object"}),
                encoding="utf-8",
            )

            with self.assertRaises(ConfigError) as raised:
                ConfigStore(path).load()

            self.assertEqual("config_recovery_unavailable", raised.exception.code)

    def test_legacy_migration_is_idempotent_and_never_rewrites_its_backup(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = b'{"device":"SERIAL","unknown":{"keep":[1,2,3]}}'
            path.write_bytes(original)
            store = ConfigStore(path)

            first = store.load()
            migrated = path.read_bytes()
            rolling_backup = store.backup_path.read_bytes()
            migration_backup = store.migration_backup_path.read_bytes()

            with patch(
                "pixelflasher_core.config_store.os.replace",
                side_effect=AssertionError("schema-v2 load attempted a write"),
            ):
                second = store.load()

            self.assertEqual(first, second)
            self.assertEqual(migrated, path.read_bytes())
            self.assertEqual(original, rolling_backup)
            self.assertEqual(original, migration_backup)
            self.assertEqual(rolling_backup, store.backup_path.read_bytes())
            self.assertEqual(
                migration_backup,
                store.migration_backup_path.read_bytes(),
            )

    def test_failed_migration_keeps_legacy_primary_and_retries_from_durable_backup(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = b'{"device":"SERIAL","unknown":"keep"}'
            path.write_bytes(original)
            store = ConfigStore(path)
            real_replace = os.replace

            def fail_primary_replace(
                source: str | os.PathLike[str],
                target: str | os.PathLike[str],
            ) -> None:
                if Path(target) == path:
                    raise OSError("injected migration commit failure")
                real_replace(source, target)

            with (
                patch(
                    "pixelflasher_core.config_store.os.replace",
                    side_effect=fail_primary_replace,
                ),
                self.assertRaises(ConfigError) as raised,
            ):
                store.load()

            self.assertEqual("config_save_failed", raised.exception.code)
            self.assertEqual(original, path.read_bytes())
            self.assertEqual(original, store.backup_path.read_bytes())
            self.assertEqual(original, store.migration_backup_path.read_bytes())
            self.assertEqual([], list(path.parent.glob(".config.json.*.tmp")))

            recovered = store.load()
            self.assertEqual("SERIAL", recovered.values["device"])
            self.assertEqual(
                CURRENT_SCHEMA_VERSION,
                json.loads(path.read_text(encoding="utf-8"))[SCHEMA_KEY],
            )
            self.assertEqual(original, store.migration_backup_path.read_bytes())

    def test_atomic_save_orders_file_fsync_replace_and_directory_fsync(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            store = ConfigStore(path)
            events: list[str] = []
            real_fsync = os.fsync
            real_replace = os.replace

            def record_fsync(descriptor: int) -> None:
                events.append("file-fsync")
                real_fsync(descriptor)

            def record_replace(source: str | os.PathLike[str], target: str | os.PathLike[str]) -> None:
                events.append("replace")
                real_replace(source, target)

            def record_directory(_path: Path) -> None:
                events.append("directory-fsync")

            with (
                patch(
                    "pixelflasher_core.config_store.os.fsync",
                    side_effect=record_fsync,
                ),
                patch(
                    "pixelflasher_core.config_store.os.replace",
                    side_effect=record_replace,
                ),
                patch.object(
                    ConfigStore,
                    "_fsync_directory",
                    side_effect=record_directory,
                ),
            ):
                store.save(ConfigDocument(values={"device": "SERIAL"}))

            self.assertEqual(
                ["file-fsync", "replace", "directory-fsync"],
                events,
            )
            self.assertEqual(
                "SERIAL",
                json.loads(path.read_text(encoding="utf-8"))["device"],
            )
            self.assertEqual([], list(path.parent.glob(".config.json.*.tmp")))

    def test_faults_before_replace_leave_original_and_remove_temporary_file(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            store = ConfigStore(path)
            store.save(ConfigDocument(values={"generation": 1}))
            original = path.read_bytes()
            real_replace = os.replace

            def reject_main_replace(
                source: str | os.PathLike[str],
                target: str | os.PathLike[str],
            ) -> None:
                if Path(target) == path:
                    raise OSError("injected replace failure")
                real_replace(source, target)

            cases = (
                (
                    "dump",
                    patch(
                        "pixelflasher_core.config_store.json.dump",
                        side_effect=OSError("injected dump failure"),
                    ),
                ),
                (
                    "replace",
                    patch(
                        "pixelflasher_core.config_store.os.replace",
                        side_effect=reject_main_replace,
                    ),
                ),
            )
            for label, failure in cases:
                with self.subTest(label=label), failure:
                    with self.assertRaises(ConfigError):
                        store.save(ConfigDocument(values={"generation": 2}))
                self.assertEqual(original, path.read_bytes())
                self.assertEqual([], list(path.parent.glob(".config.json.*.tmp")))

    def test_fsync_and_tempfile_faults_do_not_publish_partial_configuration(self):
        cases = ("mkstemp", "fsync")
        for failure in cases:
            with self.subTest(failure=failure), TemporaryDirectory() as directory:
                path = Path(directory) / "config.json"
                store = ConfigStore(path)
                context = (
                    patch(
                        "pixelflasher_core.config_store.tempfile.mkstemp",
                        side_effect=OSError("injected tempfile failure"),
                    )
                    if failure == "mkstemp"
                    else patch(
                        "pixelflasher_core.config_store.os.fsync",
                        side_effect=OSError("injected fsync failure"),
                    )
                )
                with context, self.assertRaises(ConfigError):
                    store.save(ConfigDocument(values={"generation": 1}))

                self.assertFalse(path.exists())
                self.assertEqual([], list(path.parent.glob(".config.json.*.tmp")))

    def test_directory_fsync_failure_never_leaves_partial_json(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            store = ConfigStore(path)

            with (
                patch.object(
                    ConfigStore,
                    "_fsync_directory",
                    side_effect=OSError("injected directory fsync failure"),
                ),
                self.assertRaises(ConfigError),
            ):
                store.save(ConfigDocument(values={"generation": 1}))

            # replace already committed before the durability error; the file
            # must therefore be the complete old or complete new generation.
            self.assertEqual(
                1,
                json.loads(path.read_text(encoding="utf-8"))["generation"],
            )
            self.assertEqual([], list(path.parent.glob(".config.json.*.tmp")))

    def test_corrupt_primary_is_preserved_and_recovered_from_valid_backup(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            store = ConfigStore(path)
            store.save(ConfigDocument(values={"generation": 1}))
            store.save(ConfigDocument(values={"generation": 2}))
            backup = store.backup_path.read_bytes()
            corrupt = b'{"generation":'
            path.write_bytes(corrupt)

            recovered = store.load()

            self.assertEqual(1, recovered.values["generation"])
            self.assertEqual(backup, path.read_bytes())
            self.assertEqual(backup, store.backup_path.read_bytes())
            self.assertEqual(corrupt, store.corrupt_backup_path.read_bytes())

    def test_duplicate_keys_nonfinite_numbers_and_corrupt_backup_fail_closed(self):
        invalid_payloads = (
            b'{"device":"A","device":"B"}',
            b'{"zoom":NaN}',
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload), TemporaryDirectory() as directory:
                path = Path(directory) / "config.json"
                store = ConfigStore(path)
                path.write_bytes(payload)
                store.backup_path.write_bytes(b"{also-corrupt")

                with self.assertRaises(ConfigError) as raised:
                    store.load()

                self.assertEqual(
                    "config_recovery_unavailable",
                    raised.exception.code,
                )
                self.assertEqual(payload, path.read_bytes())

    def test_newer_schema_never_downgrades_to_an_older_backup(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            store = ConfigStore(path)
            newer = json.dumps({SCHEMA_KEY: 99, "future": True}).encode()
            path.write_bytes(newer)
            store.backup_path.write_text(
                json.dumps({SCHEMA_KEY: 2, MODERN_KEY: {}, "device": "OLD"}),
                encoding="utf-8",
            )

            with self.assertRaises(ConfigError) as raised:
                store.load()

            self.assertEqual("config_schema_newer", raised.exception.code)
            self.assertEqual(newer, path.read_bytes())
            self.assertFalse(store.corrupt_backup_path.exists())

    def test_unknown_root_and_modern_fields_round_trip_without_stale_canonical_data(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            raw = {
                SCHEMA_KEY: 2,
                "toolbar": {"custom": [1, 2, 3]},
                "_pixelflasher_core_state": {"selected_serials": ["OLD"]},
                MODERN_KEY: {
                    "_pixelflasher_core_state": {
                        "selected_serials": ["NEW"],
                    },
                    "futureNamespace": {"preserve": True},
                },
            }
            path.write_text(json.dumps(raw), encoding="utf-8")
            store = ConfigStore(path)

            document = store.load()
            store.save(document)
            saved = json.loads(path.read_text(encoding="utf-8"))

            self.assertEqual(raw["toolbar"], saved["toolbar"])
            self.assertEqual(
                {"preserve": True},
                saved[MODERN_KEY]["futureNamespace"],
            )
            self.assertEqual(
                ["NEW"],
                saved["_pixelflasher_core_state"]["selected_serials"],
            )
            self.assertEqual(
                saved["_pixelflasher_core_state"],
                saved[MODERN_KEY]["_pixelflasher_core_state"],
            )

            # Runtime composition can rebuild ConfigDocument from logical
            # values only; ConfigStore still owns preservation of future data.
            store.save(
                ConfigDocument(
                    values={
                        "_pixelflasher_core_state": {
                            "selected_serials": ["LATEST"],
                        }
                    }
                )
            )
            rebuilt = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(raw["toolbar"], rebuilt["toolbar"])
            self.assertEqual(
                {"preserve": True},
                rebuilt[MODERN_KEY]["futureNamespace"],
            )
            self.assertEqual(
                ["LATEST"],
                rebuilt["_pixelflasher_core_state"]["selected_serials"],
            )

    def test_legacy_reserved_namespace_conflict_refuses_lossy_migration(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = json.dumps(
                {"device": "SERIAL", MODERN_KEY: "unrelated-9x-value"}
            ).encode()
            path.write_bytes(original)
            store = ConfigStore(path)

            with self.assertRaises(ConfigError) as raised:
                store.load()

            self.assertEqual(
                "config_legacy_reserved_key",
                raised.exception.code,
            )
            self.assertEqual(original, path.read_bytes())
            self.assertFalse(store.backup_path.exists())
            self.assertFalse(store.migration_backup_path.exists())


if __name__ == "__main__":
    unittest.main()
