import hashlib
import io
import json
import sqlite3
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pixelflasher_core.config_store import ConfigDocument, ConfigStore
from pixelflasher_core.contracts import AppCommand
from pixelflasher_core.repositories import ArtifactRepository
from pixelflasher_core.runtime import ApplicationRuntime
from tests.test_persistent_artifact_repository import _legacy_database


def _write_factory(path: Path) -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("boot.img", b"ANDROID!" + b"stock")
        archive.writestr("vbmeta.img", b"vbmeta")
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("flash-all.sh", b"never execute")
        archive.writestr("image-husky-AP4A.260705.001.zip", inner.getvalue())


class RuntimeArtifactRepositoryTests(unittest.TestCase):
    def test_firmware_selection_roundtrips_by_repository_identity_not_json_path(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            source = root / "factory.zip"
            decoy = root / "decoy.zip"
            _write_factory(source)
            decoy.write_bytes(b"private decoy")
            runtime = ApplicationRuntime.open(config)

            selected = runtime.execute(
                AppCommand(
                    "firmware.select",
                    payload={"path": str(source)},
                    expected_revision=0,
                    operation_id="select-canonical-firmware",
                )
            )
            canonical = runtime.snapshot().firmware

            self.assertTrue(selected.ok)
            self.assertNotEqual(str(source.resolve()), canonical.path)
            self.assertTrue(
                Path(canonical.path).is_relative_to(
                    runtime.artifact_repository.objects_root
                )
            )
            runtime.shutdown()

            persisted = json.loads(config.read_text(encoding="utf-8"))
            reference = persisted["_pixelflasher_core_state"]["firmware"]
            self.assertEqual({"artifact_id", "hash"}, set(reference))
            self.assertEqual(canonical.hash, reference["hash"])

            store = ConfigStore(config)
            document = store.load()
            values = dict(document.values)
            core = dict(values["_pixelflasher_core_state"])
            core["firmware"] = {
                **reference,
                "path": str(decoy),
                "type": "ota",
                "build": "ATTACKER",
                "verified": False,
            }
            values["_pixelflasher_core_state"] = core
            values["firmware_path"] = str(decoy)
            store.save(
                ConfigDocument(
                    values=values,
                    modern_extras=document.modern_extras,
                )
            )

            reopened = ApplicationRuntime.open(config)
            restored = reopened.snapshot().firmware

            self.assertEqual(canonical.hash, restored.hash)
            self.assertEqual("factory", restored.type)
            self.assertEqual(canonical.build, restored.build)
            self.assertNotEqual("ATTACKER", restored.build)
            self.assertTrue(restored.verified)
            self.assertEqual(canonical.path, restored.path)
            self.assertNotEqual(str(decoy.resolve()), restored.path)
            reopened.shutdown()

    def test_mismatched_or_path_only_config_selections_are_cleared(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            package = root / "factory.zip"
            boot = root / "boot.img"
            _write_factory(package)
            boot.write_bytes(b"ANDROID!" + b"boot")
            runtime = ApplicationRuntime.open(config)
            firmware_record = runtime.firmware_repository.import_selection(
                package,
                firmware_type="factory",
                build="AP4A.260705.001",
                expected_sha256=hashlib.sha256(package.read_bytes()).hexdigest(),
            )
            boot_record = runtime.boot_repository.import_selection(
                boot,
                partition="boot",
                patched=False,
                expected_sha256=hashlib.sha256(boot.read_bytes()).hexdigest(),
            )
            runtime.shutdown()

            store = ConfigStore(config)
            document = store.load()
            values = dict(document.values)
            core = dict(values["_pixelflasher_core_state"])
            core["firmware"] = {
                "artifact_id": firmware_record.artifact_id,
                "hash": "0" * 64,
                "path": str(package),
            }
            core["boot"] = {
                "artifact_id": boot_record.artifact_id,
                "hash": "f" * 64,
                "path": str(boot),
            }
            core["processed_artifacts"] = [
                {
                    "path": str(boot),
                    "sha256": boot_record.sha256,
                    "role": "partition:boot",
                }
            ]
            values["_pixelflasher_core_state"] = core
            values["firmware_path"] = str(package)
            store.save(
                ConfigDocument(
                    values=values,
                    modern_extras=document.modern_extras,
                )
            )

            reopened = ApplicationRuntime.open(config)

            self.assertEqual("", reopened.snapshot().firmware.path)
            self.assertEqual("", reopened.snapshot().boot.path)
            self.assertEqual(
                (),
                reopened.processed_artifact_repository.resolve(reopened.snapshot()),
            )
            self.assertEqual(2, len(reopened.artifact_repository.list()))
            reopened.shutdown()

    def test_first_migration_follows_config_backup_and_composes_one_repository(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            config.write_text(json.dumps({"theme": "dark"}), encoding="utf-8")
            package = root / "factory.zip"
            boot = root / "boot.img"
            package.write_bytes(b"factory")
            boot.write_bytes(b"boot")
            legacy = root / "PixelFlasher4.db"
            _legacy_database(legacy, package, boot)

            runtime = ApplicationRuntime.open(config)

            self.assertTrue((root / "PixelFlasher.json.v9.bak").is_file())
            self.assertTrue((root / "PixelFlasher4.db.v9.bak").is_file())
            self.assertEqual("migrated", runtime.legacy_migration_report.status)
            self.assertEqual(1, runtime.legacy_migration_report.imported_firmware)
            self.assertEqual(1, runtime.legacy_migration_report.imported_boot)
            self.assertIs(runtime.artifact_repository, runtime.content_artifact_repository)
            self.assertIs(runtime.artifact_repository, runtime.firmware_repository.repository)
            self.assertIs(runtime.artifact_repository, runtime.boot_repository.repository)
            self.assertIs(
                runtime.processed_artifact_repository,
                runtime.command_engine.operation_planner.artifact_repository,
            )
            self.assertIs(
                runtime.processed_artifact_repository,
                runtime.command_engine.firmware_artifact_service.repository,
            )
            self.assertEqual(1, len(runtime.firmware_repository.list()))
            self.assertEqual(1, len(runtime.boot_repository.list()))
            runtime.shutdown()

    def test_reopening_migration_is_idempotent(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            config.write_text(json.dumps({"theme": "dark"}), encoding="utf-8")
            package = root / "factory.zip"
            boot = root / "boot.img"
            package.write_bytes(b"factory")
            boot.write_bytes(b"boot")
            _legacy_database(root / "PixelFlasher4.db", package, boot)
            first = ApplicationRuntime.open(config)
            first.shutdown()

            reopened = ApplicationRuntime.open(config)

            self.assertEqual(0, reopened.legacy_migration_report.imported_firmware)
            self.assertEqual(0, reopened.legacy_migration_report.imported_boot)
            self.assertEqual(2, reopened.legacy_migration_report.already_imported)
            self.assertEqual(2, len(reopened.artifact_repository.list()))
            reopened.shutdown()

    def test_missing_legacy_database_records_noop_report(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = ApplicationRuntime.open(root / "PixelFlasher.json")

            self.assertEqual("not_found", runtime.legacy_migration_report.status)
            self.assertEqual(
                root / "PixelFlasher4.db",
                Path(runtime.legacy_migration_report.source_database),
            )
            self.assertEqual((), runtime.artifact_repository.list())
            runtime.shutdown()

    def test_failed_migration_closes_repository_after_config_backup(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            config.write_text(json.dumps({"theme": "dark"}), encoding="utf-8")
            legacy = root / "PixelFlasher4.db"
            legacy.write_bytes(b"database placeholder")
            close_calls: list[Path] = []
            real_close = ArtifactRepository.close

            def fail_after_config_backup(
                repository: ArtifactRepository,
                _source: str | Path,
            ) -> object:
                self.assertTrue((root / "PixelFlasher.json.v9.bak").is_file())
                raise OSError("injected migration failure")

            def close(repository: ArtifactRepository) -> None:
                close_calls.append(repository.database_path)
                real_close(repository)

            with (
                patch.object(
                    ArtifactRepository,
                    "migrate_legacy_v9",
                    autospec=True,
                    side_effect=fail_after_config_backup,
                ),
                patch.object(
                    ArtifactRepository,
                    "close",
                    autospec=True,
                    side_effect=close,
                ),
            ):
                with self.assertRaisesRegex(OSError, "injected migration failure"):
                    ApplicationRuntime.open(config)

            self.assertEqual(1, len(close_calls))

    def test_shutdown_closes_the_single_repository_and_is_idempotent(self) -> None:
        with TemporaryDirectory() as directory:
            runtime = ApplicationRuntime.open(Path(directory) / "PixelFlasher.json")
            repository = runtime.artifact_repository

            runtime.shutdown()
            runtime.shutdown()

            with self.assertRaises(sqlite3.ProgrammingError):
                repository.list()

    def test_shutdown_closes_repository_when_config_persistence_fails(self) -> None:
        with TemporaryDirectory() as directory:
            runtime = ApplicationRuntime.open(Path(directory) / "PixelFlasher.json")
            repository = runtime.artifact_repository

            with patch.object(
                runtime.config_store,
                "save",
                side_effect=OSError("injected persistence failure"),
            ):
                with self.assertRaisesRegex(OSError, "injected persistence failure"):
                    runtime.shutdown()

            with self.assertRaises(sqlite3.ProgrammingError):
                repository.list()
            runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
