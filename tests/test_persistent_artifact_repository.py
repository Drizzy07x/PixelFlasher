import hashlib
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pixelflasher_core.contracts import AppSnapshot, FileArtifact, FirmwareInfo
from pixelflasher_core.persistent_artifacts import PersistentProcessedArtifactRepository
from pixelflasher_core.repositories import (
    ArtifactProvenance,
    ArtifactRepository,
    FirmwareRepository,
)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _legacy_database(path: Path, package: Path, boot: Path) -> None:
    connection = sqlite3.connect(path)
    with connection:
        connection.execute(
            "CREATE TABLE PACKAGE(id INTEGER PRIMARY KEY, boot_hash TEXT, type TEXT, package_sig TEXT, file_path TEXT, epoch INTEGER)"
        )
        connection.execute(
            "CREATE TABLE BOOT(id INTEGER PRIMARY KEY, boot_hash TEXT, file_path TEXT, is_patched INTEGER, magisk_version TEXT, hardware TEXT, epoch INTEGER, patch_method TEXT, is_init_boot INTEGER, is_stock_boot INTEGER)"
        )
        connection.execute(
            "INSERT INTO PACKAGE VALUES(1, 'package-sha1', 'firmware', 'akita-build', ?, 1)",
            (str(package),),
        )
        connection.execute(
            "INSERT INTO BOOT VALUES(2, 'boot-sha1', ?, 0, '', 'akita', 1, '', 0, 1)",
            (str(boot),),
        )
    connection.close()


class PersistentProcessedArtifactRepositoryTests(unittest.TestCase):
    def test_processed_firmware_reopens_from_the_shared_content_repository(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "factory.zip"
            boot = root / "boot.img"
            source.write_bytes(b"factory")
            boot.write_bytes(b"boot")
            content_root = root / "content"
            artifact_repository = ArtifactRepository(content_root)
            firmware_repository = FirmwareRepository(artifact_repository)
            planner_repository = PersistentProcessedArtifactRepository(
                firmware_repository,
                metadata_provider=lambda: {
                    "firmwareBuild": "akita-build",
                    "firmwareType": "factory",
                },
                device_codename_provider=lambda: ("akita",),
            )
            firmware_hash = _digest(source)
            planner_repository.register(
                (
                    FileArtifact(str(source), firmware_hash, "firmware"),
                    FileArtifact(str(boot), _digest(boot), "partition:boot"),
                ),
                firmware_hash=firmware_hash,
            )
            first = planner_repository.resolve(
                AppSnapshot(
                    firmware=FirmwareInfo(
                        str(source),
                        "factory",
                        "akita-build",
                        firmware_hash,
                        True,
                        True,
                    )
                )
            )
            artifact_repository.close()

            reopened_artifacts = ArtifactRepository(content_root)
            reopened_firmware = FirmwareRepository(reopened_artifacts)
            reopened_planner = PersistentProcessedArtifactRepository(reopened_firmware)
            second = reopened_planner.resolve(
                AppSnapshot(
                    firmware=FirmwareInfo(
                        str(source),
                        "factory",
                        "akita-build",
                        firmware_hash,
                        True,
                        True,
                    )
                )
            )

            self.assertEqual(
                [(item.role, item.sha256) for item in first],
                [(item.role, item.sha256) for item in second],
            )
            self.assertTrue(all(Path(item.path).is_relative_to(content_root) for item in second))
            self.assertTrue(
                all(
                    record.provenance is ArtifactProvenance.PROCESSED
                    for record in reopened_firmware.list()
                )
            )
            self.assertTrue(
                all(
                    record.source_hash == firmware_hash
                    and record.device_codenames == ("akita",)
                    and record.metadata["firmwareBuild"] == "akita-build"
                    and record.metadata["firmwareType"] == "factory"
                    for record in reopened_firmware.list()
                )
            )
            reopened_artifacts.close()

    def test_legacy_migration_rolls_back_new_metadata_and_can_retry(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "factory.zip"
            boot = root / "boot.img"
            package.write_bytes(b"factory")
            boot.write_bytes(b"boot")
            legacy = root / "PixelFlasher4.db"
            _legacy_database(legacy, package, boot)
            repository = ArtifactRepository(root / "content")
            real_import = repository.import_file
            calls = 0

            def fail_second(*args: object, **kwargs: object):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected migration failure")
                return real_import(*args, **kwargs)

            with patch.object(repository, "import_file", side_effect=fail_second):
                with self.assertRaisesRegex(OSError, "injected migration failure"):
                    repository.migrate_legacy_v9(legacy)

            self.assertEqual((), repository.list())
            self.assertTrue((root / "PixelFlasher4.db.v9.bak").is_file())
            retried = repository.migrate_legacy_v9(legacy)
            self.assertEqual((1, 1, 0), (
                retried.imported_firmware,
                retried.imported_boot,
                retried.already_imported,
            ))
            repository.close()


if __name__ == "__main__":
    unittest.main()
