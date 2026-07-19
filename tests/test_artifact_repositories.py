import hashlib
import json
import os
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pixelflasher_core.repositories import (
    ArtifactKind,
    ArtifactProvenance,
    ArtifactRepository,
    BootRepository,
    FirmwareRepository,
    RepositoryError,
)


class ArtifactRepositoryTests(unittest.TestCase):
    def test_orphan_collection_is_bounded_and_preserves_owned_or_unknown_files(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "boot.img"
            image.write_bytes(b"boot")
            repository = ArtifactRepository(root / "repository")
            owned = BootRepository(repository).import_boot(image, partition="boot")
            orphan_digest = hashlib.sha256(b"orphan").hexdigest()
            orphan = repository.objects_root / orphan_digest[:2] / orphan_digest[2:]
            orphan.parent.mkdir(parents=True, exist_ok=True)
            orphan.write_bytes(b"orphan")
            unknown = orphan.parent / "manual-file"
            unknown.write_bytes(b"unknown")

            limited = repository.collect_orphaned_objects(maximum_files=1)
            self.assertTrue(limited.scan_limited)
            self.assertTrue(orphan.is_file())
            orphan.touch()
            orphan_mtime = 1
            os.utime(orphan, (orphan_mtime, orphan_mtime))

            report = repository.collect_orphaned_objects()
            self.assertEqual(1, report.removed_files)
            self.assertEqual(0, report.failed_files)
            self.assertFalse(report.scan_limited)
            self.assertFalse(orphan.exists())
            self.assertTrue(owned.path.is_file())
            self.assertTrue(unknown.is_file())
            self.assertTrue(repository.verify(owned.artifact_id))
            repository.close()

    def test_content_addressed_import_deduplicates_bytes_and_hides_paths(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "factory.zip"
            second = root / "copy.zip"
            first.write_bytes(b"same firmware")
            second.write_bytes(first.read_bytes())
            repository = ArtifactRepository(root / "repository")
            firmware = FirmwareRepository(repository)

            one = firmware.import_firmware(
                first,
                provenance=ArtifactProvenance.OFFICIAL,
                device_codenames=("akita",),
                signature="google-release",
            )
            two = firmware.import_firmware(second)

            self.assertEqual(one.sha256, two.sha256)
            self.assertEqual(2, len(firmware.list()))
            self.assertEqual(1, len(list((root / "repository" / "objects").glob("*/*"))))
            self.assertTrue(repository.verify(one.artifact_id))
            self.assertNotIn(str(first), str(one.to_public_dict()))
            self.assertNotIn("path", one.to_public_dict())
            repository.close()

    def test_selection_resolution_is_identity_bound_and_hash_fallback_is_fail_closed(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "factory.zip"
            package.write_bytes(b"same inspected firmware")
            repository = ArtifactRepository(root / "repository")
            firmware = FirmwareRepository(repository)
            digest = hashlib.sha256(package.read_bytes()).hexdigest()

            supplied = firmware.import_selection(
                package,
                firmware_type="factory",
                build="AP4A.260705.001",
                expected_sha256=digest,
            )
            official = firmware.import_selection(
                package,
                firmware_type="factory",
                build="AP4A.260705.001",
                expected_sha256=digest,
                provenance=ArtifactProvenance.OFFICIAL,
            )

            self.assertNotEqual(supplied.artifact_id, official.artifact_id)
            self.assertIsNone(firmware.resolve_selection(sha256=digest))
            self.assertEqual(
                supplied.artifact_id,
                firmware.resolve_selection(
                    artifact_id=supplied.artifact_id,
                    sha256=digest,
                ).artifact_id,
            )
            self.assertIsNone(
                firmware.resolve_selection(
                    artifact_id=supplied.artifact_id,
                    sha256="0" * 64,
                )
            )
            repository.close()

    def test_hash_mismatch_boot_partition_and_deletion_fail_closed(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "boot.img"
            image.write_bytes(b"boot")
            repository = ArtifactRepository(root / "repository")
            boots = BootRepository(repository)

            with self.assertRaises(RepositoryError) as mismatch:
                repository.import_file(
                    image,
                    kind=ArtifactKind.BOOT,
                    role="partition:boot",
                    provenance=ArtifactProvenance.USER_SUPPLIED,
                    expected_sha256="0" * 64,
                )
            self.assertEqual("artifact_hash_mismatch", mismatch.exception.code)
            with self.assertRaises(RepositoryError) as partition:
                boots.import_boot(image, partition="userdata")
            self.assertEqual("boot_partition_invalid", partition.exception.code)

            record = boots.import_boot(image, partition="boot")
            object_path = record.path
            self.assertTrue(repository.delete(record.artifact_id))
            self.assertFalse(object_path.exists())
            self.assertFalse(repository.delete(record.artifact_id))
            repository.close()

    def test_legacy_v9_migration_is_backed_up_and_idempotent(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "factory.zip"
            boot = root / "boot.img"
            package.write_bytes(b"factory")
            boot.write_bytes(b"boot")
            legacy_path = root / "PixelFlasher.db"
            connection = sqlite3.connect(legacy_path)
            with connection:
                connection.execute(
                    "CREATE TABLE PACKAGE(id INTEGER PRIMARY KEY, boot_hash TEXT, type TEXT, package_sig TEXT, file_path TEXT, epoch INTEGER)"
                )
                connection.execute(
                    "CREATE TABLE BOOT(id INTEGER PRIMARY KEY, boot_hash TEXT, file_path TEXT, is_patched INTEGER, magisk_version TEXT, hardware TEXT, epoch INTEGER, patch_method TEXT, is_init_boot INTEGER, is_stock_boot INTEGER)"
                )
                connection.execute(
                    "INSERT INTO PACKAGE VALUES(1, 'legacy-package-sha1', 'firmware', 'akita-build', ?, 1)",
                    (str(package),),
                )
                connection.execute(
                    "INSERT INTO BOOT VALUES(2, 'legacy-boot-sha1', ?, 1, '29.0', 'akita', 1, 'Magisk', 1, 0)",
                    (str(boot),),
                )
            connection.close()

            repository = ArtifactRepository(root / "repository")
            first = repository.migrate_legacy_v9(legacy_path)
            second = repository.migrate_legacy_v9(legacy_path)

            self.assertEqual((1, 1, 0), (
                first.imported_firmware,
                first.imported_boot,
                first.already_imported,
            ))
            self.assertEqual(2, second.already_imported)
            self.assertEqual(2, len(repository.list()))
            self.assertTrue(legacy_path.with_name("PixelFlasher.db.v9.bak").is_file())
            boot_record = BootRepository(repository).list()[0]
            self.assertEqual("init_boot", boot_record.partition)
            self.assertEqual("legacy-boot-sha1", boot_record.metadata["legacyHash"])
            self.assertEqual(hashlib.sha256(boot.read_bytes()).hexdigest(), boot_record.sha256)
            repository.close()

    def test_artifact_id_replay_requires_complete_identity(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.zip"
            second = root / "second.img"
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            repository = ArtifactRepository(root / "repository")
            artifact_id = "a" * 32
            original = repository.import_file(
                first,
                kind=ArtifactKind.FIRMWARE,
                role="firmware",
                provenance=ArtifactProvenance.USER_SUPPLIED,
                metadata={"firmwareBuild": "akita-build"},
                artifact_id=artifact_id,
            )

            replay = repository.import_file(
                first,
                kind=ArtifactKind.FIRMWARE,
                role="firmware",
                provenance=ArtifactProvenance.USER_SUPPLIED,
                metadata={"firmwareBuild": "akita-build"},
                artifact_id=artifact_id,
            )
            self.assertEqual(original, replay)

            with self.assertRaises(RepositoryError) as conflict:
                repository.import_file(
                    second,
                    kind=ArtifactKind.BOOT,
                    role="partition:boot",
                    provenance=ArtifactProvenance.PATCHED,
                    partition="boot",
                    artifact_id=artifact_id,
                )
            self.assertEqual("artifact_identity_conflict", conflict.exception.code)
            self.assertEqual(original.sha256, repository.get(artifact_id).sha256)  # type: ignore[union-attr]
            repository.close()

    def test_tampered_object_path_cannot_escape_repository_on_get_verify_or_delete(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "firmware.zip"
            victim = root / "victim.txt"
            source.write_bytes(b"firmware")
            victim.write_text("keep", encoding="utf-8")
            repository_path = root / "repository"
            repository = ArtifactRepository(repository_path)
            record = FirmwareRepository(repository).import_firmware(source)
            database_path = repository.database_path
            repository.close()

            connection = sqlite3.connect(database_path)
            with connection:
                connection.execute(
                    "UPDATE objects SET relative_path = '../../victim.txt' WHERE sha256 = ?",
                    (record.sha256,),
                )
            connection.close()

            reopened = ArtifactRepository(repository_path)
            for action in (
                lambda: reopened.get(record.artifact_id),
                lambda: reopened.verify(record.artifact_id),
                lambda: reopened.delete(record.artifact_id),
            ):
                with self.assertRaises(RepositoryError) as unsafe:
                    action()
                self.assertEqual("repository_metadata_corrupt", unsafe.exception.code)
                self.assertTrue(victim.is_file())
            reopened.close()

    def test_symlinked_object_is_rejected_even_when_target_hash_matches(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "firmware.zip"
            target = root / "external.zip"
            source.write_bytes(b"same bytes")
            target.write_bytes(source.read_bytes())
            repository = ArtifactRepository(root / "repository")
            record = FirmwareRepository(repository).import_firmware(source)
            record.path.unlink()
            try:
                record.path.symlink_to(target)
            except OSError as error:
                repository.close()
                self.skipTest(f"symlinks are unavailable: {error}")

            with self.assertRaises(RepositoryError) as unsafe:
                repository.get(record.artifact_id)
            self.assertEqual("repository_path_unsafe", unsafe.exception.code)
            self.assertEqual(b"same bytes", target.read_bytes())
            repository.close()

    def test_live_wal_rows_use_fresh_snapshot_while_initial_backup_stays_immutable(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            files = tuple(root / name for name in ("one.zip", "one.img", "two.zip", "two.img"))
            for index, path in enumerate(files, 1):
                path.write_bytes(f"artifact-{index}".encode())
            source = root / "PixelFlasher4.db"
            legacy = sqlite3.connect(source)
            legacy.execute("PRAGMA journal_mode = WAL")
            legacy.execute("PRAGMA wal_autocheckpoint = 0")
            legacy.execute(
                "CREATE TABLE PACKAGE(id INTEGER PRIMARY KEY, boot_hash TEXT, type TEXT, package_sig TEXT, file_path TEXT, epoch INTEGER)"
            )
            legacy.execute(
                "CREATE TABLE BOOT(id INTEGER PRIMARY KEY, boot_hash TEXT, file_path TEXT, is_patched INTEGER, magisk_version TEXT, hardware TEXT, epoch INTEGER, patch_method TEXT, is_init_boot INTEGER, is_stock_boot INTEGER)"
            )
            legacy.commit()
            legacy.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            legacy.execute(
                "INSERT INTO PACKAGE VALUES(1, 'package-1', 'firmware', 'build-1', ?, 1)",
                (str(files[0]),),
            )
            legacy.execute(
                "INSERT INTO BOOT VALUES(2, 'boot-1', ?, 0, '', 'akita', 1, '', 0, 1)",
                (str(files[1]),),
            )
            legacy.commit()

            repository = ArtifactRepository(root / "repository")
            first = repository.migrate_legacy_v9(source)
            backup = source.with_name(f"{source.name}.v9.bak")
            initial_backup_hash = hashlib.sha256(backup.read_bytes()).hexdigest()
            self.assertEqual((1, 1, "migrated"), (
                first.imported_firmware,
                first.imported_boot,
                first.status,
            ))

            legacy.execute(
                "INSERT INTO PACKAGE VALUES(3, 'package-2', 'firmware', 'build-2', ?, 2)",
                (str(files[2]),),
            )
            legacy.execute(
                "INSERT INTO BOOT VALUES(4, 'boot-2', ?, 0, '', 'akita', 2, '', 0, 1)",
                (str(files[3]),),
            )
            legacy.commit()
            second = repository.migrate_legacy_v9(source)

            self.assertEqual((1, 1, 2, "migrated"), (
                second.imported_firmware,
                second.imported_boot,
                second.already_imported,
                second.status,
            ))
            self.assertEqual(4, len(repository.list()))
            self.assertEqual(initial_backup_hash, hashlib.sha256(backup.read_bytes()).hexdigest())
            repository.close()
            legacy.close()

    def test_unsupported_and_partial_legacy_schema_never_report_migrated(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            unsupported = root / "unsupported.db"
            connection = sqlite3.connect(unsupported)
            connection.execute("CREATE TABLE OTHER(id INTEGER PRIMARY KEY)")
            connection.commit()
            connection.close()
            repository = ArtifactRepository(root / "repository")
            report = repository.migrate_legacy_v9(unsupported)
            self.assertEqual("unsupported_schema", report.status)
            self.assertEqual((), repository.list())

            partial = root / "partial.db"
            connection = sqlite3.connect(partial)
            connection.execute(
                "CREATE TABLE PACKAGE(id INTEGER PRIMARY KEY, file_path TEXT)"
            )
            connection.execute(
                "CREATE TABLE BOOT(id INTEGER PRIMARY KEY, file_path TEXT)"
            )
            connection.execute(
                "INSERT INTO PACKAGE VALUES(1, ?)",
                (str(root / "missing.zip"),),
            )
            connection.commit()
            connection.close()
            report = repository.migrate_legacy_v9(partial)
            self.assertEqual("partial", report.status)
            self.assertEqual((str(root / "missing.zip"),), report.missing_files)
            repository.close()

    def test_public_metadata_is_allowlisted_and_cannot_expose_paths_or_secrets(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "firmware.zip"
            source.write_bytes(b"firmware")
            repository = ArtifactRepository(root / "repository")
            record = FirmwareRepository(repository).import_firmware(
                source,
                source_hash=str(root / "private-source.zip"),
                signature=str(root / "private-signature.txt"),
                metadata={
                    "firmwareBuild": "akita-build",
                    "planFingerprint": "abcd1234",
                    "packageSignature": str(root / "private-package.txt"),
                    "sourcePath": str(source),
                    "apiToken": "super-secret",
                },
            )

            public = record.to_public_dict()
            encoded = json.dumps(public)
            self.assertEqual("", public["sourceHash"])
            self.assertEqual("", public["signature"])
            self.assertEqual(
                {"firmwareBuild": "akita-build", "planFingerprint": "abcd1234"},
                public["metadata"],
            )
            self.assertNotIn(str(root), encoded)
            self.assertNotIn("super-secret", encoded)
            repository.close()

    def test_replace_race_verifies_competing_object_before_publishing_metadata(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "firmware.zip"
            source.write_bytes(b"expected firmware")
            repository = ArtifactRepository(root / "repository")

            def competing_replace(_temporary: object, destination: object) -> None:
                Path(str(destination)).write_bytes(b"attacker bytes")
                raise PermissionError("injected replace race")

            with patch(
                "pixelflasher_core.repositories.os.replace",
                side_effect=competing_replace,
            ):
                with self.assertRaises(RepositoryError) as corrupt:
                    FirmwareRepository(repository).import_firmware(source)
            self.assertEqual("repository_object_corrupt", corrupt.exception.code)
            self.assertEqual((), repository.list())
            repository.close()


if __name__ == "__main__":
    unittest.main()
