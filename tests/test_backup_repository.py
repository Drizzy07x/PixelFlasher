from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest

from pixelflasher_core.backup_repository import (
    BackupProvenance,
    BackupRepository,
    BackupRepositoryError,
)


def _import(repository: BackupRepository, source: Path, **overrides: object):
    values: dict[str, object] = {
        "expected_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "target_serial": "SERIAL-123456",
        "device_codename": "akita",
        "partition": "boot",
        "slot": "a",
        "provenance": BackupProvenance.CREATED,
    }
    values.update(overrides)
    return repository.import_file(source, **values)  # type: ignore[arg-type]


def test_import_is_content_addressed_persistent_and_route_free() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "private" / "boot_a.img"
        source.parent.mkdir()
        source.write_bytes(b"verified raw partition")
        repository = BackupRepository(root / "repository")

        record = _import(repository, source)
        public = record.to_public_dict(available=repository.is_available(record))

        assert record.path.read_bytes() == source.read_bytes()
        assert record.path != source
        assert public["available"] is True
        assert public["integrity"] == "stored"
        assert public["targetPartition"] == "boot_a"
        assert str(source) not in repr(public)
        repository.close()

        reopened = BackupRepository(root / "repository")
        assert reopened.list() == (reopened.get(record.backup_id),)
        reopened.close()


def test_duplicate_content_is_shared_until_last_record_is_deleted() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        first = root / "first.img"
        second = root / "second.img"
        first.write_bytes(b"same backup")
        second.write_bytes(first.read_bytes())
        repository = BackupRepository(root / "repository")
        one = _import(repository, first)
        two = _import(repository, second, slot="b")

        first_receipt = repository.delete(one.backup_id)
        assert first_receipt.deleted
        assert first_receipt.shared_object_retained
        assert two.path.exists()

        second_receipt = repository.delete(two.backup_id)
        assert second_receipt.deleted
        assert second_receipt.object_removed
        assert not two.path.exists()
        repository.close()


def test_resolve_rehashes_and_rejects_tampered_or_missing_objects() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "boot.img"
        source.write_bytes(b"original")
        repository = BackupRepository(root / "repository")
        record = _import(repository, source)

        resolved_record, artifact = repository.resolve_verified(record.backup_id)
        assert resolved_record == record
        assert artifact.sha256 == record.sha256
        assert artifact.role == "backup:boot_a"

        record.path.write_bytes(b"tampered")
        with pytest.raises(BackupRepositoryError) as mismatch:
            repository.resolve_verified(record.backup_id)
        assert mismatch.value.code == "backup_integrity_mismatch"

        record.path.unlink()
        with pytest.raises(BackupRepositoryError) as missing:
            repository.resolve_verified(record.backup_id)
        assert missing.value.code == "backup_integrity_missing"
        repository.close()


def test_import_rejects_wrong_hash_empty_oversized_and_cancelled_sources() -> None:
    class Cancelled:
        cancelled = True

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "boot.img"
        source.write_bytes(b"backup")
        repository = BackupRepository(root / "repository", maximum_backup_bytes=6)

        with pytest.raises(BackupRepositoryError) as wrong_hash:
            _import(repository, source, expected_sha256="0" * 64)
        assert wrong_hash.value.code == "backup_hash_mismatch"

        source.write_bytes(b"")
        with pytest.raises(BackupRepositoryError) as empty:
            _import(repository, source)
        assert empty.value.code == "backup_empty"

        source.write_bytes(b"1234567")
        with pytest.raises(BackupRepositoryError) as oversized:
            _import(repository, source)
        assert oversized.value.code == "backup_too_large"

        source.write_bytes(b"backup")
        with pytest.raises(BackupRepositoryError) as cancelled:
            repository.import_file(
                source,
                expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                target_serial="SERIAL-123456",
                device_codename="akita",
                partition="boot",
                slot="a",
                provenance=BackupProvenance.CREATED,
                cancellation=Cancelled(),
            )
        assert cancelled.value.code == "backup_import_cancelled"
        repository.close()


def test_filters_validate_ids_and_confirmation_is_record_bound() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "boot.img"
        source.write_bytes(b"backup")
        repository = BackupRepository(root / "repository")
        record = _import(repository, source)

        assert repository.list(target_serial="SERIAL-123456") == (record,)
        assert repository.list(target_serial="OTHER-SERIAL") == ()
        assert (
            repository.required_delete_confirmation(record.backup_id)
            == f"DELETE {record.backup_id[-8:].upper()}"
        )
        with pytest.raises(BackupRepositoryError):
            repository.get("../private")
        repository.close()


def test_delete_reports_missing_storage_and_startup_cleanup_removes_orphans() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "boot.img"
        source.write_bytes(b"backup")
        repository = BackupRepository(root / "repository")
        record = _import(repository, source)
        record.path.unlink()

        receipt = repository.delete(record.backup_id)
        assert receipt.deleted
        assert receipt.object_missing
        assert not receipt.object_removed

        orphan = repository.objects_root / "f0" / f"{'f' * 62}.img"
        orphan.parent.mkdir(parents=True)
        orphan.write_bytes(b"orphan")
        cleanup = repository.collect_orphaned_objects()
        assert cleanup.scanned == 1
        assert cleanup.removed == 1
        assert cleanup.deferred == 0
        assert not orphan.exists()
        repository.close()
