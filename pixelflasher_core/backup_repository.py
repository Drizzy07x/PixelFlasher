"""Persistent, content-addressed raw partition backup inventory."""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
import tempfile
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, Protocol
from uuid import uuid4

from .backups import SUPPORTED_BACKUP_PARTITIONS
from .contracts import FileArtifact, JSONValue, is_valid_target_serial

BACKUP_REPOSITORY_SCHEMA_VERSION = 1
_BACKUP_ID = re.compile(r"[0-9a-f]{32}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_CODENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SLOTS = frozenset({"a", "b"})


class CancellationProbe(Protocol):
    @property
    def cancelled(self) -> bool: ...


class BackupProvenance(StrEnum):
    CREATED = "created"
    USER_SUPPLIED = "user_supplied"


class BackupRepositoryError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class BackupRecord:
    backup_id: str
    sha256: str
    size_bytes: int
    created_at: int
    target_serial: str
    device_codename: str
    partition: str
    slot: str
    provenance: BackupProvenance
    _path: Path

    @property
    def target_partition(self) -> str:
        return f"{self.partition}_{self.slot}"

    @property
    def path(self) -> Path:
        """Backend-only object path; never serialize it to the WebView."""

        return self._path

    def to_public_dict(self, *, available: bool) -> dict[str, JSONValue]:
        return {
            "id": self.backup_id,
            "sha256": self.sha256,
            "sizeBytes": self.size_bytes,
            "createdAt": self.created_at,
            "targetSerial": self.target_serial,
            "deviceCodename": self.device_codename,
            "partition": self.partition,
            "slot": self.slot,
            "targetPartition": self.target_partition,
            "provenance": self.provenance.value,
            "available": available,
            "integrity": "stored" if available else "missing",
        }


@dataclass(frozen=True, slots=True)
class BackupDeletionReceipt:
    backup_id: str
    deleted: bool
    object_removed: bool
    shared_object_retained: bool
    object_missing: bool
    cleanup_deferred: bool

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "backupId": self.backup_id,
            "deleted": self.deleted,
            "objectRemoved": self.object_removed,
            "sharedObjectRetained": self.shared_object_retained,
            "objectMissing": self.object_missing,
            "cleanupDeferred": self.cleanup_deferred,
        }


@dataclass(frozen=True, slots=True)
class BackupCleanupReport:
    scanned: int
    removed: int
    deferred: int


class BackupRepository:
    """Own verified raw backup objects and route-free inventory metadata."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        maximum_backup_bytes: int = 1024 * 1024 * 1024,
    ) -> None:
        if maximum_backup_bytes <= 0:
            raise ValueError("maximum_backup_bytes must be positive")
        self.root = Path(root).expanduser().resolve()
        self.objects_root = self.root / "objects"
        self.database_path = self.root / "backups.sqlite3"
        self.maximum_backup_bytes = maximum_backup_bytes
        self._lock = threading.RLock()
        self.objects_root.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            self.database_path,
            timeout=30,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        try:
            self._initialize()
        except Exception:
            self._connection.close()
            raise

    def _initialize(self) -> None:
        with self._lock, self._connection:
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS repository_meta "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            row = self._connection.execute(
                "SELECT value FROM repository_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is not None and int(row["value"]) > BACKUP_REPOSITORY_SCHEMA_VERSION:
                raise BackupRepositoryError(
                    "backup_repository_schema_newer",
                    "backup repository was created by a newer PixelFlasher version",
                )
            self._connection.execute(
                "INSERT OR REPLACE INTO repository_meta(key, value) VALUES('schema_version', ?)",
                (str(BACKUP_REPOSITORY_SCHEMA_VERSION),),
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS objects (
                    sha256 TEXT PRIMARY KEY,
                    size_bytes INTEGER NOT NULL,
                    relative_path TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS backups (
                    backup_id TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL REFERENCES objects(sha256),
                    created_at INTEGER NOT NULL,
                    target_serial TEXT NOT NULL,
                    device_codename TEXT NOT NULL,
                    partition_name TEXT NOT NULL,
                    slot TEXT NOT NULL CHECK(slot IN ('a', 'b')),
                    provenance TEXT NOT NULL CHECK(provenance IN ('created', 'user_supplied'))
                )
                """
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS backups_created "
                "ON backups(created_at DESC, backup_id)"
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS backups_serial "
                "ON backups(target_serial, created_at DESC)"
            )

    def import_file(
        self,
        source: str | os.PathLike[str],
        *,
        expected_sha256: str,
        target_serial: str,
        device_codename: str,
        partition: str,
        slot: str,
        provenance: BackupProvenance,
        cancellation: CancellationProbe | None = None,
    ) -> BackupRecord:
        digest_expected = self._validate_digest(expected_sha256)
        serial = self._validate_serial(target_serial)
        codename = self._validate_codename(device_codename)
        partition_name = self._validate_partition(partition)
        slot_name = self._validate_slot(slot)
        if not isinstance(provenance, BackupProvenance):
            raise TypeError("provenance must use BackupProvenance")
        self._check_cancelled(cancellation)
        try:
            source_path = Path(source).expanduser().resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise BackupRepositoryError(
                "backup_source_unavailable", "backup source is unavailable"
            ) from error
        if self._is_link_like(source_path):
            raise BackupRepositoryError(
                "backup_source_invalid", "backup source cannot be a link"
            )

        staging_descriptor, staging_name = tempfile.mkstemp(
            prefix="backup-import-",
            suffix=".tmp",
            dir=self.root,
        )
        staging = Path(staging_name)
        created_object = False
        try:
            with os.fdopen(staging_descriptor, "wb") as output:
                digest, size = self._copy_and_hash(
                    source_path,
                    output,
                    cancellation=cancellation,
                )
                output.flush()
                os.fsync(output.fileno())
            if digest != digest_expected:
                raise BackupRepositoryError(
                    "backup_hash_mismatch",
                    "backup source no longer matches its verified SHA-256",
                )
            relative = self._relative_object_path(digest)
            object_path = self.root / relative
            object_path.parent.mkdir(parents=True, exist_ok=True)
            record_id = uuid4().hex
            created_at = int(time.time())
            with self._lock:
                existing = self._connection.execute(
                    "SELECT size_bytes, relative_path FROM objects WHERE sha256 = ?",
                    (digest,),
                ).fetchone()
                if existing is None:
                    if object_path.exists():
                        self._verify_object_path(object_path, digest, size)
                        staging.unlink(missing_ok=True)
                    else:
                        os.replace(staging, object_path)
                        created_object = True
                        self._fsync_directory(object_path.parent)
                    try:
                        with self._connection:
                            self._connection.execute(
                                "INSERT INTO objects VALUES(?, ?, ?, ?)",
                                (digest, size, relative.as_posix(), created_at),
                            )
                            self._connection.execute(
                                "INSERT INTO backups VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                                (
                                    record_id,
                                    digest,
                                    created_at,
                                    serial,
                                    codename,
                                    partition_name,
                                    slot_name,
                                    provenance.value,
                                ),
                            )
                    except Exception:
                        if created_object:
                            object_path.unlink(missing_ok=True)
                        raise
                else:
                    if (
                        int(existing["size_bytes"]) != size
                        or str(existing["relative_path"]) != relative.as_posix()
                    ):
                        raise BackupRepositoryError(
                            "backup_repository_corrupt",
                            "backup object metadata does not match its digest",
                        )
                    self._verify_object_path(object_path, digest, size)
                    staging.unlink(missing_ok=True)
                    with self._connection:
                        self._connection.execute(
                            "INSERT INTO backups VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                record_id,
                                digest,
                                created_at,
                                serial,
                                codename,
                                partition_name,
                                slot_name,
                                provenance.value,
                            ),
                        )
            record = self.get(record_id)
            if record is None:  # pragma: no cover - transactional invariant
                raise BackupRepositoryError(
                    "backup_repository_corrupt", "created backup record is missing"
                )
            return record
        except BackupRepositoryError:
            raise
        except (OSError, sqlite3.Error) as error:
            raise BackupRepositoryError(
                "backup_import_failed", "backup could not be imported atomically"
            ) from error
        finally:
            staging.unlink(missing_ok=True)

    def list(
        self,
        *,
        target_serial: str | None = None,
        maximum_records: int = 1000,
    ) -> tuple[BackupRecord, ...]:
        if not 1 <= maximum_records <= 10_000:
            raise ValueError("maximum_records must be between 1 and 10000")
        parameters: tuple[object, ...] = ()
        query = self._record_query()
        if target_serial is not None:
            query += " WHERE backups.target_serial = ?"
            parameters = (self._validate_serial(target_serial),)
        query += " ORDER BY backups.created_at DESC, backups.backup_id LIMIT ?"
        parameters += (maximum_records,)
        with self._lock:
            return tuple(
                self._record_from_row(row)
                for row in self._connection.execute(query, parameters)
            )

    def count(self, *, target_serial: str | None = None) -> int:
        query = "SELECT COUNT(*) AS count FROM backups"
        parameters: tuple[str, ...] = ()
        if target_serial is not None:
            query += " WHERE target_serial = ?"
            parameters = (self._validate_serial(target_serial),)
        with self._lock:
            return int(self._connection.execute(query, parameters).fetchone()["count"])

    def get(self, backup_id: str) -> BackupRecord | None:
        identifier = self._validate_backup_id(backup_id)
        with self._lock:
            row = self._connection.execute(
                f"{self._record_query()} WHERE backups.backup_id = ?",
                (identifier,),
            ).fetchone()
        return self._record_from_row(row) if row is not None else None

    def is_available(self, record: BackupRecord) -> bool:
        try:
            details = record.path.lstat()
        except OSError:
            return False
        return (
            stat.S_ISREG(details.st_mode)
            and not self._is_link_like(record.path)
            and details.st_size == record.size_bytes
        )

    def resolve_verified(
        self,
        backup_id: str,
        *,
        cancellation: CancellationProbe | None = None,
    ) -> tuple[BackupRecord, FileArtifact]:
        record = self.get(backup_id)
        if record is None:
            raise BackupRepositoryError("backup_not_found", "backup record was not found")
        try:
            details = record.path.lstat()
        except OSError as error:
            raise BackupRepositoryError(
                "backup_integrity_missing",
                "stored backup object is missing",
            ) from error
        if not stat.S_ISREG(details.st_mode) or self._is_link_like(record.path):
            raise BackupRepositoryError(
                "backup_integrity_missing",
                "stored backup object is no longer a safe regular file",
            )
        if details.st_size != record.size_bytes:
            raise BackupRepositoryError(
                "backup_integrity_mismatch",
                "stored backup no longer matches its content-addressed record",
            )
        digest, size = self._hash_file(record.path, cancellation=cancellation)
        if digest != record.sha256 or size != record.size_bytes:
            raise BackupRepositoryError(
                "backup_integrity_mismatch",
                "stored backup no longer matches its content-addressed record",
            )
        return record, FileArtifact(
            str(record.path),
            record.sha256,
            f"backup:{record.target_partition}",
        )

    def delete(self, backup_id: str) -> BackupDeletionReceipt:
        identifier = self._validate_backup_id(backup_id)
        with self._lock:
            row = self._connection.execute(
                "SELECT sha256 FROM backups WHERE backup_id = ?",
                (identifier,),
            ).fetchone()
            if row is None:
                return BackupDeletionReceipt(
                    identifier, False, False, False, False, False
                )
            digest = self._validate_digest(str(row["sha256"]))
            object_path = self.root / self._relative_object_path(digest)
            with self._connection:
                self._connection.execute(
                    "DELETE FROM backups WHERE backup_id = ?", (identifier,)
                )
                remaining = int(
                    self._connection.execute(
                        "SELECT COUNT(*) AS count FROM backups WHERE sha256 = ?",
                        (digest,),
                    ).fetchone()["count"]
                )
                if not remaining:
                    self._connection.execute(
                        "DELETE FROM objects WHERE sha256 = ?", (digest,)
                    )
            if remaining:
                return BackupDeletionReceipt(identifier, True, False, True, False, False)
            try:
                object_path.lstat()
            except FileNotFoundError:
                return BackupDeletionReceipt(identifier, True, False, False, True, False)
            except OSError:
                return BackupDeletionReceipt(identifier, True, False, False, False, True)
            try:
                object_path.unlink()
                self._fsync_directory(object_path.parent)
            except OSError:
                return BackupDeletionReceipt(identifier, True, False, False, False, True)
            return BackupDeletionReceipt(identifier, True, True, False, False, False)

    def collect_orphaned_objects(self) -> BackupCleanupReport:
        """Remove regular repository objects no longer referenced by metadata."""

        with self._lock:
            live = {
                str(row["relative_path"])
                for row in self._connection.execute("SELECT relative_path FROM objects")
            }
            scanned = removed = deferred = 0
            for candidate in self.objects_root.rglob("*.img"):
                try:
                    relative = candidate.relative_to(self.root).as_posix()
                except ValueError:  # pragma: no cover - rooted traversal invariant
                    deferred += 1
                    continue
                if relative in live:
                    continue
                scanned += 1
                try:
                    details = candidate.lstat()
                    if not stat.S_ISREG(details.st_mode) or self._is_link_like(candidate):
                        deferred += 1
                        continue
                    candidate.unlink()
                    self._fsync_directory(candidate.parent)
                except OSError:
                    deferred += 1
                else:
                    removed += 1
            return BackupCleanupReport(scanned, removed, deferred)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    @staticmethod
    def required_delete_confirmation(backup_id: str) -> str:
        identifier = BackupRepository._validate_backup_id(backup_id)
        return f"DELETE {identifier[-8:].upper()}"

    @staticmethod
    def _record_query() -> str:
        return (
            "SELECT backups.*, objects.size_bytes, objects.relative_path "
            "FROM backups JOIN objects ON objects.sha256 = backups.sha256"
        )

    def _record_from_row(self, row: sqlite3.Row) -> BackupRecord:
        digest = self._validate_digest(str(row["sha256"]))
        relative = self._relative_object_path(digest)
        if str(row["relative_path"]) != relative.as_posix():
            raise BackupRepositoryError(
                "backup_repository_corrupt", "backup object path metadata is invalid"
            )
        return BackupRecord(
            self._validate_backup_id(str(row["backup_id"])),
            digest,
            int(row["size_bytes"]),
            int(row["created_at"]),
            self._validate_serial(str(row["target_serial"])),
            self._validate_codename(str(row["device_codename"])),
            self._validate_partition(str(row["partition_name"])),
            self._validate_slot(str(row["slot"])),
            BackupProvenance(str(row["provenance"])),
            self.root / relative,
        )

    def _copy_and_hash(
        self,
        source: Path,
        output: BinaryIO | None,
        *,
        cancellation: CancellationProbe | None,
    ) -> tuple[str, int]:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(source, flags)
        except OSError as error:
            raise BackupRepositoryError(
                "backup_source_unavailable", "backup source is unavailable"
            ) from error
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise BackupRepositoryError(
                    "backup_source_invalid", "backup source must be a regular file"
                )
            while chunk := stream.read(1024 * 1024):
                self._check_cancelled(cancellation)
                size += len(chunk)
                if size > self.maximum_backup_bytes:
                    raise BackupRepositoryError(
                        "backup_too_large", "backup exceeds the configured size limit"
                    )
                digest.update(chunk)
                if output is not None:
                    output.write(chunk)
            after = os.fstat(stream.fileno())
        if size <= 0:
            raise BackupRepositoryError("backup_empty", "backup image is empty")
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after or before.st_size != size:
            raise BackupRepositoryError(
                "backup_source_changed", "backup changed while it was being imported"
            )
        self._check_cancelled(cancellation)
        return digest.hexdigest(), size

    def _hash_file(
        self,
        path: Path,
        *,
        cancellation: CancellationProbe | None,
    ) -> tuple[str, int]:
        return self._copy_and_hash(path, None, cancellation=cancellation)

    def _verify_object_path(self, path: Path, digest: str, size: int) -> None:
        try:
            actual_digest, actual_size = self._hash_file(path, cancellation=None)
        except BackupRepositoryError as error:
            raise BackupRepositoryError(
                "backup_repository_corrupt",
                "existing content-addressed backup object is unavailable",
            ) from error
        if actual_digest != digest or actual_size != size:
            raise BackupRepositoryError(
                "backup_repository_corrupt",
                "existing content-addressed backup object is invalid",
            )

    @staticmethod
    def _validate_backup_id(value: str) -> str:
        identifier = str(value).casefold()
        if _BACKUP_ID.fullmatch(identifier) is None:
            raise BackupRepositoryError("backup_id_invalid", "backup ID is invalid")
        return identifier

    @staticmethod
    def _validate_digest(value: str) -> str:
        digest = str(value).casefold()
        if _DIGEST.fullmatch(digest) is None:
            raise BackupRepositoryError("backup_hash_invalid", "backup SHA-256 is invalid")
        return digest

    @staticmethod
    def _validate_serial(value: str) -> str:
        serial = str(value)
        if not is_valid_target_serial(serial):
            raise BackupRepositoryError("backup_serial_invalid", "backup serial is invalid")
        return serial

    @staticmethod
    def _validate_codename(value: str) -> str:
        codename = str(value)
        if _CODENAME.fullmatch(codename) is None:
            raise BackupRepositoryError(
                "backup_codename_invalid", "backup device codename is invalid"
            )
        return codename

    @staticmethod
    def _validate_partition(value: str) -> str:
        partition = str(value).casefold()
        if partition not in SUPPORTED_BACKUP_PARTITIONS:
            raise BackupRepositoryError(
                "backup_partition_invalid", "backup partition is invalid"
            )
        return partition

    @staticmethod
    def _validate_slot(value: str) -> str:
        slot = str(value).casefold()
        if slot not in _SLOTS:
            raise BackupRepositoryError("backup_slot_invalid", "backup slot is invalid")
        return slot

    @staticmethod
    def _relative_object_path(digest: str) -> Path:
        validated = BackupRepository._validate_digest(digest)
        return Path("objects") / validated[:2] / f"{validated[2:]}.img"

    @staticmethod
    def _is_link_like(path: Path) -> bool:
        try:
            return path.is_symlink() or path.is_junction()
        except OSError:
            return True

    @staticmethod
    def _check_cancelled(cancellation: CancellationProbe | None) -> None:
        if cancellation is not None and cancellation.cancelled:
            raise BackupRepositoryError(
                "backup_import_cancelled", "backup import was cancelled"
            )

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


__all__ = [
    "BACKUP_REPOSITORY_SCHEMA_VERSION",
    "BackupCleanupReport",
    "BackupDeletionReceipt",
    "BackupProvenance",
    "BackupRecord",
    "BackupRepository",
    "BackupRepositoryError",
]
