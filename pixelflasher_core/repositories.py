"""Persistent content-addressed firmware and boot artifact repositories."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
import threading
import time
from collections.abc import Generator, Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType
from typing import Any, BinaryIO, Protocol, cast
from uuid import uuid4

from .contracts import FileArtifact, JSONValue

REPOSITORY_SCHEMA_VERSION = 1
# PixelFlasher 9.x ``runtime.get_pf_db()`` resolves to this exact filename and
# opens it under ``get_sys_config_path()``.  Keep the audited legacy contract
# explicit rather than guessing among historical database names.
LEGACY_V9_DATABASE_NAME = "PixelFlasher4.db"
FIRMWARE_SELECTION_ROLE = "firmware-package"
FIRMWARE_SELECTION_RECORD_TYPE = "firmware_selection"
BOOT_SELECTION_RECORD_TYPE = "boot_selection"

_PUBLIC_METADATA_KEYS = frozenset(
    {
        "firmwareBuild",
        "firmwareHash",
        "firmwareType",
        "isOdin",
        "isPatched",
        "isStockBoot",
        "legacyHash",
        "legacyRowId",
        "legacyTable",
        "packageSignature",
        "planFingerprint",
        "recordType",
    }
)
_PUBLIC_TEXT_LIMIT = 512
_OMIT_PUBLIC_VALUE = object()


class RepositoryError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CancellationProbe(Protocol):
    @property
    def cancelled(self) -> bool: ...


class ArtifactKind(StrEnum):
    FIRMWARE = "firmware"
    BOOT = "boot"


class ArtifactProvenance(StrEnum):
    OFFICIAL = "official"
    USER_SUPPLIED = "user_supplied"
    PROCESSED = "processed"
    PATCHED = "patched"
    LEGACY_V9 = "legacy_v9"


def _metadata_json(value: object) -> JSONValue:
    """Accept only deterministic JSON metadata for backend persistence."""

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        converted: dict[str, JSONValue] = {}
        mapping = cast(Mapping[object, object], value)
        for key, item in mapping.items():
            if not isinstance(key, str):
                raise RepositoryError("artifact_metadata_invalid", "artifact metadata keys must be strings")
            converted[key] = _metadata_json(item)
        return converted
    if isinstance(value, (tuple, list)):
        sequence = cast(tuple[object, ...] | list[object], value)
        return [_metadata_json(item) for item in sequence]
    raise RepositoryError("artifact_metadata_invalid", "artifact metadata must contain only JSON values")


def _validate_digest(value: str, *, field_name: str = "sha256") -> str:
    normalized = str(value).casefold()
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        raise RepositoryError("artifact_hash_invalid", f"{field_name} must be 64 hexadecimal characters")
    return normalized


def _empty_metadata() -> Mapping[str, object]:
    return {}


def _looks_like_path(value: str) -> bool:
    if not value:
        return False
    return (
        value.startswith("~")
        or "/" in value
        or "\\" in value
        or PurePosixPath(value).is_absolute()
        or PureWindowsPath(value).is_absolute()
    )


def _public_metadata_value(value: object) -> JSONValue | object:
    if value is None or isinstance(value, (bool, int, float)):
        return cast(JSONValue, value)
    if isinstance(value, str):
        if len(value) > _PUBLIC_TEXT_LIMIT or _looks_like_path(value):
            return _OMIT_PUBLIC_VALUE
        return value
    return _OMIT_PUBLIC_VALUE


def _public_metadata(metadata: Mapping[str, object]) -> dict[str, JSONValue]:
    public: dict[str, JSONValue] = {}
    for key in sorted(_PUBLIC_METADATA_KEYS):
        if key not in metadata:
            continue
        value = _public_metadata_value(metadata[key])
        if value is not _OMIT_PUBLIC_VALUE:
            public[key] = cast(JSONValue, value)
    return public


def _public_text(value: str) -> str:
    if len(value) > _PUBLIC_TEXT_LIMIT or _looks_like_path(value):
        return ""
    return value


def _check_cancelled(cancellation: CancellationProbe | None) -> None:
    if cancellation is not None and cancellation.cancelled:
        raise RepositoryError(
            "artifact_import_cancelled",
            "artifact import was cancelled",
        )


def _sha256(
    path: Path,
    *,
    maximum_bytes: int | None = None,
    cancellation: CancellationProbe | None = None,
) -> tuple[str, int]:
    _check_cancelled(cancellation)
    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    descriptor_open = True
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise RepositoryError("artifact_not_file", "artifact must be a regular file")
        stream = os.fdopen(descriptor, "rb")
        descriptor_open = False
        with stream:
            while True:
                _check_cancelled(cancellation)
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
                if maximum_bytes is not None and size > maximum_bytes:
                    raise RepositoryError("artifact_too_large", "artifact exceeds repository size limit")
    finally:
        if descriptor_open:
            os.close(descriptor)
    _check_cancelled(cancellation)
    return digest.hexdigest(), size


def _copy_to_stream(
    source: Path,
    output_stream: BinaryIO,
    *,
    cancellation: CancellationProbe | None = None,
) -> None:
    with source.open("rb") as input_stream:
        while True:
            _check_cancelled(cancellation)
            chunk = input_stream.read(1024 * 1024)
            if not chunk:
                break
            output_stream.write(chunk)
            _check_cancelled(cancellation)


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    artifact_id: str
    kind: ArtifactKind
    sha256: str
    size: int
    role: str
    provenance: ArtifactProvenance
    created_at: int
    source_hash: str = ""
    device_codenames: tuple[str, ...] = ()
    partition: str = ""
    patcher: str = ""
    patcher_version: str = ""
    signature: str = ""
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)
    _path: Path = field(default=Path(), repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "device_codenames", tuple(self.device_codenames))
        converted = _metadata_json(self.metadata)
        if not isinstance(converted, dict):  # pragma: no cover - field invariant
            raise RepositoryError("artifact_metadata_invalid", "artifact metadata must be an object")
        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(cast(dict[str, JSONValue], converted)),
        )

    @property
    def path(self) -> Path:
        """Backend-only object path; never include it in a bridge payload."""

        return self._path

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "id": self.artifact_id,
            "kind": self.kind.value,
            "sha256": self.sha256,
            "size": self.size,
            "role": _public_text(self.role),
            "provenance": self.provenance.value,
            "createdAt": self.created_at,
            "sourceHash": _public_text(self.source_hash),
            "deviceCodenames": [
                public
                for value in self.device_codenames
                if (public := _public_text(value))
            ],
            "partition": _public_text(self.partition),
            "patcher": _public_text(self.patcher),
            "patcherVersion": _public_text(self.patcher_version),
            "signature": _public_text(self.signature),
            "metadata": _public_metadata(self.metadata),
        }

    def to_file_artifact(self) -> FileArtifact:
        return FileArtifact(str(self._path), self.sha256, self.role)


@dataclass(frozen=True, slots=True)
class LegacyMigrationReport:
    imported_firmware: int = 0
    imported_boot: int = 0
    already_imported: int = 0
    missing_files: tuple[str, ...] = ()
    source_database: str = ""
    status: str = "not_found"


@dataclass(frozen=True, slots=True)
class OrphanCollectionReport:
    scanned_files: int = 0
    removed_files: int = 0
    retained_files: int = 0
    failed_files: int = 0
    scan_limited: bool = False


class ArtifactRepository:
    """SQLite metadata plus immutable SHA-256-addressed object storage."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        database_path: str | os.PathLike[str] | None = None,
        maximum_import_bytes: int = 16 * 1024 * 1024 * 1024,
    ) -> None:
        if maximum_import_bytes <= 0:
            raise ValueError("maximum_import_bytes must be positive")
        self.root = Path(root).expanduser().resolve()
        self.objects_root = self.root / "objects"
        self.database_path = (
            Path(database_path).expanduser().resolve()
            if database_path is not None
            else self.root / "artifacts.sqlite3"
        )
        self.maximum_import_bytes = int(maximum_import_bytes)
        self._lock = threading.RLock()
        self.objects_root.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            self.database_path,
            timeout=30,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        with self._lock, self._connection:
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS repository_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            row = self._connection.execute(
                "SELECT value FROM repository_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is not None and int(row["value"]) > REPOSITORY_SCHEMA_VERSION:
                raise RepositoryError(
                    "repository_schema_newer",
                    "artifact repository was created by a newer PixelFlasher version",
                )
            self._connection.execute(
                "INSERT OR REPLACE INTO repository_meta(key, value) VALUES('schema_version', ?)",
                (str(REPOSITORY_SCHEMA_VERSION),),
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS objects (
                    sha256 TEXT PRIMARY KEY,
                    size INTEGER NOT NULL,
                    relative_path TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL CHECK(kind IN ('firmware', 'boot')),
                    sha256 TEXT NOT NULL REFERENCES objects(sha256),
                    role TEXT NOT NULL,
                    provenance TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    source_hash TEXT NOT NULL DEFAULT '',
                    device_codenames TEXT NOT NULL DEFAULT '[]',
                    partition_name TEXT NOT NULL DEFAULT '',
                    patcher TEXT NOT NULL DEFAULT '',
                    patcher_version TEXT NOT NULL DEFAULT '',
                    signature TEXT NOT NULL DEFAULT '',
                    metadata TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS artifact_kind_created ON artifacts(kind, created_at DESC)"
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS artifact_sha256 ON artifacts(sha256)"
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS legacy_imports (
                    source_database TEXT NOT NULL,
                    source_table TEXT NOT NULL,
                    source_row_id INTEGER NOT NULL,
                    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                    PRIMARY KEY(source_database, source_table, source_row_id)
                )
                """
            )

    def import_file(
        self,
        source: str | os.PathLike[str],
        *,
        kind: ArtifactKind,
        role: str,
        provenance: ArtifactProvenance,
        expected_sha256: str | None = None,
        source_hash: str = "",
        device_codenames: Iterable[str] = (),
        partition: str = "",
        patcher: str = "",
        patcher_version: str = "",
        signature: str = "",
        metadata: Mapping[str, object] | None = None,
        artifact_id: str | None = None,
        cancellation: CancellationProbe | None = None,
    ) -> ArtifactRecord:
        _check_cancelled(cancellation)
        if not isinstance(kind, ArtifactKind) or not isinstance(provenance, ArtifactProvenance):
            raise TypeError("kind and provenance must use repository enum values")
        source_path = Path(source).expanduser().resolve(strict=True)
        _check_cancelled(cancellation)
        if not source_path.is_file():
            raise RepositoryError("artifact_not_file", "artifact source must be a regular file")
        if source_path.stat().st_size > self.maximum_import_bytes:
            raise RepositoryError("artifact_too_large", "artifact exceeds repository size limit")
        sha256, size = _sha256(
            source_path,
            maximum_bytes=self.maximum_import_bytes,
            cancellation=cancellation,
        )
        if expected_sha256 is not None and sha256 != _validate_digest(expected_sha256):
            raise RepositoryError("artifact_hash_mismatch", "artifact SHA-256 does not match expectation")
        relative_path = self._canonical_relative_path(sha256)
        object_path = self._validated_object_path(sha256)
        created_at = int(time.time())
        record_id = self._validate_artifact_id(artifact_id or uuid4().hex)
        codenames = tuple(sorted({str(value).strip() for value in device_codenames if str(value).strip()}))
        normalized_metadata = _metadata_json(metadata or {})
        if not isinstance(normalized_metadata, dict):  # pragma: no cover - mapping invariant
            raise RepositoryError("artifact_metadata_invalid", "artifact metadata must be an object")
        metadata_json = json.dumps(
            normalized_metadata,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        role_value = str(role)
        source_hash_value = str(source_hash)
        partition_value = str(partition)
        patcher_value = str(patcher)
        patcher_version_value = str(patcher_version)
        signature_value = str(signature)

        with self._lock:
            _check_cancelled(cancellation)
            existing = self._connection.execute(
                "SELECT * FROM artifacts WHERE artifact_id = ?",
                (record_id,),
            ).fetchone()
            if existing is not None:
                record = self._record_from_row(existing)
                if not self._identity_matches(
                    record,
                    kind=kind,
                    sha256=sha256,
                    size=size,
                    role=role_value,
                    provenance=provenance,
                    source_hash=source_hash_value,
                    device_codenames=codenames,
                    partition=partition_value,
                    patcher=patcher_value,
                    patcher_version=patcher_version_value,
                    signature=signature_value,
                    metadata=normalized_metadata,
                ):
                    raise RepositoryError(
                        "artifact_identity_conflict",
                        "artifact id is already bound to different content or metadata",
                    )
                if not self._verify_record(record, cancellation=cancellation):
                    raise RepositoryError(
                        "repository_object_corrupt",
                        "stored artifact hash or size is invalid",
                    )
                _check_cancelled(cancellation)
                return record
            object_created = self._commit_object(
                source_path,
                object_path,
                sha256,
                cancellation=cancellation,
            )
            artifact_inserted = False
            try:
                _check_cancelled(cancellation)
                with self._connection:
                    self._connection.execute(
                        "INSERT OR IGNORE INTO objects(sha256, size, relative_path, created_at) VALUES(?, ?, ?, ?)",
                        (sha256, size, relative_path.as_posix(), created_at),
                    )
                    object_row = self._connection.execute(
                        "SELECT size, relative_path FROM objects WHERE sha256 = ?",
                        (sha256,),
                    ).fetchone()
                    if (
                        object_row is None
                        or int(object_row["size"]) != size
                        or str(object_row["relative_path"]) != relative_path.as_posix()
                    ):
                        raise RepositoryError(
                            "repository_object_conflict",
                            "stored object metadata conflicts with its content address",
                        )
                    _check_cancelled(cancellation)
                    self._connection.execute(
                        """
                        INSERT INTO artifacts(
                            artifact_id, kind, sha256, role, provenance, created_at,
                            source_hash, device_codenames, partition_name, patcher,
                            patcher_version, signature, metadata
                        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record_id,
                            kind.value,
                            sha256,
                            role_value,
                            provenance.value,
                            created_at,
                            source_hash_value,
                            json.dumps(codenames),
                            partition_value,
                            patcher_value,
                            patcher_version_value,
                            signature_value,
                            metadata_json,
                        ),
                    )
                    _check_cancelled(cancellation)
                artifact_inserted = True
                _check_cancelled(cancellation)
            except RepositoryError as error:
                if error.code == "artifact_import_cancelled":
                    self._rollback_cancelled_import(
                        record_id=record_id,
                        object_path=object_path,
                        object_created=object_created,
                        artifact_inserted=artifact_inserted,
                    )
                raise
            row = self._connection.execute(
                "SELECT * FROM artifacts WHERE artifact_id = ?",
                (record_id,),
            ).fetchone()
            assert row is not None
            return self._record_from_row(row)

    @staticmethod
    def _validate_artifact_id(value: str) -> str:
        normalized = str(value).casefold()
        if len(normalized) != 32 or any(character not in "0123456789abcdef" for character in normalized):
            raise RepositoryError(
                "artifact_id_invalid",
                "artifact id must be 32 lowercase hexadecimal characters",
            )
        return normalized

    @staticmethod
    def _canonical_relative_path(sha256: str) -> Path:
        digest = _validate_digest(sha256)
        return Path(digest[:2]) / digest[2:]

    @staticmethod
    def _is_link_like(path: Path) -> bool:
        return path.is_symlink() or path.is_junction()

    def _validated_object_path(
        self,
        sha256: str,
        stored_relative_path: str | None = None,
    ) -> Path:
        relative = self._canonical_relative_path(sha256)
        if stored_relative_path is not None and stored_relative_path != relative.as_posix():
            raise RepositoryError(
                "repository_metadata_corrupt",
                "stored object path does not match its content address",
            )
        if self._is_link_like(self.objects_root) or not self.objects_root.is_dir():
            raise RepositoryError(
                "repository_path_unsafe",
                "artifact object root is not a trusted directory",
            )
        parent = self.objects_root / relative.parent
        if (parent.exists() or self._is_link_like(parent)) and (
            self._is_link_like(parent) or not parent.is_dir()
        ):
            raise RepositoryError(
                "repository_path_unsafe",
                "artifact object directory is not a trusted directory",
            )
        path = self.objects_root / relative
        if path.exists() or self._is_link_like(path):
            if self._is_link_like(path) or not path.is_file():
                raise RepositoryError(
                    "repository_path_unsafe",
                    "artifact object is not a trusted regular file",
                )
        return path

    @staticmethod
    def _identity_matches(
        record: ArtifactRecord,
        *,
        kind: ArtifactKind,
        sha256: str,
        size: int,
        role: str,
        provenance: ArtifactProvenance,
        source_hash: str,
        device_codenames: tuple[str, ...],
        partition: str,
        patcher: str,
        patcher_version: str,
        signature: str,
        metadata: Mapping[str, object],
    ) -> bool:
        return (
            record.kind is kind
            and record.sha256 == sha256
            and record.size == size
            and record.role == role
            and record.provenance is provenance
            and record.source_hash == source_hash
            and record.device_codenames == device_codenames
            and record.partition == partition
            and record.patcher == patcher
            and record.patcher_version == patcher_version
            and record.signature == signature
            and record.metadata == metadata
        )

    @staticmethod
    def _verify_record(
        record: ArtifactRecord,
        *,
        cancellation: CancellationProbe | None = None,
    ) -> bool:
        try:
            digest, size = _sha256(record.path, cancellation=cancellation)
        except RepositoryError as error:
            if error.code == "artifact_import_cancelled":
                raise
            return False
        except OSError:
            return False
        return digest == record.sha256 and size == record.size

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _commit_object(
        self,
        source: Path,
        destination: Path,
        expected_sha256: str,
        *,
        cancellation: CancellationProbe | None = None,
    ) -> bool:
        _check_cancelled(cancellation)
        expected_path = self._validated_object_path(expected_sha256)
        if destination != expected_path:
            raise RepositoryError(
                "repository_path_unsafe",
                "artifact destination does not match its content address",
            )
        if destination.exists():
            actual, _size = _sha256(destination, cancellation=cancellation)
            if actual != expected_sha256:
                raise RepositoryError("repository_object_corrupt", "stored artifact hash is invalid")
            return False
        destination.parent.mkdir(parents=True, exist_ok=True)
        _check_cancelled(cancellation)
        destination = self._validated_object_path(expected_sha256)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{expected_sha256}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary = Path(temporary_name)
        published = False
        try:
            with os.fdopen(descriptor, "wb") as output_stream:
                _copy_to_stream(
                    source,
                    output_stream,
                    cancellation=cancellation,
                )
                output_stream.flush()
                os.fsync(output_stream.fileno())
                _check_cancelled(cancellation)
            actual, _size = _sha256(temporary, cancellation=cancellation)
            if actual != expected_sha256:
                raise RepositoryError("artifact_copy_corrupt", "artifact changed while being copied")
            _check_cancelled(cancellation)
            try:
                os.replace(temporary, destination)
                published = True
            except OSError:
                if not destination.exists():
                    raise
            final_path = self._validated_object_path(expected_sha256)
            actual, _size = _sha256(final_path, cancellation=cancellation)
            if actual != expected_sha256:
                raise RepositoryError(
                    "repository_object_corrupt",
                    "published artifact hash is invalid",
                )
            self._fsync_directory(destination.parent)
            _check_cancelled(cancellation)
            return published
        except Exception as error:
            if published:
                try:
                    destination.unlink(missing_ok=True)
                    self._fsync_directory(destination.parent)
                except OSError as rollback_error:
                    if (
                        isinstance(error, RepositoryError)
                        and error.code == "artifact_import_cancelled"
                    ):
                        raise RepositoryError(
                            "artifact_import_rollback_failed",
                            "cancelled artifact content could not be rolled back",
                        ) from rollback_error
                    raise
            raise
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as cleanup_error:
                if cancellation is not None and cancellation.cancelled:
                    raise RepositoryError(
                        "artifact_import_rollback_failed",
                        "cancelled artifact temporary content could not be rolled back",
                    ) from cleanup_error
                raise

    def _rollback_cancelled_import(
        self,
        *,
        record_id: str,
        object_path: Path,
        object_created: bool,
        artifact_inserted: bool,
    ) -> None:
        try:
            if artifact_inserted:
                if not self.delete(record_id):
                    raise RepositoryError(
                        "artifact_import_rollback_failed",
                        "cancelled artifact metadata could not be rolled back",
                    )
                return
            if object_created:
                object_path.unlink(missing_ok=True)
                self._fsync_directory(object_path.parent)
        except (OSError, RepositoryError) as error:
            if (
                isinstance(error, RepositoryError)
                and error.code == "artifact_import_rollback_failed"
            ):
                raise
            raise RepositoryError(
                "artifact_import_rollback_failed",
                "cancelled artifact content could not be rolled back",
            ) from error

    def get(self, artifact_id: str) -> ArtifactRecord | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM artifacts WHERE artifact_id = ?",
                (str(artifact_id),),
            ).fetchone()
            return self._record_from_row(row) if row is not None else None

    def list(self, *, kind: ArtifactKind | None = None) -> tuple[ArtifactRecord, ...]:
        if kind is not None and not isinstance(kind, ArtifactKind):
            raise TypeError("kind must be ArtifactKind or None")
        query = "SELECT * FROM artifacts"
        parameters: tuple[str, ...] = ()
        if kind is not None:
            query += " WHERE kind = ?"
            parameters = (kind.value,)
        query += " ORDER BY created_at DESC, artifact_id"
        with self._lock:
            return tuple(self._record_from_row(row) for row in self._connection.execute(query, parameters))

    def find_by_hash(self, sha256: str, *, kind: ArtifactKind | None = None) -> tuple[ArtifactRecord, ...]:
        digest = _validate_digest(sha256)
        records = self.list(kind=kind)
        return tuple(record for record in records if record.sha256 == digest)

    def verify(self, artifact_id: str) -> bool:
        record = self.get(artifact_id)
        if record is None:
            return False
        return self._verify_record(record)

    def delete(self, artifact_id: str) -> bool:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT artifacts.sha256, objects.relative_path
                FROM artifacts
                LEFT JOIN objects ON objects.sha256 = artifacts.sha256
                WHERE artifacts.artifact_id = ?
                """,
                (str(artifact_id),),
            ).fetchone()
            if row is None:
                return False
            if row["relative_path"] is None:
                raise RepositoryError(
                    "repository_metadata_corrupt",
                    "artifact object metadata is missing",
                )
            try:
                digest = _validate_digest(str(row["sha256"]))
            except RepositoryError as error:
                raise RepositoryError(
                    "repository_metadata_corrupt",
                    "artifact digest metadata is invalid",
                ) from error
            object_path = self._validated_object_path(
                digest,
                str(row["relative_path"]),
            )
            remove_object = False
            with self._connection:
                self._connection.execute("DELETE FROM legacy_imports WHERE artifact_id = ?", (str(artifact_id),))
                self._connection.execute("DELETE FROM artifacts WHERE artifact_id = ?", (str(artifact_id),))
                remaining = self._connection.execute(
                    "SELECT COUNT(*) AS count FROM artifacts WHERE sha256 = ?",
                    (digest,),
                ).fetchone()["count"]
                if not remaining:
                    self._connection.execute("DELETE FROM objects WHERE sha256 = ?", (digest,))
                    remove_object = True
            if remove_object:
                # Metadata commits first.  A failed unlink leaves a harmless
                # orphan for later garbage collection, never a live record
                # pointing at a missing object.
                object_path.unlink(missing_ok=True)
                self._fsync_directory(object_path.parent)
            return True

    def collect_orphaned_objects(
        self,
        *,
        maximum_files: int = 10_000,
        minimum_age_seconds: int = 300,
    ) -> OrphanCollectionReport:
        """Remove only canonical object files that have no SQLite owner.

        Deletion intentionally commits metadata before unlinking. A transient
        Windows handle can therefore leave one harmless content-addressed file
        behind. This bounded startup pass reclaims such files without touching
        unknown names, links, temporary imports, or database-owned objects.
        """

        if maximum_files <= 0 or minimum_age_seconds < 0:
            raise ValueError(
                "maximum_files must be positive and minimum_age_seconds non-negative"
            )
        with self._lock:
            try:
                active_digests = {
                    _validate_digest(str(row["sha256"]))
                    for row in self._connection.execute("SELECT sha256 FROM objects")
                }
            except (OSError, sqlite3.Error, RepositoryError):
                return OrphanCollectionReport(failed_files=1)

            candidates: list[tuple[Path, str]] = []
            scanned = 0
            retained = 0
            prefix_entries = 0
            now = time.time()
            try:
                for prefix in self.objects_root.iterdir():
                    prefix_entries += 1
                    if prefix_entries > 512:
                        return OrphanCollectionReport(
                            scanned_files=scanned,
                            retained_files=retained + len(candidates),
                            scan_limited=True,
                        )
                    if (
                        self._is_link_like(prefix)
                        or not prefix.is_dir()
                        or re.fullmatch(r"[0-9a-f]{2}", prefix.name) is None
                    ):
                        continue
                    for path in prefix.iterdir():
                        scanned += 1
                        if scanned > maximum_files:
                            return OrphanCollectionReport(
                                scanned_files=scanned,
                                retained_files=retained + len(candidates),
                                scan_limited=True,
                            )
                        if (
                            self._is_link_like(path)
                            or not path.is_file()
                            or re.fullmatch(r"[0-9a-f]{62}", path.name) is None
                        ):
                            retained += 1
                            continue
                        digest = prefix.name + path.name
                        try:
                            old_enough = (
                                now - path.stat().st_mtime >= minimum_age_seconds
                            )
                        except OSError:
                            retained += 1
                            continue
                        if digest in active_digests or not old_enough:
                            retained += 1
                        else:
                            candidates.append((path, digest))
            except OSError:
                return OrphanCollectionReport(
                    scanned_files=scanned,
                    retained_files=retained + len(candidates),
                    failed_files=1,
                )

            removed = 0
            failed = 0
            for path, digest in candidates:
                try:
                    owner = self._connection.execute(
                        "SELECT 1 FROM objects WHERE sha256 = ?",
                        (digest,),
                    ).fetchone()
                    if owner is not None:
                        retained += 1
                        continue
                    path.unlink()
                except (OSError, sqlite3.Error):
                    failed += 1
                else:
                    removed += 1
                    try:
                        self._fsync_directory(path.parent)
                    except OSError:
                        failed += 1
            return OrphanCollectionReport(
                scanned_files=scanned,
                removed_files=removed,
                retained_files=retained,
                failed_files=failed,
            )

    def migrate_legacy_v9(self, legacy_database: str | os.PathLike[str]) -> LegacyMigrationReport:
        source = Path(legacy_database).expanduser().resolve(strict=True)
        if not source.is_file():
            raise RepositoryError(
                "legacy_database_invalid",
                "legacy database must be a regular file",
            )
        if source == self.database_path:
            raise RepositoryError("legacy_database_conflict", "legacy and modern database paths must differ")
        backup = source.with_name(f"{source.name}.v9.bak")
        with self._fresh_legacy_snapshot(source) as snapshot:
            self._ensure_legacy_backup(snapshot, backup)
            legacy = sqlite3.connect(self._read_only_sqlite_uri(snapshot), uri=True)
            legacy.row_factory = sqlite3.Row
            try:
                if not self._legacy_schema_supported(legacy):
                    return LegacyMigrationReport(
                        source_database=str(source),
                        status="unsupported_schema",
                    )
                return self._migrate_legacy_snapshot(legacy, source)
            finally:
                legacy.close()

    def _migrate_legacy_snapshot(
        self,
        legacy: sqlite3.Connection,
        source: Path,
    ) -> LegacyMigrationReport:
        imported_firmware = 0
        imported_boot = 0
        already_imported = 0
        missing: list[str] = []
        added_artifacts: list[str] = []
        added_mappings: list[tuple[str, int]] = []
        try:
            for table, kind in (("PACKAGE", ArtifactKind.FIRMWARE), ("BOOT", ArtifactKind.BOOT)):
                for row in legacy.execute(f"SELECT * FROM {table} ORDER BY id"):
                    row_id = int(row["id"])
                    if self._legacy_was_imported(source, table, row_id):
                        already_imported += 1
                        continue
                    raw_file_path = Path(str(row["file_path"])).expanduser()
                    file_path = (
                        raw_file_path
                        if raw_file_path.is_absolute()
                        else source.parent / raw_file_path
                    )
                    if not file_path.is_file():
                        missing.append(str(file_path))
                        continue
                    deterministic_id = hashlib.sha256(
                        f"{source}|{table}|{row_id}".encode()
                    ).hexdigest()[:32]
                    existed_before = self.get(deterministic_id) is not None
                    values = dict(row)
                    legacy_hash = str(values.get("boot_hash", "") or "")
                    role = str(values.get("type", "") or "boot")
                    partition = "init_boot" if values.get("is_init_boot") else "boot"
                    metadata = {
                        "legacyTable": table,
                        "legacyRowId": row_id,
                        "legacyHash": legacy_hash,
                        "isPatched": bool(values.get("is_patched", 0)),
                        "isStockBoot": bool(values.get("is_stock_boot", 0)),
                        "isOdin": bool(values.get("is_odin", 0)),
                        "packageSignature": str(values.get("package_sig", "") or ""),
                    }
                    record = self.import_file(
                        file_path,
                        kind=kind,
                        role=role,
                        provenance=ArtifactProvenance.LEGACY_V9,
                        source_hash=str(values.get("patch_source_sha1", "") or legacy_hash),
                        device_codenames=(str(values.get("hardware", "") or ""),),
                        partition=partition if kind is ArtifactKind.BOOT else "",
                        patcher=str(values.get("patch_method", "") or ""),
                        patcher_version=str(values.get("magisk_version", "") or ""),
                        metadata=metadata,
                        artifact_id=deterministic_id,
                    )
                    if not existed_before:
                        added_artifacts.append(record.artifact_id)
                    with self._lock, self._connection:
                        cursor = self._connection.execute(
                            "INSERT OR IGNORE INTO legacy_imports VALUES(?, ?, ?, ?)",
                            (str(source), table, row_id, record.artifact_id),
                        )
                    if cursor.rowcount:
                        added_mappings.append((table, row_id))
                    if kind is ArtifactKind.FIRMWARE:
                        imported_firmware += 1
                    else:
                        imported_boot += 1
        except Exception:
            self._rollback_legacy_migration(
                source,
                added_mappings=added_mappings,
                added_artifacts=added_artifacts,
            )
            raise
        return LegacyMigrationReport(
            imported_firmware,
            imported_boot,
            already_imported,
            tuple(missing),
            str(source),
            "partial" if missing else "migrated",
        )

    @staticmethod
    def _read_only_sqlite_uri(path: Path) -> str:
        return f"{path.resolve(strict=True).as_uri()}?mode=ro"

    @classmethod
    @contextmanager
    def _fresh_legacy_snapshot(cls, source: Path) -> Generator[Path]:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{source.name}.migration.",
            suffix=".sqlite3",
            dir=source.parent,
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        source_connection: sqlite3.Connection | None = None
        snapshot_connection: sqlite3.Connection | None = None
        try:
            source_connection = sqlite3.connect(
                cls._read_only_sqlite_uri(source),
                uri=True,
                timeout=30,
            )
            snapshot_connection = sqlite3.connect(temporary, timeout=30)
            source_connection.backup(snapshot_connection)
            snapshot_connection.commit()
            quick_check = tuple(
                str(row[0]) for row in snapshot_connection.execute("PRAGMA quick_check")
            )
            if quick_check != ("ok",):
                raise RepositoryError(
                    "legacy_database_corrupt",
                    "legacy database snapshot failed SQLite quick_check",
                )
            snapshot_connection.close()
            snapshot_connection = None
            source_connection.close()
            source_connection = None
            file_descriptor = os.open(
                temporary,
                os.O_RDWR | getattr(os, "O_BINARY", 0),
            )
            try:
                os.fsync(file_descriptor)
            finally:
                os.close(file_descriptor)
            cls._fsync_directory(temporary.parent)
            yield temporary
        except sqlite3.DatabaseError as error:
            raise RepositoryError(
                "legacy_database_invalid",
                "legacy database could not be snapshotted safely",
            ) from error
        finally:
            if snapshot_connection is not None:
                snapshot_connection.close()
            if source_connection is not None:
                source_connection.close()
            temporary.unlink(missing_ok=True)

    @classmethod
    def _ensure_legacy_backup(cls, snapshot: Path, backup: Path) -> None:
        if backup.is_symlink() or backup.is_junction():
            raise RepositoryError(
                "legacy_backup_invalid",
                "legacy database backup must not be a link",
            )
        if backup.exists():
            if not backup.is_file():
                raise RepositoryError(
                    "legacy_backup_invalid",
                    "legacy database backup is not a regular file",
                )
            return
        try:
            os.link(snapshot, backup)
        except FileExistsError as error:
            if backup.is_symlink() or backup.is_junction() or not backup.is_file():
                raise RepositoryError(
                    "legacy_backup_invalid",
                    "legacy database backup is not a trusted regular file",
                ) from error
        cls._fsync_directory(backup.parent)

    @staticmethod
    def _legacy_schema_supported(connection: sqlite3.Connection) -> bool:
        tables = {
            str(row[0]).upper()
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        required_tables = {"PACKAGE", "BOOT"}
        if not required_tables <= tables:
            return False
        for table in sorted(required_tables):
            columns = {
                str(row[1]).casefold()
                for row in connection.execute(f"PRAGMA table_info({table})")
            }
            if not {"id", "file_path"} <= columns:
                return False
        return True

    def _rollback_legacy_migration(
        self,
        source: Path,
        *,
        added_mappings: Iterable[tuple[str, int]],
        added_artifacts: Iterable[str],
    ) -> None:
        with self._lock, self._connection:
            for table, row_id in reversed(tuple(added_mappings)):
                self._connection.execute(
                    "DELETE FROM legacy_imports WHERE source_database = ? AND source_table = ? AND source_row_id = ?",
                    (str(source), table, row_id),
                )
        for artifact_id in reversed(tuple(added_artifacts)):
            self.delete(artifact_id)

    def _legacy_was_imported(self, source: Path, table: str, row_id: int) -> bool:
        with self._lock:
            return self._connection.execute(
                "SELECT 1 FROM legacy_imports WHERE source_database = ? AND source_table = ? AND source_row_id = ?",
                (str(source), table, row_id),
            ).fetchone() is not None

    def _record_from_row(self, row: sqlite3.Row) -> ArtifactRecord:
        try:
            digest = _validate_digest(str(row["sha256"]))
        except RepositoryError as error:
            raise RepositoryError(
                "repository_metadata_corrupt",
                "artifact digest metadata is invalid",
            ) from error
        relative = self._connection.execute(
            "SELECT relative_path, size FROM objects WHERE sha256 = ?",
            (digest,),
        ).fetchone()
        if relative is None:
            raise RepositoryError("repository_metadata_corrupt", "artifact object metadata is missing")
        object_path = self._validated_object_path(
            digest,
            str(relative["relative_path"]),
        )
        try:
            decoded_codenames = cast(
                object,
                json.loads(str(row["device_codenames"])),
            )
            decoded_metadata = cast(object, json.loads(str(row["metadata"])))
        except json.JSONDecodeError as error:
            raise RepositoryError(
                "repository_metadata_corrupt",
                "artifact metadata is not valid JSON",
            ) from error
        if not isinstance(decoded_codenames, list):
            raise RepositoryError(
                "repository_metadata_corrupt",
                "artifact device metadata is invalid",
            )
        codename_values = cast(list[object], decoded_codenames)
        if not all(isinstance(value, str) for value in codename_values):
            raise RepositoryError(
                "repository_metadata_corrupt",
                "artifact device metadata is invalid",
            )
        if not isinstance(decoded_metadata, dict):
            raise RepositoryError(
                "repository_metadata_corrupt",
                "artifact metadata must be an object",
            )
        metadata = cast(dict[str, object], decoded_metadata)
        return ArtifactRecord(
            artifact_id=str(row["artifact_id"]),
            kind=ArtifactKind(str(row["kind"])),
            sha256=digest,
            size=int(relative["size"]),
            role=str(row["role"]),
            provenance=ArtifactProvenance(str(row["provenance"])),
            created_at=int(row["created_at"]),
            source_hash=str(row["source_hash"]),
            device_codenames=tuple(cast(str, value) for value in codename_values),
            partition=str(row["partition_name"]),
            patcher=str(row["patcher"]),
            patcher_version=str(row["patcher_version"]),
            signature=str(row["signature"]),
            metadata=metadata,
            _path=object_path,
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> ArtifactRepository:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


class FirmwareRepository:
    def __init__(self, repository: ArtifactRepository) -> None:
        self.repository = repository

    def import_firmware(
        self,
        path: str | os.PathLike[str],
        *,
        cancellation: CancellationProbe | None = None,
        **metadata: Any,
    ) -> ArtifactRecord:
        return self.repository.import_file(
            path,
            kind=ArtifactKind.FIRMWARE,
            role=str(metadata.pop("role", "firmware")),
            provenance=metadata.pop("provenance", ArtifactProvenance.USER_SUPPLIED),
            cancellation=cancellation,
            **metadata,
        )

    def list(self) -> tuple[ArtifactRecord, ...]:
        return self.repository.list(kind=ArtifactKind.FIRMWARE)

    def import_selection(
        self,
        path: str | os.PathLike[str],
        *,
        firmware_type: str,
        build: str,
        expected_sha256: str,
        provenance: ArtifactProvenance = ArtifactProvenance.USER_SUPPLIED,
        device_codenames: Iterable[str] = (),
        cancellation: CancellationProbe | None = None,
    ) -> ArtifactRecord:
        """Store one inspected firmware package under a stable repository identity."""

        normalized_type = str(firmware_type).strip().casefold()
        if normalized_type not in {"factory", "ota", "custom"}:
            raise RepositoryError(
                "firmware_type_invalid",
                "selected firmware type must be factory, ota, or custom",
            )
        normalized_build = str(build).strip()
        if len(normalized_build) > 512:
            raise RepositoryError(
                "firmware_build_invalid",
                "selected firmware build metadata is too large",
            )
        if not isinstance(provenance, ArtifactProvenance):
            raise TypeError("provenance must be ArtifactProvenance")
        digest = _validate_digest(expected_sha256)
        codenames = tuple(
            sorted(
                {
                    str(value).strip()
                    for value in device_codenames
                    if str(value).strip()
                }
            )
        )
        identity = "\0".join(
            (
                "firmware-selection-v1",
                digest,
                normalized_type,
                normalized_build,
                provenance.value,
                *codenames,
            )
        )
        artifact_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
        return self.import_firmware(
            path,
            role=FIRMWARE_SELECTION_ROLE,
            provenance=provenance,
            expected_sha256=digest,
            device_codenames=codenames,
            metadata={
                "recordType": FIRMWARE_SELECTION_RECORD_TYPE,
                "firmwareBuild": normalized_build,
                "firmwareType": normalized_type,
            },
            artifact_id=artifact_id,
            cancellation=cancellation,
        )

    def resolve_selection(
        self,
        *,
        artifact_id: str = "",
        sha256: str = "",
    ) -> ArtifactRecord | None:
        """Resolve only verified package-selection rows; hash fallback must be unique."""

        digest = ""
        if sha256:
            try:
                digest = _validate_digest(sha256)
            except RepositoryError:
                return None
        if artifact_id:
            try:
                normalized_id = self.repository._validate_artifact_id(artifact_id)
            except RepositoryError:
                return None
            record = self.repository.get(normalized_id)
            candidates = (record,) if record is not None else ()
        elif digest:
            candidates = self.repository.find_by_hash(
                digest,
                kind=ArtifactKind.FIRMWARE,
            )
        else:
            return None
        matching = tuple(
            record
            for record in candidates
            if record.kind is ArtifactKind.FIRMWARE
            and record.role == FIRMWARE_SELECTION_ROLE
            and record.metadata.get("recordType") == FIRMWARE_SELECTION_RECORD_TYPE
            and (not digest or record.sha256 == digest)
        )
        if len(matching) != 1:
            return None
        record = matching[0]
        return record if self.repository.verify(record.artifact_id) else None

    def register_processed(
        self,
        artifacts: Iterable[FileArtifact],
        *,
        firmware_hash: str = "",
        plan_fingerprint: str = "",
        device_codenames: Iterable[str] = (),
        metadata: Mapping[str, object] | None = None,
    ) -> tuple[ArtifactRecord, ...]:
        normalized = tuple(artifacts)
        if not normalized or any(not isinstance(item, FileArtifact) for item in normalized):
            raise ValueError("verified FileArtifact values are required")
        if not firmware_hash and not plan_fingerprint:
            raise ValueError("firmware_hash or plan_fingerprint is required")
        firmware_digest = firmware_hash.casefold()
        compatible_devices = tuple(device_codenames)
        provenance_metadata = dict(metadata or {})
        provenance_metadata.update(
            {
                "recordType": "processed_firmware_artifact",
                "firmwareHash": firmware_digest,
                "planFingerprint": plan_fingerprint,
            }
        )
        records: list[ArtifactRecord] = []
        added_artifacts: list[str] = []
        try:
            for artifact in normalized:
                identity = "\0".join(
                    (
                        "processed-v1",
                        firmware_digest,
                        plan_fingerprint,
                        artifact.role,
                        artifact.sha256,
                    )
                )
                artifact_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
                existed_before = self.repository.get(artifact_id) is not None
                record = self.import_firmware(
                    artifact.path,
                    role=artifact.role,
                    provenance=ArtifactProvenance.PROCESSED,
                    expected_sha256=artifact.sha256,
                    source_hash=firmware_digest,
                    device_codenames=compatible_devices,
                    metadata=provenance_metadata,
                    artifact_id=artifact_id,
                )
                if not existed_before:
                    added_artifacts.append(record.artifact_id)
                expected = (
                    record.provenance is ArtifactProvenance.PROCESSED
                    and record.role == artifact.role
                    and record.sha256 == artifact.sha256
                    and record.source_hash == firmware_digest
                    and record.metadata.get("recordType") == "processed_firmware_artifact"
                    and record.metadata.get("firmwareHash") == firmware_digest
                    and record.metadata.get("planFingerprint") == plan_fingerprint
                    and self.repository.verify(record.artifact_id)
                )
                if not expected:
                    raise RepositoryError(
                        "processed_artifact_conflict",
                        "processed firmware artifact identity conflicts with repository metadata",
                    )
                records.append(record)
        except Exception:
            for artifact_id in reversed(added_artifacts):
                self.repository.delete(artifact_id)
            raise
        return tuple(records)

    def resolve_processed(
        self,
        *,
        firmware_hash: str = "",
        plan_fingerprint: str = "",
    ) -> tuple[ArtifactRecord, ...]:
        keys = (
            (firmware_hash.casefold(), plan_fingerprint),
            (firmware_hash.casefold(), ""),
            ("", plan_fingerprint),
        )
        records = tuple(
            record
            for record in self.list()
            if record.provenance is ArtifactProvenance.PROCESSED
            and record.metadata.get("recordType") == "processed_firmware_artifact"
        )
        for expected_hash, expected_fingerprint in keys:
            if not expected_hash and not expected_fingerprint:
                continue
            matched = tuple(
                record
                for record in records
                if record.metadata.get("firmwareHash") == expected_hash
                and record.metadata.get("planFingerprint") == expected_fingerprint
            )
            if matched:
                return tuple(sorted(matched, key=lambda record: (record.role, record.artifact_id)))
        return ()


class BootRepository:
    def __init__(self, repository: ArtifactRepository) -> None:
        self.repository = repository

    def import_boot(
        self,
        path: str | os.PathLike[str],
        *,
        partition: str,
        provenance: ArtifactProvenance = ArtifactProvenance.USER_SUPPLIED,
        cancellation: CancellationProbe | None = None,
        **metadata: Any,
    ) -> ArtifactRecord:
        normalized_partition = str(partition).strip()
        if normalized_partition not in {"boot", "init_boot", "vendor_boot", "vendor_kernel_boot"}:
            raise RepositoryError("boot_partition_invalid", "unsupported boot-chain partition")
        return self.repository.import_file(
            path,
            kind=ArtifactKind.BOOT,
            role=f"partition:{normalized_partition}",
            provenance=provenance,
            partition=normalized_partition,
            cancellation=cancellation,
            **metadata,
        )

    def list(self) -> tuple[ArtifactRecord, ...]:
        return self.repository.list(kind=ArtifactKind.BOOT)

    def import_selection(
        self,
        path: str | os.PathLike[str],
        *,
        partition: str,
        patched: bool,
        expected_sha256: str,
        source_hash: str = "",
        device_codenames: Iterable[str] = (),
        cancellation: CancellationProbe | None = None,
    ) -> ArtifactRecord:
        """Canonicalize a backend-produced stock or patched boot selection."""

        if not isinstance(patched, bool):
            raise TypeError("patched must be a boolean")
        normalized_partition = str(partition).strip().casefold()
        if normalized_partition not in {
            "boot",
            "init_boot",
            "vendor_boot",
            "vendor_kernel_boot",
        }:
            raise RepositoryError(
                "boot_partition_invalid",
                "unsupported boot-chain partition",
            )
        digest = _validate_digest(expected_sha256)
        provenance = (
            ArtifactProvenance.PATCHED
            if patched
            else ArtifactProvenance.PROCESSED
        )
        normalized_source_hash = _validate_digest(source_hash) if source_hash else ""
        normalized_devices = tuple(
            sorted(
                {
                    str(value).strip()
                    for value in device_codenames
                    if str(value).strip()
                }
            )
        )
        identity_fields = (
            (
                "boot-selection-v2",
                digest,
                normalized_partition,
                provenance.value,
                normalized_source_hash,
                *normalized_devices,
            )
            if normalized_source_hash or normalized_devices
            else (
                "boot-selection-v1",
                digest,
                normalized_partition,
                provenance.value,
            )
        )
        identity = "\0".join(identity_fields)
        artifact_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
        return self.import_boot(
            path,
            partition=normalized_partition,
            provenance=provenance,
            expected_sha256=digest,
            source_hash=normalized_source_hash,
            device_codenames=normalized_devices,
            metadata={
                "recordType": BOOT_SELECTION_RECORD_TYPE,
                "isPatched": patched,
            },
            artifact_id=artifact_id,
            cancellation=cancellation,
        )

    def resolve_selection(
        self,
        *,
        artifact_id: str = "",
        sha256: str = "",
    ) -> ArtifactRecord | None:
        """Resolve an exact boot id or one unambiguous verified hash."""

        digest = ""
        if sha256:
            try:
                digest = _validate_digest(sha256)
            except RepositoryError:
                return None
        if artifact_id:
            try:
                normalized_id = self.repository._validate_artifact_id(artifact_id)
            except RepositoryError:
                return None
            record = self.repository.get(normalized_id)
            candidates = (record,) if record is not None else ()
        elif digest:
            candidates = self.repository.find_by_hash(
                digest,
                kind=ArtifactKind.BOOT,
            )
        else:
            return None
        matching = tuple(
            record
            for record in candidates
            if record.kind is ArtifactKind.BOOT
            and record.partition
            in {"boot", "init_boot", "vendor_boot", "vendor_kernel_boot"}
            and (not digest or record.sha256 == digest)
        )
        if len(matching) != 1:
            return None
        record = matching[0]
        return record if self.repository.verify(record.artifact_id) else None
