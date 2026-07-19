"""Safe host-side inventory for content-addressed boot-chain images."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from .contracts import BootInfo, FileArtifact, JSONValue
from .repositories import (
    ArtifactKind,
    ArtifactProvenance,
    ArtifactRecord,
    BootRepository,
    CancellationProbe,
    RepositoryError,
)

BOOT_INVENTORY_COMMAND = "boot.inventory"
BOOT_SELECT_COMMAND = "boot.select"
BOOT_DELETE_COMMAND = "boot.delete"
BOOT_INVENTORY_COMMANDS = frozenset(
    {BOOT_INVENTORY_COMMAND, BOOT_SELECT_COMMAND, BOOT_DELETE_COMMAND}
)

BOOT_CHAIN_PARTITIONS = frozenset(
    {"boot", "init_boot", "vendor_boot", "vendor_kernel_boot"}
)
_BOOT_ID = re.compile(r"^[0-9a-f]{32}$")
_IMAGE_MAGIC = {
    "boot": b"ANDROID!",
    "init_boot": b"ANDROID!",
    "vendor_boot": b"VNDRBOOT",
    "vendor_kernel_boot": b"VNDRBOOT",
}


class BootInventoryError(RuntimeError):
    """Stable, non-sensitive boot inventory failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class BootInventoryEntry:
    """Bridge-safe metadata. Backend object paths are deliberately absent."""

    boot_id: str
    sha256: str
    size: int
    provenance: str
    created_at: int
    partition: str
    device_codenames: tuple[str, ...]
    patcher: str
    patcher_version: str
    signature: str
    source_hash: str
    patched: bool
    verified: bool

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "bootId": self.boot_id,
            "sha256": self.sha256,
            "size": self.size,
            "provenance": self.provenance,
            "createdAt": self.created_at,
            "partition": self.partition,
            "deviceCodenames": list(self.device_codenames),
            "patcher": self.patcher,
            "patcherVersion": self.patcher_version,
            "signature": self.signature,
            "sourceHash": self.source_hash,
            "patched": self.patched,
            "verified": self.verified,
        }


@dataclass(frozen=True, slots=True)
class BootSelection:
    info: BootInfo
    entry: BootInventoryEntry
    imported: bool = False


@dataclass(frozen=True, slots=True)
class BootDeletionReceipt:
    boot_id: str
    sha256: str
    object_retained: bool
    cleanup_deferred: bool

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "bootId": self.boot_id,
            "sha256": self.sha256,
            "objectRetained": self.object_retained,
            "cleanupDeferred": self.cleanup_deferred,
        }


class BootInventoryService:
    """List, import, verify, and resolve boot images from one repository.

    The service accepts a backend path only after the WebView host has consumed
    a purpose-bound read grant. Public results never serialize that path.
    """

    def __init__(
        self,
        repository: BootRepository,
        *,
        maximum_entries: int = 2_000,
        maximum_image_bytes: int = 2 * 1024 * 1024 * 1024,
    ) -> None:
        if maximum_entries <= 0 or maximum_image_bytes <= 0:
            raise ValueError("boot inventory limits must be positive")
        self.repository = repository
        self.maximum_entries = maximum_entries
        self.maximum_image_bytes = maximum_image_bytes

    def list_public(
        self,
        cancellation: CancellationProbe | None = None,
    ) -> tuple[BootInventoryEntry, ...]:
        self._check_cancelled(cancellation)
        try:
            records = self.repository.list()
        except (OSError, RepositoryError) as error:
            raise BootInventoryError(
                "boot_inventory_unavailable",
                "the boot image inventory could not be read",
            ) from error
        if len(records) > self.maximum_entries:
            raise BootInventoryError(
                "boot_inventory_too_large",
                "the boot image inventory exceeds its safe response limit",
            )
        return tuple(
            self._entry(record, cancellation=cancellation)
            for record in records
        )

    def select(
        self,
        boot_id: str,
        cancellation: CancellationProbe | None = None,
    ) -> BootSelection:
        self._check_cancelled(cancellation)
        normalized_id = self._validate_id(boot_id)
        try:
            record = self.repository.repository.get(normalized_id)
        except (OSError, RepositoryError) as error:
            raise BootInventoryError(
                "boot_repository_unavailable",
                "the boot image repository could not be read",
            ) from error
        if record is None or record.kind is not ArtifactKind.BOOT:
            raise BootInventoryError(
                "boot_not_found",
                "the requested boot image is not in the repository",
            )
        if record.partition not in BOOT_CHAIN_PARTITIONS:
            raise BootInventoryError(
                "boot_metadata_invalid",
                "the boot image has an unsupported partition",
            )
        if not self._record_verified(record, cancellation):
            raise BootInventoryError(
                "boot_integrity_failed",
                "the stored boot image failed SHA-256 verification",
            )
        return self._selection(record, verified=True)

    def delete(self, boot_id: str) -> BootDeletionReceipt:
        """Delete one metadata record while preserving shared content objects."""

        normalized_id = self._validate_id(boot_id)
        try:
            record = self.repository.repository.get(normalized_id)
            if record is None or record.kind is not ArtifactKind.BOOT:
                raise BootInventoryError(
                    "boot_not_found",
                    "the requested boot image is not in the repository",
                )
            shared = sum(
                candidate.sha256 == record.sha256
                for candidate in self.repository.repository.list()
            ) > 1
            cleanup_deferred = False
            try:
                removed = self.repository.repository.delete(normalized_id)
            except (OSError, RepositoryError) as error:
                # Metadata commits before an unshared object is unlinked. If
                # the row is gone, deletion succeeded and only GC is deferred.
                if self.repository.repository.get(normalized_id) is not None:
                    raise BootInventoryError(
                        "boot_delete_failed",
                        "the boot image record could not be deleted safely",
                    ) from error
                removed = True
                cleanup_deferred = True
        except BootInventoryError:
            raise
        except (OSError, RepositoryError) as error:
            raise BootInventoryError(
                "boot_repository_unavailable",
                "the boot image repository could not be updated",
            ) from error
        if not removed:
            raise BootInventoryError(
                "boot_not_found",
                "the requested boot image is not in the repository",
            )
        return BootDeletionReceipt(
            boot_id=normalized_id,
            sha256=record.sha256,
            object_retained=shared,
            cleanup_deferred=cleanup_deferred,
        )

    def import_image(
        self,
        path: str | Path,
        *,
        partition: str,
        cancellation: CancellationProbe | None = None,
    ) -> BootSelection:
        self._check_cancelled(cancellation)
        normalized_partition = str(partition).strip().casefold()
        if normalized_partition not in BOOT_CHAIN_PARTITIONS:
            raise BootInventoryError(
                "boot_partition_invalid",
                "the boot image partition is not supported",
            )
        try:
            source = Path(path).expanduser().resolve(strict=True)
            stat = source.stat()
        except (OSError, ValueError) as error:
            raise BootInventoryError(
                "boot_source_invalid",
                "the granted boot image is not available",
            ) from error
        if not source.is_file():
            raise BootInventoryError(
                "boot_source_invalid",
                "the granted boot image must be a regular file",
            )
        if stat.st_size <= 8 or stat.st_size > self.maximum_image_bytes:
            raise BootInventoryError(
                "boot_image_size_invalid",
                "the granted boot image has an invalid size",
            )
        try:
            with source.open("rb") as stream:
                magic = stream.read(8)
        except OSError as error:
            raise BootInventoryError(
                "boot_source_invalid",
                "the granted boot image could not be read",
            ) from error
        if magic != _IMAGE_MAGIC[normalized_partition]:
            raise BootInventoryError(
                "boot_image_format_invalid",
                "the granted file does not match the selected boot-chain partition",
            )
        try:
            record = self.repository.import_boot(
                source,
                partition=normalized_partition,
                provenance=ArtifactProvenance.USER_SUPPLIED,
                cancellation=cancellation,
            )
        except RepositoryError as error:
            if error.code == "artifact_import_cancelled":
                raise BootInventoryError(
                    "boot_cancelled",
                    "boot inventory operation was cancelled",
                ) from error
            if error.code == "artifact_import_rollback_failed":
                raise BootInventoryError(
                    "boot_import_rollback_failed",
                    "the cancelled boot import could not be rolled back",
                ) from error
            raise BootInventoryError(error.code, str(error)) from error
        except OSError as error:
            raise BootInventoryError(
                "boot_import_failed",
                "the boot image could not be imported",
            ) from error
        try:
            self._check_cancelled(cancellation)
            verified = self._record_verified(record, cancellation)
        except BootInventoryError as error:
            if error.code == "boot_cancelled":
                self._rollback_cancelled_import(record.artifact_id)
            raise
        if not verified:
            self.repository.repository.delete(record.artifact_id)
            raise BootInventoryError(
                "boot_integrity_failed",
                "the imported boot image failed SHA-256 verification",
            )
        return self._selection(record, verified=True, imported=True)

    def import_processed(
        self,
        artifact: FileArtifact,
        *,
        firmware_hash: str,
        device_codenames: tuple[str, ...] = (),
        cancellation: CancellationProbe | None = None,
    ) -> BootSelection:
        """Persist one processor-verified stock image with source provenance."""

        self._check_cancelled(cancellation)
        if not isinstance(artifact, FileArtifact):
            raise BootInventoryError(
                "boot_artifact_invalid",
                "a verified boot artifact is required",
            )
        partition = artifact.role.removeprefix("partition:")
        if artifact.role != f"partition:{partition}" or partition not in BOOT_CHAIN_PARTITIONS:
            raise BootInventoryError(
                "boot_partition_invalid",
                "the processed boot artifact partition is not supported",
            )
        existing_ids = {record.artifact_id for record in self.repository.list()}
        try:
            record = self.repository.import_selection(
                artifact.path,
                partition=partition,
                patched=False,
                expected_sha256=artifact.sha256,
                source_hash=firmware_hash,
                device_codenames=device_codenames,
                cancellation=cancellation,
            )
        except RepositoryError as error:
            if error.code == "artifact_import_cancelled":
                raise BootInventoryError(
                    "boot_cancelled",
                    "processed boot import was cancelled",
                ) from error
            raise BootInventoryError(error.code, str(error)) from error
        except OSError as error:
            raise BootInventoryError(
                "boot_import_failed",
                "the processed boot image could not be imported",
            ) from error
        imported = record.artifact_id not in existing_ids
        try:
            self._check_cancelled(cancellation)
            verified = self._record_verified(record, cancellation)
        except BootInventoryError:
            if imported:
                self._rollback_processed_record(record.artifact_id)
            raise
        if not verified:
            if imported:
                self._rollback_processed_record(record.artifact_id)
            raise BootInventoryError(
                "boot_integrity_failed",
                "the processed boot image failed format or SHA-256 verification",
            )
        return self._selection(record, verified=True, imported=imported)

    def _rollback_cancelled_import(self, boot_id: str) -> None:
        try:
            removed = self.repository.repository.delete(boot_id)
        except (OSError, RepositoryError) as error:
            raise BootInventoryError(
                "boot_import_rollback_failed",
                "the cancelled boot import could not be rolled back",
            ) from error
        if not removed:
            raise BootInventoryError(
                "boot_import_rollback_failed",
                "the cancelled boot import could not be rolled back",
            )

    def rollback_import(self, boot_id: str) -> None:
        """Remove only a newly imported user record after state promotion fails."""

        normalized_id = self._validate_id(boot_id)
        record = self.repository.repository.get(normalized_id)
        if (
            record is None
            or record.kind is not ArtifactKind.BOOT
            or record.provenance is not ArtifactProvenance.USER_SUPPLIED
        ):
            raise BootInventoryError(
                "boot_import_rollback_refused",
                "the boot import is no longer safe to roll back",
            )
        if not self.repository.repository.delete(normalized_id):
            raise BootInventoryError(
                "boot_import_rollback_failed",
                "the boot import metadata could not be rolled back",
            )

    def rollback_processed_import(self, boot_id: str) -> None:
        """Remove only a newly imported processor-owned stock selection."""

        normalized_id = self._validate_id(boot_id)
        record = self.repository.repository.get(normalized_id)
        if (
            record is None
            or record.kind is not ArtifactKind.BOOT
            or record.provenance is not ArtifactProvenance.PROCESSED
            or record.metadata.get("recordType") != "boot_selection"
            or record.metadata.get("isPatched") is not False
        ):
            raise BootInventoryError(
                "boot_import_rollback_refused",
                "the processed boot import is no longer safe to roll back",
            )
        self._rollback_processed_record(normalized_id)

    def _rollback_processed_record(self, boot_id: str) -> None:
        try:
            removed = self.repository.repository.delete(boot_id)
        except (OSError, RepositoryError) as error:
            raise BootInventoryError(
                "boot_import_rollback_failed",
                "the processed boot import could not be rolled back",
            ) from error
        if not removed:
            raise BootInventoryError(
                "boot_import_rollback_failed",
                "the processed boot import could not be rolled back",
            )

    def _selection(
        self,
        record: ArtifactRecord,
        *,
        verified: bool,
        imported: bool = False,
    ) -> BootSelection:
        entry = self._entry(record, verified=verified)
        return BootSelection(
            BootInfo(
                id=record.artifact_id,
                path=str(record.path),
                hash=record.sha256,
                flavor=record.partition,
                patched=entry.patched,
            ),
            entry,
            imported,
        )

    def _entry(
        self,
        record: ArtifactRecord,
        *,
        verified: bool | None = None,
        cancellation: CancellationProbe | None = None,
    ) -> BootInventoryEntry:
        self._check_cancelled(cancellation)
        if record.kind is not ArtifactKind.BOOT:
            raise BootInventoryError(
                "boot_metadata_invalid",
                "the repository returned a non-boot artifact",
            )
        if record.partition not in BOOT_CHAIN_PARTITIONS:
            raise BootInventoryError(
                "boot_metadata_invalid",
                "the repository returned an unsupported boot-chain partition",
            )
        patched = record.provenance is ArtifactProvenance.PATCHED or bool(
            record.metadata.get("isPatched", False)
        )
        if verified is None:
            try:
                verified = self._record_verified(record, cancellation)
            except (OSError, RepositoryError):
                verified = False
        return BootInventoryEntry(
            boot_id=self._validate_id(record.artifact_id),
            sha256=record.sha256,
            size=record.size,
            provenance=record.provenance.value,
            created_at=record.created_at,
            partition=record.partition,
            device_codenames=tuple(
                self._bounded_text(value, 128) for value in record.device_codenames[:64]
            ),
            patcher=self._bounded_text(record.patcher, 128),
            patcher_version=self._bounded_text(record.patcher_version, 128),
            signature=self._bounded_text(record.signature, 256),
            source_hash=self._bounded_text(record.source_hash, 128),
            patched=patched,
            verified=bool(verified),
        )

    def _record_verified(
        self,
        record: ArtifactRecord,
        cancellation: CancellationProbe | None = None,
    ) -> bool:
        self._check_cancelled(cancellation)
        expected_magic = _IMAGE_MAGIC.get(record.partition)
        if expected_magic is None or record.size <= 8 or record.size > self.maximum_image_bytes:
            return False
        digest = hashlib.sha256()
        size = 0
        try:
            with record.path.open("rb") as stream:
                first = stream.read(8)
                if first != expected_magic:
                    return False
                digest.update(first)
                size += len(first)
                while True:
                    self._check_cancelled(cancellation)
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
                    if size > self.maximum_image_bytes:
                        return False
                self._check_cancelled(cancellation)
        except OSError:
            return False
        return size == record.size and digest.hexdigest() == record.sha256

    @staticmethod
    def _check_cancelled(cancellation: CancellationProbe | None) -> None:
        if cancellation is not None and cancellation.cancelled:
            raise BootInventoryError(
                "boot_cancelled",
                "boot inventory operation was cancelled",
            )

    @staticmethod
    def _validate_id(value: object) -> str:
        if not isinstance(value, str) or _BOOT_ID.fullmatch(value) is None:
            raise BootInventoryError(
                "boot_id_invalid",
                "bootId must be 32 lowercase hexadecimal characters",
            )
        return value

    @staticmethod
    def _bounded_text(value: object, limit: int) -> str:
        text = value if isinstance(value, str) else ""
        return text[:limit]
