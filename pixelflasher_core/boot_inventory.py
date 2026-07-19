"""Safe host-side inventory for content-addressed boot-chain images."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from .contracts import BootInfo, JSONValue
from .repositories import (
    ArtifactKind,
    ArtifactProvenance,
    ArtifactRecord,
    BootRepository,
    RepositoryError,
)

BOOT_INVENTORY_COMMAND = "boot.inventory"
BOOT_SELECT_COMMAND = "boot.select"
BOOT_INVENTORY_COMMANDS = frozenset({BOOT_INVENTORY_COMMAND, BOOT_SELECT_COMMAND})

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

    def list_public(self) -> tuple[BootInventoryEntry, ...]:
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
        return tuple(self._entry(record) for record in records)

    def select(self, boot_id: str) -> BootSelection:
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
        if not self._record_verified(record):
            raise BootInventoryError(
                "boot_integrity_failed",
                "the stored boot image failed SHA-256 verification",
            )
        return self._selection(record, verified=True)

    def import_image(self, path: str | Path, *, partition: str) -> BootSelection:
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
            )
        except RepositoryError as error:
            raise BootInventoryError(error.code, str(error)) from error
        except OSError as error:
            raise BootInventoryError(
                "boot_import_failed",
                "the boot image could not be imported",
            ) from error
        if not self._record_verified(record):
            self.repository.repository.delete(record.artifact_id)
            raise BootInventoryError(
                "boot_integrity_failed",
                "the imported boot image failed SHA-256 verification",
            )
        return self._selection(record, verified=True, imported=True)

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
    ) -> BootInventoryEntry:
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
                verified = self._record_verified(record)
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

    def _record_verified(self, record: ArtifactRecord) -> bool:
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
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
                    if size > self.maximum_image_bytes:
                        return False
        except OSError:
            return False
        return size == record.size and digest.hexdigest() == record.sha256

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
