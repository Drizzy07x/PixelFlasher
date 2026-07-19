"""Fail-closed firmware processing and planner artifact registration.

The service in this module never executes archive-provided scripts and never
uses ``ZipFile.extract``.  A firmware package is opened as data, every archive
member is validated and CRC-checked, and only allow-listed ``*.img`` members
are copied to fixed backend-chosen filenames.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import secrets
import shutil
import stat
import tempfile
import unicodedata
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import BinaryIO

from .contracts import FileArtifact, FirmwareInfo
from .executor import CancellationToken
from .firmware import FirmwareInspection, FirmwareKind
from .payload import (
    PayloadErrorCode,
    PayloadExtractionError,
    PayloadExtractionRequest,
    PayloadExtractionResult,
    PayloadExtractor,
    PayloadExtractorIdentity,
    PayloadLimits,
    PayloadManifest,
    PayloadParser,
    PayloadValidationError,
)
from .planner import ProcessedArtifactRepository

FLASHABLE_PARTITIONS = frozenset(
    {
        "boot",
        "init_boot",
        "vendor_boot",
        "vendor_kernel_boot",
        "recovery",
        "dtbo",
        "vbmeta",
        "vbmeta_system",
        "vbmeta_vendor",
        "system",
        "system_ext",
        "product",
        "vendor",
        "odm",
        "odm_dlkm",
        "system_dlkm",
        "vendor_dlkm",
        "super",
        "bootloader",
        "radio",
    }
)


class FirmwareProcessingStatus(StrEnum):
    SUCCESS = "SUCCESS"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class FirmwareProcessingCode(StrEnum):
    READY = "firmware_artifacts_ready"
    CANCELLED = "firmware_processing_cancelled"
    INVALID_PATH = "invalid_path"
    FILE_NOT_FOUND = "file_not_found"
    FILE_TOO_LARGE = "firmware_file_too_large"
    READ_FAILED = "firmware_read_failed"
    CORRUPT_ARCHIVE = "corrupt_firmware"
    UNSAFE_PATH = "unsafe_archive_path"
    UNSAFE_FILE_TYPE = "unsafe_archive_file_type"
    ENCRYPTED_MEMBER = "encrypted_archive_member"
    TOO_MANY_ENTRIES = "archive_entry_limit_exceeded"
    MEMBER_TOO_LARGE = "archive_member_limit_exceeded"
    EXPANDED_SIZE_EXCEEDED = "archive_expanded_size_exceeded"
    SUSPICIOUS_COMPRESSION = "suspicious_compression_ratio"
    DUPLICATE_ENTRY = "duplicate_archive_entry"
    AMBIGUOUS_METADATA = "ambiguous_firmware_metadata"
    METADATA_TOO_LARGE = "firmware_metadata_too_large"
    DEVICE_MISMATCH = "device_mismatch"
    FACTORY_LAYOUT_INVALID = "factory_layout_invalid"
    OTA_LAYOUT_INVALID = "ota_layout_invalid"
    DUPLICATE_PARTITION = "duplicate_partition_artifact"
    DUPLICATE_PAYLOAD = "duplicate_payload_member"
    NO_FLASHABLE_ARTIFACTS = "no_flashable_artifacts"
    PAYLOAD_INVALID = "invalid_payload"
    PAYLOAD_LIMIT_EXCEEDED = "payload_limit_exceeded"
    PAYLOAD_PARTITION_REJECTED = "payload_partition_rejected"
    PAYLOAD_HASH_MISMATCH = "payload_hash_mismatch"
    PAYLOAD_EXTRACTOR_UNAVAILABLE = "payload_extractor_unavailable"
    PAYLOAD_EXTRACTION_FAILED = "payload_extraction_failed"
    PAYLOAD_OUTPUT_INVALID = "payload_output_invalid"
    STOCK_BOOT_REQUIRED = "stock_boot_artifact_required"
    OUTPUT_UNAVAILABLE = "artifact_output_unavailable"
    SOURCE_CHANGED = "firmware_source_changed"
    REGISTRATION_FAILED = "artifact_registration_failed"
    PROCESSING_FAILED = "firmware_processing_failed"


@dataclass(frozen=True, slots=True)
class FirmwareArtifactLimits:
    hash_chunk_size: int = 1024 * 1024
    maximum_archive_bytes: int = 64 * 1024 * 1024 * 1024
    maximum_entries: int = 100_000
    maximum_member_bytes: int = 16 * 1024 * 1024 * 1024
    maximum_uncompressed_bytes: int = 64 * 1024 * 1024 * 1024
    maximum_compression_ratio: float = 1_000.0
    metadata_limit_bytes: int = 1024 * 1024
    maximum_payload_manifest_bytes: int = 32 * 1024 * 1024
    maximum_payload_metadata_signature_bytes: int = 16 * 1024 * 1024
    maximum_payload_partitions: int = 256
    maximum_payload_operations: int = 1_000_000
    maximum_payload_protobuf_fields: int = 4_000_000
    maximum_payload_output_bytes: int = 64 * 1024 * 1024 * 1024
    maximum_payload_referenced_data_bytes: int = 64 * 1024 * 1024 * 1024

    def __post_init__(self) -> None:
        numeric_limits = (
            self.hash_chunk_size,
            self.maximum_archive_bytes,
            self.maximum_entries,
            self.maximum_member_bytes,
            self.maximum_uncompressed_bytes,
            self.metadata_limit_bytes,
            self.maximum_payload_manifest_bytes,
            self.maximum_payload_metadata_signature_bytes,
            self.maximum_payload_partitions,
            self.maximum_payload_operations,
            self.maximum_payload_protobuf_fields,
            self.maximum_payload_output_bytes,
            self.maximum_payload_referenced_data_bytes,
        )
        if any(value <= 0 for value in numeric_limits):
            raise ValueError("firmware processing limits must be positive")
        if self.maximum_compression_ratio < 1:
            raise ValueError("maximum_compression_ratio must be at least 1")


@dataclass(frozen=True, slots=True)
class FirmwareProcessingResult:
    status: FirmwareProcessingStatus
    code: FirmwareProcessingCode
    message: str
    inspection: FirmwareInspection
    firmware: FirmwareInfo
    artifacts: tuple[FileArtifact, ...] = ()
    output_directory: str = ""
    detected_devices: tuple[str, ...] = ()
    registered: bool = False
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "detected_devices", tuple(self.detected_devices))
        object.__setattr__(self, "warnings", tuple(self.warnings))
        if self.status is FirmwareProcessingStatus.SUCCESS:
            if not self.firmware.verified or not self.firmware.processed:
                raise ValueError("successful processing requires verified, processed firmware")
            if not self.artifacts or not self.registered:
                raise ValueError("successful processing requires registered artifacts")
        elif self.firmware.processed:
            raise ValueError("failed or cancelled processing cannot mark firmware processed")

    @property
    def ok(self) -> bool:
        return self.status is FirmwareProcessingStatus.SUCCESS

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "code": self.code.value,
            "message": self.message,
            "inspection": self.inspection.to_dict(),
            "firmware": self.firmware.to_dict(),
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "outputDirectory": self.output_directory,
            "detectedDevices": list(self.detected_devices),
            "registered": self.registered,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class _ArchiveIndex:
    infos: tuple[zipfile.ZipInfo, ...]
    normalized_names: Mapping[str, zipfile.ZipInfo] = field(default_factory=dict[str, zipfile.ZipInfo])

    def __post_init__(self) -> None:
        object.__setattr__(self, "infos", tuple(self.infos))
        object.__setattr__(
            self,
            "normalized_names",
            MappingProxyType(dict(self.normalized_names)),
        )


class _ProcessingFailure(Exception):
    def __init__(self, code: FirmwareProcessingCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class _ProcessingCancelled(Exception):
    pass


class FirmwareArtifactService:
    """Turn a verified ZIP into immutable artifacts consumable by the planner.

    Pass the same ``ProcessedArtifactRepository`` owned by ``OperationPlanner``.
    Registration is performed only after every archive and extracted hash has
    been validated successfully.
    """

    def __init__(
        self,
        repository: ProcessedArtifactRepository,
        output_root: str | os.PathLike[str],
        *,
        limits: FirmwareArtifactLimits | None = None,
        payload_extractor: PayloadExtractor | None = None,
    ) -> None:
        if not isinstance(repository, ProcessedArtifactRepository):
            raise TypeError("repository must be a ProcessedArtifactRepository")
        self.repository = repository
        self.output_root = Path(output_root).expanduser()
        self.limits = limits or FirmwareArtifactLimits()
        self.payload_extractor = payload_extractor
        self.payload_parser = PayloadParser(
            PayloadLimits(
                maximum_payload_bytes=self.limits.maximum_member_bytes,
                maximum_manifest_bytes=self.limits.maximum_payload_manifest_bytes,
                maximum_metadata_signature_bytes=(self.limits.maximum_payload_metadata_signature_bytes),
                maximum_partitions=self.limits.maximum_payload_partitions,
                maximum_operations=self.limits.maximum_payload_operations,
                maximum_protobuf_fields=self.limits.maximum_payload_protobuf_fields,
                maximum_partition_bytes=self.limits.maximum_member_bytes,
                maximum_output_bytes=self.limits.maximum_payload_output_bytes,
                maximum_referenced_data_bytes=(self.limits.maximum_payload_referenced_data_bytes),
                hash_chunk_size=self.limits.hash_chunk_size,
            )
        )

    def process(
        self,
        path: str | os.PathLike[str],
        *,
        expected_devices: Sequence[str] = (),
        cancellation: CancellationToken | None = None,
    ) -> FirmwareProcessingResult:
        token = cancellation or CancellationToken()
        inspection = self._empty_inspection(path)
        staging: Path | None = None
        committed: Path | None = None
        try:
            source = self._source_path(path)
            if token.cancelled:
                raise _ProcessingCancelled
            source_size = source.stat().st_size
            if source_size > self.limits.maximum_archive_bytes:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.FILE_TOO_LARGE,
                    "firmware archive exceeds the configured file-size limit",
                )

            with source.open("rb") as source_stream:
                digest = self._sha256_stream(source_stream, token)
                source_stream.seek(0)
                try:
                    with zipfile.ZipFile(source_stream) as archive:
                        outer = self._validate_archive(archive, "firmware")
                        self._verify_archive(archive, outer, token)
                        inspection = self._classify(source, archive, outer, digest)
                        detected = self._detected_devices(inspection, archive, outer)
                        self._validate_compatibility(detected, expected_devices)

                        source_artifact = FileArtifact(str(source), digest, "firmware")
                        if inspection.kind is FirmwareKind.OTA:
                            self._validate_ota_layout(outer)
                            if not self._payload_members(outer):
                                self._revalidate_source(source, digest, token)
                                if token.cancelled:
                                    raise _ProcessingCancelled
                                self._register((source_artifact,), digest)
                                return self._success(
                                    inspection,
                                    (source_artifact,),
                                    detected,
                                    output_directory="",
                                )

                        root, staging = self._create_staging()
                        extracted: tuple[tuple[str, str], ...]
                        if inspection.kind is FirmwareKind.FACTORY:
                            extracted = self._process_factory(
                                archive,
                                outer,
                                staging,
                                token,
                            )
                        elif self._payload_members(outer):
                            extracted = self._process_payload(
                                archive,
                                outer,
                                staging,
                                token,
                            )
                        else:
                            extracted = self._process_custom(
                                archive,
                                outer,
                                staging,
                                token,
                            )
                        if inspection.kind is not FirmwareKind.OTA and not any(
                            partition in {"init_boot", "boot"} for partition, _image_hash in extracted
                        ):
                            raise _ProcessingFailure(
                                FirmwareProcessingCode.STOCK_BOOT_REQUIRED,
                                ("processed factory/custom firmware has no verified init_boot or boot image"),
                            )

                except _ProcessingCancelled:
                    raise
                except _ProcessingFailure:
                    raise
                except (
                    zipfile.BadZipFile,
                    zipfile.LargeZipFile,
                    RuntimeError,
                    NotImplementedError,
                    EOFError,
                ) as error:
                    raise _ProcessingFailure(
                        FirmwareProcessingCode.CORRUPT_ARCHIVE,
                        str(error) or "firmware archive is corrupt",
                    ) from error

            self._revalidate_source(source, digest, token)
            if token.cancelled:
                raise _ProcessingCancelled
            committed = self._commit_staging(root, staging, inspection, digest)
            staging = None
            if token.cancelled:
                raise _ProcessingCancelled
            extracted = self._revalidate_committed_artifacts(
                committed,
                extracted,
                token,
            )
            artifacts = (source_artifact,) + tuple(
                FileArtifact(
                    str((committed / f"{partition}.img").resolve()),
                    image_hash,
                    f"partition:{partition}",
                )
                for partition, image_hash in extracted
            )
            self._register(artifacts, digest)
            return self._success(
                inspection,
                artifacts,
                detected,
                output_directory=str(committed),
            )
        except _ProcessingCancelled:
            self._cleanup(staging)
            self._cleanup(committed)
            return self._failure(
                FirmwareProcessingStatus.CANCELLED,
                FirmwareProcessingCode.CANCELLED,
                "firmware processing was cancelled",
                inspection,
            )
        except _ProcessingFailure as error:
            self._cleanup(staging)
            self._cleanup(committed)
            return self._failure(
                FirmwareProcessingStatus.FAILED,
                error.code,
                str(error),
                inspection,
            )
        except (OSError, TypeError, ValueError) as error:
            self._cleanup(staging)
            self._cleanup(committed)
            return self._failure(
                FirmwareProcessingStatus.FAILED,
                FirmwareProcessingCode.PROCESSING_FAILED,
                str(error),
                inspection,
            )

    def _source_path(self, raw_path: str | os.PathLike[str]) -> Path:
        try:
            source = Path(raw_path).expanduser().resolve(strict=True)
        except (OSError, TypeError, ValueError) as error:
            code = (
                FirmwareProcessingCode.FILE_NOT_FOUND
                if isinstance(error, FileNotFoundError)
                else FirmwareProcessingCode.INVALID_PATH
            )
            raise _ProcessingFailure(code, str(error)) from error
        if not source.is_file():
            raise _ProcessingFailure(
                FirmwareProcessingCode.FILE_NOT_FOUND,
                "firmware path is not a regular file",
            )
        return source

    def _sha256_stream(
        self,
        stream: BinaryIO,
        token: CancellationToken,
    ) -> str:
        digest = hashlib.sha256()
        while True:
            if token.cancelled:
                raise _ProcessingCancelled
            chunk = stream.read(self.limits.hash_chunk_size)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)

    def _validate_archive(
        self,
        archive: zipfile.ZipFile,
        label: str,
    ) -> _ArchiveIndex:
        infos = tuple(archive.infolist())
        if len(infos) > self.limits.maximum_entries:
            raise _ProcessingFailure(
                FirmwareProcessingCode.TOO_MANY_ENTRIES,
                f"{label} archive contains too many entries",
            )
        total_size = 0
        normalized_names: dict[str, zipfile.ZipInfo] = {}
        for info in infos:
            key = self._safe_member_key(info)
            if key in normalized_names:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.DUPLICATE_ENTRY,
                    f"{label} archive has duplicate path {info.filename!r}",
                )
            normalized_names[key] = info
            if info.flag_bits & 0x1:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.ENCRYPTED_MEMBER,
                    f"encrypted archive member is not supported: {info.filename!r}",
                )
            if info.file_size < 0 or info.compress_size < 0:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.CORRUPT_ARCHIVE,
                    f"archive member has an invalid size: {info.filename!r}",
                )
            if info.file_size > self.limits.maximum_member_bytes:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.MEMBER_TOO_LARGE,
                    f"archive member exceeds the configured limit: {info.filename!r}",
                )
            total_size += info.file_size
            if total_size > self.limits.maximum_uncompressed_bytes:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.EXPANDED_SIZE_EXCEEDED,
                    f"{label} archive expands beyond the configured limit",
                )
            if info.file_size:
                ratio = info.file_size / max(1, info.compress_size)
                if ratio > self.limits.maximum_compression_ratio:
                    raise _ProcessingFailure(
                        FirmwareProcessingCode.SUSPICIOUS_COMPRESSION,
                        f"archive member has a suspicious compression ratio: {info.filename!r}",
                    )
        return _ArchiveIndex(infos, normalized_names)

    def _safe_member_key(self, info: zipfile.ZipInfo) -> str:
        name = info.filename
        normalized = name.replace("\\", "/")
        if "\x00" in normalized or not normalized or normalized.startswith("/"):
            raise _ProcessingFailure(
                FirmwareProcessingCode.UNSAFE_PATH,
                f"unsafe archive path: {name!r}",
            )
        if re.match(r"^[a-zA-Z]:", normalized):
            raise _ProcessingFailure(
                FirmwareProcessingCode.UNSAFE_PATH,
                f"unsafe archive path: {name!r}",
            )
        body = normalized[:-1] if normalized.endswith("/") else normalized
        parts = body.split("/")
        if (
            not body
            or any(part in {"", ".", ".."} for part in parts)
            or any(":" in part for part in parts)
            or any(any(ord(character) < 32 for character in part) for part in parts)
        ):
            raise _ProcessingFailure(
                FirmwareProcessingCode.UNSAFE_PATH,
                f"unsafe archive path: {name!r}",
            )
        pure_path = PurePosixPath(body)
        if pure_path.is_absolute() or any(part == ".." for part in pure_path.parts):
            raise _ProcessingFailure(
                FirmwareProcessingCode.UNSAFE_PATH,
                f"unsafe archive path: {name!r}",
            )

        unix_mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(unix_mode)
        if file_type == stat.S_IFLNK:
            raise _ProcessingFailure(
                FirmwareProcessingCode.UNSAFE_FILE_TYPE,
                f"symbolic links are not allowed: {name!r}",
            )
        allowed_types = {0, stat.S_IFREG, stat.S_IFDIR}
        if file_type not in allowed_types:
            raise _ProcessingFailure(
                FirmwareProcessingCode.UNSAFE_FILE_TYPE,
                f"non-regular archive entry is not allowed: {name!r}",
            )
        if (file_type == stat.S_IFDIR) != info.is_dir() and file_type != 0:
            raise _ProcessingFailure(
                FirmwareProcessingCode.UNSAFE_FILE_TYPE,
                f"archive type and path disagree: {name!r}",
            )
        if info.is_dir() and (info.file_size or info.compress_size):
            raise _ProcessingFailure(
                FirmwareProcessingCode.CORRUPT_ARCHIVE,
                f"archive directory contains unexpected data: {name!r}",
            )
        return unicodedata.normalize("NFC", body).casefold()

    def _verify_archive(
        self,
        archive: zipfile.ZipFile,
        index: _ArchiveIndex,
        token: CancellationToken,
    ) -> None:
        for info in index.infos:
            if token.cancelled:
                raise _ProcessingCancelled
            if info.is_dir():
                continue
            observed = 0
            with archive.open(info, "r") as member:
                while True:
                    if token.cancelled:
                        raise _ProcessingCancelled
                    chunk = member.read(self.limits.hash_chunk_size)
                    if not chunk:
                        break
                    observed += len(chunk)
                    if observed > info.file_size:
                        raise _ProcessingFailure(
                            FirmwareProcessingCode.CORRUPT_ARCHIVE,
                            f"archive member expanded beyond its declared size: {info.filename!r}",
                        )
            if observed != info.file_size:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.CORRUPT_ARCHIVE,
                    f"archive member size does not match metadata: {info.filename!r}",
                )

    def _classify(
        self,
        source: Path,
        archive: zipfile.ZipFile,
        index: _ArchiveIndex,
        digest: str,
    ) -> FirmwareInspection:
        metadata_path = "meta-inf/com/android/metadata"
        metadata_members = tuple(
            info
            for info in index.infos
            if (
                self._normalized_name(info).casefold() == metadata_path
                or self._normalized_name(info).casefold().endswith(f"/{metadata_path}")
            )
        )
        if len(metadata_members) > 1:
            raise _ProcessingFailure(
                FirmwareProcessingCode.AMBIGUOUS_METADATA,
                "firmware archive contains multiple Android metadata files",
            )
        metadata = self._read_metadata(archive, metadata_members[0]) if metadata_members else {}
        image_archives = self._factory_image_members(index)
        has_flash_script = any(
            PurePosixPath(self._normalized_name(info)).name.casefold() in {"flash-all.sh", "flash-all.bat"}
            for info in index.infos
        )
        factory = has_flash_script and bool(image_archives)
        ota = bool(metadata_members) and bool(
            {"ota-type", "post-build", "post-build-incremental"}.intersection(metadata)
        )
        if factory:
            if len(image_archives) != 1:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.FACTORY_LAYOUT_INVALID,
                    "factory firmware must contain exactly one image-*.zip archive",
                )
            basename = PurePosixPath(self._normalized_name(image_archives[0])).name
            match = re.match(r"^image-([^-]+)-(.+)\.zip$", basename, re.IGNORECASE)
            if not match:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.FACTORY_LAYOUT_INVALID,
                    "factory image archive name does not identify device and build",
                )
            device, build = match.group(1), match.group(2)
            kind = FirmwareKind.FACTORY
        elif ota:
            device = metadata.get("pre-device", "")
            build = metadata.get("post-build-incremental", "") or metadata.get("post-build", "")
            kind = FirmwareKind.OTA
        else:
            device = metadata.get("pre-device", "")
            build = metadata.get("post-build-incremental", "") or metadata.get("post-build", "")
            kind = FirmwareKind.CUSTOM
        return FirmwareInspection(
            path=str(source),
            kind=kind,
            sha256=digest,
            build=build,
            device=device,
            metadata=metadata,
        )

    def _read_metadata(
        self,
        archive: zipfile.ZipFile,
        info: zipfile.ZipInfo,
    ) -> dict[str, str]:
        if info.file_size > self.limits.metadata_limit_bytes:
            raise _ProcessingFailure(
                FirmwareProcessingCode.METADATA_TOO_LARGE,
                "firmware metadata exceeds the configured safety limit",
            )
        raw = archive.read(info)
        metadata: dict[str, str] = {}
        for line in raw.decode("utf-8", errors="replace").splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip():
                metadata[key.strip().casefold()] = value.strip()
        return metadata

    def _detected_devices(
        self,
        inspection: FirmwareInspection,
        archive: zipfile.ZipFile,
        index: _ArchiveIndex,
    ) -> tuple[str, ...]:
        devices = self._split_device_names(inspection.device)
        android_info_members = tuple(
            info
            for info in index.infos
            if PurePosixPath(self._normalized_name(info)).name.casefold() == "android-info.txt"
        )
        for info in android_info_members:
            if info.file_size > self.limits.metadata_limit_bytes:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.METADATA_TOO_LARGE,
                    "android-info.txt exceeds the configured safety limit",
                )
            text = archive.read(info).decode("utf-8", errors="replace")
            for line in text.splitlines():
                match = re.match(
                    r"^\s*require\s+(?:board|product|device)\s*=\s*(.+?)\s*$",
                    line,
                    re.IGNORECASE,
                )
                if match:
                    devices.update(self._split_device_names(match.group(1)))
        return tuple(sorted(devices))

    @staticmethod
    def _split_device_names(value: str) -> set[str]:
        return {item.strip().casefold() for item in re.split(r"[,|]", value) if item.strip()}

    def _validate_compatibility(
        self,
        detected_devices: Sequence[str],
        expected_devices: Sequence[str],
    ) -> None:
        if isinstance(expected_devices, str):
            expected_devices = (expected_devices,)
        expected = {item.strip().casefold() for item in expected_devices if isinstance(item, str) and item.strip()}
        detected = set(detected_devices)
        if expected and detected and not expected.intersection(detected):
            raise _ProcessingFailure(
                FirmwareProcessingCode.DEVICE_MISMATCH,
                f"firmware targets {sorted(detected)!r}, selected device is {sorted(expected)!r}",
            )

    def _validate_ota_layout(self, index: _ArchiveIndex) -> None:
        names = {self._normalized_name(info).casefold() for info in index.infos if not info.is_dir()}
        basenames = {PurePosixPath(name).name for name in names}
        legacy_paths = (
            "meta-inf/com/google/android/update-binary",
            "meta-inf/com/google/android/updater-script",
        )
        legacy_updater = any(
            name == legacy_path or name.endswith(f"/{legacy_path}") for name in names for legacy_path in legacy_paths
        )
        if "payload.bin" not in basenames and not legacy_updater:
            raise _ProcessingFailure(
                FirmwareProcessingCode.OTA_LAYOUT_INVALID,
                "OTA package contains neither payload.bin nor a legacy update script",
            )

    def _process_factory(
        self,
        archive: zipfile.ZipFile,
        outer: _ArchiveIndex,
        staging: Path,
        token: CancellationToken,
    ) -> tuple[tuple[str, str], ...]:
        candidates = self._factory_image_members(outer)
        if len(candidates) != 1:
            raise _ProcessingFailure(
                FirmwareProcessingCode.FACTORY_LAYOUT_INVALID,
                "factory firmware must contain exactly one image-*.zip archive",
            )
        nested_path = staging / ".factory-images.zip"
        self._copy_member(archive, candidates[0], nested_path, token)
        try:
            with nested_path.open("rb") as stream, zipfile.ZipFile(stream) as nested:
                index = self._validate_archive(nested, "factory image")
                self._verify_archive(nested, index, token)
                extracted = self._extract_partition_images(nested, index, staging, token)
        except _ProcessingCancelled:
            raise
        except _ProcessingFailure:
            raise
        except (
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
            RuntimeError,
            NotImplementedError,
            EOFError,
        ) as error:
            raise _ProcessingFailure(
                FirmwareProcessingCode.CORRUPT_ARCHIVE,
                f"factory image archive is corrupt: {error}",
            ) from error
        finally:
            try:
                nested_path.unlink(missing_ok=True)
            except OSError:
                pass
        combined = list(extracted)
        known_partitions = {partition for partition, _image_hash in combined}
        for partition, info in self._factory_outer_partition_candidates(outer):
            if partition in known_partitions:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.DUPLICATE_PARTITION,
                    f"multiple factory members map to partition {partition}",
                )
            image_hash = self._copy_member(
                archive,
                info,
                staging / f"{partition}.img",
                token,
            )
            combined.append((partition, image_hash))
            known_partitions.add(partition)
        if not combined:
            raise _ProcessingFailure(
                FirmwareProcessingCode.NO_FLASHABLE_ARTIFACTS,
                "factory image archive has no allow-listed partition images",
            )
        return tuple(sorted(combined))

    def _process_custom(
        self,
        archive: zipfile.ZipFile,
        index: _ArchiveIndex,
        staging: Path,
        token: CancellationToken,
    ) -> tuple[tuple[str, str], ...]:
        if self._payload_members(index):
            return self._process_payload(archive, index, staging, token)
        candidates = self._partition_candidates(index)
        if not candidates:
            raise _ProcessingFailure(
                FirmwareProcessingCode.NO_FLASHABLE_ARTIFACTS,
                "custom firmware has no allow-listed partition images",
            )
        return self._extract_partition_images(archive, index, staging, token)

    def _process_payload(
        self,
        archive: zipfile.ZipFile,
        index: _ArchiveIndex,
        staging: Path,
        token: CancellationToken,
    ) -> tuple[tuple[str, str], ...]:
        payload_members = self._payload_members(index)
        if len(payload_members) != 1:
            raise _ProcessingFailure(
                FirmwareProcessingCode.DUPLICATE_PAYLOAD,
                "firmware archive must contain exactly one unambiguous payload.bin",
            )
        payload_path = staging / ".payload.bin"
        payload_hash = self._copy_member(
            archive,
            payload_members[0],
            payload_path,
            token,
        )
        try:
            manifest = self.payload_parser.parse(
                payload_path,
                allowed_partitions=FLASHABLE_PARTITIONS,
                cancellation=token,
            )
        except InterruptedError as error:
            raise _ProcessingCancelled from error
        except PayloadValidationError as error:
            raise _ProcessingFailure(
                self._payload_failure_code(error.code),
                str(error),
            ) from error

        self._validate_payload_properties(
            archive,
            index,
            manifest,
            payload_hash,
        )
        extractor, _identity = self._trusted_payload_extractor()
        extractor_output = staging / ".payload-images"
        try:
            extractor_output.mkdir(mode=0o700)
            request = PayloadExtractionRequest(
                payload_path,
                extractor_output,
                manifest,
                manifest.partitions,
            )
            result = extractor.extract(request, token)
        except PayloadExtractionError as error:
            if token.cancelled:
                raise _ProcessingCancelled from error
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_EXTRACTION_FAILED,
                f"verified payload extractor failed: {error.code}",
            ) from error
        except _ProcessingCancelled:
            raise
        except Exception as error:
            if token.cancelled:
                raise _ProcessingCancelled from error
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_EXTRACTION_FAILED,
                f"verified payload extractor failed: {type(error).__name__}",
            ) from error
        if token.cancelled:
            raise _ProcessingCancelled

        self._revalidate_payload_copy(payload_path, payload_hash, token)
        extracted = self._validate_payload_outputs(
            staging,
            extractor_output,
            manifest,
            result,
            token,
        )
        try:
            payload_path.unlink()
            extractor_output.rmdir()
            self._fsync_directory(staging)
        except OSError as error:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                f"could not finalize confined payload output: {error}",
            ) from error
        return extracted

    def _validate_payload_outputs(
        self,
        staging: Path,
        output: Path,
        manifest: PayloadManifest,
        result: object,
        token: CancellationToken,
    ) -> tuple[tuple[str, str], ...]:
        if not isinstance(result, PayloadExtractionResult):
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                "payload extractor did not return an explicit typed result",
            )
        expected = {partition.name: partition for partition in manifest.partitions}
        if set(result.partitions) != set(expected) or len(result.partitions) != len(expected):
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                "payload extractor did not report exactly the requested partitions",
            )
        self._validate_confined_directory(staging, output)
        try:
            staging_entries = {entry.name for entry in staging.iterdir()}
            expected_staging = {".payload.bin", ".payload-images"}
            if staging_entries != expected_staging:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                    "payload extractor wrote outside its confined output directory",
                )
            entries = tuple(output.iterdir())
        except OSError as error:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                f"could not inspect payload extractor output: {error}",
            ) from error
        expected_names = {f"{partition}.img" for partition in expected}
        if {entry.name for entry in entries} != expected_names or len(entries) != len(expected_names):
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                "payload extractor output contains missing, extra, or misnamed files",
            )

        validated: list[tuple[str, str]] = []
        total_size = 0
        for partition_name in sorted(expected):
            if token.cancelled:
                raise _ProcessingCancelled
            partition = expected[partition_name]
            candidate = output / f"{partition_name}.img"
            total_size += partition.size
            if total_size > self.limits.maximum_payload_output_bytes:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.PAYLOAD_LIMIT_EXCEEDED,
                    "payload extractor output exceeds the configured size limit",
                )
            observed_hash = self._copy_verified_payload_output(
                output,
                candidate,
                staging / f"{partition_name}.img",
                expected_size=partition.size,
                expected_hash=partition.sha256_hex,
                token=token,
            )
            validated.append((partition_name, observed_hash))

        return tuple(validated)

    def _copy_verified_payload_output(
        self,
        output: Path,
        candidate: Path,
        destination: Path,
        *,
        expected_size: int,
        expected_hash: str,
        token: CancellationToken,
    ) -> str:
        """Copy untrusted extractor bytes into an exclusive backend-owned file.

        The source descriptor is identity-checked before and after the copy. The
        promoted path is then opened and hashed again, closing the validate-then-
        rename race where an extractor could swap a filename after validation.
        """

        self._validate_confined_regular_file(output, candidate)
        temporary_descriptor: int | None = None
        temporary_path: Path | None = None
        try:
            before = candidate.lstat()
            source_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            source_flags |= getattr(os, "O_NOFOLLOW", 0)
            source_descriptor = os.open(candidate, source_flags)
            source = os.fdopen(source_descriptor, "rb", closefd=True)
            temporary_descriptor, raw_temporary = tempfile.mkstemp(
                prefix=".payload-verified-",
                dir=destination.parent,
            )
            temporary_path = Path(raw_temporary)
            digest = hashlib.sha256()
            observed_size = 0
            with source, os.fdopen(temporary_descriptor, "wb", closefd=True) as target:
                temporary_descriptor = None
                opened = os.fstat(source.fileno())
                self._require_same_private_regular_file(before, opened)
                while True:
                    if token.cancelled:
                        raise _ProcessingCancelled
                    chunk = source.read(self.limits.hash_chunk_size)
                    if not chunk:
                        break
                    observed_size += len(chunk)
                    if observed_size > expected_size:
                        raise _ProcessingFailure(
                            FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                            "extracted payload image exceeds its manifest size",
                        )
                    digest.update(chunk)
                    target.write(chunk)
                after = os.fstat(source.fileno())
                self._require_unchanged_open_file(opened, after)
                target.flush()
                os.fsync(target.fileno())
            observed_hash = digest.hexdigest()
            if observed_size != expected_size:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                    "extracted payload image size does not match its manifest",
                )
            if not hmac.compare_digest(observed_hash, expected_hash):
                raise _ProcessingFailure(
                    FirmwareProcessingCode.PAYLOAD_HASH_MISMATCH,
                    "extracted payload image hash does not match its manifest",
                )
            os.replace(temporary_path, destination)
            temporary_path = None
            candidate.unlink()
            promoted_hash, promoted_size = self._hash_private_regular_file(
                destination.parent,
                destination,
                token,
            )
            if promoted_size != expected_size or not hmac.compare_digest(
                promoted_hash,
                expected_hash,
            ):
                raise _ProcessingFailure(
                    FirmwareProcessingCode.PAYLOAD_HASH_MISMATCH,
                    "promoted payload image changed after verification",
                )
            return promoted_hash
        except _ProcessingCancelled:
            raise
        except _ProcessingFailure:
            raise
        except OSError as error:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                f"could not securely promote extracted payload image: {error}",
            ) from error
        finally:
            if temporary_descriptor is not None:
                os.close(temporary_descriptor)
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except OSError:
                    pass

    def _hash_private_regular_file(
        self,
        parent: Path,
        candidate: Path,
        token: CancellationToken,
    ) -> tuple[str, int]:
        self._validate_confined_regular_file(parent, candidate)
        before = candidate.lstat()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(candidate, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            opened = os.fstat(stream.fileno())
            self._require_same_private_regular_file(before, opened)
            observed_hash = self._sha256_stream(stream, token)
            after = os.fstat(stream.fileno())
            self._require_unchanged_open_file(opened, after)
            return observed_hash, after.st_size

    def _revalidate_committed_artifacts(
        self,
        committed: Path,
        extracted: tuple[tuple[str, str], ...],
        token: CancellationToken,
    ) -> tuple[tuple[str, str], ...]:
        expected_names = {f"{partition}.img" for partition, _digest in extracted}
        try:
            observed_names = {entry.name for entry in committed.iterdir()}
        except OSError as error:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                f"could not inspect committed firmware artifacts: {error}",
            ) from error
        if observed_names != expected_names:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                "committed firmware artifacts contain unexpected files",
            )
        verified: list[tuple[str, str]] = []
        for partition, expected_hash in extracted:
            try:
                observed_hash, _size = self._hash_private_regular_file(
                    committed,
                    committed / f"{partition}.img",
                    token,
                )
            except OSError as error:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                    f"could not revalidate committed {partition} image: {error}",
                ) from error
            if not hmac.compare_digest(observed_hash, expected_hash):
                raise _ProcessingFailure(
                    FirmwareProcessingCode.PAYLOAD_HASH_MISMATCH,
                    f"committed {partition} image changed before registration",
                )
            verified.append((partition, observed_hash))
        return tuple(verified)

    @classmethod
    def _require_same_private_regular_file(
        cls,
        before: os.stat_result,
        opened: os.stat_result,
    ) -> None:
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or cls._is_link_or_reparse(before)
            or before.st_nlink != 1
            or opened.st_nlink != 1
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                "extractor output identity changed before it could be copied",
            )

    @staticmethod
    def _require_unchanged_open_file(
        before: os.stat_result,
        after: os.stat_result,
    ) -> None:
        if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size) or getattr(
            before, "st_mtime_ns", None
        ) != getattr(after, "st_mtime_ns", None):
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                "extractor output changed while it was being copied",
            )

    def _validate_payload_properties(
        self,
        archive: zipfile.ZipFile,
        index: _ArchiveIndex,
        manifest: PayloadManifest,
        payload_hash: str,
    ) -> None:
        members = tuple(
            info
            for info in index.infos
            if not info.is_dir()
            and PurePosixPath(self._normalized_name(info)).name.casefold() == "payload_properties.txt"
        )
        if len(members) > 1:
            raise _ProcessingFailure(
                FirmwareProcessingCode.DUPLICATE_PAYLOAD,
                "firmware archive contains multiple payload_properties.txt files",
            )
        if not members:
            return
        info = members[0]
        if info.file_size > self.limits.metadata_limit_bytes:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_LIMIT_EXCEEDED,
                "payload properties exceed the configured metadata limit",
            )
        try:
            raw = archive.read(info).decode("ascii", errors="strict")
        except (UnicodeDecodeError, OSError, zipfile.BadZipFile, RuntimeError) as error:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_INVALID,
                "payload properties are not valid ASCII metadata",
            ) from error
        properties: dict[str, str] = {}
        for raw_line in raw.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            key, separator, value = line.partition("=")
            if not separator or not key or key != key.strip() or value != value.strip() or key in properties:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.PAYLOAD_INVALID,
                    "payload properties contain malformed or duplicate fields",
                )
            properties[key] = value
        required = {"FILE_HASH", "FILE_SIZE", "METADATA_HASH", "METADATA_SIZE"}
        if not required.issubset(properties):
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_INVALID,
                "payload properties omit required hash or size fields",
            )
        file_size = self._payload_property_size(properties["FILE_SIZE"], "FILE_SIZE")
        metadata_size = self._payload_property_size(
            properties["METADATA_SIZE"],
            "METADATA_SIZE",
        )
        file_hash = self._payload_property_hash(properties["FILE_HASH"], "FILE_HASH")
        metadata_hash = self._payload_property_hash(
            properties["METADATA_HASH"],
            "METADATA_HASH",
        )
        if file_size != manifest.payload_size or metadata_size != manifest.metadata_size:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_HASH_MISMATCH,
                "payload property sizes do not match payload.bin",
            )
        if not hmac.compare_digest(file_hash, bytes.fromhex(payload_hash)) or not hmac.compare_digest(
            metadata_hash,
            bytes.fromhex(manifest.metadata_sha256),
        ):
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_HASH_MISMATCH,
                "payload property hashes do not match payload.bin",
            )

    @staticmethod
    def _payload_property_size(value: str, label: str) -> int:
        if not value or not value.isascii() or not value.isdecimal():
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_INVALID,
                f"payload property {label} is not a canonical decimal size",
            )
        parsed = int(value)
        if value != str(parsed):
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_INVALID,
                f"payload property {label} is not a canonical decimal size",
            )
        return parsed

    @staticmethod
    def _payload_property_hash(value: str, label: str) -> bytes:
        try:
            digest = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as error:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_INVALID,
                f"payload property {label} is not canonical base64",
            ) from error
        if len(digest) != hashlib.sha256().digest_size:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_INVALID,
                f"payload property {label} is not a SHA-256 digest",
            )
        return digest

    def _trusted_payload_extractor(
        self,
    ) -> tuple[PayloadExtractor, PayloadExtractorIdentity]:
        extractor = self.payload_extractor
        if extractor is None:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_EXTRACTOR_UNAVAILABLE,
                "payload extraction requires a packaged and manifest-verified runner",
            )
        try:
            identity = extractor.identity
        except Exception as error:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_EXTRACTOR_UNAVAILABLE,
                "payload extractor identity could not be verified",
            ) from error
        if not isinstance(identity, PayloadExtractorIdentity) or not identity.trusted:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_EXTRACTOR_UNAVAILABLE,
                "payload extraction requires a packaged and manifest-verified runner",
            )
        return extractor, identity

    def _revalidate_payload_copy(
        self,
        payload_path: Path,
        expected_hash: str,
        token: CancellationToken,
    ) -> None:
        try:
            with payload_path.open("rb") as stream:
                observed_hash = self._sha256_stream(stream, token)
        except OSError as error:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                f"could not revalidate confined payload.bin: {error}",
            ) from error
        if not hmac.compare_digest(observed_hash, expected_hash):
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_HASH_MISMATCH,
                "payload extractor modified payload.bin",
            )

    @staticmethod
    def _payload_failure_code(code: PayloadErrorCode) -> FirmwareProcessingCode:
        if code is PayloadErrorCode.DATA_HASH_MISMATCH:
            return FirmwareProcessingCode.PAYLOAD_HASH_MISMATCH
        if code in {
            PayloadErrorCode.MANIFEST_LIMIT_EXCEEDED,
            PayloadErrorCode.PARTITION_LIMIT_EXCEEDED,
            PayloadErrorCode.OPERATION_LIMIT_EXCEEDED,
            PayloadErrorCode.SIZE_LIMIT_EXCEEDED,
        }:
            return FirmwareProcessingCode.PAYLOAD_LIMIT_EXCEEDED
        if code in {
            PayloadErrorCode.UNSAFE_PARTITION,
            PayloadErrorCode.NO_FLASHABLE_PARTITIONS,
        }:
            return FirmwareProcessingCode.PAYLOAD_PARTITION_REJECTED
        return FirmwareProcessingCode.PAYLOAD_INVALID

    @staticmethod
    def _payload_members(index: _ArchiveIndex) -> tuple[zipfile.ZipInfo, ...]:
        return tuple(
            info
            for info in index.infos
            if not info.is_dir() and PurePosixPath(info.filename.replace("\\", "/")).name.casefold() == "payload.bin"
        )

    def _validate_confined_directory(self, parent: Path, candidate: Path) -> None:
        try:
            metadata = candidate.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or self._is_link_or_reparse(metadata):
                raise ValueError("extractor output is not a plain directory")
            parent_root = parent.resolve(strict=True)
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(parent_root)
        except (OSError, ValueError) as error:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                f"payload extractor output directory is not confined: {error}",
            ) from error

    def _validate_confined_regular_file(self, parent: Path, candidate: Path) -> None:
        try:
            metadata = candidate.lstat()
            if not stat.S_ISREG(metadata.st_mode) or self._is_link_or_reparse(metadata) or metadata.st_nlink != 1:
                raise ValueError("extractor output is not a private regular file")
            parent_root = parent.resolve(strict=True)
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(parent_root)
        except (OSError, ValueError) as error:
            raise _ProcessingFailure(
                FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                f"payload extractor output file is not confined: {error}",
            ) from error

    @staticmethod
    def _is_link_or_reparse(metadata: os.stat_result) -> bool:
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        file_attributes = getattr(metadata, "st_file_attributes", 0)
        return stat.S_ISLNK(metadata.st_mode) or bool(file_attributes & reparse_flag)

    def _extract_partition_images(
        self,
        archive: zipfile.ZipFile,
        index: _ArchiveIndex,
        staging: Path,
        token: CancellationToken,
    ) -> tuple[tuple[str, str], ...]:
        candidates = self._partition_candidates(index)
        by_partition: dict[str, zipfile.ZipInfo] = {}
        for partition, info in candidates:
            if partition in by_partition:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.DUPLICATE_PARTITION,
                    f"multiple archive members map to partition {partition}",
                )
            by_partition[partition] = info
        extracted: list[tuple[str, str]] = []
        for partition in sorted(by_partition):
            destination = staging / f"{partition}.img"
            image_hash = self._copy_member(
                archive,
                by_partition[partition],
                destination,
                token,
            )
            extracted.append((partition, image_hash))
        return tuple(extracted)

    def _partition_candidates(
        self,
        index: _ArchiveIndex,
    ) -> tuple[tuple[str, zipfile.ZipInfo], ...]:
        candidates: list[tuple[str, zipfile.ZipInfo]] = []
        for info in index.infos:
            if info.is_dir():
                continue
            basename = PurePosixPath(self._normalized_name(info)).name.casefold()
            if not basename.endswith(".img"):
                continue
            partition = basename[:-4]
            if partition in FLASHABLE_PARTITIONS:
                candidates.append((partition, info))
        return tuple(candidates)

    def _copy_member(
        self,
        archive: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        destination: Path,
        token: CancellationToken,
    ) -> str:
        digest = hashlib.sha256()
        observed = 0
        try:
            with archive.open(info, "r") as source, destination.open("xb") as target:
                while True:
                    if token.cancelled:
                        raise _ProcessingCancelled
                    chunk = source.read(self.limits.hash_chunk_size)
                    if not chunk:
                        break
                    observed += len(chunk)
                    if observed > info.file_size:
                        raise _ProcessingFailure(
                            FirmwareProcessingCode.CORRUPT_ARCHIVE,
                            f"archive member expanded beyond its declared size: {info.filename!r}",
                        )
                    target.write(chunk)
                    digest.update(chunk)
                target.flush()
                os.fsync(target.fileno())
        except _ProcessingCancelled:
            raise
        except _ProcessingFailure:
            raise
        except (OSError, zipfile.BadZipFile, RuntimeError, EOFError) as error:
            raise _ProcessingFailure(
                FirmwareProcessingCode.READ_FAILED,
                f"could not copy archive member {info.filename!r}: {error}",
            ) from error
        if observed != info.file_size:
            raise _ProcessingFailure(
                FirmwareProcessingCode.CORRUPT_ARCHIVE,
                f"archive member size does not match metadata: {info.filename!r}",
            )
        return digest.hexdigest()

    def _create_staging(self) -> tuple[Path, Path]:
        try:
            self.output_root.mkdir(parents=True, exist_ok=True)
            root = self.output_root.resolve(strict=True)
            if not root.is_dir():
                raise NotADirectoryError(str(root))
            staging = Path(tempfile.mkdtemp(prefix=".pf-firmware-", dir=root)).resolve()
            staging.relative_to(root)
            return root, staging
        except (OSError, ValueError) as error:
            raise _ProcessingFailure(
                FirmwareProcessingCode.OUTPUT_UNAVAILABLE,
                f"firmware artifact output is unavailable: {error}",
            ) from error

    def _commit_staging(
        self,
        root: Path,
        staging: Path,
        inspection: FirmwareInspection,
        digest: str,
    ) -> Path:
        for _attempt in range(8):
            name = f"{inspection.kind.value}-{digest[:16]}-{secrets.token_hex(4)}"
            destination = root / name
            if destination.exists():
                continue
            try:
                os.replace(staging, destination)
                self._fsync_directory(root)
                return destination.resolve(strict=True)
            except FileExistsError:
                continue
            except OSError as error:
                raise _ProcessingFailure(
                    FirmwareProcessingCode.OUTPUT_UNAVAILABLE,
                    f"could not commit processed firmware artifacts: {error}",
                ) from error
        raise _ProcessingFailure(
            FirmwareProcessingCode.OUTPUT_UNAVAILABLE,
            "could not allocate a unique artifact directory",
        )

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        if os.name == "nt":
            return
        descriptor: int | None = None
        try:
            descriptor = os.open(directory, os.O_RDONLY)
            os.fsync(descriptor)
        except OSError:
            return
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _register(self, artifacts: Sequence[FileArtifact], firmware_hash: str) -> None:
        try:
            self.repository.register(artifacts, firmware_hash=firmware_hash)
        except (TypeError, ValueError) as error:
            raise _ProcessingFailure(
                FirmwareProcessingCode.REGISTRATION_FAILED,
                f"could not register processed artifacts: {error}",
            ) from error

    def _revalidate_source(
        self,
        source: Path,
        expected_hash: str,
        token: CancellationToken,
    ) -> None:
        try:
            with source.open("rb") as stream:
                observed_hash = self._sha256_stream(stream, token)
        except OSError as error:
            raise _ProcessingFailure(
                FirmwareProcessingCode.READ_FAILED,
                f"could not revalidate firmware source: {error}",
            ) from error
        if not hmac.compare_digest(observed_hash, expected_hash):
            raise _ProcessingFailure(
                FirmwareProcessingCode.SOURCE_CHANGED,
                "firmware source changed while it was being processed",
            )

    def _cleanup(self, candidate: Path | None) -> None:
        if candidate is None:
            return
        try:
            root = self.output_root.resolve(strict=True)
            candidate = candidate.absolute()
            if candidate == root or candidate.parent.resolve(strict=True) != root:
                return
            quarantine = root / f".pf-cleanup-{secrets.token_hex(8)}"
            os.replace(candidate, quarantine)
            metadata = quarantine.lstat()
            if self._is_link_or_reparse(metadata):
                if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                    os.rmdir(quarantine)
                else:
                    quarantine.unlink()
            elif stat.S_ISDIR(metadata.st_mode):
                shutil.rmtree(quarantine)
            elif stat.S_ISREG(metadata.st_mode):
                quarantine.unlink()
        except (FileNotFoundError, OSError, ValueError):
            return

    @staticmethod
    def _normalized_name(info: zipfile.ZipInfo) -> str:
        return info.filename.replace("\\", "/")

    def _factory_image_members(
        self,
        index: _ArchiveIndex,
    ) -> tuple[zipfile.ZipInfo, ...]:
        return tuple(
            info
            for info in index.infos
            if not info.is_dir()
            and re.match(
                r"^image-.+-.+\.zip$",
                PurePosixPath(self._normalized_name(info)).name,
                re.IGNORECASE,
            )
        )

    def _factory_outer_partition_candidates(
        self,
        index: _ArchiveIndex,
    ) -> tuple[tuple[str, zipfile.ZipInfo], ...]:
        candidates: list[tuple[str, zipfile.ZipInfo]] = []
        for info in index.infos:
            if info.is_dir():
                continue
            basename = PurePosixPath(self._normalized_name(info)).name.casefold()
            for partition in ("bootloader", "radio"):
                if basename == f"{partition}.img" or (
                    basename.startswith(f"{partition}-") and basename.endswith(".img")
                ):
                    candidates.append((partition, info))
                    break
        return tuple(candidates)

    @staticmethod
    def _empty_inspection(path: object) -> FirmwareInspection:
        return FirmwareInspection(
            path=str(path),
            kind=FirmwareKind.CORRUPT,
            code="not_processed",
            message="firmware has not been processed",
        )

    def _success(
        self,
        inspection: FirmwareInspection,
        artifacts: tuple[FileArtifact, ...],
        detected_devices: tuple[str, ...],
        *,
        output_directory: str,
    ) -> FirmwareProcessingResult:
        return FirmwareProcessingResult(
            status=FirmwareProcessingStatus.SUCCESS,
            code=FirmwareProcessingCode.READY,
            message="firmware was verified and its artifacts were registered",
            inspection=inspection,
            firmware=inspection.to_firmware_info(processed=True),
            artifacts=artifacts,
            output_directory=output_directory,
            detected_devices=detected_devices,
            registered=True,
        )

    @staticmethod
    def _failure(
        status: FirmwareProcessingStatus,
        code: FirmwareProcessingCode,
        message: str,
        inspection: FirmwareInspection,
    ) -> FirmwareProcessingResult:
        return FirmwareProcessingResult(
            status=status,
            code=code,
            message=message,
            inspection=inspection,
            firmware=inspection.to_firmware_info(processed=False),
            artifacts=(),
            output_directory="",
            detected_devices=(),
            registered=False,
        )
