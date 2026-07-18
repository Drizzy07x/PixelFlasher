"""Fail-closed firmware processing and planner artifact registration.

The service in this module never executes archive-provided scripts and never
uses ``ZipFile.extract``.  A firmware package is opened as data, every archive
member is validated and CRC-checked, and only allow-listed ``*.img`` members
are copied to fixed backend-chosen filenames.
"""

from __future__ import annotations

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
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import BinaryIO, Mapping, Sequence

from .contracts import FileArtifact, FirmwareInfo
from .executor import CancellationToken
from .firmware import FirmwareInspection, FirmwareKind
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


class FirmwareProcessingStatus(str, Enum):
    SUCCESS = "SUCCESS"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class FirmwareProcessingCode(str, Enum):
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
    NO_FLASHABLE_ARTIFACTS = "no_flashable_artifacts"
    CUSTOM_PAYLOAD_UNSUPPORTED = "custom_payload_processing_required"
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

    def __post_init__(self) -> None:
        numeric_limits = (
            self.hash_chunk_size,
            self.maximum_archive_bytes,
            self.maximum_entries,
            self.maximum_member_bytes,
            self.maximum_uncompressed_bytes,
            self.metadata_limit_bytes,
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
    normalized_names: Mapping[str, zipfile.ZipInfo] = field(default_factory=dict)

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
        limits: FirmwareArtifactLimits = FirmwareArtifactLimits(),
    ) -> None:
        if not isinstance(repository, ProcessedArtifactRepository):
            raise TypeError("repository must be a ProcessedArtifactRepository")
        self.repository = repository
        self.output_root = Path(output_root).expanduser()
        self.limits = limits

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
                            self._revalidate_source(source, digest, token)
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
                        else:
                            extracted = self._process_custom(
                                archive,
                                outer,
                                staging,
                                token,
                            )
                        if not any(
                            partition in {"init_boot", "boot"}
                            for partition, _image_hash in extracted
                        ):
                            raise _ProcessingFailure(
                                FirmwareProcessingCode.STOCK_BOOT_REQUIRED,
                                (
                                    "processed factory/custom firmware has no verified "
                                    "init_boot or boot image"
                                ),
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
            committed = self._commit_staging(root, staging, inspection, digest)
            staging = None
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
        metadata = (
            self._read_metadata(archive, metadata_members[0])
            if metadata_members
            else {}
        )
        image_archives = self._factory_image_members(index)
        has_flash_script = any(
            PurePosixPath(self._normalized_name(info)).name.casefold()
            in {"flash-all.sh", "flash-all.bat"}
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
            build = metadata.get("post-build-incremental", "") or metadata.get(
                "post-build", ""
            )
            kind = FirmwareKind.OTA
        else:
            device = metadata.get("pre-device", "")
            build = metadata.get("post-build-incremental", "") or metadata.get(
                "post-build", ""
            )
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
        return {
            item.strip().casefold()
            for item in re.split(r"[,|]", value)
            if item.strip()
        }

    def _validate_compatibility(
        self,
        detected_devices: Sequence[str],
        expected_devices: Sequence[str],
    ) -> None:
        if isinstance(expected_devices, str):
            expected_devices = (expected_devices,)
        expected = {
            item.strip().casefold()
            for item in expected_devices
            if isinstance(item, str) and item.strip()
        }
        detected = set(detected_devices)
        if expected and detected and not expected.intersection(detected):
            raise _ProcessingFailure(
                FirmwareProcessingCode.DEVICE_MISMATCH,
                f"firmware targets {sorted(detected)!r}, selected device is {sorted(expected)!r}",
            )

    def _validate_ota_layout(self, index: _ArchiveIndex) -> None:
        names = {
            self._normalized_name(info).casefold()
            for info in index.infos
            if not info.is_dir()
        }
        basenames = {PurePosixPath(name).name for name in names}
        legacy_paths = (
            "meta-inf/com/google/android/update-binary",
            "meta-inf/com/google/android/updater-script",
        )
        legacy_updater = any(
            name == legacy_path or name.endswith(f"/{legacy_path}")
            for name in names
            for legacy_path in legacy_paths
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
        has_payload = any(
            PurePosixPath(self._normalized_name(info)).name.casefold() == "payload.bin"
            for info in index.infos
        )
        if has_payload:
            # Registering only any incidental boot image next to a payload would
            # create a dangerously partial ROM plan.  Payload images require a
            # separate, fully validating typed extractor.
            raise _ProcessingFailure(
                FirmwareProcessingCode.CUSTOM_PAYLOAD_UNSUPPORTED,
                "custom payload.bin requires a typed payload extractor before registration",
            )
        candidates = self._partition_candidates(index)
        if not candidates:
            raise _ProcessingFailure(
                FirmwareProcessingCode.NO_FLASHABLE_ARTIFACTS,
                "custom firmware has no allow-listed partition images",
            )
        return self._extract_partition_images(archive, index, staging, token)

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
            resolved = candidate.resolve(strict=True)
            if resolved == root:
                return
            resolved.relative_to(root)
            if resolved.is_dir():
                shutil.rmtree(resolved)
            elif resolved.is_file():
                resolved.unlink()
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
