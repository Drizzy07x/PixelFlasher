"""Streaming firmware inspection with archive traversal and device guards."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Mapping, Sequence

from .contracts import FirmwareInfo
from .executor import CancellationToken


class FirmwareKind(str, Enum):
    FACTORY = "factory"
    OTA = "ota"
    CUSTOM = "custom"
    CORRUPT = "corrupt"


@dataclass(frozen=True, slots=True)
class FirmwareInspection:
    path: str
    kind: FirmwareKind
    sha256: str = ""
    build: str = ""
    device: str = ""
    metadata: Mapping[str, str] = field(default_factory=dict)
    code: str = "ok"
    message: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    @property
    def ok(self) -> bool:
        return self.kind is not FirmwareKind.CORRUPT and self.code == "ok"

    def to_firmware_info(self, *, processed: bool) -> FirmwareInfo:
        return FirmwareInfo(
            path=self.path,
            type=self.kind.value,
            build=self.build,
            hash=self.sha256,
            verified=self.ok,
            processed=processed and self.ok,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "type": self.kind.value,
            "sha256": self.sha256,
            "build": self.build,
            "device": self.device,
            "metadata": dict(self.metadata),
            "code": self.code,
            "message": self.message,
            "ok": self.ok,
        }


class FirmwareInspector:
    def __init__(
        self,
        *,
        hash_chunk_size: int = 1024 * 1024,
        metadata_limit_bytes: int = 1024 * 1024,
        maximum_entries: int = 100_000,
        maximum_uncompressed_bytes: int = 64 * 1024 * 1024 * 1024,
    ) -> None:
        if hash_chunk_size <= 0 or metadata_limit_bytes <= 0:
            raise ValueError("hash and metadata limits must be positive")
        if maximum_entries <= 0 or maximum_uncompressed_bytes <= 0:
            raise ValueError("archive limits must be positive")
        self.hash_chunk_size = hash_chunk_size
        self.metadata_limit_bytes = metadata_limit_bytes
        self.maximum_entries = maximum_entries
        self.maximum_uncompressed_bytes = maximum_uncompressed_bytes

    def inspect(
        self,
        path: str | os.PathLike[str],
        *,
        expected_devices: Sequence[str] = (),
        cancellation: CancellationToken | None = None,
    ) -> FirmwareInspection:
        token = cancellation or CancellationToken()
        try:
            candidate = Path(path).expanduser().resolve()
        except (OSError, TypeError, ValueError) as error:
            return FirmwareInspection(
                str(path),
                FirmwareKind.CORRUPT,
                code="invalid_path",
                message=str(error),
            )
        if not candidate.is_file():
            return self._failed(candidate, "file_not_found", "firmware file does not exist")

        try:
            digest = self._sha256(candidate, token)
        except _InspectionCancelled:
            return self._failed(candidate, "firmware_cancelled", "firmware inspection was cancelled")
        except OSError as error:
            return self._failed(candidate, "firmware_read_failed", str(error))

        try:
            with zipfile.ZipFile(candidate) as archive:
                infos = archive.infolist()
                unsafe = self._validate_entries(infos)
                if unsafe:
                    return self._failed(candidate, "unsafe_archive", unsafe, digest)
                corrupt_member = self._verify_entries(archive, infos, token)
                if corrupt_member:
                    return self._failed(
                        candidate,
                        "corrupt_firmware",
                        f"archive member failed validation: {corrupt_member}",
                        digest,
                    )
                inspection = self._classify(candidate, archive, infos, digest)
        except _InspectionCancelled:
            return self._failed(
                candidate,
                "firmware_cancelled",
                "firmware inspection was cancelled",
                digest,
            )
        except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, RuntimeError) as error:
            return self._failed(candidate, "corrupt_firmware", str(error), digest)

        if isinstance(expected_devices, str):
            expected_devices = (expected_devices,)
        expected = {
            item.strip().casefold()
            for item in expected_devices
            if isinstance(item, str) and item.strip()
        }
        detected = _device_names(inspection.device)
        if expected and detected and not expected.intersection(detected):
            return FirmwareInspection(
                path=inspection.path,
                kind=inspection.kind,
                sha256=inspection.sha256,
                build=inspection.build,
                device=inspection.device,
                metadata=inspection.metadata,
                code="device_mismatch",
                message=(
                    f"firmware targets {sorted(detected)!r}, selected device is "
                    f"{sorted(expected)!r}"
                ),
            )
        return inspection

    def _sha256(self, path: Path, token: CancellationToken) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while True:
                if token.cancelled:
                    raise _InspectionCancelled
                chunk = stream.read(self.hash_chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    def _validate_entries(self, infos: list[zipfile.ZipInfo]) -> str:
        if len(infos) > self.maximum_entries:
            return "archive contains too many entries"
        if sum(info.file_size for info in infos) > self.maximum_uncompressed_bytes:
            return "archive expands beyond the configured safety limit"
        for info in infos:
            normalized = info.filename.replace("\\", "/")
            path = PurePosixPath(normalized)
            if (
                not normalized
                or normalized.startswith("/")
                or any(part in {"", ".", ".."} for part in path.parts)
                or (path.parts and ":" in path.parts[0])
            ):
                return f"unsafe archive path: {info.filename!r}"
            file_type = (info.external_attr >> 16) & 0o170000
            if file_type == stat.S_IFLNK:
                return f"symbolic links are not allowed: {info.filename!r}"
        return ""

    def _verify_entries(
        self,
        archive: zipfile.ZipFile,
        infos: list[zipfile.ZipInfo],
        token: CancellationToken,
    ) -> str:
        current = ""
        try:
            for info in infos:
                current = info.filename
                if token.cancelled:
                    raise _InspectionCancelled
                if info.is_dir():
                    continue
                with archive.open(info) as member:
                    while member.read(self.hash_chunk_size):
                        if token.cancelled:
                            raise _InspectionCancelled
        except (zipfile.BadZipFile, RuntimeError, OSError, EOFError):
            return current
        return ""

    def _classify(
        self,
        path: Path,
        archive: zipfile.ZipFile,
        infos: list[zipfile.ZipInfo],
        digest: str,
    ) -> FirmwareInspection:
        names = {info.filename.replace("\\", "/").casefold(): info for info in infos}
        basenames = {PurePosixPath(name).name: info for name, info in names.items()}
        metadata_info = next(
            (
                info
                for name, info in names.items()
                if name == "meta-inf/com/android/metadata"
                or name.endswith("/meta-inf/com/android/metadata")
            ),
            None,
        )
        metadata = self._read_metadata(archive, metadata_info) if metadata_info else {}

        inner_image = next(
            (name for name in basenames if name.startswith("image-") and name.endswith(".zip")),
            "",
        )
        factory = bool(inner_image) and ("flash-all.sh" in basenames or "flash-all.bat" in basenames)
        ota = bool(metadata_info) and bool(
            {"ota-type", "post-build", "post-build-incremental"}.intersection(metadata)
        )

        if factory:
            match = re.match(r"^image-([^-]+)-(.+)\.zip$", inner_image, re.IGNORECASE)
            device = match.group(1) if match else ""
            build = match.group(2) if match else ""
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
            str(path),
            kind,
            digest,
            build,
            device,
            metadata,
        )

    def _read_metadata(
        self,
        archive: zipfile.ZipFile,
        info: zipfile.ZipInfo,
    ) -> dict[str, str]:
        if info.file_size > self.metadata_limit_bytes:
            raise RuntimeError("firmware metadata exceeds the safety limit")
        raw = archive.read(info)
        text = raw.decode("utf-8", errors="replace")
        metadata: dict[str, str] = {}
        for line in text.splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip():
                metadata[key.strip()] = value.strip()
        return metadata

    @staticmethod
    def _failed(
        path: Path,
        code: str,
        message: str,
        digest: str = "",
    ) -> FirmwareInspection:
        return FirmwareInspection(
            str(path),
            FirmwareKind.CORRUPT,
            digest,
            code=code,
            message=message,
        )


class _InspectionCancelled(Exception):
    pass


def _device_names(value: str) -> set[str]:
    return {
        item.strip().casefold()
        for item in re.split(r"[,|]", value)
        if item.strip()
    }
