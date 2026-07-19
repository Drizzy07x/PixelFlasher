"""Verified backend firmware catalog and download orchestration."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Protocol

from .artifact_downloads import (
    ArtifactCancelledError,
    ArtifactDownloader,
    ArtifactDownloadError,
    ArtifactManifest,
)
from .contracts import JSONValue, ProgressPhase
from .executor import CancellationToken

_DEVICE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_CHANNELS = frozenset({"stable", "beta", "canary"})
_KINDS = frozenset({"factory", "ota"})
_MAXIMUM_ENTRIES = 512

ProgressReporter = Callable[[ProgressPhase, str, int | None], None]


class FirmwareCatalogStatus(StrEnum):
    SUCCESS = "SUCCESS"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class FirmwareCatalogError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class FirmwareCatalogSource:
    device: str
    channel: str
    kind: str
    manifest_document: bytes


class FirmwareManifestCatalog(Protocol):
    def manifests_for(
        self,
        *,
        device: str,
        channel: str,
    ) -> Sequence[FirmwareCatalogSource]: ...


class UnavailableFirmwareManifestCatalog:
    def manifests_for(
        self,
        *,
        device: str,
        channel: str,
    ) -> Sequence[FirmwareCatalogSource]:
        del device, channel
        raise FirmwareCatalogError(
            "firmware_catalog_unavailable",
            "The signed firmware catalog is not provisioned in this build.",
        )


class MappingFirmwareManifestCatalog:
    def __init__(
        self,
        entries: Mapping[tuple[str, str], Sequence[FirmwareCatalogSource]],
    ) -> None:
        prepared: dict[tuple[str, str], tuple[FirmwareCatalogSource, ...]] = {}
        for raw_key, raw_entries in entries.items():
            if not isinstance(raw_key, tuple) or len(raw_key) != 2:
                raise TypeError("firmware catalog keys must be device/channel pairs")
            device = _normalized_device(raw_key[0])
            channel = _normalized_channel(raw_key[1])
            values = tuple(raw_entries)
            if len(values) > _MAXIMUM_ENTRIES:
                raise ValueError("firmware catalog contains too many entries")
            if any(not isinstance(item, FirmwareCatalogSource) for item in values):
                raise TypeError("firmware catalog entries must be FirmwareCatalogSource values")
            prepared[(device, channel)] = values
        self._entries = MappingProxyType(prepared)

    def manifests_for(
        self,
        *,
        device: str,
        channel: str,
    ) -> Sequence[FirmwareCatalogSource]:
        return self._entries.get(
            (_normalized_device(device), _normalized_channel(channel)),
            (),
        )


@dataclass(frozen=True, slots=True)
class FirmwareCatalogEntry:
    artifact_id: str
    device: str
    channel: str
    kind: str
    version: str
    sha256: str
    size: int
    license: str
    provenance: str

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "artifactId": self.artifact_id,
            "device": self.device,
            "channel": self.channel,
            "kind": self.kind,
            "version": self.version,
            "sha256": self.sha256,
            "size": self.size,
            "license": self.license,
            "provenance": self.provenance,
        }


@dataclass(frozen=True, slots=True)
class _ResolvedEntry:
    public: FirmwareCatalogEntry
    document: bytes


@dataclass(frozen=True, slots=True)
class FirmwareCatalogResult:
    status: FirmwareCatalogStatus
    code: str
    message: str
    entries: tuple[FirmwareCatalogEntry, ...] = ()

    @property
    def ok(self) -> bool:
        return self.status is FirmwareCatalogStatus.SUCCESS

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "count": len(self.entries),
            "entries": [entry.to_public_dict() for entry in self.entries],
        }


@dataclass(frozen=True, slots=True)
class FirmwareDownloadResult:
    status: FirmwareCatalogStatus
    code: str
    message: str
    entry: FirmwareCatalogEntry | None = None
    path: Path | None = None
    cache_hit: bool = False
    resumed: bool = False

    @property
    def ok(self) -> bool:
        return (
            self.status is FirmwareCatalogStatus.SUCCESS
            and self.entry is not None
            and self.path is not None
        )


class FirmwareCatalogService:
    """Own verified manifests and never expose their URLs to the browser."""

    def __init__(
        self,
        *,
        cache_directory: str | Path,
        catalog: FirmwareManifestCatalog | None = None,
        downloader: ArtifactDownloader | None = None,
    ) -> None:
        self.cache_directory = Path(cache_directory)
        self.catalog = catalog or UnavailableFirmwareManifestCatalog()
        self.downloader = downloader
        self._entries: Mapping[str, _ResolvedEntry] = MappingProxyType({})

    def refresh(
        self,
        *,
        device: str,
        channel: str,
        cancellation: CancellationToken,
    ) -> FirmwareCatalogResult:
        # A failed or cancelled refresh must not leave a previously scoped
        # catalog downloadable under stale browser IDs.
        self._entries = MappingProxyType({})
        try:
            normalized_device = _normalized_device(device)
            normalized_channel = _normalized_channel(channel)
            if cancellation.cancelled:
                return _cancelled("firmware_catalog_cancelled")
            if self.downloader is None:
                raise FirmwareCatalogError(
                    "firmware_catalog_verifier_unavailable",
                    "The signed firmware catalog verifier is unavailable.",
                )
            sources = tuple(
                self.catalog.manifests_for(
                    device=normalized_device,
                    channel=normalized_channel,
                )
            )
            if len(sources) > _MAXIMUM_ENTRIES:
                raise FirmwareCatalogError(
                    "firmware_catalog_too_large",
                    "The firmware catalog exceeds its entry limit.",
                )
            resolved: dict[str, _ResolvedEntry] = {}
            for source in sources:
                if cancellation.cancelled:
                    return _cancelled("firmware_catalog_cancelled")
                entry = self._verify_source(
                    source,
                    device=normalized_device,
                    channel=normalized_channel,
                )
                if entry.public.artifact_id in resolved:
                    raise FirmwareCatalogError(
                        "firmware_catalog_duplicate",
                        "The firmware catalog contains a duplicate artifact.",
                    )
                resolved[entry.public.artifact_id] = entry
            self._entries = MappingProxyType(resolved)
            entries = tuple(
                sorted(
                    (entry.public for entry in resolved.values()),
                    key=lambda item: (item.kind, item.version, item.artifact_id),
                    reverse=True,
                )
            )
            return FirmwareCatalogResult(
                FirmwareCatalogStatus.SUCCESS,
                "firmware_catalog_refreshed",
                f"Loaded {len(entries)} verified firmware artifact(s).",
                entries,
            )
        except (ArtifactDownloadError, FirmwareCatalogError) as error:
            return FirmwareCatalogResult(
                FirmwareCatalogStatus.FAILED,
                error.code,
                str(error),
            )
        except (OSError, TypeError, ValueError):
            return FirmwareCatalogResult(
                FirmwareCatalogStatus.FAILED,
                "firmware_catalog_invalid",
                "The firmware catalog is invalid.",
            )

    def download(
        self,
        artifact_id: str,
        *,
        cancellation: CancellationToken,
        progress: ProgressReporter | None = None,
    ) -> FirmwareDownloadResult:
        if not isinstance(artifact_id, str) or not re.fullmatch(r"[0-9a-f]{32}", artifact_id):
            return FirmwareDownloadResult(
                FirmwareCatalogStatus.FAILED,
                "firmware_artifact_id_invalid",
                "The firmware artifact ID is invalid.",
            )
        resolved = self._entries.get(artifact_id)
        if resolved is None:
            return FirmwareDownloadResult(
                FirmwareCatalogStatus.FAILED,
                "firmware_artifact_unknown",
                "Refresh the firmware catalog before downloading this artifact.",
            )
        if self.downloader is None:
            return FirmwareDownloadResult(
                FirmwareCatalogStatus.FAILED,
                "firmware_downloader_unavailable",
                "Firmware downloads are unavailable in this build.",
            )
        if cancellation.cancelled:
            return FirmwareDownloadResult(
                FirmwareCatalogStatus.CANCELLED,
                "firmware_download_cancelled",
                "Firmware download was cancelled.",
            )
        try:
            self._progress(progress, ProgressPhase.STARTED, "Downloading verified firmware.", 0)
            cache = self.cache_directory.resolve(strict=False)
            cache.mkdir(parents=True, exist_ok=True)
            destination = cache / f"{resolved.public.sha256}.zip"
            downloaded = self.downloader.download(
                resolved.document,
                destination,
                expected_platform="android",
                expected_arch=resolved.public.device,
                cancelled=lambda: cancellation.cancelled,
            )
            if cancellation.cancelled:
                return FirmwareDownloadResult(
                    FirmwareCatalogStatus.CANCELLED,
                    "firmware_download_cancelled",
                    "Firmware download was cancelled.",
                )
            self._progress(progress, ProgressPhase.COMPLETED, "Firmware download verified.", 100)
            return FirmwareDownloadResult(
                FirmwareCatalogStatus.SUCCESS,
                "firmware_download_verified",
                "Firmware was downloaded and verified.",
                resolved.public,
                Path(downloaded.path),
                downloaded.cache_hit,
                downloaded.resumed,
            )
        except ArtifactCancelledError:
            self._progress(progress, ProgressPhase.CANCELLED, "Firmware download cancelled.", None)
            return FirmwareDownloadResult(
                FirmwareCatalogStatus.CANCELLED,
                "firmware_download_cancelled",
                "Firmware download was cancelled.",
            )
        except (ArtifactDownloadError, OSError) as error:
            self._progress(progress, ProgressPhase.FAILED, "Firmware download failed.", None)
            return FirmwareDownloadResult(
                FirmwareCatalogStatus.FAILED,
                error.code if isinstance(error, ArtifactDownloadError) else "firmware_download_failed",
                str(error) if isinstance(error, ArtifactDownloadError) else "Firmware download failed.",
            )

    def _verify_source(
        self,
        source: FirmwareCatalogSource,
        *,
        device: str,
        channel: str,
    ) -> _ResolvedEntry:
        if not isinstance(source, FirmwareCatalogSource):
            raise FirmwareCatalogError("firmware_catalog_invalid", "Catalog entry type is invalid.")
        if _normalized_device(source.device) != device or _normalized_channel(source.channel) != channel:
            raise FirmwareCatalogError("firmware_catalog_scope_mismatch", "Catalog entry scope is invalid.")
        kind = source.kind.strip().casefold() if isinstance(source.kind, str) else ""
        if kind not in _KINDS:
            raise FirmwareCatalogError("firmware_catalog_kind_invalid", "Catalog firmware kind is invalid.")
        if not isinstance(source.manifest_document, bytes) or not source.manifest_document:
            raise FirmwareCatalogError("firmware_catalog_manifest_invalid", "Catalog manifest is invalid.")
        assert self.downloader is not None
        manifest: ArtifactManifest = self.downloader.verifier.verify(
            source.manifest_document,
            expected_platform="android",
            expected_arch=device,
        )
        artifact_id = hashlib.sha256(
            b"pixelflasher-firmware-catalog-v1\0" + source.manifest_document
        ).hexdigest()[:32]
        public = FirmwareCatalogEntry(
            artifact_id,
            device,
            channel,
            kind,
            manifest.version,
            manifest.sha256,
            manifest.size,
            manifest.license,
            manifest.provenance,
        )
        return _ResolvedEntry(public, bytes(source.manifest_document))

    @staticmethod
    def _progress(
        reporter: ProgressReporter | None,
        phase: ProgressPhase,
        message: str,
        percent: int | None,
    ) -> None:
        if reporter is None:
            return
        try:
            reporter(phase, message, percent)
        except Exception:
            pass


def _normalized_device(value: object) -> str:
    if not isinstance(value, str) or _DEVICE.fullmatch(value.strip().casefold()) is None:
        raise FirmwareCatalogError("firmware_catalog_device_invalid", "Firmware device is invalid.")
    return value.strip().casefold()


def _normalized_channel(value: object) -> str:
    normalized = value.strip().casefold() if isinstance(value, str) else ""
    if normalized not in _CHANNELS:
        raise FirmwareCatalogError("firmware_catalog_channel_invalid", "Firmware channel is invalid.")
    return normalized


def _cancelled(code: str) -> FirmwareCatalogResult:
    return FirmwareCatalogResult(
        FirmwareCatalogStatus.CANCELLED,
        code,
        "Firmware catalog refresh was cancelled.",
    )


__all__ = [
    "FirmwareCatalogEntry",
    "FirmwareCatalogError",
    "FirmwareCatalogResult",
    "FirmwareCatalogService",
    "FirmwareCatalogSource",
    "FirmwareCatalogStatus",
    "FirmwareDownloadResult",
    "FirmwareManifestCatalog",
    "MappingFirmwareManifestCatalog",
    "UnavailableFirmwareManifestCatalog",
]
