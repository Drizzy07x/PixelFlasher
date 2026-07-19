"""Verified backend catalog and download orchestration for rooting APKs."""

from __future__ import annotations

import hashlib
import json
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
from .rooting import RootAppInfo, RootAppSource, RootingPlanningError, RootingService

_CHANNELS = frozenset({"stable", "beta", "canary"})
_PROVIDERS = frozenset(
    {
        "magisk",
        "apatch",
        "kernelsu",
        "kernelsu-next",
        "sukisu",
        "wild-ksu",
        "legacy",
    }
)
_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. +()-]{0,63}$")
_PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_ID = re.compile(r"^[0-9a-f]{32}$")
_MAXIMUM_ENTRIES = 64

ProgressReporter = Callable[[ProgressPhase, str, int | None], None]


class RootAppCatalogStatus(StrEnum):
    SUCCESS = "SUCCESS"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class RootAppCatalogError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class RootAppCatalogSource:
    provider: str
    channel: str
    flavor: str
    package_name: str
    signer_sha256: tuple[str, ...]
    manifest_document: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "signer_sha256", tuple(self.signer_sha256))


class RootAppManifestCatalog(Protocol):
    def manifests_for(self, *, channel: str) -> Sequence[RootAppCatalogSource]: ...


class UnavailableRootAppManifestCatalog:
    def manifests_for(self, *, channel: str) -> Sequence[RootAppCatalogSource]:
        del channel
        raise RootAppCatalogError(
            "root_app_catalog_unavailable",
            "The signed root-app catalog is not provisioned in this build.",
        )


class MappingRootAppManifestCatalog:
    def __init__(
        self,
        entries: Mapping[str, Sequence[RootAppCatalogSource]],
    ) -> None:
        prepared: dict[str, tuple[RootAppCatalogSource, ...]] = {}
        for raw_channel, raw_entries in entries.items():
            channel = _normalized_channel(raw_channel)
            values = tuple(raw_entries)
            if len(values) > _MAXIMUM_ENTRIES:
                raise ValueError("root-app catalog contains too many entries")
            if any(not isinstance(item, RootAppCatalogSource) for item in values):
                raise TypeError(
                    "root-app catalog entries must be RootAppCatalogSource values"
                )
            prepared[channel] = values
        self._entries = MappingProxyType(prepared)

    def manifests_for(self, *, channel: str) -> Sequence[RootAppCatalogSource]:
        return self._entries.get(_normalized_channel(channel), ())


@dataclass(frozen=True, slots=True)
class RootAppCatalogEntry:
    artifact_id: str
    provider: str
    channel: str
    flavor: str
    version: str
    architecture: str
    package_name: str
    signer_sha256: tuple[str, ...]
    sha256: str
    size: int
    license: str
    provenance: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "signer_sha256", tuple(self.signer_sha256))

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "artifactId": self.artifact_id,
            "provider": self.provider,
            "channel": self.channel,
            "flavor": self.flavor,
            "version": self.version,
            "architecture": self.architecture,
            "packageName": self.package_name,
            "signerSha256": list(self.signer_sha256),
            "sha256": self.sha256,
            "size": self.size,
            "license": self.license,
            "provenance": self.provenance,
        }


@dataclass(frozen=True, slots=True)
class _ResolvedEntry:
    public: RootAppCatalogEntry
    document: bytes


@dataclass(frozen=True, slots=True)
class RootAppCatalogResult:
    status: RootAppCatalogStatus
    code: str
    message: str
    entries: tuple[RootAppCatalogEntry, ...] = ()

    @property
    def ok(self) -> bool:
        return self.status is RootAppCatalogStatus.SUCCESS

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "count": len(self.entries),
            "entries": [entry.to_public_dict() for entry in self.entries],
        }


@dataclass(frozen=True, slots=True)
class RootAppDownloadResult:
    status: RootAppCatalogStatus
    code: str
    message: str
    entry: RootAppCatalogEntry | None = None
    app: RootAppInfo | None = None
    cache_hit: bool = False
    resumed: bool = False
    previous_sources: tuple[RootAppSource, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "previous_sources", tuple(self.previous_sources))

    @property
    def ok(self) -> bool:
        return (
            self.status is RootAppCatalogStatus.SUCCESS
            and self.entry is not None
            and self.app is not None
        )


class RootAppCatalogService:
    """Verify remote metadata, download APKs, and promote inspected identities."""

    def __init__(
        self,
        *,
        cache_directory: str | Path,
        rooting_service: RootingService,
        catalog: RootAppManifestCatalog | None = None,
        downloader: ArtifactDownloader | None = None,
    ) -> None:
        if not isinstance(rooting_service, RootingService):
            raise TypeError("rooting_service must be a RootingService")
        self.cache_directory = Path(cache_directory)
        self.rooting_service = rooting_service
        self.catalog = catalog or UnavailableRootAppManifestCatalog()
        self.downloader = downloader
        self._entries: Mapping[str, _ResolvedEntry] = MappingProxyType({})

    def refresh(
        self,
        *,
        channel: str,
        cancellation: CancellationToken,
    ) -> RootAppCatalogResult:
        self._entries = MappingProxyType({})
        try:
            normalized_channel = _normalized_channel(channel)
            if cancellation.cancelled:
                return _cancelled("root_app_catalog_cancelled")
            if self.downloader is None:
                raise RootAppCatalogError(
                    "root_app_catalog_verifier_unavailable",
                    "The signed root-app catalog verifier is unavailable.",
                )
            sources = tuple(self.catalog.manifests_for(channel=normalized_channel))
            if len(sources) > _MAXIMUM_ENTRIES:
                raise RootAppCatalogError(
                    "root_app_catalog_too_large",
                    "The root-app catalog exceeds its entry limit.",
                )
            resolved: dict[str, _ResolvedEntry] = {}
            for source in sources:
                if cancellation.cancelled:
                    return _cancelled("root_app_catalog_cancelled")
                entry = self._verify_source(source, channel=normalized_channel)
                if entry.public.artifact_id in resolved:
                    raise RootAppCatalogError(
                        "root_app_catalog_duplicate",
                        "The root-app catalog contains a duplicate artifact.",
                    )
                resolved[entry.public.artifact_id] = entry
            self._entries = MappingProxyType(resolved)
            entries = tuple(
                sorted(
                    (entry.public for entry in resolved.values()),
                    key=lambda item: (
                        _provider_key(item.provider),
                        item.version,
                        item.architecture,
                        item.artifact_id,
                    ),
                )
            )
            return RootAppCatalogResult(
                RootAppCatalogStatus.SUCCESS,
                "root_app_catalog_refreshed",
                f"Loaded {len(entries)} verified root application(s).",
                entries,
            )
        except (ArtifactDownloadError, RootAppCatalogError) as error:
            return RootAppCatalogResult(
                RootAppCatalogStatus.FAILED,
                error.code,
                str(error),
            )
        except (OSError, TypeError, ValueError):
            return RootAppCatalogResult(
                RootAppCatalogStatus.FAILED,
                "root_app_catalog_invalid",
                "The root-app catalog is invalid.",
            )

    def download(
        self,
        artifact_id: str,
        *,
        cancellation: CancellationToken,
        progress: ProgressReporter | None = None,
    ) -> RootAppDownloadResult:
        if not isinstance(artifact_id, str) or _ARTIFACT_ID.fullmatch(artifact_id) is None:
            return RootAppDownloadResult(
                RootAppCatalogStatus.FAILED,
                "root_app_artifact_id_invalid",
                "The root-app artifact ID is invalid.",
            )
        resolved = self._entries.get(artifact_id)
        if resolved is None:
            return RootAppDownloadResult(
                RootAppCatalogStatus.FAILED,
                "root_app_artifact_unknown",
                "Refresh the root-app catalog before downloading this artifact.",
            )
        if self.downloader is None:
            return RootAppDownloadResult(
                RootAppCatalogStatus.FAILED,
                "root_app_downloader_unavailable",
                "Root-app downloads are unavailable in this build.",
            )
        if cancellation.cancelled:
            return _download_cancelled()
        try:
            self._progress(progress, ProgressPhase.STARTED, "Downloading verified root app.", 0)
            cache = self.cache_directory.resolve(strict=False)
            cache.mkdir(parents=True, exist_ok=True)
            destination = cache / f"{resolved.public.sha256}.apk"
            downloaded = self.downloader.download(
                resolved.document,
                destination,
                expected_platform="android",
                expected_arch=resolved.public.architecture,
                cancelled=lambda: cancellation.cancelled,
            )
            if cancellation.cancelled:
                return _download_cancelled()
            previous_sources = self.rooting_service.root_app_sources
            app = self.rooting_service.register_verified_source(
                RootAppSource(
                    path=downloaded.path,
                    provider=resolved.public.provider,
                    flavor=resolved.public.flavor,
                    version=resolved.public.version,
                    provenance="verified-download",
                    expected_sha256=resolved.public.sha256,
                    package_name=resolved.public.package_name,
                    expected_signer_sha256=resolved.public.signer_sha256,
                    architecture=resolved.public.architecture,
                ),
                cancellation,
            )
            self._progress(progress, ProgressPhase.COMPLETED, "Root app verified.", 100)
            return RootAppDownloadResult(
                RootAppCatalogStatus.SUCCESS,
                "root_app_download_verified",
                "Root application was downloaded and verified.",
                resolved.public,
                app,
                downloaded.cache_hit,
                downloaded.resumed,
                previous_sources,
            )
        except ArtifactCancelledError:
            self._progress(progress, ProgressPhase.CANCELLED, "Root-app download cancelled.", None)
            return _download_cancelled()
        except (ArtifactDownloadError, RootingPlanningError, OSError) as error:
            self._progress(progress, ProgressPhase.FAILED, "Root-app download failed.", None)
            typed = isinstance(error, (ArtifactDownloadError, RootingPlanningError))
            return RootAppDownloadResult(
                RootAppCatalogStatus.FAILED,
                error.code if typed else "root_app_download_failed",
                str(error) if typed else "Root-app download failed.",
            )

    def _verify_source(
        self,
        source: RootAppCatalogSource,
        *,
        channel: str,
    ) -> _ResolvedEntry:
        if not isinstance(source, RootAppCatalogSource):
            raise RootAppCatalogError(
                "root_app_catalog_invalid",
                "Catalog entry type is invalid.",
            )
        if _normalized_channel(source.channel) != channel:
            raise RootAppCatalogError(
                "root_app_catalog_scope_mismatch",
                "Catalog entry channel does not match the requested channel.",
            )
        _provider_key(source.provider)
        flavor = _metadata(source.flavor, "flavor")
        package_name = source.package_name.strip()
        if _PACKAGE.fullmatch(package_name) is None:
            raise RootAppCatalogError(
                "root_app_package_name_invalid",
                "Catalog package name is invalid.",
            )
        signers = tuple(signer.strip().casefold() for signer in source.signer_sha256)
        if (
            not signers
            or len(signers) != len(set(signers))
            or any(_SHA256.fullmatch(signer) is None for signer in signers)
        ):
            raise RootAppCatalogError(
                "root_app_signer_invalid",
                "Catalog signer identity is invalid.",
            )
        if not isinstance(source.manifest_document, bytes) or not source.manifest_document:
            raise RootAppCatalogError(
                "root_app_catalog_manifest_invalid",
                "Catalog manifest is invalid.",
            )
        assert self.downloader is not None
        manifest: ArtifactManifest = self.downloader.verifier.verify(
            source.manifest_document,
            expected_platform="android",
        )
        identity = json.dumps(
            {
                "provider": _provider_key(source.provider),
                "channel": channel,
                "flavor": flavor,
                "packageName": package_name,
                "signerSha256": sorted(signers),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        artifact_id = hashlib.sha256(
            b"pixelflasher-root-app-catalog-v1\0"
            + identity
            + b"\0"
            + source.manifest_document
        ).hexdigest()[:32]
        public = RootAppCatalogEntry(
            artifact_id=artifact_id,
            provider=_metadata(source.provider, "provider"),
            channel=channel,
            flavor=flavor,
            version=manifest.version,
            architecture=manifest.arch,
            package_name=package_name,
            signer_sha256=tuple(sorted(signers)),
            sha256=manifest.sha256,
            size=manifest.size,
            license=manifest.license,
            provenance=manifest.provenance,
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


def _normalized_channel(value: object) -> str:
    normalized = value.strip().casefold() if isinstance(value, str) else ""
    if normalized not in _CHANNELS:
        raise RootAppCatalogError(
            "root_app_catalog_channel_invalid",
            "Root-app catalog channel is invalid.",
        )
    return normalized


def _provider_key(value: object) -> str:
    if not isinstance(value, str):
        normalized = ""
    else:
        normalized = value.strip().casefold().replace("_", "-").replace(" ", "-")
        normalized = re.sub(r"-+", "-", normalized)
    aliases = {
        "sukisu-ultra": "sukisu",
        "wild-ksu": "wild-ksu",
        "kernelsu-legacy": "legacy",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in _PROVIDERS:
        raise RootAppCatalogError(
            "root_app_provider_invalid",
            "Root-app provider is not supported.",
        )
    return normalized


def _metadata(value: object, field: str) -> str:
    if not isinstance(value, str) or _TEXT.fullmatch(value.strip()) is None:
        raise RootAppCatalogError(
            f"root_app_{field}_invalid",
            f"Root-app {field} is invalid.",
        )
    return value.strip()


def _cancelled(code: str) -> RootAppCatalogResult:
    return RootAppCatalogResult(
        RootAppCatalogStatus.CANCELLED,
        code,
        "Root-app catalog refresh was cancelled.",
    )


def _download_cancelled() -> RootAppDownloadResult:
    return RootAppDownloadResult(
        RootAppCatalogStatus.CANCELLED,
        "root_app_download_cancelled",
        "Root-app download was cancelled.",
    )


__all__ = [
    "MappingRootAppManifestCatalog",
    "RootAppCatalogEntry",
    "RootAppCatalogError",
    "RootAppCatalogResult",
    "RootAppCatalogService",
    "RootAppCatalogSource",
    "RootAppCatalogStatus",
    "RootAppDownloadResult",
    "RootAppManifestCatalog",
]
