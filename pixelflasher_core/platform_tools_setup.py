"""Backend-only orchestration for local or signed Platform Tools setup."""

from __future__ import annotations

import platform as host_platform
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast

from .artifact_downloads import ArtifactDownloader, ArtifactDownloadError
from .contracts import JSONValue, ProgressPhase, ToolchainInfo
from .executor import CancellationToken
from .platform_tools import (
    PlatformToolsError,
    PlatformToolsInstallation,
    PlatformToolsInstaller,
    PlatformToolsStatus,
    architecture_key,
    platform_key,
    validate_platform_tools_directory,
)
from .toolchain import ToolchainService

ProgressReporter = Callable[[ProgressPhase, str, int | None], None]


class PlatformToolsCatalogError(RuntimeError):
    """A signed manifest is unavailable for the requested host target."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class PlatformToolsManifestCatalog(Protocol):
    def manifest_for(self, *, platform: str, architecture: str) -> bytes: ...


class UnavailablePlatformToolsManifestCatalog:
    """Fail-closed default until release engineering provisions signed manifests."""

    def manifest_for(self, *, platform: str, architecture: str) -> bytes:
        del platform, architecture
        raise PlatformToolsCatalogError(
            "platform_tools_catalog_unavailable",
            "Official Platform Tools are not provisioned in this build.",
        )


class MappingPlatformToolsManifestCatalog:
    """Immutable target-to-manifest catalog suitable for packaged resources."""

    def __init__(self, manifests: Mapping[tuple[str, str], bytes]) -> None:
        prepared: dict[tuple[str, str], bytes] = {}
        for raw_target, raw_document in manifests.items():
            if not isinstance(raw_target, tuple) or len(raw_target) != 2:
                raise TypeError("manifest catalog targets must be platform/architecture pairs")
            target_platform = platform_key(raw_target[0])
            target_arch = architecture_key(raw_target[1])
            if not isinstance(raw_document, bytes) or not raw_document:
                raise TypeError("manifest catalog documents must be non-empty bytes")
            key = (target_platform, target_arch)
            if key in prepared:
                raise ValueError("manifest catalog contains a duplicate normalized target")
            prepared[key] = bytes(raw_document)
        self._manifests = MappingProxyType(prepared)

    def manifest_for(self, *, platform: str, architecture: str) -> bytes:
        key = (platform_key(platform), architecture_key(architecture))
        document = self._manifests.get(key)
        if document is None:
            raise PlatformToolsCatalogError(
                "platform_tools_target_unavailable",
                "Official Platform Tools are unavailable for this host target.",
            )
        return document


@dataclass(frozen=True, slots=True)
class PlatformToolsSetupResult:
    status: PlatformToolsStatus
    code: str
    message: str
    source: str
    toolchain: ToolchainInfo | None = None
    installation: PlatformToolsInstallation | None = None

    @property
    def ok(self) -> bool:
        return self.status is PlatformToolsStatus.SUCCESS and self.toolchain is not None

    def to_public_dict(self) -> dict[str, JSONValue]:
        installation = (
            cast(dict[str, JSONValue], self.installation.to_public_dict())
            if self.installation is not None
            else None
        )
        return {
            "source": self.source,
            "ready": self.ok,
            "version": self.toolchain.version if self.toolchain is not None else "",
            "installation": installation,
        }


class PlatformToolsSetupService:
    """Validate a granted directory or install one authenticated official build.

    The service never owns browser input paths. A trusted native grant resolver
    must turn a directory grant into ``directory`` before this API is called.
    Official network access is possible only when both a signed catalog and a
    downloader with pinned Ed25519 keys are injected by ``ApplicationRuntime``.
    """

    def __init__(
        self,
        toolchain_service: ToolchainService,
        *,
        cache_directory: str | Path,
        install_directory: str | Path,
        catalog: PlatformToolsManifestCatalog | None = None,
        downloader: ArtifactDownloader | None = None,
        installer: PlatformToolsInstaller | None = None,
        platform: str | None = None,
        architecture: str | None = None,
    ) -> None:
        if not isinstance(toolchain_service, ToolchainService):
            raise TypeError("toolchain_service must be a ToolchainService")
        self.toolchain_service = toolchain_service
        self.cache_directory = Path(cache_directory)
        self.install_directory = Path(install_directory)
        self.catalog = catalog or UnavailablePlatformToolsManifestCatalog()
        self.downloader = downloader
        self.installer = installer or PlatformToolsInstaller()
        self.platform = platform if platform is not None else sys.platform
        self.architecture = (
            architecture if architecture is not None else host_platform.machine()
        )

    def setup(
        self,
        *,
        source: str,
        directory: str | Path | None,
        cancellation: CancellationToken,
        progress: ProgressReporter | None = None,
    ) -> PlatformToolsSetupResult:
        if not isinstance(cancellation, CancellationToken):
            raise TypeError("cancellation must be a CancellationToken")
        if source == "directory":
            return self._setup_directory(directory, cancellation, progress)
        if source == "official":
            if directory is not None:
                return self._failed(
                    source,
                    "platform_tools_source_ambiguous",
                    "Official setup does not accept a local directory.",
                )
            return self._setup_official(cancellation, progress)
        return self._failed(
            "unknown",
            "platform_tools_source_invalid",
            "Platform Tools source must be official or directory.",
        )

    def _setup_directory(
        self,
        directory: str | Path | None,
        cancellation: CancellationToken,
        progress: ProgressReporter | None,
    ) -> PlatformToolsSetupResult:
        if directory is None or not isinstance(directory, (str, Path)):
            return self._failed(
                "directory",
                "platform_tools_directory_required",
                "Choose a Platform Tools directory.",
            )
        self._progress(progress, ProgressPhase.STARTED, "Validating Platform Tools.", 0)
        if cancellation.cancelled:
            return PlatformToolsSetupResult(
                PlatformToolsStatus.CANCELLED,
                "platform_tools_setup_cancelled",
                "Platform Tools setup was cancelled.",
                "directory",
            )
        try:
            validated = validate_platform_tools_directory(
                Path(directory),
                platform=self.platform,
                expected_arch=self.architecture,
            )
        except (OSError, RuntimeError, ValueError, PlatformToolsError) as error:
            code = (
                error.code
                if isinstance(error, PlatformToolsError)
                else "toolchain_directory_invalid"
            )
            self._progress(progress, ProgressPhase.FAILED, "Validation failed.", None)
            return self._failed(
                "directory",
                code,
                "The selected Platform Tools directory could not be verified.",
            )
        check = self.toolchain_service.discover(
            validated.root,
            cancellation=cancellation,
        )
        if check.code == "cancelled" or cancellation.cancelled:
            self._progress(progress, ProgressPhase.CANCELLED, "Setup cancelled.", None)
            return PlatformToolsSetupResult(
                PlatformToolsStatus.CANCELLED,
                "platform_tools_setup_cancelled",
                "Platform Tools setup was cancelled.",
                "directory",
            )
        if not check.ok:
            self._progress(progress, ProgressPhase.FAILED, "Validation failed.", None)
            return self._failed(
                "directory",
                check.code,
                "The selected Platform Tools directory could not be verified.",
            )
        self._progress(progress, ProgressPhase.COMPLETED, "Platform Tools ready.", 100)
        return PlatformToolsSetupResult(
            PlatformToolsStatus.SUCCESS,
            "toolchain_ready",
            "Platform Tools were verified.",
            "directory",
            check.info,
        )

    def _setup_official(
        self,
        cancellation: CancellationToken,
        progress: ProgressReporter | None,
    ) -> PlatformToolsSetupResult:
        if cancellation.cancelled:
            return PlatformToolsSetupResult(
                PlatformToolsStatus.CANCELLED,
                "platform_tools_setup_cancelled",
                "Platform Tools setup was cancelled.",
                "official",
            )
        self._progress(progress, ProgressPhase.STARTED, "Verifying signed manifest.", 0)
        try:
            target_platform = platform_key(self.platform)
            target_arch = architecture_key(self.architecture)
            document = self.catalog.manifest_for(
                platform=target_platform,
                architecture=target_arch,
            )
            if self.downloader is None:
                raise PlatformToolsCatalogError(
                    "platform_tools_downloader_unavailable",
                    "Official Platform Tools downloads are unavailable in this build.",
                )
            manifest = self.downloader.verifier.verify(
                document,
                expected_platform=target_platform,
                expected_arch=target_arch,
            )
            version_root = self._version_root(manifest.sha256)
        except (PlatformToolsCatalogError, PlatformToolsError, ArtifactDownloadError) as error:
            self._progress(progress, ProgressPhase.FAILED, "Manifest verification failed.", None)
            return self._failed("official", error.code, str(error))
        except (OSError, TypeError, ValueError):
            self._progress(progress, ProgressPhase.FAILED, "Manifest verification failed.", None)
            return self._failed(
                "official",
                "platform_tools_manifest_unavailable",
                "The signed Platform Tools manifest could not be loaded.",
            )

        self._progress(progress, ProgressPhase.RUNNING, "Downloading and installing Platform Tools.", 20)
        installed = self.installer.install_from_manifest(
            document,
            downloader=self.downloader,
            cache_directory=self.cache_directory,
            install_root=version_root,
            expected_platform=target_platform,
            expected_arch=target_arch,
            cancelled=lambda: cancellation.cancelled,
        )
        if installed.status is PlatformToolsStatus.CANCELLED or cancellation.cancelled:
            self._progress(progress, ProgressPhase.CANCELLED, "Setup cancelled.", None)
            return PlatformToolsSetupResult(
                PlatformToolsStatus.CANCELLED,
                installed.code,
                "Platform Tools setup was cancelled.",
                "official",
            )
        if not installed.ok or installed.installation is None:
            self._progress(progress, ProgressPhase.FAILED, "Installation failed.", None)
            return self._failed(
                "official",
                installed.code,
                installed.message,
            )

        self._progress(progress, ProgressPhase.RUNNING, "Confirming installed toolchain.", 90)
        check = self.toolchain_service.discover(
            installed.installation.root,
            cancellation=cancellation,
        )
        if check.code == "cancelled" or cancellation.cancelled:
            self._progress(progress, ProgressPhase.CANCELLED, "Setup cancelled.", None)
            return PlatformToolsSetupResult(
                PlatformToolsStatus.CANCELLED,
                "platform_tools_setup_cancelled",
                "Platform Tools setup was cancelled before activation.",
                "official",
            )
        if not check.ok or check.info.version != manifest.version:
            self._progress(progress, ProgressPhase.FAILED, "Installed version mismatch.", None)
            return self._failed(
                "official",
                (
                    check.code
                    if not check.ok
                    else "toolchain_manifest_version_mismatch"
                ),
                "Installed Platform Tools did not match the signed manifest.",
            )
        self._progress(progress, ProgressPhase.COMPLETED, "Platform Tools ready.", 100)
        return PlatformToolsSetupResult(
            PlatformToolsStatus.SUCCESS,
            "platform_tools_installed",
            "Official Platform Tools were verified and installed.",
            "official",
            check.info,
            installed.installation,
        )

    def _version_root(self, digest: str) -> Path:
        root = self.install_directory.resolve(strict=False)
        versions = root / "versions"
        target = versions / digest
        if target.parent != versions or len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise PlatformToolsError(
                "platform_tools_install_target_invalid",
                "Platform Tools install target is invalid.",
            )
        return target

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

    @staticmethod
    def _failed(source: str, code: str, message: str) -> PlatformToolsSetupResult:
        return PlatformToolsSetupResult(
            PlatformToolsStatus.FAILED,
            code,
            message,
            source,
        )


__all__ = [
    "MappingPlatformToolsManifestCatalog",
    "PlatformToolsCatalogError",
    "PlatformToolsManifestCatalog",
    "PlatformToolsSetupResult",
    "PlatformToolsSetupService",
    "UnavailablePlatformToolsManifestCatalog",
]
