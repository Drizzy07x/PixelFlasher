"""Backend-only orchestration for signed Scrcpy setup."""

from __future__ import annotations

import platform as host_platform
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast

from .artifact_downloads import ArtifactDownloader, ArtifactDownloadError
from .contracts import JSONValue, ProgressPhase
from .executor import CancellationToken
from .platform_tools import architecture_key, platform_key
from .scrcpy_artifacts import (
    ScrcpyArtifactError,
    ScrcpyInstallation,
    ScrcpyInstaller,
    ScrcpyStatus,
)

ProgressReporter = Callable[[ProgressPhase, str, int | None], None]


class ScrcpyCatalogError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ScrcpyManifestCatalog(Protocol):
    def manifest_for(self, *, platform: str, architecture: str) -> bytes: ...


class UnavailableScrcpyManifestCatalog:
    def manifest_for(self, *, platform: str, architecture: str) -> bytes:
        del platform, architecture
        raise ScrcpyCatalogError(
            "scrcpy_catalog_unavailable",
            "Official Scrcpy is not provisioned in this build.",
        )


class MappingScrcpyManifestCatalog:
    def __init__(self, manifests: Mapping[tuple[str, str], bytes]) -> None:
        prepared: dict[tuple[str, str], bytes] = {}
        for raw_target, raw_document in manifests.items():
            if not isinstance(raw_target, tuple) or len(raw_target) != 2:
                raise TypeError("Scrcpy catalog targets must be platform/architecture pairs")
            key = (platform_key(raw_target[0]), architecture_key(raw_target[1]))
            if not isinstance(raw_document, bytes) or not raw_document:
                raise TypeError("Scrcpy manifests must be non-empty bytes")
            if key in prepared:
                raise ValueError("Scrcpy catalog contains a duplicate normalized target")
            prepared[key] = bytes(raw_document)
        self._manifests = MappingProxyType(prepared)

    def manifest_for(self, *, platform: str, architecture: str) -> bytes:
        document = self._manifests.get((platform_key(platform), architecture_key(architecture)))
        if document is None:
            raise ScrcpyCatalogError(
                "scrcpy_target_unavailable",
                "Official Scrcpy is unavailable for this host target.",
            )
        return document


@dataclass(frozen=True, slots=True)
class ScrcpySetupResult:
    status: ScrcpyStatus
    code: str
    message: str
    installation: ScrcpyInstallation | None = None

    @property
    def ok(self) -> bool:
        return self.status is ScrcpyStatus.SUCCESS and self.installation is not None

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "ready": self.ok,
            "installation": (
                cast(dict[str, JSONValue], self.installation.to_public_dict())
                if self.installation is not None
                else None
            ),
        }


class ScrcpySetupService:
    """Resolve, authenticate, install, and verify one official Scrcpy build."""

    def __init__(
        self,
        *,
        cache_directory: str | Path,
        install_directory: str | Path,
        catalog: ScrcpyManifestCatalog | None = None,
        downloader: ArtifactDownloader | None = None,
        installer: ScrcpyInstaller | None = None,
        platform: str | None = None,
        architecture: str | None = None,
    ) -> None:
        self.cache_directory = Path(cache_directory)
        self.install_directory = Path(install_directory)
        self.catalog = catalog or UnavailableScrcpyManifestCatalog()
        self.downloader = downloader
        self.installer = installer or ScrcpyInstaller()
        self.platform = platform if platform is not None else sys.platform
        self.architecture = architecture if architecture is not None else host_platform.machine()

    def setup(
        self,
        *,
        cancellation: CancellationToken,
        progress: ProgressReporter | None = None,
    ) -> ScrcpySetupResult:
        if not isinstance(cancellation, CancellationToken):
            raise TypeError("cancellation must be a CancellationToken")
        if cancellation.cancelled:
            return ScrcpySetupResult(
                ScrcpyStatus.CANCELLED,
                "scrcpy_setup_cancelled",
                "Scrcpy setup was cancelled.",
            )
        self._progress(progress, ProgressPhase.STARTED, "Verifying signed Scrcpy manifest.", 0)
        try:
            target_platform = platform_key(self.platform)
            target_arch = architecture_key(self.architecture)
            document = self.catalog.manifest_for(
                platform=target_platform,
                architecture=target_arch,
            )
            if self.downloader is None:
                raise ScrcpyCatalogError(
                    "scrcpy_downloader_unavailable",
                    "Official Scrcpy downloads are unavailable in this build.",
                )
            manifest = self.downloader.verifier.verify(
                document,
                expected_platform=target_platform,
                expected_arch=target_arch,
            )
            install_root = self._version_root(manifest.sha256)
        except (ScrcpyCatalogError, ScrcpyArtifactError, ArtifactDownloadError) as error:
            self._progress(progress, ProgressPhase.FAILED, "Scrcpy manifest verification failed.", None)
            return ScrcpySetupResult(ScrcpyStatus.FAILED, error.code, str(error))
        except (OSError, TypeError, ValueError):
            self._progress(progress, ProgressPhase.FAILED, "Scrcpy manifest verification failed.", None)
            return ScrcpySetupResult(
                ScrcpyStatus.FAILED,
                "scrcpy_manifest_unavailable",
                "The signed Scrcpy manifest could not be loaded.",
            )

        self._progress(progress, ProgressPhase.RUNNING, "Downloading and installing Scrcpy.", 20)
        installed = self.installer.install_from_manifest(
            document,
            downloader=self.downloader,
            cache_directory=self.cache_directory,
            install_root=install_root,
            expected_platform=target_platform,
            expected_arch=target_arch,
            cancelled=lambda: cancellation.cancelled,
        )
        if installed.status is ScrcpyStatus.CANCELLED or cancellation.cancelled:
            self._progress(progress, ProgressPhase.CANCELLED, "Scrcpy setup cancelled.", None)
            return ScrcpySetupResult(
                ScrcpyStatus.CANCELLED,
                installed.code,
                "Scrcpy setup was cancelled.",
            )
        if not installed.ok or installed.installation is None:
            self._progress(progress, ProgressPhase.FAILED, "Scrcpy installation failed.", None)
            return ScrcpySetupResult(
                ScrcpyStatus.FAILED,
                installed.code,
                installed.message,
            )
        self._progress(progress, ProgressPhase.COMPLETED, "Scrcpy ready.", 100)
        return ScrcpySetupResult(
            ScrcpyStatus.SUCCESS,
            "scrcpy_installed",
            "Official Scrcpy was verified and installed.",
            installed.installation,
        )

    def _version_root(self, digest: str) -> Path:
        root = self.install_directory.resolve(strict=False)
        versions = root / "versions"
        target = versions / digest
        if target.parent != versions or len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise ScrcpyArtifactError(
                "scrcpy_install_target_invalid",
                "Scrcpy install target is invalid.",
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


__all__ = [
    "MappingScrcpyManifestCatalog",
    "ScrcpyCatalogError",
    "ScrcpyManifestCatalog",
    "ScrcpySetupResult",
    "ScrcpySetupService",
    "UnavailableScrcpyManifestCatalog",
]
