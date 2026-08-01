"""Authenticated, atomic Scrcpy artifact installation for the modern runtime."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import uuid
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Protocol

from .artifact_downloads import (
    ArtifactCancelledError,
    ArtifactDownloader,
    ArtifactDownloadError,
)
from .platform_tools import (
    PlatformToolsError,
    architecture_key,
    binary_architecture_is_compatible,
    binary_architectures,
    platform_key,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?(?:[-+][A-Za-z0-9.-]+)?$")
# Scrcpy prints its banner as "scrcpy <version> <https://github.com/...>", so the
# version must stay anchored to the start of a line without anchoring its tail.
_SCRCPY_VERSION = re.compile(r"(?im)^scrcpy\s+(\d+)\.(\d+)(?:\.(\d+))?(?:[-+][A-Za-z0-9.-]+)?\b")
_METADATA_NAME = ".pixelflasher-scrcpy.json"


class ScrcpyStatus(StrEnum):
    SUCCESS = "SUCCESS"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class ScrcpyArtifactError(RuntimeError):
    """Stable fail-closed Scrcpy artifact error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ScrcpyLimits:
    maximum_archive_bytes: int = 512 * 1024 * 1024
    maximum_entries: int = 4096
    maximum_entry_bytes: int = 256 * 1024 * 1024
    maximum_extracted_bytes: int = 2 * 1024 * 1024 * 1024
    maximum_compression_ratio: int = 300

    def __post_init__(self) -> None:
        if any(
            value <= 0
            for value in (
                self.maximum_archive_bytes,
                self.maximum_entries,
                self.maximum_entry_bytes,
                self.maximum_extracted_bytes,
                self.maximum_compression_ratio,
            )
        ):
            raise ValueError("Scrcpy archive limits must be positive")


@dataclass(frozen=True, slots=True)
class ScrcpyInstallation:
    root: Path
    executable: Path
    archive_sha256: str
    archive_size: int
    version: str
    platform: str
    architecture: str
    license: str
    provenance: str

    def to_public_dict(self) -> dict[str, object]:
        return {
            "installed": True,
            "version": self.version,
            "platform": self.platform,
            "architecture": self.architecture,
            "license": self.license,
            "provenance": self.provenance,
            "archiveSha256": self.archive_sha256,
            "archiveSize": self.archive_size,
        }


@dataclass(frozen=True, slots=True)
class ScrcpyInstallResult:
    status: ScrcpyStatus
    code: str
    message: str
    installation: ScrcpyInstallation | None = None

    @property
    def ok(self) -> bool:
        return self.status is ScrcpyStatus.SUCCESS and self.installation is not None


@dataclass(frozen=True, slots=True)
class ScrcpyProbeResult:
    status: ScrcpyStatus
    code: str
    message: str
    version: str = ""

    @property
    def ok(self) -> bool:
        return self.status is ScrcpyStatus.SUCCESS


class CompletedProcessLike(Protocol):
    returncode: int
    stdout: str
    stderr: str


class ProbeRunner(Protocol):
    def __call__(self, argv: tuple[str, ...], timeout: float) -> CompletedProcessLike: ...


def _default_probe_runner(argv: tuple[str, ...], timeout: float) -> CompletedProcessLike:
    return subprocess.run(
        list(argv),
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _normalized_version(value: str) -> str:
    matched = _VERSION.fullmatch(value)
    if matched is None:
        raise ScrcpyArtifactError(
            "scrcpy_manifest_version_invalid",
            "Scrcpy manifest version is not semantic",
        )
    major, minor, patch = matched.groups()
    return f"{major}.{minor}.{patch or '0'}"


def probe_scrcpy(
    executable: Path,
    *,
    runner: ProbeRunner | None = None,
    timeout: float = 10.0,
) -> ScrcpyProbeResult:
    if timeout <= 0 or timeout > 60:
        raise ValueError("Scrcpy probe timeout must be between zero and sixty seconds")
    try:
        completed = (runner or _default_probe_runner)(
            (str(executable), "--version"),
            timeout,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return ScrcpyProbeResult(
            ScrcpyStatus.FAILED,
            "scrcpy_probe_failed",
            "Scrcpy version probe failed",
        )
    if completed.returncode != 0:
        return ScrcpyProbeResult(
            ScrcpyStatus.FAILED,
            "scrcpy_probe_failed",
            "Scrcpy version probe returned a failure status",
        )
    matched = _SCRCPY_VERSION.search(f"{completed.stdout}\n{completed.stderr}")
    if matched is None:
        return ScrcpyProbeResult(
            ScrcpyStatus.FAILED,
            "scrcpy_version_unverified",
            "Scrcpy did not provide recognizable version evidence",
        )
    version = ".".join((matched.group(1), matched.group(2), matched.group(3) or "0"))
    return ScrcpyProbeResult(
        ScrcpyStatus.SUCCESS,
        "scrcpy_version_verified",
        "Scrcpy version was verified",
        version,
    )


class ScrcpyInstaller:
    """Install one signed Scrcpy archive without exposing partial contents."""

    def __init__(
        self,
        *,
        limits: ScrcpyLimits | None = None,
        probe_runner: ProbeRunner | None = None,
        probe_timeout: float = 10.0,
    ) -> None:
        if probe_timeout <= 0 or probe_timeout > 60:
            raise ValueError("Scrcpy probe timeout must be between zero and sixty seconds")
        self.limits = limits or ScrcpyLimits()
        self.probe_runner = probe_runner or _default_probe_runner
        self.probe_timeout = probe_timeout

    def install_from_manifest(
        self,
        manifest_document: str | bytes,
        *,
        downloader: ArtifactDownloader,
        cache_directory: Path,
        install_root: Path,
        expected_platform: str,
        expected_arch: str,
        cancelled: Callable[[], bool] | None = None,
    ) -> ScrcpyInstallResult:
        try:
            target_platform = platform_key(expected_platform)
            target_arch = architecture_key(expected_arch)
            manifest = downloader.verifier.verify(
                manifest_document,
                expected_platform=target_platform,
                expected_arch=target_arch,
            )
            cache_root = cache_directory.resolve()
            cache_root.mkdir(parents=True, exist_ok=True)
            archive = cache_root / f"scrcpy-{manifest.sha256}.archive"
            downloaded = downloader.download(
                manifest_document,
                archive,
                expected_platform=target_platform,
                expected_arch=target_arch,
                cancelled=cancelled,
            )
        except ArtifactCancelledError as error:
            return ScrcpyInstallResult(ScrcpyStatus.CANCELLED, error.code, str(error))
        except (ArtifactDownloadError, ScrcpyArtifactError) as error:
            return ScrcpyInstallResult(ScrcpyStatus.FAILED, error.code, str(error))
        except (OSError, TypeError, ValueError):
            return ScrcpyInstallResult(
                ScrcpyStatus.FAILED,
                "scrcpy_download_failed",
                "Scrcpy download failed",
            )
        return self.install_archive(
            Path(downloaded.path),
            install_root=install_root,
            expected_sha256=downloaded.sha256,
            expected_size=downloaded.size,
            expected_version=manifest.version,
            platform=target_platform,
            expected_arch=target_arch,
            license_value=manifest.license,
            provenance=manifest.provenance,
            cancelled=cancelled,
        )

    def install_archive(
        self,
        archive_path: Path,
        *,
        install_root: Path,
        expected_sha256: str,
        expected_size: int,
        expected_version: str,
        platform: str,
        expected_arch: str,
        license_value: str,
        provenance: str,
        cancelled: Callable[[], bool] | None = None,
    ) -> ScrcpyInstallResult:
        is_cancelled = cancelled or (lambda: False)
        staging: Path | None = None
        try:
            archive, digest, size = self._validate_archive(
                archive_path,
                expected_sha256=expected_sha256,
                expected_size=expected_size,
            )
            if is_cancelled():
                return ScrcpyInstallResult(
                    ScrcpyStatus.CANCELLED,
                    "cancelled_before_mutation",
                    "Scrcpy installation was cancelled before activation",
                )
            target_platform = platform_key(platform)
            target_arch = architecture_key(expected_arch)
            expected = _normalized_version(expected_version)
            root = install_root.resolve(strict=False)
            root.mkdir(parents=True, exist_ok=True)
            if root.is_symlink() or not root.is_dir():
                raise ScrcpyArtifactError(
                    "scrcpy_install_root_invalid",
                    "Scrcpy install root is invalid",
                )
            staging = root / f".scrcpy-{uuid.uuid4().hex}.staging"
            staging.mkdir(mode=0o700)
            self._extract(archive, staging, cancelled=is_cancelled)
            executable = self._locate_executable(staging, target_platform)
            try:
                observed_arches = binary_architectures(executable, platform=target_platform)
            except PlatformToolsError as error:
                raise ScrcpyArtifactError(
                    "scrcpy_binary_unreadable",
                    "Scrcpy executable header could not be read",
                ) from error
            if not observed_arches:
                raise ScrcpyArtifactError(
                    "scrcpy_binary_format_invalid",
                    "Scrcpy executable format could not be verified",
                )
            if not binary_architecture_is_compatible(
                platform=target_platform,
                requested_arch=target_arch,
                observed_arches=observed_arches,
            ):
                raise ScrcpyArtifactError(
                    "scrcpy_arch_mismatch",
                    "Scrcpy executable architecture does not match its manifest",
                )
            if target_platform != "windows":
                executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            probe = probe_scrcpy(
                executable,
                runner=self.probe_runner,
                timeout=self.probe_timeout,
            )
            if not probe.ok or probe.version != expected:
                raise ScrcpyArtifactError(
                    probe.code if not probe.ok else "scrcpy_manifest_version_mismatch",
                    "Scrcpy executable does not match its signed manifest",
                )
            relative_executable = executable.relative_to(staging)
            self._write_metadata(
                staging,
                {
                    "schemaVersion": 1,
                    "archiveSha256": digest,
                    "archiveSize": size,
                    "version": expected,
                    "platform": target_platform,
                    "architecture": target_arch,
                    "license": license_value,
                    "provenance": provenance,
                    "executable": relative_executable.as_posix(),
                },
            )
            if is_cancelled():
                return ScrcpyInstallResult(
                    ScrcpyStatus.CANCELLED,
                    "cancelled_before_mutation",
                    "Scrcpy installation was cancelled before activation",
                )
            target = self._activate(root, staging)
            staging = None
            installed_executable = target.joinpath(*relative_executable.parts)
            return ScrcpyInstallResult(
                ScrcpyStatus.SUCCESS,
                "scrcpy_installed",
                "Scrcpy was verified and installed",
                ScrcpyInstallation(
                    target,
                    installed_executable,
                    digest,
                    size,
                    expected,
                    target_platform,
                    target_arch,
                    license_value,
                    provenance,
                ),
            )
        except (OSError, tarfile.TarError, zipfile.BadZipFile, ScrcpyArtifactError) as error:
            code = error.code if isinstance(error, ScrcpyArtifactError) else "scrcpy_install_failed"
            if code == "cancelled_before_mutation":
                return ScrcpyInstallResult(
                    ScrcpyStatus.CANCELLED,
                    code,
                    str(error),
                )
            return ScrcpyInstallResult(
                ScrcpyStatus.FAILED,
                code,
                str(error) if isinstance(error, ScrcpyArtifactError) else "Scrcpy installation failed",
            )
        finally:
            if staging is not None and staging.exists():
                shutil.rmtree(staging, ignore_errors=True)

    def _validate_archive(
        self,
        path: Path,
        *,
        expected_sha256: str,
        expected_size: int,
    ) -> tuple[Path, str, int]:
        if _SHA256.fullmatch(expected_sha256) is None:
            raise ScrcpyArtifactError("scrcpy_hash_invalid", "Expected Scrcpy SHA-256 is invalid")
        try:
            archive = path.resolve(strict=True)
        except OSError as error:
            raise ScrcpyArtifactError("scrcpy_archive_missing", "Scrcpy archive is missing") from error
        if path.is_symlink() or not archive.is_file():
            raise ScrcpyArtifactError("scrcpy_archive_invalid", "Scrcpy archive must be a regular file")
        size = archive.stat().st_size
        if size <= 0 or size > self.limits.maximum_archive_bytes:
            raise ScrcpyArtifactError("scrcpy_archive_size_invalid", "Scrcpy archive size is outside policy")
        if size != expected_size:
            raise ScrcpyArtifactError("scrcpy_archive_size_mismatch", "Scrcpy archive size does not match its manifest")
        hasher = hashlib.sha256()
        with archive.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(block)
        digest = hasher.hexdigest()
        if digest != expected_sha256:
            raise ScrcpyArtifactError("scrcpy_archive_hash_mismatch", "Scrcpy archive hash does not match its manifest")
        return archive, digest, size

    def _extract(
        self,
        archive: Path,
        destination: Path,
        *,
        cancelled: Callable[[], bool],
    ) -> None:
        if zipfile.is_zipfile(archive):
            self._extract_zip(archive, destination, cancelled=cancelled)
            return
        if tarfile.is_tarfile(archive):
            self._extract_tar(archive, destination, cancelled=cancelled)
            return
        raise ScrcpyArtifactError(
            "scrcpy_archive_format_invalid",
            "Scrcpy archive must be ZIP or TAR",
        )

    def _safe_member(self, raw_name: str) -> PurePosixPath:
        if not raw_name or "\\" in raw_name or "\x00" in raw_name:
            raise ScrcpyArtifactError("scrcpy_archive_entry_invalid", "Scrcpy archive entry is invalid")
        path = PurePosixPath(raw_name)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ScrcpyArtifactError("scrcpy_archive_traversal", "Scrcpy archive contains an unsafe path")
        return path

    def _validate_entry_sizes(self, sizes: list[tuple[int, int]]) -> None:
        if len(sizes) > self.limits.maximum_entries:
            raise ScrcpyArtifactError("scrcpy_archive_entries_exceeded", "Scrcpy archive contains too many entries")
        total = 0
        for expanded, compressed in sizes:
            if expanded < 0 or expanded > self.limits.maximum_entry_bytes:
                raise ScrcpyArtifactError("scrcpy_archive_entry_too_large", "Scrcpy archive entry exceeds policy")
            total += expanded
            if total > self.limits.maximum_extracted_bytes:
                raise ScrcpyArtifactError("scrcpy_archive_expansion_exceeded", "Scrcpy archive expands beyond policy")
            if expanded and compressed == 0:
                raise ScrcpyArtifactError("scrcpy_archive_ratio_exceeded", "Scrcpy archive compression ratio exceeds policy")
            if compressed and expanded > compressed * self.limits.maximum_compression_ratio:
                raise ScrcpyArtifactError("scrcpy_archive_ratio_exceeded", "Scrcpy archive compression ratio exceeds policy")

    def _extract_zip(self, archive: Path, destination: Path, *, cancelled: Callable[[], bool]) -> None:
        with zipfile.ZipFile(archive) as source:
            infos = source.infolist()
            self._validate_entry_sizes([(item.file_size, item.compress_size) for item in infos])
            for item in infos:
                if cancelled():
                    raise ScrcpyArtifactError("cancelled_before_mutation", "Scrcpy installation was cancelled")
                relative = self._safe_member(item.filename.rstrip("/"))
                mode = item.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ScrcpyArtifactError("scrcpy_archive_link_forbidden", "Scrcpy archive links are forbidden")
                entry_type = stat.S_IFMT(mode)
                if entry_type and not item.is_dir() and entry_type != stat.S_IFREG:
                    raise ScrcpyArtifactError(
                        "scrcpy_archive_link_forbidden",
                        "Scrcpy archive special entries are forbidden",
                    )
                target = destination.joinpath(*relative.parts)
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open(item) as reader, target.open("xb") as writer:
                    shutil.copyfileobj(reader, writer, length=1024 * 1024)

    def _extract_tar(self, archive: Path, destination: Path, *, cancelled: Callable[[], bool]) -> None:
        with tarfile.open(archive, mode="r:*") as source:
            members = source.getmembers()
            self._validate_entry_sizes([(item.size, max(item.size, 1)) for item in members])
            for item in members:
                if cancelled():
                    raise ScrcpyArtifactError("cancelled_before_mutation", "Scrcpy installation was cancelled")
                relative = self._safe_member(item.name.rstrip("/"))
                if item.issym() or item.islnk() or item.isdev() or item.isfifo():
                    raise ScrcpyArtifactError("scrcpy_archive_link_forbidden", "Scrcpy archive special entries are forbidden")
                target = destination.joinpath(*relative.parts)
                if item.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not item.isfile():
                    raise ScrcpyArtifactError("scrcpy_archive_entry_invalid", "Scrcpy archive entry type is invalid")
                reader = source.extractfile(item)
                if reader is None:
                    raise ScrcpyArtifactError("scrcpy_archive_entry_invalid", "Scrcpy archive entry cannot be read")
                target.parent.mkdir(parents=True, exist_ok=True)
                with reader, target.open("xb") as writer:
                    shutil.copyfileobj(reader, writer, length=1024 * 1024)

    @staticmethod
    def _locate_executable(root: Path, platform: str) -> Path:
        name = "scrcpy.exe" if platform == "windows" else "scrcpy"
        candidates = [
            path
            for path in root.rglob(name)
            if path.is_file() and not path.is_symlink()
        ]
        if len(candidates) != 1:
            raise ScrcpyArtifactError(
                "scrcpy_executable_ambiguous",
                "Scrcpy archive must contain exactly one executable",
            )
        return candidates[0]

    @staticmethod
    def _write_metadata(root: Path, metadata: Mapping[str, object]) -> None:
        path = root / _METADATA_NAME
        encoded = json.dumps(dict(metadata), sort_keys=True, separators=(",", ":")).encode("utf-8")
        with path.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())

    @staticmethod
    def _activate(root: Path, staging: Path) -> Path:
        target = root / "scrcpy"
        backup = root / f".scrcpy-{uuid.uuid4().hex}.backup"
        moved_existing = False
        try:
            if target.exists():
                os.replace(target, backup)
                moved_existing = True
            os.replace(staging, target)
        except Exception:
            if moved_existing and backup.exists() and not target.exists():
                os.replace(backup, target)
            raise
        if backup.exists():
            # Activation has already committed at this point.  Failure to clean
            # an old backup must not turn a verified installation into a false
            # failure while leaving the new target active.
            shutil.rmtree(backup, ignore_errors=True)
        return target


__all__ = [
    "ScrcpyArtifactError",
    "ScrcpyInstallation",
    "ScrcpyInstaller",
    "ScrcpyInstallResult",
    "ScrcpyLimits",
    "ScrcpyProbeResult",
    "ScrcpyStatus",
    "probe_scrcpy",
]
