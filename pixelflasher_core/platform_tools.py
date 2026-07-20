"""Verified, atomic Android Platform Tools installation for the modern core."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import uuid
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol

from .artifact_downloads import (
    ArtifactCancelledError,
    ArtifactDownloader,
    ArtifactDownloadError,
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_VERSION_PATTERN = re.compile(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?:[-\w.]*)?")
_PLATFORM_KEYS: Mapping[str, str] = {
    "win32": "windows",
    "windows": "windows",
    "darwin": "darwin",
    "linux": "linux",
}
_ARCHITECTURE_KEYS: Mapping[str, str] = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "x86_64": "x86_64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "x86": "x86",
    "i386": "x86",
    "i686": "x86",
    "arm": "arm",
    "armv7": "arm",
    "armv7l": "arm",
}


class PlatformToolsStatus(StrEnum):
    SUCCESS = "SUCCESS"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class PlatformToolsError(RuntimeError):
    """A stable, user-safe Platform Tools validation failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PlatformToolsLimits:
    maximum_archive_bytes: int = 512 * 1024 * 1024
    maximum_entries: int = 512
    maximum_entry_bytes: int = 256 * 1024 * 1024
    maximum_extracted_bytes: int = 1024 * 1024 * 1024
    maximum_compression_ratio: int = 250

    def __post_init__(self) -> None:
        values = (
            self.maximum_archive_bytes,
            self.maximum_entries,
            self.maximum_entry_bytes,
            self.maximum_extracted_bytes,
            self.maximum_compression_ratio,
        )
        if any(value <= 0 for value in values):
            raise ValueError("Platform Tools limits must be positive")


@dataclass(frozen=True, slots=True)
class PlatformToolsInstallation:
    root: Path
    adb_path: Path
    fastboot_path: Path
    archive_sha256: str
    archive_size: int
    version: str = ""

    def to_public_dict(self) -> dict[str, object]:
        return {
            "installed": True,
            "adbAvailable": self.adb_path.is_file(),
            "fastbootAvailable": self.fastboot_path.is_file(),
            "archiveSha256": self.archive_sha256,
            "archiveSize": self.archive_size,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class PlatformToolsInstallResult:
    status: PlatformToolsStatus
    code: str
    message: str
    installation: PlatformToolsInstallation | None = None

    @property
    def ok(self) -> bool:
        return self.status is PlatformToolsStatus.SUCCESS


@dataclass(frozen=True, slots=True)
class PlatformToolsProbeResult:
    status: PlatformToolsStatus
    code: str
    message: str
    adb_version: str = ""
    fastboot_version: str = ""
    version: str = ""

    @property
    def ok(self) -> bool:
        return self.status is PlatformToolsStatus.SUCCESS


class CompletedProcessLike(Protocol):
    returncode: int
    stdout: str
    stderr: str


class ProbeRunner(Protocol):
    def __call__(self, argv: tuple[str, ...], timeout: float) -> CompletedProcessLike: ...


def platform_key(platform: str) -> str:
    normalized = platform.casefold()
    if normalized.startswith("linux"):
        normalized = "linux"
    try:
        return _PLATFORM_KEYS[normalized]
    except KeyError as error:
        raise PlatformToolsError("platform_unsupported", "Platform Tools are not available for this platform") from error


def platform_tools_binary_names(platform: str) -> tuple[str, str]:
    return ("adb.exe", "fastboot.exe") if platform_key(platform) == "windows" else ("adb", "fastboot")


def _is_link_like(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def architecture_key(architecture: str) -> str:
    try:
        return _ARCHITECTURE_KEYS[architecture.casefold()]
    except (AttributeError, KeyError) as error:
        raise PlatformToolsError(
            "architecture_unsupported",
            "Platform Tools are not available for this architecture",
        ) from error


def _binary_architecture_is_compatible(
    *,
    platform: str,
    requested_arch: str,
    observed_arches: frozenset[str],
) -> bool:
    if requested_arch in observed_arches:
        return True
    # Google currently ships the Windows Platform Tools as PE x86. Windows
    # x64 and Windows 11 on ARM both provide the corresponding compatibility
    # layer, while no equivalent cross-architecture promise exists on POSIX.
    return (
        platform_key(platform) == "windows"
        and requested_arch in {"x86_64", "arm64"}
        and observed_arches == frozenset({"x86"})
    )


def _cpu_architecture(cpu_type: int) -> str | None:
    return {
        0x00000007: "x86",
        0x01000007: "x86_64",
        0x0000000C: "arm",
        0x0100000C: "arm64",
    }.get(cpu_type)


def binary_architectures(path: Path, *, platform: str) -> frozenset[str]:
    """Read executable headers without executing untrusted archive content."""

    target_platform = platform_key(platform)
    try:
        with path.open("rb") as stream:
            header = stream.read(4096)
            if target_platform == "windows":
                if len(header) < 64 or header[:2] != b"MZ":
                    return frozenset()
                pe_offset = int.from_bytes(header[60:64], "little")
                if pe_offset < 64 or pe_offset > 1024 * 1024:
                    return frozenset()
                stream.seek(pe_offset)
                pe_header = stream.read(6)
                if len(pe_header) != 6 or pe_header[:4] != b"PE\x00\x00":
                    return frozenset()
                architecture = {
                    0x014C: "x86",
                    0x8664: "x86_64",
                    0x01C4: "arm",
                    0xAA64: "arm64",
                }.get(int.from_bytes(pe_header[4:6], "little"))
                return frozenset((architecture,)) if architecture else frozenset()

            if target_platform == "linux":
                if len(header) < 20 or header[:4] != b"\x7fELF":
                    return frozenset()
                if header[5] == 1:
                    byte_order: Literal["little", "big"] = "little"
                elif header[5] == 2:
                    byte_order = "big"
                else:
                    return frozenset()
                architecture = {
                    3: "x86",
                    40: "arm",
                    62: "x86_64",
                    183: "arm64",
                }.get(int.from_bytes(header[18:20], byte_order))
                return frozenset((architecture,)) if architecture else frozenset()

            if len(header) < 8:
                return frozenset()
            magic = header[:4]
            thin_byte_orders: Mapping[bytes, Literal["little", "big"]] = {
                b"\xfe\xed\xfa\xce": "big",
                b"\xfe\xed\xfa\xcf": "big",
                b"\xce\xfa\xed\xfe": "little",
                b"\xcf\xfa\xed\xfe": "little",
            }
            thin_byte_order = thin_byte_orders.get(magic)
            if thin_byte_order:
                architecture = _cpu_architecture(int.from_bytes(header[4:8], thin_byte_order))
                return frozenset((architecture,)) if architecture else frozenset()

            fat_layouts: Mapping[bytes, tuple[Literal["little", "big"], int]] = {
                b"\xca\xfe\xba\xbe": ("big", 20),
                b"\xbe\xba\xfe\xca": ("little", 20),
                b"\xca\xfe\xba\xbf": ("big", 32),
                b"\xbf\xba\xfe\xca": ("little", 32),
            }
            fat_layout = fat_layouts.get(magic)
            if fat_layout is None:
                return frozenset()
            byte_order, entry_size = fat_layout
            count = int.from_bytes(header[4:8], byte_order)
            if count <= 0 or count > 32 or len(header) < 8 + count * entry_size:
                return frozenset()
            found: set[str] = set()
            for index in range(count):
                offset = 8 + index * entry_size
                architecture = _cpu_architecture(
                    int.from_bytes(header[offset : offset + 4], byte_order)
                )
                if architecture:
                    found.add(architecture)
            return frozenset(found)
    except OSError as error:
        raise PlatformToolsError(
            "toolchain_binary_unreadable",
            "Platform Tools executable headers could not be read",
        ) from error


def validate_platform_tools_directory(
    path: Path,
    *,
    platform: str,
    expected_arch: str | None = None,
) -> PlatformToolsInstallation:
    root = path.resolve(strict=True)
    if _is_link_like(path) or not root.is_dir():
        raise PlatformToolsError("toolchain_directory_invalid", "Platform Tools directory is not a regular directory")
    adb_name, fastboot_name = platform_tools_binary_names(platform)
    adb_path = root / adb_name
    fastboot_path = root / fastboot_name
    for binary in (adb_path, fastboot_path):
        if _is_link_like(binary) or not binary.is_file():
            raise PlatformToolsError("toolchain_binary_missing", "Platform Tools must contain regular adb and fastboot binaries")
        if expected_arch is not None:
            requested_arch = architecture_key(expected_arch)
            observed_arches = binary_architectures(binary, platform=platform)
            if not observed_arches:
                raise PlatformToolsError(
                    "toolchain_binary_format_invalid",
                    "Platform Tools contains an unrecognized executable format",
                )
            if not _binary_architecture_is_compatible(
                platform=platform,
                requested_arch=requested_arch,
                observed_arches=observed_arches,
            ):
                raise PlatformToolsError(
                    "toolchain_arch_mismatch",
                    "Platform Tools executable architecture does not match its manifest",
                )
    return PlatformToolsInstallation(
        root=root,
        adb_path=adb_path,
        fastboot_path=fastboot_path,
        archive_sha256="",
        archive_size=0,
    )


class PlatformToolsInstaller:
    """Installs an authenticated Platform Tools ZIP without partial activation."""

    def __init__(
        self,
        *,
        limits: PlatformToolsLimits | None = None,
        probe_runner: ProbeRunner | None = None,
        probe_timeout: float = 10.0,
    ) -> None:
        if probe_timeout <= 0 or probe_timeout > 60:
            raise ValueError("Platform Tools probe timeout must be between zero and sixty seconds")
        self.limits = limits or PlatformToolsLimits()
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
    ) -> PlatformToolsInstallResult:
        """Download through the signed-manifest service and activate atomically."""

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
            archive = cache_root / f"platform-tools-{manifest.sha256}.zip"
            downloaded = downloader.download(
                manifest_document,
                archive,
                expected_platform=target_platform,
                expected_arch=target_arch,
                cancelled=cancelled,
            )
        except ArtifactCancelledError as error:
            return PlatformToolsInstallResult(
                PlatformToolsStatus.CANCELLED,
                error.code,
                str(error),
            )
        except Exception as error:
            if isinstance(error, PlatformToolsError | ArtifactDownloadError):
                return PlatformToolsInstallResult(
                    PlatformToolsStatus.FAILED,
                    error.code,
                    str(error),
                )
            return PlatformToolsInstallResult(
                PlatformToolsStatus.FAILED,
                "platform_tools_download_failed",
                "Platform Tools download failed",
            )
        return self.install_archive(
            Path(downloaded.path),
            install_root=install_root,
            expected_sha256=downloaded.sha256,
            expected_size=downloaded.size,
            expected_version=manifest.version,
            platform=target_platform,
            expected_arch=target_arch,
            cancelled=cancelled,
        )

    def install_archive(
        self,
        archive_path: Path,
        *,
        install_root: Path,
        expected_sha256: str,
        platform: str,
        expected_size: int | None = None,
        expected_arch: str | None = None,
        expected_version: str | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> PlatformToolsInstallResult:
        is_cancelled = cancelled or (lambda: False)
        staging: Path | None = None
        try:
            archive, observed_hash, observed_size = self._validate_archive_file(
                archive_path,
                expected_sha256=expected_sha256,
                expected_size=expected_size,
            )
            if is_cancelled():
                return PlatformToolsInstallResult(
                    PlatformToolsStatus.CANCELLED,
                    "cancelled_before_mutation",
                    "Platform Tools installation was cancelled before activation",
                )
            root = install_root.resolve()
            root.mkdir(parents=True, exist_ok=True)
            if _is_link_like(install_root) or not root.is_dir():
                raise PlatformToolsError("install_root_invalid", "Platform Tools install root is invalid")
            self._fsync_directory(root.parent)
            staging = root / f".platform-tools-{uuid.uuid4().hex}.staging"
            self._assert_direct_child(root, staging)
            staging.mkdir(mode=0o700)
            self._extract_archive(archive, staging, platform=platform, cancelled=is_cancelled)
            validated = validate_platform_tools_directory(
                staging,
                platform=platform,
                expected_arch=expected_arch,
            )
            self._fsync_tree(staging)
            staged_probe = probe_platform_tools(
                validated,
                runner=self.probe_runner,
                timeout=self.probe_timeout,
            )
            if not staged_probe.ok:
                raise PlatformToolsError(staged_probe.code, staged_probe.message)
            self._validate_expected_version(staged_probe, expected_version)
            if is_cancelled():
                return PlatformToolsInstallResult(
                    PlatformToolsStatus.CANCELLED,
                    "cancelled_before_mutation",
                    "Platform Tools installation was cancelled before activation",
                )
            installed = self._activate(
                root,
                staging,
                validated,
                archive_sha256=observed_hash,
                archive_size=observed_size,
                probe_runner=self.probe_runner,
                probe_timeout=self.probe_timeout,
                expected_version=expected_version,
                cancelled=is_cancelled,
            )
            staging = None
            return PlatformToolsInstallResult(
                PlatformToolsStatus.SUCCESS,
                "platform_tools_installed",
                "Platform Tools were verified and installed",
                installed,
            )
        except (OSError, zipfile.BadZipFile, PlatformToolsError) as error:
            code = error.code if isinstance(error, PlatformToolsError) else "platform_tools_install_failed"
            if code == "cancelled_before_mutation":
                return PlatformToolsInstallResult(PlatformToolsStatus.CANCELLED, code, str(error))
            message = str(error) if isinstance(error, PlatformToolsError) else "Platform Tools installation failed"
            return PlatformToolsInstallResult(PlatformToolsStatus.FAILED, code, message)
        finally:
            if staging is not None and staging.exists():
                shutil.rmtree(staging, ignore_errors=True)

    def _validate_archive_file(
        self,
        archive_path: Path,
        *,
        expected_sha256: str,
        expected_size: int | None,
    ) -> tuple[Path, str, int]:
        if not _SHA256.fullmatch(expected_sha256):
            raise PlatformToolsError("archive_hash_invalid", "Expected Platform Tools SHA-256 is invalid")
        try:
            archive = archive_path.resolve(strict=True)
        except OSError as error:
            raise PlatformToolsError("archive_missing", "Platform Tools archive is missing") from error
        if _is_link_like(archive_path) or not archive.is_file():
            raise PlatformToolsError("archive_invalid", "Platform Tools archive must be a regular file")
        observed_size = archive.stat().st_size
        if observed_size <= 0 or observed_size > self.limits.maximum_archive_bytes:
            raise PlatformToolsError("archive_size_invalid", "Platform Tools archive size is outside policy")
        if expected_size is not None and observed_size != expected_size:
            raise PlatformToolsError("archive_size_mismatch", "Platform Tools archive size does not match its manifest")
        digest = hashlib.sha256()
        with archive.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        observed_hash = digest.hexdigest()
        if observed_hash != expected_sha256:
            raise PlatformToolsError("archive_hash_mismatch", "Platform Tools archive hash does not match its manifest")
        return archive, observed_hash, observed_size

    def _extract_archive(
        self,
        archive_path: Path,
        staging: Path,
        *,
        platform: str,
        cancelled: Callable[[], bool],
    ) -> None:
        seen: set[str] = set()
        extracted = 0
        binaries = set(platform_tools_binary_names(platform))
        found_binaries: set[str] = set()
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if not members or len(members) > self.limits.maximum_entries:
                raise PlatformToolsError("archive_entry_count_invalid", "Platform Tools archive entry count is outside policy")
            for member in members:
                if member.is_dir() and member.filename.rstrip("/") == "platform-tools":
                    continue
                relative = self._member_relative_path(member)
                key = relative.as_posix().casefold()
                if key in seen:
                    raise PlatformToolsError("archive_duplicate_entry", "Platform Tools archive contains duplicate paths")
                seen.add(key)
                if member.is_dir():
                    (staging / relative).mkdir(parents=True, exist_ok=True)
                    continue
                if member.file_size < 0 or member.file_size > self.limits.maximum_entry_bytes:
                    raise PlatformToolsError("archive_entry_size_invalid", "Platform Tools archive contains an oversized entry")
                extracted += member.file_size
                if extracted > self.limits.maximum_extracted_bytes:
                    raise PlatformToolsError("archive_expanded_size_invalid", "Platform Tools archive expands beyond policy")
                if member.file_size and member.compress_size == 0:
                    raise PlatformToolsError("archive_compression_invalid", "Platform Tools archive has an invalid compressed entry")
                if member.compress_size and member.file_size > member.compress_size * self.limits.maximum_compression_ratio:
                    raise PlatformToolsError("archive_compression_ratio_invalid", "Platform Tools archive compression ratio is unsafe")
                destination = staging / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member, "r") as source, destination.open("xb") as output:
                    copied = 0
                    while True:
                        if cancelled():
                            raise PlatformToolsError("cancelled_before_mutation", "Platform Tools installation was cancelled")
                        block = source.read(1024 * 1024)
                        if not block:
                            break
                        copied += len(block)
                        if copied > member.file_size:
                            raise PlatformToolsError("archive_entry_size_mismatch", "Platform Tools entry exceeds its declared size")
                        output.write(block)
                    output.flush()
                    os.fsync(output.fileno())
                if copied != member.file_size:
                    raise PlatformToolsError("archive_entry_size_mismatch", "Platform Tools entry size is inconsistent")
                if relative.as_posix() in binaries:
                    found_binaries.add(relative.as_posix())
                    if platform_key(platform) != "windows":
                        destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        if found_binaries != binaries:
            raise PlatformToolsError("toolchain_binary_missing", "Platform Tools archive does not contain adb and fastboot")

    @staticmethod
    def _member_relative_path(member: zipfile.ZipInfo) -> PurePosixPath:
        name = member.filename
        if not name or "\\" in name or "\x00" in name or name.startswith("/"):
            raise PlatformToolsError("archive_path_invalid", "Platform Tools archive contains an invalid path")
        path = PurePosixPath(name)
        parts = path.parts
        if not parts or parts[0] != "platform-tools" or len(parts) < 2:
            raise PlatformToolsError("archive_layout_invalid", "Platform Tools archive must have one platform-tools root")
        relative = PurePosixPath(*parts[1:])
        if any(part in {"", ".", ".."} or ":" in part for part in relative.parts):
            raise PlatformToolsError("archive_path_invalid", "Platform Tools archive contains an unsafe path")
        mode = member.external_attr >> 16
        if (
            stat.S_ISLNK(mode)
            or stat.S_ISCHR(mode)
            or stat.S_ISBLK(mode)
            or stat.S_ISFIFO(mode)
            or stat.S_ISSOCK(mode)
        ):
            raise PlatformToolsError("archive_special_file_forbidden", "Platform Tools archive contains a special file")
        if member.flag_bits & 0x1:
            raise PlatformToolsError("archive_encrypted_forbidden", "Encrypted Platform Tools entries are not supported")
        return relative

    def _activate(
        self,
        root: Path,
        staging: Path,
        validated: PlatformToolsInstallation,
        *,
        archive_sha256: str,
        archive_size: int,
        probe_runner: ProbeRunner,
        probe_timeout: float,
        expected_version: str | None,
        cancelled: Callable[[], bool],
    ) -> PlatformToolsInstallation:
        target = root / "platform-tools"
        backup = root / f".platform-tools-{uuid.uuid4().hex}.backup"
        self._assert_direct_child(root, target)
        self._assert_direct_child(root, backup)
        moved_existing = False
        activated = False
        try:
            if cancelled():
                raise PlatformToolsError(
                    "cancelled_before_mutation",
                    "Platform Tools installation was cancelled before activation",
                )
            if target.exists():
                if _is_link_like(target) or not target.is_dir():
                    raise PlatformToolsError("existing_install_invalid", "Existing Platform Tools target is unsafe")
                os.replace(target, backup)
                moved_existing = True
            os.replace(staging, target)
            activated = True
            self._fsync_directory(root)
            installed = PlatformToolsInstallation(
                root=target,
                adb_path=target / validated.adb_path.name,
                fastboot_path=target / validated.fastboot_path.name,
                archive_sha256=archive_sha256,
                archive_size=archive_size,
            )
            probe = probe_platform_tools(
                installed,
                runner=probe_runner,
                timeout=probe_timeout,
            )
            if not probe.ok:
                raise PlatformToolsError(probe.code, probe.message)
            self._validate_expected_version(probe, expected_version)
            installed = PlatformToolsInstallation(
                root=installed.root,
                adb_path=installed.adb_path,
                fastboot_path=installed.fastboot_path,
                archive_sha256=installed.archive_sha256,
                archive_size=installed.archive_size,
                version=probe.version,
            )
        except Exception:
            try:
                self._rollback_activation(
                    root,
                    target,
                    backup,
                    moved_existing=moved_existing,
                    activated=activated,
                )
            except Exception as rollback_error:
                raise PlatformToolsError(
                    "platform_tools_rollback_failed",
                    "Platform Tools activation failed and the previous installation could not be restored",
                ) from rollback_error
            raise
        if backup.exists():
            shutil.rmtree(backup)
            self._fsync_directory(root)
        return installed

    @staticmethod
    def _validate_expected_version(
        probe: PlatformToolsProbeResult,
        expected_version: str | None,
    ) -> None:
        if expected_version is None:
            return
        match = _VERSION_PATTERN.fullmatch(expected_version)
        if match is None:
            raise PlatformToolsError(
                "manifest_version_invalid",
                "Platform Tools manifest version is not a semantic version",
            )
        expected = ".".join(match.group(index) for index in (1, 2, 3))
        if probe.version != expected:
            raise PlatformToolsError(
                "toolchain_manifest_version_mismatch",
                "Platform Tools binaries do not match the signed manifest version",
            )

    def _rollback_activation(
        self,
        root: Path,
        target: Path,
        backup: Path,
        *,
        moved_existing: bool,
        activated: bool,
    ) -> None:
        failed = root / f".platform-tools-{uuid.uuid4().hex}.failed"
        self._assert_direct_child(root, failed)
        moved_failed = False
        if activated and target.exists():
            os.replace(target, failed)
            moved_failed = True
        if moved_existing and backup.exists():
            os.replace(backup, target)
        self._fsync_directory(root)
        if moved_failed and failed.exists():
            shutil.rmtree(failed)
            self._fsync_directory(root)

    @classmethod
    def _fsync_tree(cls, root: Path) -> None:
        if os.name == "nt":
            return
        directories: list[Path] = []
        for directory, _names, files in os.walk(root):
            current = Path(directory)
            directories.append(current)
            for name in files:
                path = current / name
                if _is_link_like(path) or not path.is_file():
                    raise PlatformToolsError(
                        "staging_tree_invalid",
                        "Platform Tools staging contains an unsafe file",
                    )
                descriptor = os.open(path, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        for directory in reversed(directories):
            cls._fsync_directory(directory)

    @staticmethod
    def _assert_direct_child(root: Path, path: Path) -> None:
        if path.parent != root or path == root:
            raise PlatformToolsError("install_path_invalid", "Platform Tools activation path escaped its install root")

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _default_probe_runner(argv: tuple[str, ...], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def probe_platform_tools(
    installation: PlatformToolsInstallation,
    *,
    runner: ProbeRunner = _default_probe_runner,
    timeout: float = 10.0,
) -> PlatformToolsProbeResult:
    """Require semantic version evidence from both binaries before declaring ready."""

    if timeout <= 0 or timeout > 60:
        return PlatformToolsProbeResult(PlatformToolsStatus.FAILED, "probe_timeout_invalid", "Probe timeout is invalid")
    commands = (
        ("adb", installation.adb_path, "version", "Android Debug Bridge version"),
        ("fastboot", installation.fastboot_path, "--version", "fastboot version"),
    )
    versions: dict[str, str] = {}
    parsed_versions: dict[str, tuple[int, int, int]] = {}
    try:
        for name, executable, version_argument, expected in commands:
            completed = runner((str(executable), version_argument), timeout)
            output = "\n".join(value for value in (completed.stdout, completed.stderr) if value).strip()
            if completed.returncode != 0:
                return PlatformToolsProbeResult(
                    PlatformToolsStatus.FAILED,
                    f"{name}_probe_failed",
                    f"{name} version probe failed",
                )
            if expected.casefold() not in output.casefold():
                return PlatformToolsProbeResult(
                    PlatformToolsStatus.FAILED,
                    f"{name}_version_unverified",
                    f"{name} did not provide recognizable version evidence",
                )
            parsed = [
                (int(match.group(1)), int(match.group(2)), int(match.group(3)))
                for match in _VERSION_PATTERN.finditer(output)
            ]
            if not parsed:
                return PlatformToolsProbeResult(
                    PlatformToolsStatus.FAILED,
                    f"{name}_version_unverified",
                    f"{name} did not provide a parseable Platform Tools version",
                )
            parsed_versions[name] = max(parsed)
            versions[name] = output.splitlines()[0][:256]
    except (OSError, subprocess.SubprocessError):
        return PlatformToolsProbeResult(
            PlatformToolsStatus.FAILED,
            "toolchain_probe_failed",
            "adb or fastboot could not be executed",
        )
    if parsed_versions["adb"] != parsed_versions["fastboot"]:
        return PlatformToolsProbeResult(
            PlatformToolsStatus.FAILED,
            "tool_version_mismatch",
            "adb and fastboot report different Platform Tools versions",
        )
    return PlatformToolsProbeResult(
        PlatformToolsStatus.SUCCESS,
        "toolchain_verified",
        "adb and fastboot version evidence was verified",
        adb_version=versions["adb"],
        fastboot_version=versions["fastboot"],
        version=".".join(str(part) for part in parsed_versions["adb"]),
    )
