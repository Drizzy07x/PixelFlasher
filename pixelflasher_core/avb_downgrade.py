"""Headless AVB downgrade-artifact production for preserve-data factory flash.

The browser never supplies a path to this service.  Its inputs are artifacts
already registered by the firmware backend, and its output is registered back
under the same firmware binding with the reserved ``downgrade:boot`` role.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tempfile
import threading
from collections.abc import Mapping
from contextlib import redirect_stderr, redirect_stdout, suppress
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from io import StringIO
from pathlib import Path
from typing import Protocol, cast

from .contracts import FileArtifact
from .planner import ProcessedArtifactCheckpoint, ProcessedArtifactRepository

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_AVB_FIELDS = frozenset(
    {
        "Image Size",
        "Partition Name",
        "Salt",
        "Rollback Index",
        "Algorithm",
        "Hash Algorithm",
        "com.android.build.boot.os_version",
        "com.android.build.boot.fingerprint",
        "com.android.build.boot.security_patch",
    }
)


class CancellationProbe(Protocol):
    @property
    def cancelled(self) -> bool: ...


class AvbDowngradeTool(Protocol):
    def inspect(self, image: Path) -> Mapping[str, str]: ...

    def patch(
        self,
        image: Path,
        *,
        target_info: Mapping[str, str],
        security_patch: str,
        fingerprint: str,
    ) -> None: ...


class _AvbToolRunner(Protocol):
    def run(self, argv: list[str]) -> object: ...


class DowngradePatchStatus(StrEnum):
    SUCCESS = "SUCCESS"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class DowngradePatchCode(StrEnum):
    READY = "downgrade_artifact_ready"
    CANCELLED = "downgrade_patch_cancelled"
    INVALID_FIRMWARE_HASH = "firmware_hash_invalid"
    ARTIFACTS_UNAVAILABLE = "processed_artifacts_unavailable"
    TARGET_UNAVAILABLE = "stock_boot_artifact_required"
    CURRENT_INVALID = "current_boot_artifact_invalid"
    TARGET_INVALID = "target_boot_artifact_invalid"
    IMAGE_TOO_LARGE = "boot_image_too_large"
    AVB_METADATA_INVALID = "avb_metadata_invalid"
    NOT_A_DOWNGRADE = "target_not_downgrade"
    FINGERPRINT_UNAVAILABLE = "current_fingerprint_unavailable"
    PATCH_FAILED = "downgrade_patch_failed"
    POSTCONDITION_MISMATCH = "downgrade_patch_postcondition_mismatch"
    REGISTRATION_FAILED = "downgrade_artifact_registration_failed"


@dataclass(frozen=True, slots=True)
class DowngradePatchResult:
    status: DowngradePatchStatus
    code: DowngradePatchCode
    message: str
    artifact: FileArtifact | None = None
    current_security_patch: str = ""
    target_security_patch: str = ""
    registration_checkpoint: ProcessedArtifactCheckpoint | None = None
    output_created: bool = field(default=False, repr=False)

    @property
    def ok(self) -> bool:
        return self.status is DowngradePatchStatus.SUCCESS


@dataclass(frozen=True, slots=True)
class AvbImageMetadata:
    image_size: str
    partition_name: str
    salt: str
    rollback_index: str
    algorithm: str
    hash_algorithm: str
    os_version: str
    fingerprint: str
    security_patch: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, str]) -> AvbImageMetadata:
        if not _REQUIRED_AVB_FIELDS.issubset(raw):
            raise ValueError("required AVB metadata is missing")
        values = {key: str(raw[key]).strip() for key in _REQUIRED_AVB_FIELDS}
        if any(not value for value in values.values()):
            raise ValueError("required AVB metadata is empty")
        if values["Partition Name"] != "boot":
            raise ValueError("AVB image is not a boot partition image")
        date.fromisoformat(values["com.android.build.boot.security_patch"])
        image_size = int(values["Image Size"], 0)
        rollback_index = int(values["Rollback Index"], 0)
        if image_size <= 0 or rollback_index < 0:
            raise ValueError("AVB numeric metadata is invalid")
        return cls(
            image_size=values["Image Size"],
            partition_name=values["Partition Name"],
            salt=values["Salt"],
            rollback_index=values["Rollback Index"],
            algorithm=values["Algorithm"],
            hash_algorithm=values["Hash Algorithm"],
            os_version=values["com.android.build.boot.os_version"],
            fingerprint=values["com.android.build.boot.fingerprint"],
            security_patch=values["com.android.build.boot.security_patch"],
        )


class BundledAvbDowngradeTool:
    """Direct, shell-free adapter around the bundled AOSP avbtool module."""

    _lock = threading.RLock()

    def __init__(self, signing_key: FileArtifact) -> None:
        if signing_key.role != "avb-signing-key":
            raise ValueError("signing key must use the avb-signing-key role")
        self.signing_key = signing_key

    def inspect(self, image: Path) -> Mapping[str, str]:
        tool = self._tool()
        with self._lock, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            result = tool.run(["avbtool.py", "info_image", "--image", str(image)])
        if not isinstance(result, Mapping):
            raise ValueError("avbtool did not return image metadata")
        values = cast(Mapping[object, object], result)
        return {str(key): str(value) for key, value in values.items()}

    def patch(
        self,
        image: Path,
        *,
        target_info: Mapping[str, str],
        security_patch: str,
        fingerprint: str,
    ) -> None:
        self._verify_signing_key()
        metadata = AvbImageMetadata.from_mapping(target_info)
        tool = self._tool()
        argv = [
            "avbtool.py",
            "add_hash_footer",
            "--image",
            str(image),
            "--partition_size",
            metadata.image_size,
            "--partition_name",
            metadata.partition_name,
            "--salt",
            metadata.salt,
            "--rollback_index",
            metadata.rollback_index,
            "--key",
            self.signing_key.path,
            "--algorithm",
            metadata.algorithm,
            "--hash_algorithm",
            metadata.hash_algorithm,
            "--prop",
            f"com.android.build.boot.os_version:{metadata.os_version}",
            "--prop",
            f"com.android.build.boot.fingerprint:{fingerprint}",
            "--prop",
            f"com.android.build.boot.security_patch:{security_patch}",
        ]
        with self._lock, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            tool.run(argv)

    @staticmethod
    def _tool() -> _AvbToolRunner:
        import avbtool

        return cast(_AvbToolRunner, avbtool.AvbTool(verbose=False))

    def _verify_signing_key(self) -> None:
        path = Path(self.signing_key.path)
        actual = DowngradePatchService.hash_file(path)
        if actual != self.signing_key.sha256:
            raise ValueError("bundled AVB signing key hash changed")


class _DowngradeFailure(Exception):
    def __init__(self, code: DowngradePatchCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class _DowngradeCancelled(Exception):
    pass


class DowngradePatchService:
    """Produce and register one firmware-bound no-wipe downgrade artifact."""

    def __init__(
        self,
        repository: ProcessedArtifactRepository,
        output_root: str | os.PathLike[str],
        tool: AvbDowngradeTool,
        *,
        maximum_image_bytes: int = 512 * 1024 * 1024,
    ) -> None:
        if not isinstance(repository, ProcessedArtifactRepository):
            raise TypeError("repository must be a ProcessedArtifactRepository")
        if maximum_image_bytes <= 0:
            raise ValueError("maximum_image_bytes must be positive")
        self.repository = repository
        self.output_root = Path(output_root).expanduser()
        self.tool = tool
        self.maximum_image_bytes = maximum_image_bytes

    def create(
        self,
        *,
        firmware_hash: str,
        plan_fingerprint: str = "",
        current_boot: FileArtifact | None = None,
        current_security_patch: str = "",
        patch_fingerprint: bool = False,
        cancellation: CancellationProbe | None = None,
    ) -> DowngradePatchResult:
        staging: Path | None = None
        committed: Path | None = None
        committed_created = False
        current_spl = ""
        target_spl = ""
        try:
            digest = firmware_hash.casefold()
            if not _SHA256_PATTERN.fullmatch(digest):
                raise _DowngradeFailure(
                    DowngradePatchCode.INVALID_FIRMWARE_HASH,
                    "firmware hash must be 64 hexadecimal characters",
                )
            self._check_cancelled(cancellation)
            registered = self.repository.resolve_binding(
                firmware_hash=digest,
                plan_fingerprint=plan_fingerprint,
            )
            if not registered:
                raise _DowngradeFailure(
                    DowngradePatchCode.ARTIFACTS_UNAVAILABLE,
                    "processed artifacts are not registered for this firmware",
                )
            stock = tuple(item for item in registered if item.role == "partition:boot")
            if len(stock) != 1:
                raise _DowngradeFailure(
                    DowngradePatchCode.TARGET_UNAVAILABLE,
                    "exactly one backend-registered stock boot artifact is required",
                )
            target_path = self._verify_artifact(stock[0], DowngradePatchCode.TARGET_INVALID)
            target_raw = self.tool.inspect(target_path)
            target = self._metadata(target_raw)
            target_spl = target.security_patch

            current: AvbImageMetadata | None = None
            if current_boot is not None:
                if current_boot.role != "partition:boot":
                    raise _DowngradeFailure(
                        DowngradePatchCode.CURRENT_INVALID,
                        "current boot artifact must use the partition:boot role",
                    )
                current_path = self._verify_artifact(
                    current_boot, DowngradePatchCode.CURRENT_INVALID
                )
                current = self._metadata(self.tool.inspect(current_path))
                current_spl = current.security_patch
            else:
                current_spl = self._security_patch(current_security_patch)
            if date.fromisoformat(target_spl) >= date.fromisoformat(current_spl):
                raise _DowngradeFailure(
                    DowngradePatchCode.NOT_A_DOWNGRADE,
                    "target boot security patch must be older than the current security patch",
                )
            if patch_fingerprint and current is None:
                raise _DowngradeFailure(
                    DowngradePatchCode.FINGERPRINT_UNAVAILABLE,
                    "patching the fingerprint requires a verified current boot artifact",
                )
            fingerprint = current.fingerprint if patch_fingerprint and current else target.fingerprint

            self.output_root.mkdir(parents=True, exist_ok=True)
            staging = Path(tempfile.mkdtemp(prefix="downgrade-", dir=self.output_root))
            staged_image = staging / "downgrade-boot.img"
            shutil.copyfile(target_path, staged_image)
            self._check_cancelled(cancellation)
            self.tool.patch(
                staged_image,
                target_info=target_raw,
                security_patch=current_spl,
                fingerprint=fingerprint,
            )
            self._check_cancelled(cancellation)
            patched = self._metadata(self.tool.inspect(staged_image))
            if (
                patched.security_patch != current_spl
                or patched.fingerprint != fingerprint
                or patched.partition_name != target.partition_name
                or patched.os_version != target.os_version
            ):
                raise _DowngradeFailure(
                    DowngradePatchCode.POSTCONDITION_MISMATCH,
                    "patched boot AVB properties do not match the requested downgrade metadata",
                )
            output_hash = self.hash_file(staged_image, maximum_bytes=self.maximum_image_bytes)
            committed = self.output_root / f"{output_hash}.img"
            if committed.exists():
                if self.hash_file(committed, maximum_bytes=self.maximum_image_bytes) != output_hash:
                    raise _DowngradeFailure(
                        DowngradePatchCode.PATCH_FAILED,
                        "content-addressed downgrade output conflicts with an existing file",
                    )
                staged_image.unlink()
            else:
                os.replace(staged_image, committed)
                committed_created = True
            artifact = FileArtifact(str(committed.resolve()), output_hash, "downgrade:boot")
            # The downgrade boot image is a property of the firmware, never of a
            # single flash plan: registering it under the volatile plan
            # fingerprint makes it unreachable as soon as any flash option
            # changes, because the planner then falls back to the firmware
            # binding that has no downgrade artifact.
            checkpoint = self.repository.checkpoint(firmware_hash=digest)
            retained = tuple(item for item in registered if item.role != "downgrade:boot")
            try:
                self.repository.register(
                    (*retained, artifact),
                    firmware_hash=digest,
                )
                bound = self.repository.resolve_binding(firmware_hash=digest)
                # register is defined as replace-for-key.  A repository that
                # appended instead would leave two downgrade artifacts on this
                # firmware, and the planner then rejects every flash mode for
                # it; undo rather than hand the planner an unusable binding.
                if sum(1 for item in bound if item.role == "downgrade:boot") > 1:
                    self.repository.rollback(checkpoint)
                    raise RuntimeError(
                        "repository kept a superseded downgrade artifact for this firmware"
                    )
            except Exception as error:
                if committed_created:
                    with suppress(OSError):
                        committed.unlink()
                raise _DowngradeFailure(
                    DowngradePatchCode.REGISTRATION_FAILED,
                    "downgrade artifact could not be registered",
                ) from error
            return DowngradePatchResult(
                DowngradePatchStatus.SUCCESS,
                DowngradePatchCode.READY,
                "downgrade boot artifact is verified and registered",
                artifact,
                current_spl,
                target_spl,
                checkpoint,
                committed_created,
            )
        except _DowngradeCancelled:
            return DowngradePatchResult(
                DowngradePatchStatus.CANCELLED,
                DowngradePatchCode.CANCELLED,
                "downgrade patch creation was cancelled",
                current_security_patch=current_spl,
                target_security_patch=target_spl,
            )
        except _DowngradeFailure as error:
            return DowngradePatchResult(
                DowngradePatchStatus.FAILED,
                error.code,
                str(error),
                current_security_patch=current_spl,
                target_security_patch=target_spl,
            )
        except Exception:
            return DowngradePatchResult(
                DowngradePatchStatus.FAILED,
                DowngradePatchCode.PATCH_FAILED,
                "AVB downgrade patch creation failed",
                current_security_patch=current_spl,
                target_security_patch=target_spl,
            )
        finally:
            if staging is not None:
                with suppress(OSError):
                    shutil.rmtree(staging)

    def rollback(self, result: DowngradePatchResult) -> None:
        if not result.ok or result.registration_checkpoint is None:
            return
        self.repository.rollback(result.registration_checkpoint)
        if result.output_created and result.artifact is not None:
            output = Path(result.artifact.path).resolve(strict=False)
            root = self.output_root.resolve(strict=False)
            if output.parent != root:
                raise RuntimeError("downgrade rollback output escaped the service root")
            with suppress(FileNotFoundError):
                output.unlink()

    def _verify_artifact(self, artifact: FileArtifact, code: DowngradePatchCode) -> Path:
        try:
            path = Path(artifact.path).resolve(strict=True)
            details = path.stat()
            if not stat.S_ISREG(details.st_mode):
                raise OSError("artifact is not a regular file")
            if details.st_size > self.maximum_image_bytes:
                raise _DowngradeFailure(
                    DowngradePatchCode.IMAGE_TOO_LARGE,
                    "boot image exceeds the configured size limit",
                )
            if self.hash_file(path, maximum_bytes=self.maximum_image_bytes) != artifact.sha256:
                raise OSError("artifact hash changed")
            return path
        except _DowngradeFailure:
            raise
        except (OSError, ValueError) as error:
            raise _DowngradeFailure(code, "boot artifact verification failed") from error

    @staticmethod
    def _metadata(raw: Mapping[str, str]) -> AvbImageMetadata:
        try:
            return AvbImageMetadata.from_mapping(raw)
        except (KeyError, TypeError, ValueError) as error:
            raise _DowngradeFailure(
                DowngradePatchCode.AVB_METADATA_INVALID,
                "boot image does not contain valid AVB metadata",
            ) from error

    @staticmethod
    def _security_patch(value: str) -> str:
        normalized = str(value).strip()
        try:
            date.fromisoformat(normalized)
        except ValueError as error:
            raise _DowngradeFailure(
                DowngradePatchCode.AVB_METADATA_INVALID,
                "current security patch must use YYYY-MM-DD",
            ) from error
        return normalized

    @staticmethod
    def _check_cancelled(cancellation: CancellationProbe | None) -> None:
        if cancellation is not None and cancellation.cancelled:
            raise _DowngradeCancelled

    @staticmethod
    def hash_file(path: Path, *, maximum_bytes: int | None = None) -> str:
        digest = hashlib.sha256()
        size = 0
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        descriptor_open = True
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode):
                raise OSError("artifact is not a regular file")
            stream = os.fdopen(descriptor, "rb")
            descriptor_open = False
            with stream:
                while chunk := stream.read(1024 * 1024):
                    size += len(chunk)
                    if maximum_bytes is not None and size > maximum_bytes:
                        raise OSError("artifact exceeds the configured size limit")
                    digest.update(chunk)
        finally:
            if descriptor_open:
                os.close(descriptor)
        return digest.hexdigest()
