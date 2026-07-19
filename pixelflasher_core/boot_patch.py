"""Headless, fail-closed planning for provider-backed boot patching.

This module does not embed legacy UI scripts or download patch tools.  A
backend must register a hash-bound :class:`PatchToolBundle` implementing the
small PixelFlasher on-device runner protocol documented below.  The browser
can select only a flavor, a backend-issued root-app ID and a local output path.

Runner protocol (argv, never a caller-provided command string)::

    RUNNER patch --flavor FLAVOR --input STOCK --output PATCHED --app APK
        [--support FILE]... [--superkey-stdin]

The runner and any support files are backend-owned, canonical ``FileArtifact``
objects.  If a verified APK or runner is unavailable, planning fails closed.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from .contracts import (
    AppCommand,
    AppSnapshot,
    BootInfo,
    DeviceInfo,
    FileArtifact,
    OperationPlan,
    OperationPostcondition,
    OperationResult,
    OperationRisk,
    OperationStatus,
    ProcessRequest,
    SensitiveText,
)
from .path_compat import is_reserved_path
from .rooting import RootAppInfo, RootingPlanningError, RootingService

BOOT_PATCH_COMMAND = "boot.patch"

_FLAVORS = {
    "magisk": ("magisk", "magisk"),
    "apatch": ("apatch", "apatch"),
    "kernelsu": ("kernelsu", "kernelsu"),
    "kernelsu-next": ("kernelsu-next", "kernelsu-next"),
    "kernelsu_next": ("kernelsu-next", "kernelsu-next"),
    "sukisu": ("sukisu", "sukisu"),
    "wild-ksu": ("wild-ksu", "wild_ksu"),
    "wild_ksu": ("wild-ksu", "wild_ksu"),
    "legacy": ("legacy", "kernelsu-legacy"),
    "kernelsu-legacy": ("legacy", "kernelsu-legacy"),
}
SUPPORTED_BOOT_PATCH_FLAVORS = frozenset(
    {"magisk", "apatch", "kernelsu", "kernelsu-next", "sukisu", "wild-ksu", "legacy"}
)
_APP_PROVIDER_FOR_FLAVOR = {
    "magisk": "magisk",
    "apatch": "apatch",
    "kernelsu": "kernelsu",
    "kernelsu-next": "kernelsu-next",
    "sukisu": "sukisu",
    "wild-ksu": "wild_ksu",
    "legacy": "kernelsu",
}
_BOOT_PARTITIONS = frozenset({"boot", "init_boot"})
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_OUTPUT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.img$")


class CancellationProbe(Protocol):
    @property
    def cancelled(self) -> bool: ...


class BootPatchPlanningError(ValueError):
    """Typed failure raised before any provider patch command can execute."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PatchToolBundle:
    """Backend-verified implementation of the on-device runner protocol."""

    flavor: str
    app_id: str
    runner: FileArtifact
    support_artifacts: tuple[FileArtifact, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.flavor, str):
            raise TypeError("flavor must be a string")
        if not self.flavor.strip():
            raise ValueError("flavor must not be empty")
        if not isinstance(self.app_id, str):
            raise TypeError("app_id must be a string")
        if not self.app_id.strip():
            raise ValueError("app_id must not be empty")
        object.__setattr__(self, "support_artifacts", tuple(self.support_artifacts))
        if not isinstance(self.runner, FileArtifact):
            raise TypeError("runner must be a FileArtifact")
        if any(not isinstance(item, FileArtifact) for item in self.support_artifacts):
            raise TypeError("support_artifacts must contain only FileArtifact values")


@dataclass(frozen=True, slots=True)
class PatchedBootArtifact:
    artifact: FileArtifact
    source_sha256: str
    flavor: str
    partition: str

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact": self.artifact.to_dict(),
            "sourceSha256": self.source_sha256,
            "flavor": self.flavor,
            "partition": self.partition,
        }

    def to_boot_info(self) -> BootInfo:
        return BootInfo(
            id=self.artifact.sha256[:16],
            path=self.artifact.path,
            hash=self.artifact.sha256,
            # BootInfo.flavor is the flash partition selector.  The patch
            # provider remains available in PatchedBootArtifact.flavor.
            flavor=self.partition,
            patched=True,
        )


@dataclass(frozen=True, slots=True)
class BootPatchCompilation:
    plan: OperationPlan
    flavor: str
    app: RootAppInfo
    destination: str
    partition: str
    device_write: bool = True
    destructive: bool = False
    requires_confirmation: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "flavor": self.flavor,
            "app": self.app.to_dict(),
            "destination": self.destination,
            "partition": self.partition,
            "device_write": self.device_write,
            "destructive": self.destructive,
            "requires_confirmation": self.requires_confirmation,
            "plan": self.plan.to_dict(),
        }


class BootPatchService:
    """Compile verified boot-patch bundles into exact serial-bound ADB plans."""

    def __init__(
        self,
        rooting_service: RootingService | None = None,
        tool_bundles: Sequence[PatchToolBundle] = (),
        *,
        hash_chunk_size: int = 1024 * 1024,
    ) -> None:
        if not isinstance(tool_bundles, Sequence) or isinstance(tool_bundles, (str, bytes)):
            raise TypeError("tool_bundles must be a sequence")
        if any(not isinstance(bundle, PatchToolBundle) for bundle in tool_bundles):
            raise TypeError("tool_bundles must contain only PatchToolBundle values")
        if not isinstance(hash_chunk_size, int) or isinstance(hash_chunk_size, bool):
            raise TypeError("hash_chunk_size must be an integer")
        if hash_chunk_size <= 0:
            raise ValueError("hash_chunk_size must be positive")
        self.rooting_service = rooting_service or RootingService()
        self.hash_chunk_size = hash_chunk_size
        bundles: dict[str, PatchToolBundle] = {}
        for bundle in tool_bundles:
            flavor = self._flavor(bundle.flavor)
            if flavor in bundles:
                raise ValueError(f"duplicate patch tool bundle for flavor: {flavor}")
            bundles[flavor] = bundle
        self.tool_bundles = bundles

    def compile(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        cancellation: CancellationProbe | None = None,
    ) -> BootPatchCompilation:
        self._check_cancelled(cancellation)
        if command.kind != BOOT_PATCH_COMMAND:
            raise BootPatchPlanningError(
                "boot_patch_command_unsupported",
                f"unsupported boot-patch command: {command.kind}",
            )
        self._revision(command, snapshot)
        self._validate_payload(
            command,
            {"serial", "flavor", "method", "appId", "destination", "superKey"},
        )
        device = self._device(command, snapshot)
        adb = self._adb(snapshot)
        flavor = self._payload_flavor(command)
        uses_super_key = self._validate_super_key(command, flavor)
        partition, boot_artifact = self._boot_artifact(snapshot, flavor, cancellation)
        app = self._verified_app(command.payload.get("appId"), flavor, cancellation)
        bundle = self.tool_bundles.get(flavor)
        if bundle is None:
            raise BootPatchPlanningError(
                "patch_runner_unavailable",
                f"no backend-verified patch runner is registered for {flavor}",
            )
        if not _SHA256_PATTERN.fullmatch(bundle.app_id.casefold()):
            raise BootPatchPlanningError(
                "patch_bundle_app_id_invalid",
                "patch runner bundle is missing a valid backend root-app ID",
            )
        if bundle.app_id.casefold() != app.id:
            raise BootPatchPlanningError(
                "patch_bundle_app_mismatch",
                "patch runner is not bound to the selected verified root app",
            )
        runner = self._verified_artifact(bundle.runner, "patch runner", cancellation)
        support = tuple(
            self._verified_artifact(artifact, "patch support", cancellation)
            for artifact in bundle.support_artifacts
        )
        app_artifact = FileArtifact(
            app.path,
            app.sha256,
            f"root-app:{app.provider}:{app.flavor}",
        )
        self._reject_duplicate_artifacts((boot_artifact, app_artifact, runner, *support))
        destination = self._output_path(command.payload.get("destination"))
        token = hashlib.sha256(
            f"{command.operation_id}\0{boot_artifact.sha256}\0{flavor}".encode()
        ).hexdigest()[:16]
        remote_root = "/data/local/tmp"
        remote_boot = f"{remote_root}/pf-stock-{token}.img"
        remote_output = f"{remote_root}/pf-patched-{token}.img"
        remote_app = f"{remote_root}/pf-root-app-{app.sha256[:16]}.apk"
        remote_runner = f"{remote_root}/pf-patch-runner-{runner.sha256[:16]}"
        remote_support = tuple(
            f"{remote_root}/pf-patch-support-{index:02d}-{artifact.sha256[:16]}"
            for index, artifact in enumerate(support)
        )

        requests: list[ProcessRequest] = [
            ProcessRequest(
                (adb, "-s", device.serial, "push", boot_artifact.path, remote_boot),
                timeout_seconds=600.0,
            ),
            ProcessRequest(
                (adb, "-s", device.serial, "push", app.path, remote_app),
                timeout_seconds=600.0,
            ),
            ProcessRequest(
                (adb, "-s", device.serial, "push", runner.path, remote_runner),
                timeout_seconds=600.0,
            ),
        ]
        requests.extend(
            ProcessRequest(
                (adb, "-s", device.serial, "push", artifact.path, remote_path),
                timeout_seconds=600.0,
            )
            for artifact, remote_path in zip(support, remote_support, strict=True)
        )
        support_argv = tuple(
            argument
            for remote_path in remote_support
            for argument in ("--support", remote_path)
        )
        super_key_argv = ("--superkey-stdin",) if uses_super_key else ()
        requests.extend(
            (
                ProcessRequest(
                    (adb, "-s", device.serial, "shell", "chmod", "700", remote_runner),
                    timeout_seconds=30.0,
                ),
                ProcessRequest(
                    (
                        adb,
                        "-s",
                        device.serial,
                        "shell",
                        remote_runner,
                        "patch",
                        "--flavor",
                        flavor,
                        "--input",
                        remote_boot,
                        "--output",
                        remote_output,
                        "--app",
                        remote_app,
                        *support_argv,
                        *super_key_argv,
                    ),
                    timeout_seconds=900.0,
                    stdin_secret_field="superKey" if uses_super_key else None,
                ),
                ProcessRequest(
                    (adb, "-s", device.serial, "pull", remote_output, str(destination)),
                    timeout_seconds=900.0,
                ),
                ProcessRequest(
                    (
                        adb,
                        "-s",
                        device.serial,
                        "shell",
                        "rm",
                        "-f",
                        remote_boot,
                        remote_output,
                        remote_app,
                        remote_runner,
                        *remote_support,
                    ),
                    timeout_seconds=30.0,
                ),
            )
        )

        plan = OperationPlan(
            requests=tuple(requests),
            label=f"Patch {partition} with {flavor} on {device.serial}",
            risk=OperationRisk.MUTATING,
            postconditions=(
                OperationPostcondition(
                    "device_reachable",
                    {"mode": "adb"},
                    "the target remains reachable after patch artifacts are cleaned up",
                ),
                OperationPostcondition(
                    "host_artifact_written",
                    {
                        "path": str(destination),
                        "sourceSha256": boot_artifact.sha256,
                        "requireDifferentSha256": True,
                        "minimumBytes": 1,
                    },
                    (
                        "the patched host artifact exists, is non-empty, and differs "
                        "from the verified stock image"
                    ),
                ),
            ),
            snapshot_revision=snapshot.revision,
            target_serial=device.serial,
            expected_codename=device.codename,
            expected_device_state=device.mode,
            firmware_hash=snapshot.firmware.hash,
            boot_hash=boot_artifact.sha256,
            partitions=(partition,),
            data_behavior="device_temp_write",
            plan_revision=snapshot.plan.revision,
            fingerprint=snapshot.plan.fingerprint,
            artifacts=(boot_artifact, app_artifact, runner, *support),
        )
        return BootPatchCompilation(
            plan,
            flavor,
            app,
            str(destination),
            partition,
        )

    def finalize(
        self,
        compilation: BootPatchCompilation,
        cancellation: CancellationProbe | None = None,
    ) -> PatchedBootArtifact:
        """Validate the host output and bind it to the source boot hash."""

        self._check_cancelled(cancellation)
        expected = Path(compilation.destination)
        try:
            path = expected.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise BootPatchPlanningError("patch_output_missing", str(error)) from error
        if path != expected or not path.is_file():
            raise BootPatchPlanningError(
                "patch_output_invalid",
                "patch output is not the canonical regular file selected by the plan",
            )
        try:
            if path.stat().st_size <= 0:
                raise BootPatchPlanningError(
                    "patch_output_empty",
                    "patch runner produced an empty boot image",
                )
        except OSError as error:
            raise BootPatchPlanningError("patch_output_invalid", str(error)) from error
        digest = self._sha256(path, cancellation)
        if hmac.compare_digest(digest, compilation.plan.boot_hash):
            raise BootPatchPlanningError(
                "patch_output_unchanged",
                "patch runner returned an image identical to the stock boot artifact",
            )
        artifact = FileArtifact(
            str(path),
            digest,
            f"patched-boot:{compilation.flavor}",
        )
        return PatchedBootArtifact(
            artifact,
            compilation.plan.boot_hash,
            compilation.flavor,
            compilation.partition,
        )

    def finalize_result(
        self,
        compilation: BootPatchCompilation,
        result: OperationResult,
        cancellation: CancellationProbe | None = None,
    ) -> OperationResult:
        """Turn process success into one explicit, verified domain result."""

        if result.status is not OperationStatus.SUCCESS:
            return result
        try:
            patched = self.finalize(compilation, cancellation)
        except BootPatchPlanningError as error:
            if error.code == "boot_patch_cancelled":
                return OperationResult.cancelled(
                    result.operation_id,
                    code=error.code,
                    message=str(error),
                    stdout=result.stdout,
                    stderr=result.stderr,
                )
            return OperationResult.failed(
                result.operation_id,
                code=error.code,
                message=str(error),
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        return replace(
            result,
            code="boot_patched",
            message=f"patched {patched.partition} with {patched.flavor}",
            value={
                "patchedBoot": patched.to_dict(),
                "boot": patched.to_boot_info().to_dict(),
            },
        )

    def _verified_app(
        self,
        raw_app_id: object,
        flavor: str,
        cancellation: CancellationProbe | None,
    ) -> RootAppInfo:
        if not isinstance(raw_app_id, str) or not _SHA256_PATTERN.fullmatch(
            raw_app_id.strip().casefold()
        ):
            raise BootPatchPlanningError(
                "patch_app_id_required",
                "boot patching requires a backend-issued verified root-app ID",
            )
        app_id = raw_app_id.strip().casefold()
        try:
            inventory = self.rooting_service.root_app_inventory(cancellation)
        except RootingPlanningError as error:
            raise BootPatchPlanningError(error.code, str(error)) from error
        app = next((item for item in inventory if item.id == app_id), None)
        if app is None:
            raise BootPatchPlanningError(
                "patch_app_not_found",
                "selected patch app is no longer in the verified backend inventory",
            )
        expected_provider = _APP_PROVIDER_FOR_FLAVOR[flavor]
        provider = app.provider.strip().casefold().replace(" ", "-")
        provider_aliases = {
            "wild-ksu": "wild_ksu",
            "kernelsu-legacy": "kernelsu",
        }
        provider = provider_aliases.get(provider, provider)
        if provider != expected_provider:
            raise BootPatchPlanningError(
                "patch_app_provider_mismatch",
                f"{flavor} requires a verified {expected_provider} root app",
            )
        return app

    def _boot_artifact(
        self,
        snapshot: AppSnapshot,
        flavor: str,
        cancellation: CancellationProbe | None,
    ) -> tuple[str, FileArtifact]:
        boot = snapshot.boot
        if boot.patched:
            raise BootPatchPlanningError(
                "stock_boot_required",
                "an already patched boot image cannot be used as patch input",
            )
        if not boot.path or not boot.hash:
            raise BootPatchPlanningError(
                "boot_artifact_required",
                "a canonical stock boot image and SHA-256 are required",
            )
        if not _SHA256_PATTERN.fullmatch(boot.hash.casefold()):
            raise BootPatchPlanningError(
                "boot_hash_invalid",
                "canonical boot SHA-256 is invalid",
            )
        path = self._absolute_existing_file(boot.path, ".img", "boot_artifact_invalid")
        digest = self._sha256(path, cancellation)
        if not hmac.compare_digest(digest, boot.hash.casefold()):
            raise BootPatchPlanningError(
                "boot_hash_mismatch",
                "stock boot image no longer matches canonical state",
            )
        partition = boot.flavor.strip().casefold() if boot.flavor else "boot"
        if partition not in _BOOT_PARTITIONS:
            raise BootPatchPlanningError(
                "boot_partition_unsupported",
                f"unsupported patch input partition: {partition}",
            )
        if flavor != "magisk" and partition != "boot":
            raise BootPatchPlanningError(
                "boot_partition_incompatible",
                f"{flavor} requires a boot partition image",
            )
        return partition, FileArtifact(str(path), digest, f"stock-{partition}")

    def _verified_artifact(
        self,
        artifact: FileArtifact,
        label: str,
        cancellation: CancellationProbe | None,
    ) -> FileArtifact:
        path = self._absolute_existing_file(artifact.path, None, "patch_tool_invalid")
        digest = self._sha256(path, cancellation)
        if not hmac.compare_digest(digest, artifact.sha256):
            raise BootPatchPlanningError(
                "patch_tool_hash_mismatch",
                f"{label} no longer matches its backend SHA-256: {path}",
            )
        return FileArtifact(str(path), digest, artifact.role)

    @staticmethod
    def _reject_duplicate_artifacts(artifacts: Sequence[FileArtifact]) -> None:
        seen: set[str] = set()
        for artifact in artifacts:
            key = os.path.normcase(artifact.path)
            if key in seen:
                raise BootPatchPlanningError(
                    "patch_artifact_ambiguous",
                    f"one local artifact has multiple patch roles: {artifact.path}",
                )
            seen.add(key)

    def _sha256(
        self,
        path: Path,
        cancellation: CancellationProbe | None,
    ) -> str:
        self._check_cancelled(cancellation)
        try:
            before = path.stat()
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while chunk := stream.read(self.hash_chunk_size):
                    self._check_cancelled(cancellation)
                    digest.update(chunk)
            after = path.stat()
        except BootPatchPlanningError:
            raise
        except OSError as error:
            raise BootPatchPlanningError("patch_artifact_read_failed", str(error)) from error
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after:
            raise BootPatchPlanningError(
                "patch_artifact_changed",
                f"patch artifact changed while it was being hashed: {path}",
            )
        return digest.hexdigest()

    @staticmethod
    def _absolute_existing_file(
        raw_path: object,
        suffix: str | None,
        code: str,
    ) -> Path:
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise BootPatchPlanningError(code, "an absolute existing file path is required")
        try:
            raw = Path(raw_path)
            expanded = raw.expanduser()
        except (OSError, RuntimeError, ValueError) as error:
            raise BootPatchPlanningError(code, str(error)) from error
        if not expanded.is_absolute():
            raise BootPatchPlanningError(code, "relative artifact paths are not accepted")
        if ".." in raw.parts:
            raise BootPatchPlanningError(
                "boot_patch_path_traversal",
                "parent-directory traversal is not accepted in patch paths",
            )
        try:
            path = expanded.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise BootPatchPlanningError(code, str(error)) from error
        if not path.is_file() or (suffix is not None and path.suffix.casefold() != suffix):
            raise BootPatchPlanningError(code, "selected path has an invalid file type")
        try:
            if path.stat().st_size <= 0:
                raise BootPatchPlanningError(code, "selected artifact is empty")
        except OSError as error:
            raise BootPatchPlanningError(code, str(error)) from error
        return path

    @staticmethod
    def _output_path(raw_path: object) -> Path:
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise BootPatchPlanningError(
                "patch_destination_required",
                "an absolute local .img destination is required",
            )
        try:
            raw = Path(raw_path)
            expanded = raw.expanduser()
        except (OSError, RuntimeError, ValueError) as error:
            raise BootPatchPlanningError("patch_destination_invalid", str(error)) from error
        if not expanded.is_absolute():
            raise BootPatchPlanningError(
                "patch_destination_invalid",
                "relative patch destinations are not accepted",
            )
        if ".." in raw.parts:
            raise BootPatchPlanningError(
                "boot_patch_path_traversal",
                "parent-directory traversal is not accepted in patch paths",
            )
        if not _OUTPUT_NAME_PATTERN.fullmatch(expanded.name) or is_reserved_path(expanded):
            raise BootPatchPlanningError(
                "patch_destination_invalid",
                "patch destination must use a safe ASCII .img file name",
            )
        try:
            parent = expanded.parent.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise BootPatchPlanningError("patch_destination_invalid", str(error)) from error
        if not parent.is_dir() or not os.access(parent, os.W_OK):
            raise BootPatchPlanningError(
                "patch_destination_invalid",
                "patch destination parent must be an existing writable directory",
            )
        destination = parent / expanded.name
        if os.path.lexists(destination):
            raise BootPatchPlanningError(
                "patch_destination_exists",
                "boot patching never overwrites an existing destination",
            )
        return destination

    @staticmethod
    def _payload_flavor(command: AppCommand) -> str:
        raw_flavor = command.payload.get("flavor", command.payload.get("method"))
        if "flavor" in command.payload and "method" in command.payload:
            left = command.payload.get("flavor")
            right = command.payload.get("method")
            if not isinstance(left, str) or not isinstance(right, str):
                raise BootPatchPlanningError(
                    "boot_patch_flavor_invalid",
                    "flavor and method must be strings",
                )
            if BootPatchService._flavor(left) != BootPatchService._flavor(right):
                raise BootPatchPlanningError(
                    "boot_patch_flavor_ambiguous",
                    "flavor and method select different patch providers",
                )
        return BootPatchService._flavor(raw_flavor)

    @staticmethod
    def _validate_super_key(command: AppCommand, flavor: str) -> bool:
        present = "superKey" in command.payload
        raw_super_key = command.payload.get("superKey")
        if flavor != "apatch":
            if present:
                raise BootPatchPlanningError(
                    "apatch_superkey_not_applicable",
                    "superKey is accepted only for APatch boot patching",
                )
            return False
        if not isinstance(raw_super_key, SensitiveText):
            raise BootPatchPlanningError(
                "apatch_superkey_required",
                "APatch boot patching requires an opaque superkey grant",
            )
        if not raw_super_key.meets_policy(8, 128, nul_free=True):
            raise BootPatchPlanningError(
                "apatch_superkey_invalid",
                "APatch superkey must contain 8 to 128 NUL-free characters",
            )
        # The closed policy check above does not reveal the value. The service
        # deliberately never stores it in its compilation or operation plan.
        return True

    @staticmethod
    def _flavor(raw_flavor: object) -> str:
        if not isinstance(raw_flavor, str):
            raise BootPatchPlanningError(
                "boot_patch_flavor_required",
                "a supported boot patch flavor is required",
            )
        key = raw_flavor.strip().casefold().replace(" ", "-")
        normalized = _FLAVORS.get(key)
        if normalized is None:
            raise BootPatchPlanningError(
                "boot_patch_flavor_unsupported",
                f"unsupported boot patch flavor: {raw_flavor}",
            )
        return normalized[0]

    @staticmethod
    def _revision(command: AppCommand, snapshot: AppSnapshot) -> None:
        if command.expected_revision is None:
            raise BootPatchPlanningError("revision_required", "expected_revision is required")
        if command.expected_revision != snapshot.revision:
            raise BootPatchPlanningError(
                "stale_revision",
                (
                    f"state revision changed: expected {command.expected_revision}, "
                    f"current {snapshot.revision}"
                ),
            )

    @staticmethod
    def _device(command: AppCommand, snapshot: AppSnapshot) -> DeviceInfo:
        raw_serial = command.payload.get("serial")
        if raw_serial is not None and (
            not isinstance(raw_serial, str) or not raw_serial.strip()
        ):
            raise BootPatchPlanningError(
                "target_serial_invalid",
                "payload.serial must be a non-empty string",
            )
        payload_serial = raw_serial.strip() if isinstance(raw_serial, str) else None
        if command.target_serial and payload_serial and command.target_serial != payload_serial:
            raise BootPatchPlanningError(
                "ambiguous_target_serial",
                "command and payload target different devices",
            )
        serial = command.target_serial or payload_serial or snapshot.selected_serial
        if not serial:
            raise BootPatchPlanningError(
                "target_serial_required",
                "one selected device is required",
            )
        if serial not in snapshot.selected_serials:
            raise BootPatchPlanningError(
                "target_serial_changed",
                "target serial is no longer selected",
            )
        device = next((item for item in snapshot.devices if item.serial == serial), None)
        if device is None or not device.online:
            raise BootPatchPlanningError(
                "device_disconnected",
                "target device is not online",
            )
        if device.mode != "adb":
            raise BootPatchPlanningError(
                "adb_device_required",
                "boot patching requires a device in adb mode",
            )
        return device

    @staticmethod
    def _adb(snapshot: AppSnapshot) -> str:
        if not snapshot.toolchain.ready or not snapshot.toolchain.adb:
            raise BootPatchPlanningError(
                "toolchain_not_ready",
                "validated adb is required",
            )
        return snapshot.toolchain.adb

    @staticmethod
    def _check_cancelled(cancellation: CancellationProbe | None) -> None:
        if cancellation is not None and cancellation.cancelled:
            raise BootPatchPlanningError(
                "boot_patch_cancelled",
                "boot patch planning was cancelled",
            )

    @staticmethod
    def _validate_payload(command: AppCommand, allowed: set[str]) -> None:
        unknown = set(command.payload) - allowed
        if unknown:
            raise BootPatchPlanningError(
                "invalid_boot_patch_payload",
                f"unsupported semantic field: {sorted(unknown)[0]}",
            )


__all__ = [
    "BOOT_PATCH_COMMAND",
    "SUPPORTED_BOOT_PATCH_FLAVORS",
    "BootPatchCompilation",
    "BootPatchPlanningError",
    "BootPatchService",
    "PatchToolBundle",
    "PatchedBootArtifact",
]
