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
import tarfile
import tempfile
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
_PATCH_ARCHITECTURES = frozenset({"*", "arm64", "arm", "x86_64", "x86"})
_APP_ARCHITECTURE_ALIASES = {
    "universal": "*",
    "all": "*",
    "arm64-v8a": "arm64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
    "arm": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}
_KMI_PATTERN = re.compile(r"^android[0-9]{2}-[1-9][0-9]*\.[0-9]+$")


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
    architectures: tuple[str, ...] = ("*",)
    kmi_versions: tuple[str, ...] = ("*",)

    def __post_init__(self) -> None:
        if not isinstance(self.flavor, str):
            raise TypeError("flavor must be a string")
        if not self.flavor.strip():
            raise ValueError("flavor must not be empty")
        if not isinstance(self.app_id, str):
            raise TypeError("app_id must be a string")
        if self.app_id and not self.app_id.strip():
            raise ValueError("app_id must not contain only whitespace")
        app_id = self.app_id.strip().casefold()
        if app_id and _SHA256_PATTERN.fullmatch(app_id) is None:
            raise ValueError("app_id must be empty or a canonical SHA-256 value")
        object.__setattr__(self, "app_id", app_id)
        object.__setattr__(self, "support_artifacts", tuple(self.support_artifacts))
        architectures = tuple(
            item.strip().casefold() if isinstance(item, str) else ""
            for item in self.architectures
        )
        kmi_versions = tuple(
            item.strip().casefold() if isinstance(item, str) else ""
            for item in self.kmi_versions
        )
        if (
            not architectures
            or len(architectures) != len(set(architectures))
            or any(item not in _PATCH_ARCHITECTURES for item in architectures)
            or ("*" in architectures and len(architectures) != 1)
        ):
            raise ValueError("architectures must be unique canonical device architectures or *")
        if (
            not kmi_versions
            or len(kmi_versions) != len(set(kmi_versions))
            or any(item != "*" and _KMI_PATTERN.fullmatch(item) is None for item in kmi_versions)
            or ("*" in kmi_versions and len(kmi_versions) != 1)
        ):
            raise ValueError("kmi_versions must be unique canonical Android KMI values or *")
        object.__setattr__(self, "architectures", architectures)
        object.__setattr__(self, "kmi_versions", kmi_versions)
        if not isinstance(self.runner, FileArtifact):
            raise TypeError("runner must be a FileArtifact")
        if any(not isinstance(item, FileArtifact) for item in self.support_artifacts):
            raise TypeError("support_artifacts must contain only FileArtifact values")

    def matches(self, architecture: str, kmi: str) -> bool:
        architecture_match = "*" in self.architectures or architecture in self.architectures
        kmi_match = "*" in self.kmi_versions or kmi in self.kmi_versions
        return architecture_match and kmi_match


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
    tar_destination: str = ""
    device_write: bool = True
    destructive: bool = False
    requires_confirmation: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "flavor": self.flavor,
            "app": self.app.to_dict(),
            "destination": self.destination,
            "partition": self.partition,
            "createBootTar": bool(self.tar_destination),
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
        bundles: dict[str, list[PatchToolBundle]] = {}
        for bundle in tool_bundles:
            flavor = self._flavor(bundle.flavor)
            normalized = replace(bundle, flavor=flavor)
            existing = bundles.setdefault(flavor, [])
            if any(self._bundle_compatibility_overlaps(item, normalized) for item in existing):
                raise ValueError(f"overlapping patch tool bundle compatibility for flavor: {flavor}")
            existing.append(normalized)
        self.tool_bundles = {
            flavor: tuple(items)
            for flavor, items in bundles.items()
        }

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
        bundle = self._compatible_bundle(flavor, device)
        app_architecture = self._validate_app_architecture(app, device)
        if bundle.app_id and bundle.app_id != app.id:
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
        tar_destination = (
            str(destination.with_suffix(".tar"))
            if snapshot.preferences.create_boot_tar
            else ""
        )
        # The staged inputs are content addressed like the APK, runner and
        # support files: a retry after a failed patch overwrites the same
        # staging paths instead of leaving one more stock image behind. The
        # output stays operation scoped so a stale patched image from an
        # earlier attempt can never be pulled by this one.
        staging_token = hashlib.sha256(
            f"{boot_artifact.sha256}\0{flavor}".encode()
        ).hexdigest()[:16]
        token = hashlib.sha256(
            f"{command.operation_id}\0{boot_artifact.sha256}\0{flavor}".encode()
        ).hexdigest()[:16]
        remote_root = "/data/local/tmp"
        remote_boot = f"{remote_root}/pf-stock-{staging_token}.img"
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
        compatibility_argv = (
            "--architecture",
            device.architecture,
            "--kmi",
            device.kmi,
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
                        *compatibility_argv,
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
            expected_architecture=(
                device.architecture
                if "*" not in bundle.architectures or app_architecture != "*"
                else ""
            ),
            expected_kmi=device.kmi if "*" not in bundle.kmi_versions else "",
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
            tar_destination,
        )

    def _compatible_bundle(self, flavor: str, device: DeviceInfo) -> PatchToolBundle:
        bundles = self.tool_bundles.get(flavor, ())
        if not bundles:
            raise BootPatchPlanningError(
                "patch_runner_unavailable",
                f"no backend-verified patch runner is registered for {flavor}",
            )
        if any("*" not in bundle.architectures for bundle in bundles) and not device.architecture:
            raise BootPatchPlanningError(
                "device_architecture_unknown",
                "device architecture must be observed before selecting a patch runner",
            )
        architecture_candidates = tuple(
            bundle
            for bundle in bundles
            if "*" in bundle.architectures or device.architecture in bundle.architectures
        )
        if not architecture_candidates:
            raise BootPatchPlanningError(
                "patch_architecture_incompatible",
                f"no {flavor} patch runner supports device architecture {device.architecture!r}",
            )
        if (
            any("*" not in bundle.kmi_versions for bundle in architecture_candidates)
            and not device.kmi
        ):
            raise BootPatchPlanningError(
                "device_kmi_unknown",
                "device KMI must be observed before selecting a patch runner",
            )
        candidates = tuple(
            bundle
            for bundle in architecture_candidates
            if "*" in bundle.kmi_versions or device.kmi in bundle.kmi_versions
        )
        if not candidates:
            raise BootPatchPlanningError(
                "patch_kmi_incompatible",
                f"no {flavor} patch runner supports device KMI {device.kmi!r}",
            )
        if len(candidates) != 1:
            raise BootPatchPlanningError(
                "patch_runner_ambiguous",
                "multiple patch runners match the selected device",
            )
        return candidates[0]

    @staticmethod
    def _validate_app_architecture(app: RootAppInfo, device: DeviceInfo) -> str:
        architecture = _APP_ARCHITECTURE_ALIASES.get(app.architecture.strip().casefold())
        if architecture is None:
            raise BootPatchPlanningError(
                "patch_app_architecture_unsupported",
                "selected root app has an unsupported architecture declaration",
            )
        if architecture == "*":
            return architecture
        if not device.architecture:
            raise BootPatchPlanningError(
                "device_architecture_unknown",
                "device architecture must be observed before selecting a root app",
            )
        if architecture != device.architecture:
            raise BootPatchPlanningError(
                "patch_app_architecture_incompatible",
                f"selected root app does not support device architecture {device.architecture!r}",
            )
        return architecture

    @staticmethod
    def _bundle_compatibility_overlaps(
        left: PatchToolBundle,
        right: PatchToolBundle,
    ) -> bool:
        architecture_overlap = (
            "*" in left.architectures
            or "*" in right.architectures
            or bool(set(left.architectures) & set(right.architectures))
        )
        kmi_overlap = (
            "*" in left.kmi_versions
            or "*" in right.kmi_versions
            or bool(set(left.kmi_versions) & set(right.kmi_versions))
        )
        return architecture_overlap and kmi_overlap

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
            boot_tar = (
                self._create_boot_tar(
                    patched.artifact,
                    Path(compilation.tar_destination),
                    cancellation,
                )
                if compilation.tar_destination
                else None
            )
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
        value: dict[str, object] = {
            "patchedBoot": patched.to_dict(),
            "boot": patched.to_boot_info().to_dict(),
        }
        if boot_tar is not None:
            value["bootTar"] = boot_tar
        return replace(
            result,
            code="boot_patched",
            message=(
                f"patched {patched.partition} with {patched.flavor} and created boot.tar"
                if boot_tar is not None
                else f"patched {patched.partition} with {patched.flavor}"
            ),
            value=value,
        )

    def _create_boot_tar(
        self,
        patched: FileArtifact,
        destination: Path,
        cancellation: CancellationProbe | None,
    ) -> dict[str, object]:
        """Publish one deterministic Odin archive after verifying its member hash."""

        self._check_cancelled(cancellation)
        source = self._absolute_existing_file(
            patched.path,
            ".img",
            "boot_tar_source_invalid",
        )
        try:
            target = destination.resolve(strict=False)
            parent = target.parent.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise BootPatchPlanningError("boot_tar_destination_invalid", str(error)) from error
        if (
            not target.is_absolute()
            or target.parent != parent
            or target.suffix.casefold() != ".tar"
            or target.name != destination.name
            or target.is_dir()
        ):
            raise BootPatchPlanningError(
                "boot_tar_destination_invalid",
                "boot.tar destination must be a canonical file beside the patched image",
            )
        descriptor = -1
        temporary: Path | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{target.name}.",
                suffix=".tmp",
                dir=parent,
            )
            temporary = Path(temporary_name)
            size = source.stat().st_size
            with os.fdopen(descriptor, "w+b") as stream:
                descriptor = -1
                with tarfile.open(
                    fileobj=stream,
                    mode="w",
                    format=tarfile.USTAR_FORMAT,
                ) as archive:
                    member = tarfile.TarInfo("boot.img")
                    member.size = size
                    member.mode = 0o644
                    member.mtime = 0
                    member.uid = 0
                    member.gid = 0
                    member.uname = ""
                    member.gname = ""
                    with source.open("rb") as source_stream:
                        archive.addfile(member, source_stream)
                stream.flush()
                os.fsync(stream.fileno())
            self._verify_boot_tar(temporary, patched.sha256, size, cancellation)
            archive_sha256 = self._sha256(temporary, cancellation)
            archive_size = temporary.stat().st_size
            self._check_cancelled(cancellation)
            os.replace(temporary, target)
            temporary = None
            return {
                "name": target.name,
                "sha256": archive_sha256,
                "size": archive_size,
                "member": "boot.img",
                "memberSha256": patched.sha256,
            }
        except BootPatchPlanningError:
            raise
        except (OSError, tarfile.TarError) as error:
            raise BootPatchPlanningError("boot_tar_creation_failed", str(error)) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass

    def _verify_boot_tar(
        self,
        path: Path,
        expected_sha256: str,
        expected_size: int,
        cancellation: CancellationProbe | None,
    ) -> None:
        self._check_cancelled(cancellation)
        try:
            with tarfile.open(path, mode="r:") as archive:
                members = archive.getmembers()
                if (
                    len(members) != 1
                    or members[0].name != "boot.img"
                    or not members[0].isfile()
                    or members[0].size != expected_size
                ):
                    raise BootPatchPlanningError(
                        "boot_tar_verification_failed",
                        "boot.tar does not contain exactly the verified boot image",
                    )
                extracted = archive.extractfile(members[0])
                if extracted is None:
                    raise BootPatchPlanningError(
                        "boot_tar_verification_failed",
                        "boot.tar member is unreadable",
                    )
                digest = hashlib.sha256()
                while chunk := extracted.read(self.hash_chunk_size):
                    self._check_cancelled(cancellation)
                    digest.update(chunk)
        except BootPatchPlanningError:
            raise
        except (OSError, tarfile.TarError) as error:
            raise BootPatchPlanningError("boot_tar_verification_failed", str(error)) from error
        if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
            raise BootPatchPlanningError(
                "boot_tar_verification_failed",
                "boot.tar member hash does not match the patched image",
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
            # The catalog publishes the rsuntk manager as "legacy"; both
            # spellings satisfy the legacy flavor only, so a legacy manager can
            # never be paired with the official KernelSU runner.
            **(
                {"legacy": "kernelsu", "kernelsu-legacy": "kernelsu"}
                if flavor == "legacy"
                else {}
            ),
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
        # The canonical stock image lives in the content-addressed artifact store,
        # whose object names are the bare SHA-256 with no extension, so a ".img"
        # suffix requirement here rejects every boot image the inventory owns.
        # The digest comparison below binds the bytes to the canonical hash, which
        # is what actually guarantees the right image is patched.
        path = self._absolute_existing_file(boot.path, None, "boot_artifact_invalid")
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
