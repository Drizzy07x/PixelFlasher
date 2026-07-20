"""Headless, shell-free planning for fastboot partition operations.

The WebView is allowed to express a partition-management intent, but it can
never provide executable arguments.  This module binds every request to one
selected fastboot serial, validates partition names against a closed set and
canonicalizes host paths before producing an immutable :class:`OperationPlan`.

Execution remains the responsibility of the engine and its ``SafetyPolicy``.
In particular, erase plans deliberately contain both ``erase`` in their argv
and ``data_behavior`` so the existing nonce-bound reinforced-confirmation
mechanism can recognize them when this service is integrated.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import BinaryIO, Protocol

from .contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    FileArtifact,
    OperationPlan,
    OperationPostcondition,
    OperationResult,
    OperationRisk,
    ProcessRequest,
)
from .executor import CancellationToken, TransportOutcome
from .grants import (
    AtomicWriteOutcomeUnknownError,
    BoundReadFile,
    BoundWriteFile,
    GrantError,
)

PARTITION_COMMANDS = frozenset(
    {
        "partitions.list",
        "partitions.read",
        "partitions.write",
        "partitions.erase",
    }
)

# Pixel devices span several boot-chain generations and Qualcomm/Tensor
# layouts.  Keep the accepted vocabulary explicit: a syntactically plausible
# value is not enough to become a fastboot target.
_UNSLOTTED_PARTITIONS = frozenset(
    {
        "cache",
        "cdt",
        "devinfo",
        "frp",
        "fsc",
        "fsg",
        "logdump",
        "metadata",
        "misc",
        "modemst1",
        "modemst2",
        "msadp",
        "multiimgoem",
        "persist",
        "spunvm",
        "super",
        "userdata",
    }
)
_SLOT_CAPABLE_PARTITIONS = frozenset(
    {
        "abl",
        "aop",
        "aop_config",
        "apdp",
        "bluetooth",
        "boot",
        "bootloader",
        "cdsp",
        "cpucp",
        "cpucp_dtb",
        "devcfg",
        "dsp",
        "dtbo",
        "featenabler",
        "hyp",
        "hyp_dtb",
        "init_boot",
        "keymaster",
        "logo",
        "modem",
        "odm",
        "odm_dlkm",
        "product",
        "pvmfw",
        "qupfw",
        "radio",
        "recovery",
        "splash",
        "system",
        "system_dlkm",
        "system_ext",
        "toolsfv",
        "tz",
        "tzsc",
        "uefisecapp",
        "vbmeta",
        "vbmeta_system",
        "vbmeta_vendor",
        "vendor",
        "vendor_boot",
        "vendor_dlkm",
        "vendor_kernel_boot",
        "vm-bootsys",
        "xbl",
        "xbl_config",
    }
)
ALLOWED_PARTITIONS = frozenset(
    _UNSLOTTED_PARTITIONS
    | _SLOT_CAPABLE_PARTITIONS
    | {f"{partition}_{slot}" for partition in _SLOT_CAPABLE_PARTITIONS for slot in ("a", "b")}
)

_PARTITION_VARIABLE = re.compile(
    r"(?:^|\s)partition-(?P<field>size|type):"
    r"(?P<partition>[A-Za-z0-9_.-]+):\s*(?P<value>\S+)",
    re.IGNORECASE,
)
_OUTPUT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ +@=-]{0,191}$")
_MAX_PARTITION_BYTES = 16 * 1024 * 1024 * 1024
_COPY_CHUNK = 1024 * 1024


class PartitionPlanningError(ValueError):
    """A stable, typed failure raised before any process can be started."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CancellationProbe(Protocol):
    @property
    def cancelled(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class PartitionInfo:
    name: str
    size_bytes: int | None = None
    partition_type: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "size_bytes": self.size_bytes,
            "partition_type": self.partition_type,
        }


@dataclass(frozen=True, slots=True)
class PartitionCompilation:
    plan: OperationPlan
    action: str
    destructive: bool = False
    requires_confirmation: bool = False
    reinforced_confirmation: bool = False
    partition: str = ""
    destination: BoundWriteFile | None = field(default=None, repr=False)
    local_payload: Path | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "destructive": self.destructive,
            "requires_confirmation": self.requires_confirmation,
            "reinforced_confirmation": self.reinforced_confirmation,
            "plan": self.plan.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class PartitionReadEvidence:
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class PartitionReadDecision:
    allowed: bool
    code: str
    message: str
    evidence: PartitionReadEvidence | None = None


class PartitionService:
    """Compile trusted fastboot partition plans from canonical app state."""

    def __init__(
        self,
        *,
        hash_chunk_size: int = 1024 * 1024,
        temporary_root: str | Path | None = None,
    ) -> None:
        if hash_chunk_size <= 0:
            raise ValueError("hash_chunk_size must be positive")
        self.hash_chunk_size = hash_chunk_size
        self._owned_temporary_root: TemporaryDirectory[str] | None = None
        if temporary_root is None:
            self._owned_temporary_root = TemporaryDirectory(prefix="pixelflasher-partitions-")
            root = Path(self._owned_temporary_root.name)
        else:
            root = Path(temporary_root).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise ValueError("partition temporary root must be a directory")
        self.temporary_root = root

    def compile(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        cancellation: CancellationProbe | None = None,
    ) -> PartitionCompilation:
        self._check_cancelled(cancellation)
        if command.kind not in PARTITION_COMMANDS:
            raise PartitionPlanningError(
                "partition_command_unsupported",
                f"unsupported partition command: {command.kind}",
            )
        self._revision(command, snapshot)
        device = self._device(command, snapshot)
        fastboot = self._fastboot(snapshot)

        if command.kind == "partitions.list":
            return self._compile_list(command, snapshot, device, fastboot)
        if command.kind == "partitions.read":
            return self._compile_read(command, snapshot, device, fastboot)
        if command.kind == "partitions.write":
            return self._compile_write(
                command,
                snapshot,
                device,
                fastboot,
                cancellation,
            )
        return self._compile_erase(command, snapshot, device, fastboot)

    def _compile_list(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        fastboot: str,
    ) -> PartitionCompilation:
        self._validate_payload(command, {"serial"})
        request = ProcessRequest(
            (fastboot, "-s", device.serial, "getvar", "all"),
            timeout_seconds=30.0,
        )
        return PartitionCompilation(
            self._base_plan(
                snapshot,
                device,
                (request,),
                label=f"List partitions on {device.serial}",
            ),
            "list",
        )

    def _compile_read(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        fastboot: str,
    ) -> PartitionCompilation:
        self._validate_payload(
            command,
            {"serial", "partition", "destination", "overwrite"},
        )
        partition = self._partition(command.payload.get("partition"))
        overwrite = command.payload.get("overwrite", False)
        if not isinstance(overwrite, bool):
            raise PartitionPlanningError(
                "partition_overwrite_invalid",
                "overwrite must be a boolean",
            )
        destination = self._output_grant(
            command.payload.get("destination"),
            overwrite=overwrite,
        )
        nonce = hashlib.sha256(command.operation_id.encode("utf-8")).hexdigest()[:24]
        local_payload = self.temporary_root / f"{nonce}-{partition}.img"
        local_payload.unlink(missing_ok=True)
        request = ProcessRequest(
            (fastboot, "-s", device.serial, "fetch", partition, str(local_payload)),
            timeout_seconds=900.0,
            output_limit_bytes=64 * 1024,
        )
        return PartitionCompilation(
            self._base_plan(
                snapshot,
                device,
                (request,),
                label=f"Read {partition} from {device.serial}",
                partitions=(partition,),
                data_behavior="partition_read",
                risk=OperationRisk.MUTATING,
                postconditions=(
                    OperationPostcondition(
                        "partition_read_verified",
                        {
                            "targetSerial": device.serial,
                            "partition": partition,
                            "fileName": destination.name,
                        },
                        "the fetched image was hashed and atomically published",
                    ),
                ),
            ),
            "read",
            partition=partition,
            destination=destination,
            local_payload=local_payload,
        )

    def _compile_write(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        fastboot: str,
        cancellation: CancellationProbe | None,
    ) -> PartitionCompilation:
        self._validate_payload(command, {"serial", "partition", "path"})
        partition = self._partition(command.payload.get("partition"))
        source = self._input_grant(command.payload.get("path"))
        artifact = self._source_artifact(source, partition, cancellation)
        request = ProcessRequest(
            (fastboot, "-s", device.serial, "flash", partition, str(source.path)),
            timeout_seconds=900.0,
            output_limit_bytes=64 * 1024,
        )
        return PartitionCompilation(
            self._base_plan(
                snapshot,
                device,
                (request,),
                label=f"Write {partition} on {device.serial}",
                partitions=(partition,),
                data_behavior="partition_write",
                artifacts=(artifact,),
                risk=OperationRisk.DESTRUCTIVE,
                postconditions=(
                    OperationPostcondition(
                        "partition_written",
                        {
                            "partition": partition,
                            "slot": "",
                            "sha256": artifact.sha256,
                        },
                        "the selected partition contains the verified image",
                    ),
                ),
            ),
            "write",
            destructive=True,
            requires_confirmation=True,
            partition=partition,
        )

    def _compile_erase(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        fastboot: str,
    ) -> PartitionCompilation:
        self._validate_payload(command, {"serial", "partition"})
        partition = self._partition(command.payload.get("partition"))
        request = ProcessRequest(
            (fastboot, "-s", device.serial, "erase", partition),
            timeout_seconds=300.0,
        )
        return PartitionCompilation(
            self._base_plan(
                snapshot,
                device,
                (request,),
                label=f"Erase {partition} on {device.serial}",
                partitions=(partition,),
                data_behavior="erase",
                risk=OperationRisk.DESTRUCTIVE,
                postconditions=(
                    OperationPostcondition(
                        "partition_erased",
                        {"partition": partition},
                        "the selected partition is reported erased",
                    ),
                ),
            ),
            "erase",
            destructive=True,
            requires_confirmation=True,
            reinforced_confirmation=True,
            partition=partition,
        )

    def validate_read_preflight(
        self,
        compilation: PartitionCompilation,
        outcome: TransportOutcome,
        cancellation: CancellationProbe | None,
    ) -> PartitionReadDecision:
        local_payload = compilation.local_payload
        if (
            compilation.action != "read"
            or compilation.destination is None
            or local_payload is None
            or len(compilation.plan.requests) != 1
        ):
            return PartitionReadDecision(
                False,
                "partition_read_plan_invalid",
                "partition read did not produce its closed staging plan",
            )
        if outcome.timed_out:
            return PartitionReadDecision(
                False,
                "partition_read_preflight_timed_out",
                "partition read timed out before destination publication",
            )
        if outcome.cancelled:
            return PartitionReadDecision(
                False,
                "partition_read_preflight_cancelled",
                "partition read was cancelled before destination publication",
            )
        request = compilation.plan.requests[0]
        captured = len(outcome.stdout.encode(request.encoding, errors="replace"))
        captured += len(outcome.stderr.encode(request.encoding, errors="replace"))
        if outcome.output_limited or (request.output_limit_bytes is not None and captured > request.output_limit_bytes):
            return PartitionReadDecision(
                False,
                "partition_read_output_oversized",
                "partition read output exceeded its safety limit",
            )
        if outcome.returncode != 0:
            return PartitionReadDecision(
                False,
                "partition_read_failed",
                "fastboot could not fetch the selected partition",
            )
        try:
            staged = local_payload.resolve(strict=True)
            if staged.parent != self.temporary_root or staged.is_symlink() or not staged.is_file():
                raise PartitionPlanningError(
                    "partition_read_staging_invalid",
                    "partition read staging is outside its private directory",
                )
            digest, size = self._hash_path(staged, cancellation)
            if not 1 <= size <= _MAX_PARTITION_BYTES:
                raise PartitionPlanningError(
                    "partition_read_size_invalid",
                    "fetched partition image is outside its size limit",
                )
        except (OSError, PartitionPlanningError) as error:
            code = getattr(error, "code", "partition_read_staging_invalid")
            return PartitionReadDecision(
                False,
                (
                    "partition_read_preflight_cancelled"
                    if code == "partition_cancelled"
                    else code
                ),
                (
                    "partition read was cancelled before destination publication"
                    if code == "partition_cancelled"
                    else str(error)
                ),
            )
        return PartitionReadDecision(
            True,
            "partition_read_preflight_verified",
            "partition image staging hash was verified",
            PartitionReadEvidence(digest, size),
        )

    def publish_read(
        self,
        compilation: PartitionCompilation,
        evidence: PartitionReadEvidence,
        operation_id: str,
        cancellation: CancellationToken,
    ) -> OperationResult:
        destination = compilation.destination
        local_payload = compilation.local_payload
        if destination is None or local_payload is None or compilation.action != "read":
            return OperationResult.failed(
                operation_id,
                code="partition_read_plan_invalid",
                message="partition read publication has no verified destination",
            )
        try:
            digest, size = self._hash_path(local_payload, cancellation)
            if digest != evidence.sha256 or size != evidence.size_bytes:
                raise PartitionPlanningError(
                    "partition_read_staging_changed",
                    "fetched partition staging changed before publication",
                )
            with destination.begin_atomic_replace() as transaction:
                with local_payload.open("rb") as source:
                    while True:
                        self._check_cancelled(cancellation)
                        chunk = source.read(_COPY_CHUNK)
                        if not chunk:
                            break
                        transaction.stream.write(chunk)
                transaction.stream.flush()
                os.fsync(transaction.stream.fileno())
                self._check_cancelled(cancellation)
                transaction.commit()
                with transaction.open_committed() as committed:
                    committed_digest, committed_size = self._hash_stream(
                        committed,
                        cancellation,
                    )
            if committed_digest != digest or committed_size != size:
                raise AtomicWriteOutcomeUnknownError("published partition image differs from verified staging")
        except AtomicWriteOutcomeUnknownError as error:
            return OperationResult.failed(
                operation_id,
                code="outcome_unknown",
                message=str(error),
            )
        except PartitionPlanningError as error:
            if error.code == "partition_cancelled":
                return OperationResult.cancelled(
                    operation_id,
                    code="partition_read_cancelled",
                    message="partition read publication was cancelled",
                )
            return OperationResult.failed(
                operation_id,
                code=error.code,
                message=str(error),
            )
        except (GrantError, OSError) as error:
            return OperationResult.failed(
                operation_id,
                code=getattr(error, "code", "partition_read_publish_failed"),
                message=str(error),
            )
        return OperationResult.success(
            operation_id,
            code="partition_read_verified",
            message="partition image was hashed and atomically published",
            value={
                "action": "read",
                "targetSerial": compilation.plan.target_serial,
                "partition": compilation.partition,
                "fileName": destination.name,
                "sha256": digest,
                "sizeBytes": size,
                "verified": True,
            },
        )

    def cleanup_read(self, compilation: PartitionCompilation) -> None:
        local_payload = compilation.local_payload
        if local_payload is not None:
            try:
                if local_payload.parent == self.temporary_root:
                    local_payload.unlink(missing_ok=True)
            except OSError:
                pass

    def _source_artifact(
        self,
        source: BoundReadFile,
        partition: str,
        cancellation: CancellationProbe | None,
    ) -> FileArtifact:
        try:
            with source.open_verified() as stream:
                digest, size = self._hash_stream(stream, cancellation)
        except (GrantError, OSError) as error:
            raise PartitionPlanningError(
                "partition_image_read_failed",
                str(error),
            ) from error
        if not 1 <= size <= _MAX_PARTITION_BYTES:
            raise PartitionPlanningError(
                "partition_image_size_invalid",
                "the selected partition image is outside its size limit",
            )
        return FileArtifact(str(source.path), digest, f"partition:{partition}")

    def _hash_path(
        self,
        path: Path,
        cancellation: CancellationProbe | None,
    ) -> tuple[str, int]:
        try:
            with path.open("rb") as stream:
                return self._hash_stream(stream, cancellation)
        except OSError as error:
            raise PartitionPlanningError(
                "partition_image_read_failed",
                str(error),
            ) from error

    def _hash_stream(
        self,
        stream: BinaryIO,
        cancellation: CancellationProbe | None,
    ) -> tuple[str, int]:
        digest = hashlib.sha256()
        size = 0
        while True:
            self._check_cancelled(cancellation)
            chunk = stream.read(self.hash_chunk_size)
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_PARTITION_BYTES:
                raise PartitionPlanningError(
                    "partition_image_size_invalid",
                    "partition image exceeds its size limit",
                )
            digest.update(chunk)
        return digest.hexdigest(), size

    @staticmethod
    def _check_cancelled(cancellation: CancellationProbe | None) -> None:
        if cancellation is not None and cancellation.cancelled:
            raise PartitionPlanningError(
                "partition_cancelled",
                "partition planning was cancelled",
            )

    @staticmethod
    def _revision(command: AppCommand, snapshot: AppSnapshot) -> None:
        if command.expected_revision is None:
            raise PartitionPlanningError(
                "revision_required",
                "expected_revision is required",
            )
        if command.expected_revision != snapshot.revision:
            raise PartitionPlanningError(
                "stale_revision",
                (f"state revision changed: expected {command.expected_revision}, current {snapshot.revision}"),
            )

    @staticmethod
    def _device(command: AppCommand, snapshot: AppSnapshot) -> DeviceInfo:
        raw_serial = command.payload.get("serial")
        if raw_serial is not None and (not isinstance(raw_serial, str) or not raw_serial.strip()):
            raise PartitionPlanningError(
                "target_serial_invalid",
                "payload.serial must be a non-empty string",
            )
        payload_serial = raw_serial.strip() if isinstance(raw_serial, str) else None
        if command.target_serial and payload_serial and command.target_serial != payload_serial:
            raise PartitionPlanningError(
                "ambiguous_target_serial",
                "command and payload target different devices",
            )
        serial = command.target_serial or payload_serial or snapshot.selected_serial
        if not serial:
            raise PartitionPlanningError(
                "target_serial_required",
                "one selected device is required",
            )
        if serial not in snapshot.selected_serials:
            raise PartitionPlanningError(
                "target_serial_changed",
                "target serial is no longer selected",
            )
        device = next((item for item in snapshot.devices if item.serial == serial), None)
        if device is None or not device.online:
            raise PartitionPlanningError(
                "device_disconnected",
                "target device is not online",
            )
        if device.mode not in {"fastboot", "fastbootd"}:
            raise PartitionPlanningError(
                "fastboot_required",
                "partition operations require the target in fastboot or fastbootd mode",
            )
        return device

    @staticmethod
    def _fastboot(snapshot: AppSnapshot) -> str:
        if not snapshot.toolchain.ready or not snapshot.toolchain.fastboot:
            raise PartitionPlanningError(
                "toolchain_not_ready",
                "validated fastboot is required",
            )
        return snapshot.toolchain.fastboot

    @staticmethod
    def _partition(raw_partition: object) -> str:
        if not isinstance(raw_partition, str):
            raise PartitionPlanningError(
                "partition_required",
                "partition must be a string",
            )
        partition = raw_partition.strip().casefold()
        if partition not in ALLOWED_PARTITIONS:
            raise PartitionPlanningError(
                "partition_not_allowed",
                f"partition is not allow-listed: {partition}",
            )
        return partition

    @staticmethod
    def _input_grant(raw_path: object) -> BoundReadFile:
        if not isinstance(raw_path, BoundReadFile):
            raise PartitionPlanningError(
                "partition_image_grant_required",
                "an opaque native image grant is required",
            )
        return raw_path

    @staticmethod
    def _output_grant(raw_path: object, *, overwrite: bool) -> BoundWriteFile:
        if not isinstance(raw_path, BoundWriteFile):
            raise PartitionPlanningError(
                "partition_destination_grant_required",
                "an opaque native destination grant is required",
            )
        if _OUTPUT_NAME.fullmatch(raw_path.name) is None:
            raise PartitionPlanningError(
                "partition_destination_invalid",
                "the selected destination name is invalid",
            )
        if raw_path.path.exists() and not overwrite:
            raise PartitionPlanningError(
                "partition_destination_exists",
                "destination exists; explicit overwrite=true is required",
            )
        return raw_path

    def shutdown(self) -> None:
        if self._owned_temporary_root is not None:
            self._owned_temporary_root.cleanup()
            self._owned_temporary_root = None

    @staticmethod
    def _base_plan(
        snapshot: AppSnapshot,
        device: DeviceInfo,
        requests: tuple[ProcessRequest, ...],
        *,
        label: str,
        partitions: tuple[str, ...] = (),
        data_behavior: str = "preserve",
        artifacts: tuple[FileArtifact, ...] = (),
        risk: OperationRisk = OperationRisk.READ_ONLY,
        postconditions: tuple[OperationPostcondition, ...] = (),
    ) -> OperationPlan:
        return OperationPlan(
            requests=requests,
            label=label,
            snapshot_revision=snapshot.revision,
            target_serial=device.serial,
            expected_codename=device.codename,
            expected_device_state=device.mode,
            firmware_hash=snapshot.firmware.hash,
            boot_hash=snapshot.boot.hash,
            partitions=partitions,
            data_behavior=data_behavior,
            plan_revision=snapshot.plan.revision,
            fingerprint=snapshot.plan.fingerprint,
            artifacts=artifacts,
            risk=risk,
            postconditions=postconditions,
        )

    @staticmethod
    def _validate_payload(command: AppCommand, allowed: set[str]) -> None:
        unknown = set(command.payload) - allowed
        if unknown:
            raise PartitionPlanningError(
                "invalid_partition_payload",
                f"unsupported semantic field: {sorted(unknown)[0]}",
            )


def parse_fastboot_partition_list(*outputs: str) -> tuple[PartitionInfo, ...]:
    """Parse allow-listed ``getvar all`` partition metadata.

    Fastboot commonly writes ``getvar`` output to stderr, so callers may pass
    stdout and stderr independently.  Unknown or malformed partition rows are
    ignored rather than becoming future command targets.
    """

    records: dict[str, dict[str, object]] = {}
    for output in outputs:
        if not isinstance(output, str):
            continue
        for raw_line in output.splitlines():
            match = _PARTITION_VARIABLE.search(raw_line.strip())
            if match is None:
                continue
            partition = match.group("partition").casefold()
            if partition not in ALLOWED_PARTITIONS:
                continue
            record = records.setdefault(
                partition,
                {"size_bytes": None, "partition_type": ""},
            )
            value = match.group("value").strip()
            if match.group("field").casefold() == "type":
                if re.fullmatch(r"[A-Za-z0-9_.-]+", value):
                    record["partition_type"] = value.casefold()
                continue
            try:
                size = int(value, 0)
            except ValueError:
                continue
            if size >= 0:
                record["size_bytes"] = size

    return tuple(
        PartitionInfo(
            partition,
            size_bytes=records[partition]["size_bytes"],  # type: ignore[arg-type]
            partition_type=str(records[partition]["partition_type"]),
        )
        for partition in sorted(records, key=str.casefold)
    )


__all__ = [
    "ALLOWED_PARTITIONS",
    "PARTITION_COMMANDS",
    "PartitionCompilation",
    "PartitionInfo",
    "PartitionPlanningError",
    "PartitionReadDecision",
    "PartitionReadEvidence",
    "PartitionService",
    "parse_fastboot_partition_list",
]
