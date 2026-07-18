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
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    FileArtifact,
    OperationPlan,
    ProcessRequest,
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
    | {
        f"{partition}_{slot}"
        for partition in _SLOT_CAPABLE_PARTITIONS
        for slot in ("a", "b")
    }
)

_PARTITION_VARIABLE = re.compile(
    r"(?:^|\s)partition-(?P<field>size|type):"
    r"(?P<partition>[A-Za-z0-9_.-]+):\s*(?P<value>\S+)",
    re.IGNORECASE,
)


class PartitionPlanningError(ValueError):
    """A stable, typed failure raised before any process can be started."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


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

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "destructive": self.destructive,
            "requires_confirmation": self.requires_confirmation,
            "reinforced_confirmation": self.reinforced_confirmation,
            "plan": self.plan.to_dict(),
        }


class PartitionService:
    """Compile trusted fastboot partition plans from canonical app state."""

    def __init__(self, *, hash_chunk_size: int = 1024 * 1024) -> None:
        if hash_chunk_size <= 0:
            raise ValueError("hash_chunk_size must be positive")
        self.hash_chunk_size = hash_chunk_size

    def compile(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
    ) -> PartitionCompilation:
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
            return self._compile_write(command, snapshot, device, fastboot)
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
        destination = self._output_path(
            command.payload.get("destination"),
            overwrite=overwrite,
        )
        request = ProcessRequest(
            (fastboot, "-s", device.serial, "fetch", partition, str(destination)),
            timeout_seconds=900.0,
        )
        return PartitionCompilation(
            self._base_plan(
                snapshot,
                device,
                (request,),
                label=f"Read {partition} from {device.serial}",
                partitions=(partition,),
            ),
            "read",
        )

    def _compile_write(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        fastboot: str,
    ) -> PartitionCompilation:
        self._validate_payload(command, {"serial", "partition", "path"})
        partition = self._partition(command.payload.get("partition"))
        path = self._input_path(command.payload.get("path"))
        artifact = FileArtifact(
            str(path),
            self._sha256(path),
            f"partition:{partition}",
        )
        request = ProcessRequest(
            (fastboot, "-s", device.serial, "flash", partition, str(path)),
            timeout_seconds=900.0,
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
            ),
            "write",
            destructive=True,
            requires_confirmation=True,
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
            ),
            "erase",
            destructive=True,
            requires_confirmation=True,
            reinforced_confirmation=True,
        )

    def _sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        try:
            with path.open("rb") as stream:
                while chunk := stream.read(self.hash_chunk_size):
                    digest.update(chunk)
        except OSError as error:
            raise PartitionPlanningError(
                "partition_image_read_failed",
                str(error),
            ) from error
        return digest.hexdigest()

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
        if device.mode != "fastboot":
            raise PartitionPlanningError(
                "fastboot_required",
                "partition operations require the target in fastboot mode",
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
    def _input_path(raw_path: object) -> Path:
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise PartitionPlanningError(
                "partition_image_path_required",
                "an existing local image path is required",
            )
        try:
            path = Path(raw_path).expanduser().resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise PartitionPlanningError(
                "partition_image_path_invalid",
                str(error),
            ) from error
        if not path.is_file():
            raise PartitionPlanningError(
                "partition_image_path_invalid",
                "the selected partition image must be an existing regular file",
            )
        return path

    @staticmethod
    def _output_path(raw_path: object, *, overwrite: bool) -> Path:
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise PartitionPlanningError(
                "partition_destination_required",
                "a local destination path is required",
            )
        try:
            path = Path(raw_path).expanduser().resolve(strict=False)
            parent = path.parent.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise PartitionPlanningError(
                "partition_destination_invalid",
                str(error),
            ) from error
        # Resolve the final parent independently so a missing/symlinked parent
        # can never redirect fastboot outside the path validated here.
        canonical = parent / path.name
        if not path.name or not parent.is_dir():
            raise PartitionPlanningError(
                "partition_destination_invalid",
                "the destination parent must be an existing local directory",
            )
        if canonical.exists():
            if not canonical.is_file():
                raise PartitionPlanningError(
                    "partition_destination_invalid",
                    "the destination must be a regular file",
                )
            if not overwrite:
                raise PartitionPlanningError(
                    "partition_destination_exists",
                    "destination exists; explicit overwrite=true is required",
                )
        elif canonical.is_symlink():
            # Broken links are not safe output targets and ``exists`` is false
            # for them.
            raise PartitionPlanningError(
                "partition_destination_invalid",
                "the destination cannot be a broken symbolic link",
            )
        if not os.access(parent, os.W_OK):
            raise PartitionPlanningError(
                "partition_destination_not_writable",
                "the destination directory is not writable",
            )
        return canonical

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
    ) -> OperationPlan:
        return OperationPlan(
            requests=requests,
            label=label,
            target_serial=device.serial,
            expected_device_state=device.mode,
            firmware_hash=snapshot.firmware.hash,
            boot_hash=snapshot.boot.hash,
            partitions=partitions,
            data_behavior=data_behavior,
            plan_revision=snapshot.plan.revision,
            fingerprint=snapshot.plan.fingerprint,
            artifacts=artifacts,
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
    "PartitionService",
    "parse_fastboot_partition_list",
]
