"""Headless, shell-free planning for bounded partition backups.

Only a deliberately small set of boot-chain partitions is accepted.  Backup
creation uses either ``adb pull`` from a fixed ``/dev/block/by-name`` path or
the standard fastboot ``fetch`` verb, depending on canonical device state.
Restore is restricted to fastboot ``flash`` and is always marked destructive
and confirmation-required.  Browser payloads can never provide argv, remote
paths, commands, hashes, or overwrite flags.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    FileArtifact,
    OperationPlan,
    OperationPostcondition,
    OperationRisk,
    ProcessRequest,
    root_shell_argv,
)
from .path_compat import is_reserved_path

BACKUP_COMMANDS = frozenset(
    {
        "backups.create",
        "backups.restore",
        "backups.magisk.list",
        "backups.magisk.import",
        "backups.magisk.delete",
    }
)

# These are bounded boot-chain images which can be represented by one raw
# image and one exact A/B target.  Dynamic partitions, userdata, metadata and
# radio/bootloader firmware are intentionally outside this service.
SUPPORTED_BACKUP_PARTITIONS = frozenset(
    {
        "boot",
        "dtbo",
        "init_boot",
        "recovery",
        "vbmeta",
        "vbmeta_system",
        "vbmeta_vendor",
        "vendor_boot",
        "vendor_kernel_boot",
    }
)

_SLOTS = frozenset({"a", "b"})
_BACKUP_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.img$")
_MAGISK_SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_MAGISK_LIST_PREFIX = "PF_MB"
_MAX_MAGISK_BACKUPS = 256
_MAX_MAGISK_IMAGE_BYTES = 512 * 1024 * 1024
_MAX_MAGISK_ARCHIVE_BYTES = 1024 * 1024 * 1024


class CancellationProbe(Protocol):
    @property
    def cancelled(self) -> bool: ...


class BackupPlanningError(ValueError):
    """A stable, typed failure raised before a backup process can start."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class MagiskBackupInfo:
    sha1: str
    size_bytes: int
    created_at: int
    integrity: str

    def to_dict(self) -> dict[str, object]:
        return {
            "sha1": self.sha1,
            "sizeBytes": self.size_bytes,
            "createdAt": self.created_at,
            "integrity": self.integrity,
        }


@dataclass(frozen=True, slots=True)
class BackupCompilation:
    """Compiled backup plan plus backend-owned safety metadata."""

    plan: OperationPlan
    action: str
    partition: str
    output_path: str | None = None
    backup_id: str | None = None
    magisk_sha1: str | None = None
    device_write: bool = False
    destructive: bool = False
    requires_confirmation: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "partition": self.partition,
            "output_path": self.output_path,
            "backup_id": self.backup_id,
            "magisk_sha1": self.magisk_sha1,
            "device_write": self.device_write,
            "destructive": self.destructive,
            "requires_confirmation": self.requires_confirmation,
            "plan": self.plan.to_dict(),
        }


class BackupService:
    """Compile safe partition backup and restore plans from canonical state."""

    def __init__(self, *, hash_chunk_size: int = 1024 * 1024) -> None:
        if not isinstance(hash_chunk_size, int) or isinstance(hash_chunk_size, bool):
            raise TypeError("hash_chunk_size must be an integer")
        if hash_chunk_size <= 0:
            raise ValueError("hash_chunk_size must be positive")
        self.hash_chunk_size = hash_chunk_size

    def compile(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        cancellation: CancellationProbe | None = None,
    ) -> BackupCompilation:
        self._check_cancelled(cancellation)
        if command.kind not in BACKUP_COMMANDS:
            raise BackupPlanningError(
                "backup_command_unsupported",
                f"unsupported backup command: {command.kind}",
            )
        self._revision(command, snapshot)
        device = self._device(command, snapshot)
        if command.kind == "backups.create":
            return self._compile_create(command, snapshot, device)
        if command.kind == "backups.restore":
            return self._compile_restore(command, snapshot, device, cancellation)
        if command.kind == "backups.magisk.list":
            return self._compile_magisk_list(command, snapshot, device)
        if command.kind == "backups.magisk.import":
            return self._compile_magisk_import(
                command,
                snapshot,
                device,
                cancellation,
            )
        return self._compile_magisk_delete(command, snapshot, device)

    def _compile_magisk_list(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
    ) -> BackupCompilation:
        self._validate_payload(command, {"serial"})
        adb = self._magisk_adb(snapshot, device)
        script = (
            "count=0; for dir in /data/magisk_backup_*; do "
            '[ -d "$dir" ] || continue; id=${dir#/data/magisk_backup_}; '
            'case "$id" in *[!0-9A-Fa-f]*|\'\') continue;; esac; '
            '[ "${#id}" -eq 40 ] || continue; file="$dir/boot.img.gz"; '
            'if [ -f "$file" ]; then '
            'size=$(stat -c %s "$file" 2>/dev/null || echo 0); '
            'stamp=$(stat -c %Y "$dir" 2>/dev/null || echo 0); '
            'actual=$(gzip -dc "$file" 2>/dev/null | sha1sum | cut -d " " -f 1); '
            'else size=0; stamp=0; actual=missing; fi; '
            f'printf "{_MAGISK_LIST_PREFIX}|%s|%s|%s|%s\\n" "$id" "$size" "$stamp" "$actual"; '
            f'count=$((count + 1)); [ "$count" -lt {_MAX_MAGISK_BACKUPS} ] || break; '
            "done"
        )
        plan = self._base_plan(
            snapshot,
            device,
            (
                ProcessRequest(
                    root_shell_argv(adb, device.serial, script),
                    timeout_seconds=120.0,
                    output_limit_bytes=128 * 1024,
                ),
            ),
            label=f"List Magisk backups on {device.serial}",
            partitions=(),
            slots=(),
        )
        return BackupCompilation(plan, "magisk.list", partition="")

    def _compile_magisk_import(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        cancellation: CancellationProbe | None,
    ) -> BackupCompilation:
        self._validate_payload(command, {"serial", "path"})
        adb = self._magisk_adb(snapshot, device)
        path = self._input_path(command.payload.get("path"))
        sha1, sha256 = self._source_digests(path, cancellation)
        nonce = hashlib.sha256(command.operation_id.encode("utf-8")).hexdigest()[:24]
        remote = f"/data/local/tmp/pixelflasher-magisk-{nonce}.img"
        script = (
            f'staging={remote}; expected={sha1}; '
            'trap \'rm -f "$staging"\' EXIT; '
            'actual=$(sha1sum "$staging" | cut -d " " -f 1) || exit 81; '
            '[ "$actual" = "$expected" ] || exit 82; '
            'cp "$staging" /data/adb/magisk/stock_boot.img || exit 83; '
            'cd /data/adb/magisk || exit 84; '
            './magiskboot cleanup >/dev/null 2>&1 || true; '
            '. ./util_functions.sh || exit 85; run_migrations'
        )
        artifact = FileArtifact(str(path), sha256, "magisk-stock-boot")
        plan = self._base_plan(
            snapshot,
            device,
            (
                ProcessRequest(
                    (adb, "-s", device.serial, "push", str(path), remote),
                    timeout_seconds=600.0,
                    output_limit_bytes=64 * 1024,
                ),
                ProcessRequest(
                    root_shell_argv(adb, device.serial, script),
                    timeout_seconds=300.0,
                    output_limit_bytes=64 * 1024,
                ),
            ),
            label=f"Import Magisk backup {sha1[:12]} on {device.serial}",
            partitions=("magisk_backup",),
            slots=(),
            artifacts=(artifact,),
            risk=OperationRisk.MUTATING,
            postconditions=(
                OperationPostcondition(
                    "magisk_backup_state",
                    {"sha1": sha1, "state": "verified"},
                    "the on-device Magisk backup decompresses to the selected stock image",
                ),
            ),
        )
        return BackupCompilation(
            plan,
            "magisk.import",
            partition="magisk_backup",
            magisk_sha1=sha1,
            device_write=True,
            requires_confirmation=True,
        )

    def _compile_magisk_delete(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
    ) -> BackupCompilation:
        self._validate_payload(command, {"serial", "sha1", "confirmationText"})
        adb = self._magisk_adb(snapshot, device)
        sha1 = self._magisk_sha1(command.payload.get("sha1"))
        required = self.required_magisk_delete_confirmation(sha1, device.serial)
        if command.payload.get("confirmationText") != required:
            raise BackupPlanningError(
                "magisk_backup_delete_confirmation_required",
                f"type {required} to delete this Magisk backup",
            )
        target = f"/data/magisk_backup_{sha1}"
        script = (
            f'target={target}; [ -d "$target" ] || exit 86; '
            'rm -rf -- "$target"'
        )
        plan = self._base_plan(
            snapshot,
            device,
            (
                ProcessRequest(
                    root_shell_argv(adb, device.serial, script),
                    timeout_seconds=120.0,
                    output_limit_bytes=64 * 1024,
                ),
            ),
            label=f"Delete Magisk backup {sha1[:12]} on {device.serial}",
            partitions=("magisk_backup",),
            slots=(),
            data_behavior="magisk_backup_delete",
            risk=OperationRisk.DESTRUCTIVE,
            postconditions=(
                OperationPostcondition(
                    "magisk_backup_state",
                    {"sha1": sha1, "state": "absent"},
                    "the selected Magisk backup directory is absent",
                ),
            ),
        )
        return BackupCompilation(
            plan,
            "magisk.delete",
            partition="magisk_backup",
            magisk_sha1=sha1,
            device_write=True,
            destructive=True,
            requires_confirmation=True,
        )

    def _compile_create(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
    ) -> BackupCompilation:
        self._validate_payload(command, {"serial", "partition", "slot", "destination"})
        partition, slot, target = self._target_partition(command)
        destination = self._output_path(command.payload.get("destination"))

        if device.mode == "adb":
            if not device.root:
                raise BackupPlanningError(
                    "backup_root_required",
                    "ADB partition backup requires a device reporting root access",
                )
            executable = self._adb(snapshot)
            argv = (
                executable,
                "-s",
                device.serial,
                "pull",
                f"/dev/block/by-name/{target}",
                str(destination),
            )
        elif device.mode == "fastboot":
            executable = self._fastboot(snapshot)
            argv = (
                executable,
                "-s",
                device.serial,
                "fetch",
                target,
                str(destination),
            )
        else:
            raise BackupPlanningError(
                "backup_state_unsupported",
                "partition backup is supported only in rooted adb or fastboot mode",
            )

        request = ProcessRequest(argv, timeout_seconds=900.0)
        plan = self._base_plan(
            snapshot,
            device,
            (request,),
            label=f"Back up {target} from {device.serial}",
            partitions=(target,),
            slots=(slot,),
        )
        return BackupCompilation(
            plan,
            "create",
            partition,
            output_path=str(destination),
        )

    def _compile_restore(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        cancellation: CancellationProbe | None,
    ) -> BackupCompilation:
        self._validate_payload(command, {"serial", "partition", "slot", "path"})
        partition, slot, target = self._target_partition(command)
        if device.mode != "fastboot":
            raise BackupPlanningError(
                "restore_state_unsupported",
                "partition restore requires the target device in fastboot mode",
            )
        executable = self._fastboot(snapshot)
        path = self._input_path(command.payload.get("path"))
        artifact = FileArtifact(
            str(path),
            self._sha256(path, cancellation),
            f"backup:{target}",
        )
        request = ProcessRequest(
            (executable, "-s", device.serial, "flash", target, str(path)),
            timeout_seconds=900.0,
        )
        plan = self._base_plan(
            snapshot,
            device,
            (request,),
            label=f"Restore {target} on {device.serial}",
            partitions=(target,),
            slots=(slot,),
            data_behavior="partition_restore",
            artifacts=(artifact,),
            risk=OperationRisk.DESTRUCTIVE,
            postconditions=(
                OperationPostcondition(
                    "partition_written",
                    {
                        "partition": target,
                        "slot": "",
                        "sha256": artifact.sha256,
                        "sourcePartition": partition,
                        "sourceSlot": slot,
                    },
                    "the restored partition contains the selected backup image",
                ),
            ),
        )
        return BackupCompilation(
            plan,
            "restore",
            partition,
            device_write=True,
            destructive=True,
            requires_confirmation=True,
        )

    @staticmethod
    def _magisk_adb(snapshot: AppSnapshot, device: DeviceInfo) -> str:
        if device.mode != "adb" or not device.root:
            raise BackupPlanningError(
                "magisk_backup_root_required",
                "Magisk backups require one rooted device in ADB mode",
            )
        return BackupService._adb(snapshot)

    @staticmethod
    def _magisk_sha1(value: object) -> str:
        if not isinstance(value, str):
            raise BackupPlanningError(
                "magisk_backup_sha1_invalid",
                "Magisk backup SHA-1 must be a lowercase hexadecimal string",
            )
        sha1 = value.strip().casefold()
        if _MAGISK_SHA1_PATTERN.fullmatch(sha1) is None:
            raise BackupPlanningError(
                "magisk_backup_sha1_invalid",
                "Magisk backup SHA-1 must contain exactly 40 hexadecimal characters",
            )
        return sha1

    @staticmethod
    def required_magisk_delete_confirmation(sha1: str, serial: str) -> str:
        normalized = BackupService._magisk_sha1(sha1)
        if not isinstance(serial, str) or not serial:
            raise BackupPlanningError(
                "target_serial_invalid",
                "target serial is required for Magisk backup deletion",
            )
        return f"DELETE MAGISK {normalized[-8:].upper()} {serial[-6:].upper()}"

    def _source_digests(
        self,
        path: Path,
        cancellation: CancellationProbe | None,
    ) -> tuple[str, str]:
        self._check_cancelled(cancellation)
        try:
            before = path.stat()
            if not 1 <= before.st_size <= _MAX_MAGISK_IMAGE_BYTES:
                raise BackupPlanningError(
                    "magisk_backup_image_size_invalid",
                    "Magisk backup source is outside the bounded boot-image size",
                )
            sha1 = hashlib.sha1(usedforsecurity=False)
            sha256 = hashlib.sha256()
            with path.open("rb") as stream:
                while chunk := stream.read(self.hash_chunk_size):
                    self._check_cancelled(cancellation)
                    sha1.update(chunk)
                    sha256.update(chunk)
            after = path.stat()
        except BackupPlanningError:
            raise
        except OSError as error:
            raise BackupPlanningError(
                "magisk_backup_hash_failed",
                str(error),
            ) from error
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after:
            raise BackupPlanningError(
                "magisk_backup_source_changed",
                "Magisk backup source changed while it was being hashed",
            )
        return sha1.hexdigest(), sha256.hexdigest()

    def finalize_created_backup(
        self,
        compilation: BackupCompilation,
        cancellation: CancellationProbe | None = None,
    ) -> FileArtifact:
        """Validate and hash a create output after its process succeeds.

        The output cannot be a plan input artifact because it does not exist at
        compile time.  This explicit finalization step gives the engine a
        canonical SHA-256 artifact without trusting process output or the UI.
        """

        self._check_cancelled(cancellation)
        if compilation.action != "create" or not compilation.output_path:
            raise BackupPlanningError(
                "backup_output_unavailable",
                "only a compiled create operation has a backup output",
            )
        expected = Path(compilation.output_path)
        try:
            path = expected.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise BackupPlanningError("backup_output_missing", str(error)) from error
        if path != expected or not path.is_file():
            raise BackupPlanningError(
                "backup_output_invalid",
                "created backup is not the canonical regular file selected by the plan",
            )
        try:
            output_size = path.stat().st_size
        except OSError as error:
            raise BackupPlanningError("backup_output_invalid", str(error)) from error
        if output_size <= 0:
            raise BackupPlanningError(
                "backup_output_empty",
                "the backup process produced an empty partition image",
            )
        target = compilation.plan.partitions[0]
        return FileArtifact(
            str(path),
            self._sha256(path, cancellation),
            f"backup:{target}",
        )

    @staticmethod
    def _target_partition(command: AppCommand) -> tuple[str, str, str]:
        raw_partition = command.payload.get("partition")
        if not isinstance(raw_partition, str):
            raise BackupPlanningError(
                "backup_partition_required",
                "partition must be a string",
            )
        partition = raw_partition.strip().casefold()
        if partition not in SUPPORTED_BACKUP_PARTITIONS:
            raise BackupPlanningError(
                "backup_partition_not_allowed",
                f"partition is not supported for backup: {partition}",
            )
        raw_slot = command.payload.get("slot")
        if not isinstance(raw_slot, str):
            raise BackupPlanningError(
                "backup_slot_required",
                "an explicit slot a or b is required",
            )
        slot = raw_slot.strip().casefold()
        if slot not in _SLOTS:
            raise BackupPlanningError(
                "backup_slot_invalid",
                "slot must be exactly a or b",
            )
        return partition, slot, f"{partition}_{slot}"

    @staticmethod
    def _input_path(raw_path: object) -> Path:
        raw, expanded = BackupService._absolute_path(raw_path, field="path")
        BackupService._reject_parent_traversal(raw)
        try:
            path = expanded.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise BackupPlanningError("backup_image_path_invalid", str(error)) from error
        if not path.is_file() or path.suffix.casefold() != ".img":
            raise BackupPlanningError(
                "backup_image_path_invalid",
                "restore source must be an existing regular .img file",
            )
        try:
            if path.stat().st_size <= 0:
                raise BackupPlanningError(
                    "backup_image_empty",
                    "restore source must not be an empty image",
                )
        except OSError as error:
            raise BackupPlanningError("backup_image_path_invalid", str(error)) from error
        return path

    @staticmethod
    def _output_path(raw_path: object) -> Path:
        raw, expanded = BackupService._absolute_path(raw_path, field="destination")
        BackupService._reject_parent_traversal(raw)
        if not _BACKUP_NAME_PATTERN.fullmatch(expanded.name) or is_reserved_path(expanded):
            raise BackupPlanningError(
                "backup_destination_invalid",
                "destination must use a safe ASCII .img file name",
            )
        try:
            parent = expanded.parent.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise BackupPlanningError("backup_destination_invalid", str(error)) from error
        if not parent.is_dir():
            raise BackupPlanningError(
                "backup_destination_invalid",
                "destination parent must be an existing local directory",
            )
        canonical = parent / expanded.name
        if os.path.lexists(canonical):
            raise BackupPlanningError(
                "backup_destination_exists",
                "backup creation never overwrites an existing path",
            )
        if not os.access(parent, os.W_OK):
            raise BackupPlanningError(
                "backup_destination_not_writable",
                "destination directory is not writable",
            )
        return canonical

    @staticmethod
    def _absolute_path(raw_path: object, *, field: str) -> tuple[Path, Path]:
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise BackupPlanningError(
                "backup_path_required",
                f"an absolute local {field} is required",
            )
        try:
            raw = Path(raw_path)
            expanded = raw.expanduser()
        except (OSError, RuntimeError, ValueError) as error:
            raise BackupPlanningError("backup_path_invalid", str(error)) from error
        if not expanded.is_absolute():
            raise BackupPlanningError(
                "backup_path_not_absolute",
                f"{field} must be an absolute path",
            )
        return raw, expanded

    @staticmethod
    def _reject_parent_traversal(path: Path) -> None:
        if ".." in path.parts:
            raise BackupPlanningError(
                "backup_path_traversal",
                "parent-directory traversal is not accepted in backup paths",
            )

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
        except BackupPlanningError:
            raise
        except OSError as error:
            raise BackupPlanningError("backup_hash_failed", str(error)) from error
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after:
            raise BackupPlanningError(
                "backup_hash_changed",
                f"backup image changed while it was being hashed: {path}",
            )
        return digest.hexdigest()

    @staticmethod
    def _check_cancelled(cancellation: CancellationProbe | None) -> None:
        if cancellation is not None and cancellation.cancelled:
            raise BackupPlanningError(
                "backup_cancelled",
                "backup planning was cancelled",
            )

    @staticmethod
    def _revision(command: AppCommand, snapshot: AppSnapshot) -> None:
        if command.expected_revision is None:
            raise BackupPlanningError(
                "revision_required",
                "expected_revision is required",
            )
        if command.expected_revision != snapshot.revision:
            raise BackupPlanningError(
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
            raise BackupPlanningError(
                "target_serial_invalid",
                "payload.serial must be a non-empty string",
            )
        payload_serial = raw_serial.strip() if isinstance(raw_serial, str) else None
        if command.target_serial and payload_serial and command.target_serial != payload_serial:
            raise BackupPlanningError(
                "ambiguous_target_serial",
                "command and payload target different devices",
            )
        serial = command.target_serial or payload_serial or snapshot.selected_serial
        if not serial:
            raise BackupPlanningError(
                "target_serial_required",
                "one selected device is required",
            )
        if serial not in snapshot.selected_serials:
            raise BackupPlanningError(
                "target_serial_changed",
                "target serial is no longer selected",
            )
        device = next((item for item in snapshot.devices if item.serial == serial), None)
        if device is None or not device.online:
            raise BackupPlanningError(
                "device_disconnected",
                "target device is not online",
            )
        return device

    @staticmethod
    def _adb(snapshot: AppSnapshot) -> str:
        if not snapshot.toolchain.ready or not snapshot.toolchain.adb:
            raise BackupPlanningError(
                "toolchain_not_ready",
                "validated adb is required for this backup state",
            )
        return snapshot.toolchain.adb

    @staticmethod
    def _fastboot(snapshot: AppSnapshot) -> str:
        if not snapshot.toolchain.ready or not snapshot.toolchain.fastboot:
            raise BackupPlanningError(
                "toolchain_not_ready",
                "validated fastboot is required for this backup state",
            )
        return snapshot.toolchain.fastboot

    @staticmethod
    def _base_plan(
        snapshot: AppSnapshot,
        device: DeviceInfo,
        requests: tuple[ProcessRequest, ...],
        *,
        label: str,
        partitions: tuple[str, ...],
        slots: tuple[str, ...],
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
            slots=slots,
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
            raise BackupPlanningError(
                "invalid_backup_payload",
                f"unsupported semantic field: {sorted(unknown)[0]}",
            )


def parse_magisk_backup_list(output: str) -> tuple[MagiskBackupInfo, ...]:
    if not isinstance(output, str):
        raise BackupPlanningError(
            "magisk_backup_list_invalid",
            "Magisk backup inventory output must be text",
        )
    if len(output.encode("utf-8", errors="replace")) > 128 * 1024:
        raise BackupPlanningError(
            "magisk_backup_list_oversized",
            "Magisk backup inventory exceeded its output bound",
        )
    lines = tuple(line.strip() for line in output.splitlines() if line.strip())
    if len(lines) > _MAX_MAGISK_BACKUPS:
        raise BackupPlanningError(
            "magisk_backup_list_oversized",
            "Magisk backup inventory contains too many records",
        )
    records: list[MagiskBackupInfo] = []
    seen: set[str] = set()
    for line in lines:
        fields = line.split("|")
        if len(fields) != 5 or fields[0] != _MAGISK_LIST_PREFIX:
            raise BackupPlanningError(
                "magisk_backup_list_malformed",
                "Magisk backup inventory contains an invalid record",
            )
        sha1 = fields[1].casefold()
        if _MAGISK_SHA1_PATTERN.fullmatch(sha1) is None or sha1 in seen:
            raise BackupPlanningError(
                "magisk_backup_list_malformed",
                "Magisk backup inventory contains an invalid or duplicate SHA-1",
            )
        try:
            size = int(fields[2], 10)
            created_at = int(fields[3], 10)
        except ValueError as error:
            raise BackupPlanningError(
                "magisk_backup_list_malformed",
                "Magisk backup inventory size or timestamp is invalid",
            ) from error
        if not 0 <= size <= _MAX_MAGISK_ARCHIVE_BYTES or not 0 <= created_at <= 4_294_967_295:
            raise BackupPlanningError(
                "magisk_backup_list_malformed",
                "Magisk backup inventory values are outside their bounds",
            )
        actual = fields[4].casefold()
        if actual != "missing" and _MAGISK_SHA1_PATTERN.fullmatch(actual) is None:
            raise BackupPlanningError(
                "magisk_backup_list_malformed",
                "Magisk backup integrity evidence is invalid",
            )
        records.append(
            MagiskBackupInfo(
                sha1,
                size,
                created_at,
                "verified" if actual == sha1 and size > 0 else "corrupt",
            )
        )
        seen.add(sha1)
    return tuple(sorted(records, key=lambda item: (-item.created_at, item.sha1)))


__all__ = [
    "BACKUP_COMMANDS",
    "SUPPORTED_BACKUP_PARTITIONS",
    "BackupCompilation",
    "BackupPlanningError",
    "BackupService",
    "MagiskBackupInfo",
    "parse_magisk_backup_list",
]
