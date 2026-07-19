"""Compile semantic bridge commands into immutable, shell-free operation plans."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

from .bootloader import BootloaderLockPolicy
from .contracts import (
    OPERATION_PLAN_TTL_SECONDS,
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    FileArtifact,
    OperationBatch,
    OperationPlan,
    OperationPostcondition,
    OperationRisk,
    ProcessRequest,
    confirmation_serial_suffix,
)
from .safety import SafetyPolicy

PLANNED_COMMANDS = frozenset(
    {
        "device.reboot",
        "device.switchSlot",
        "device.bootloader.lock",
        "device.bootloader.unlock",
        "boot.flash",
        "boot.live",
        "flash.execute",
    }
)

_FASTBOOT_PARTITION_ORDER = (
    # Factory firmware components are staged separately and must stay first.
    "bootloader",
    "radio",
    # Remaining image partitions use a backend-owned canonical order. Browser
    # payload order and alphabetical sorting can never move a factory stage.
    "boot",
    "init_boot",
    "vendor_boot",
    "vendor_kernel_boot",
    "recovery",
    "dtbo",
    "vbmeta",
    "vbmeta_system",
    "vbmeta_vendor",
    "super",
    "system",
    "system_ext",
    "product",
    "vendor",
    "odm",
    "odm_dlkm",
    "system_dlkm",
    "vendor_dlkm",
)
_FASTBOOT_PARTITIONS = frozenset(_FASTBOOT_PARTITION_ORDER)
_FACTORY_COMPONENT_ORDER = ("bootloader", "radio")
_ADB_STATES = frozenset({"adb", "recovery", "sideload"})
_DRY_RUN_MODES = frozenset({"dryrun", "dry-run", "dry_run"})
_OTA_MODES = frozenset({"ota", "sideload"})
_IMAGE_MODES = frozenset(
    {"customflash", "images", "factory", "keepdata", "keep", "wipedata", "wipe"}
)


class PlanningError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PlanCompilation:
    plan: OperationPlan | None
    code: str = "ok"
    message: str = ""
    destructive: bool = False
    requires_confirmation: bool = False
    confirmation_text: str = ""
    confirmation_nonce: str = ""

    @property
    def ok(self) -> bool:
        return self.plan is not None and self.code == "ok"

    def to_dict(self) -> dict[str, object]:
        serialized_plan = self.plan.to_dict() if self.plan is not None else None
        if serialized_plan is not None:
            # A derived execution token is backend-only. Preview exposes the
            # nonce and exact human phrase, never the token itself.
            serialized_plan["confirmation_token"] = None
        return {
            "ok": self.ok,
            "code": self.code,
            "message": self.message,
            "destructive": self.destructive,
            "requires_confirmation": self.requires_confirmation,
            "plan": serialized_plan,
            "confirmation": {
                "required_text": self.confirmation_text,
                "nonce": self.confirmation_nonce,
            }
            if self.confirmation_text
            else None,
        }


@dataclass(frozen=True, slots=True)
class BatchCompilation:
    batch: OperationBatch | None
    code: str = "ok"
    message: str = ""
    destructive: bool = True
    requires_confirmation: bool = True
    confirmation_text: str = ""
    confirmation_nonce: str = ""

    @property
    def ok(self) -> bool:
        return self.batch is not None and self.code == "ok"

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "code": self.code,
            "message": self.message,
            "destructive": self.destructive,
            "requires_confirmation": self.requires_confirmation,
            "batch": self.batch.to_dict() if self.batch is not None else None,
            "confirmation": {
                "required_text": self.confirmation_text,
                "nonce": self.confirmation_nonce,
            }
            if self.confirmation_text
            else None,
        }


@dataclass(frozen=True, slots=True)
class ProcessedArtifactCheckpoint:
    firmware_hash: str
    plan_fingerprint: str
    existed: bool
    previous_artifacts: tuple[FileArtifact, ...] = ()
    artifact_ids: tuple[str, ...] = ()


class ProcessedArtifactRepository:
    """Backend-only registry of verified, extracted image artifacts."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._artifacts: dict[tuple[str, str], tuple[FileArtifact, ...]] = {}

    def register(
        self,
        artifacts: Sequence[FileArtifact],
        *,
        firmware_hash: str = "",
        plan_fingerprint: str = "",
    ) -> None:
        normalized = tuple(artifacts)
        if not normalized or any(not isinstance(item, FileArtifact) for item in normalized):
            raise ValueError("verified FileArtifact values are required")
        if not firmware_hash and not plan_fingerprint:
            raise ValueError("firmware_hash or plan_fingerprint is required")
        with self._lock:
            self._artifacts[(firmware_hash.casefold(), plan_fingerprint)] = normalized

    def resolve(self, snapshot: AppSnapshot) -> tuple[FileArtifact, ...]:
        keys = (
            (snapshot.firmware.hash.casefold(), snapshot.plan.fingerprint),
            (snapshot.firmware.hash.casefold(), ""),
            ("", snapshot.plan.fingerprint),
        )
        with self._lock:
            for key in keys:
                if key in self._artifacts:
                    return self._artifacts[key]
        return ()

    def checkpoint(
        self,
        *,
        firmware_hash: str = "",
        plan_fingerprint: str = "",
    ) -> ProcessedArtifactCheckpoint:
        key = (firmware_hash.casefold(), plan_fingerprint)
        with self._lock:
            previous = self._artifacts.get(key)
        return ProcessedArtifactCheckpoint(
            firmware_hash=key[0],
            plan_fingerprint=key[1],
            existed=previous is not None,
            previous_artifacts=previous or (),
        )

    def rollback(self, checkpoint: ProcessedArtifactCheckpoint) -> None:
        if not isinstance(checkpoint, ProcessedArtifactCheckpoint):
            raise TypeError("processed artifact checkpoint is required")
        key = (checkpoint.firmware_hash, checkpoint.plan_fingerprint)
        with self._lock:
            if checkpoint.existed:
                self._artifacts[key] = checkpoint.previous_artifacts
            else:
                self._artifacts.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._artifacts.clear()


class OperationPlanner:
    """Trusted compiler: payloads express intent but can never provide argv."""

    def __init__(
        self,
        *,
        confirmation_secret: bytes | None = None,
        hash_chunk_size: int = 1024 * 1024,
        artifact_repository: ProcessedArtifactRepository | None = None,
        bootloader_lock_policy: BootloaderLockPolicy | None = None,
        challenge_ttl_seconds: float = 300.0,
        maximum_pending_challenges: int = 128,
        clock: Callable[[], float] = time.time,
        challenge_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if hash_chunk_size <= 0:
            raise ValueError("hash_chunk_size must be positive")
        if challenge_ttl_seconds <= 0 or maximum_pending_challenges <= 0:
            raise ValueError("challenge limits must be positive")
        self._confirmation_secret = confirmation_secret or secrets.token_bytes(32)
        self.hash_chunk_size = hash_chunk_size
        self.artifact_repository = artifact_repository or ProcessedArtifactRepository()
        self.bootloader_lock_policy = bootloader_lock_policy or BootloaderLockPolicy()
        self.challenge_ttl_seconds = challenge_ttl_seconds
        self.maximum_pending_challenges = maximum_pending_challenges
        self.clock = clock
        self._challenge_clock = challenge_clock
        self._challenge_lock = threading.RLock()
        self._issued_challenges: OrderedDict[str, float] = OrderedDict()

    def compile(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        *,
        preview: bool = False,
    ) -> PlanCompilation:
        if command.kind not in PLANNED_COMMANDS:
            return PlanCompilation(None, "planner_not_supported", f"unsupported command: {command.kind}")
        if command.expected_revision is None:
            return PlanCompilation(None, "revision_required", "expected_revision is required")
        if command.expected_revision != snapshot.revision:
            return PlanCompilation(
                None,
                "stale_revision",
                (
                    f"state revision changed: expected {command.expected_revision}, "
                    f"current {snapshot.revision}"
                ),
            )
        if "confirmationToken" in command.payload or "confirmation_token" in command.payload:
            return PlanCompilation(
                None,
                "untrusted_confirmation_token",
                "confirmation tokens are derived only by the backend",
            )
        try:
            if command.kind == "device.reboot":
                plan, destructive, confirmation = self._reboot(command, snapshot)
            elif command.kind == "device.switchSlot":
                plan, destructive, confirmation = self._switch_slot(command, snapshot)
            elif command.kind in {"device.bootloader.lock", "device.bootloader.unlock"}:
                plan, destructive, confirmation = self._bootloader(command, snapshot)
            elif command.kind == "boot.flash":
                plan, destructive, confirmation = self._boot_flash(command, snapshot)
            elif command.kind == "boot.live":
                plan, destructive, confirmation = self._boot_live(command, snapshot)
            else:
                plan, destructive, confirmation = self._flash(command, snapshot)
        except PlanningError as error:
            return PlanCompilation(None, error.code, str(error))

        planned_command = replace(
            command,
            operation_plan=plan,
            destructive=destructive,
            requires_confirmation=confirmation,
        )
        reinforced = SafetyPolicy.requires_reinforced_confirmation(planned_command)
        if not reinforced:
            return PlanCompilation(plan, destructive=destructive, requires_confirmation=confirmation)
        return self._bind_reinforced_confirmation(
            command,
            snapshot,
            plan,
            destructive,
            confirmation,
            preview,
        )

    def compile_batch(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        *,
        preview: bool = False,
    ) -> BatchCompilation:
        """Compile one ordered flash plan per selected serial.

        Batch compilation deliberately supports only ``flash.execute``.  A
        single batch-level challenge covers the stable fingerprint of every
        per-device plan; browser-supplied plans, fingerprints and tokens are
        never accepted.
        """

        if command.kind != "flash.execute":
            return BatchCompilation(
                None,
                "batch_kind_not_supported",
                "OperationBatch supports only flash.execute",
            )
        if command.expected_revision is None:
            return BatchCompilation(None, "revision_required", "expected_revision is required")
        if command.expected_revision != snapshot.revision:
            return BatchCompilation(
                None,
                "stale_revision",
                (
                    f"state revision changed: expected {command.expected_revision}, "
                    f"current {snapshot.revision}"
                ),
            )
        if command.target_serial is not None or "serial" in command.payload:
            return BatchCompilation(
                None,
                "batch_target_not_allowed",
                "batch targets are derived from the canonical selected serials",
            )
        if any(
            key in command.payload
            for key in ("confirmationToken", "confirmation_token", "fingerprint", "plans")
        ):
            return BatchCompilation(
                None,
                "untrusted_batch_metadata",
                "batch plans, fingerprints and confirmation tokens are backend-owned",
            )
        unknown = set(command.payload) - {"confirmationText"}
        if unknown:
            return BatchCompilation(
                None,
                "invalid_plan_payload",
                f"unsupported semantic field: {sorted(unknown)[0]}",
            )
        if len(snapshot.selected_serials) < 2:
            return BatchCompilation(
                None,
                "batch_targets_required",
                "at least two selected devices are required for a flash batch",
            )

        plans: list[OperationPlan] = []
        for serial in snapshot.selected_serials:
            per_device = replace(
                command,
                target_serial=serial,
                payload={},
                operation_plan=None,
                destructive=False,
                requires_confirmation=False,
            )
            try:
                plan, destructive, requires_confirmation = self._flash(per_device, snapshot)
            except PlanningError as error:
                return BatchCompilation(
                    None,
                    error.code,
                    f"{serial}: {error}",
                )
            if not destructive or not requires_confirmation or plan.dry_run:
                return BatchCompilation(
                    None,
                    "batch_plan_not_destructive",
                    "flash batches require destructive, non-dry-run plans",
                )
            plans.append(
                replace(
                    plan,
                    confirmation_nonce=None,
                    confirmation_token=None,
                    risk=OperationRisk.DESTRUCTIVE,
                )
            )
        try:
            created = self.clock()
            batch = OperationBatch(
                tuple(plans),
                created=created,
                expires=min(
                    created + OPERATION_PLAN_TTL_SECONDS,
                    *(plan.expires for plan in plans),
                ),
            )
        except (TypeError, ValueError) as error:
            return BatchCompilation(None, "batch_invalid", str(error))
        return self._bind_batch_confirmation(command, snapshot, batch, preview)

    def revalidate(
        self,
        plan: OperationPlan,
        snapshot: AppSnapshot,
    ) -> tuple[str, str] | None:
        now = self.clock()
        if plan.expires <= now:
            return "plan_expired", "operation plan expired before execution"
        if plan.created > now + 1.0:
            return "plan_created_in_future", "operation plan creation time is invalid"
        if plan.target_serial:
            if plan.target_serial not in snapshot.selected_serials:
                return "target_serial_changed", "planned target is no longer selected"
            device = next(
                (item for item in snapshot.devices if item.serial == plan.target_serial),
                None,
            )
            if plan.expected_device_state or plan.expected_codename:
                if device is None:
                    return "device_disconnected", "planned target is no longer connected"
                if not device.online or device.mode in {"offline", "unauthorized"}:
                    return "device_disconnected", "planned target is not online"
            if plan.expected_codename and device is not None:
                if not device.codename:
                    return "device_codename_unavailable", "device codename is unavailable"
                if device.codename.casefold() != plan.expected_codename.casefold():
                    return "device_codename_changed", "device codename changed after planning"
            if plan.expected_device_state and device is not None:
                if device.mode != plan.expected_device_state:
                    return "device_state_changed", "device mode changed after planning"
        if plan.plan_revision != snapshot.plan.revision:
            return "plan_revision_changed", "canonical plan revision changed after planning"
        if plan.fingerprint != snapshot.plan.fingerprint:
            return "plan_fingerprint_changed", "canonical plan fingerprint changed after planning"
        if plan.firmware_hash != snapshot.firmware.hash:
            return "firmware_hash_changed", "selected firmware changed after planning"
        if plan.boot_hash != snapshot.boot.hash:
            return "boot_hash_changed", "selected boot image changed after planning"
        if (
            plan.snapshot_revision is not None
            and plan.snapshot_revision != snapshot.revision
        ):
            return "snapshot_revision_changed", "application revision changed after planning"
        for artifact in plan.artifacts:
            issue = self._revalidate_artifact(artifact)
            if issue is not None:
                return issue
        return None

    def _reboot(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
    ) -> tuple[OperationPlan, bool, bool]:
        self._validate_payload(command, {"serial", "mode", "confirmationText"})
        device = self._device(command, snapshot)
        target = command.payload.get("mode", "system")
        if not isinstance(target, str):
            raise PlanningError("invalid_reboot_mode", "reboot mode must be a string")
        target = target.strip().casefold()
        supported_targets = {
            "system",
            "recovery",
            "bootloader",
            "fastbootd",
            "sideload",
            "safemode",
            "download",
        }
        if target not in supported_targets:
            raise PlanningError("invalid_reboot_mode", f"unsupported reboot mode: {target}")

        if target == "download":
            # Android exposes no portable ADB/fastboot state for vendor
            # download modes.  The legacy path returned success after any
            # reconnect, which is precisely the false-positive contract the
            # modern runner forbids.
            raise PlanningError(
                "reboot_download_unverifiable",
                "download mode has no portable backend postcondition and is not supported",
            )

        adb = self._adb(snapshot) if device.mode in _ADB_STATES else None
        fastboot = (
            self._fastboot(snapshot)
            if device.mode in {"fastboot", "fastbootd"}
            else None
        )
        requests: tuple[ProcessRequest, ...]
        postconditions: tuple[OperationPostcondition, ...]

        if target == "safemode":
            if device.mode != "adb":
                raise PlanningError(
                    "safe_mode_adb_required",
                    "safe mode reboot requires the target in Android ADB mode",
                )
            if not device.root:
                raise PlanningError(
                    "safe_mode_root_required",
                    "safe mode reboot requires a backend-observed rooted device",
                )
            assert adb is not None
            requests = (
                ProcessRequest(
                    (
                        adb,
                        "-s",
                        device.serial,
                        "shell",
                        "su",
                        "-c",
                        "setprop persist.sys.safemode 1",
                    ),
                    timeout_seconds=30.0,
                ),
                ProcessRequest(
                    (adb, "-s", device.serial, "reboot"),
                    timeout_seconds=30.0,
                ),
            )
            postconditions = (
                OperationPostcondition(
                    "device_reachable",
                    {"mode": "system", "bootCompleted": True},
                    "device completes a safe-mode Android boot",
                ),
                OperationPostcondition(
                    "safe_mode_active",
                    {"active": True},
                    "AOSP ro.sys.safemode confirms safe mode",
                ),
            )
        elif target == "sideload":
            if device.mode not in {"adb", "recovery"} or adb is None:
                raise PlanningError(
                    "sideload_reboot_adb_required",
                    "sideload reboot requires Android ADB or recovery transport",
                )
            requests = (
                ProcessRequest(
                    (adb, "-s", device.serial, "reboot", "sideload"),
                    timeout_seconds=30.0,
                ),
            )
            postconditions = (
                OperationPostcondition(
                    "device_mode",
                    {"mode": "sideload"},
                    "device reconnects in ADB sideload mode",
                ),
            )
        else:
            adb_target = {
                "system": None,
                "recovery": "recovery",
                "bootloader": "bootloader",
                "fastbootd": "fastboot",
            }
            fastboot_target = {
                "system": None,
                "recovery": "recovery",
                "bootloader": "bootloader",
                "fastbootd": "fastboot",
            }
            if adb is not None:
                argument = adb_target[target]
                argv = (adb, "-s", device.serial, "reboot") + (
                    (argument,) if argument is not None else ()
                )
            elif fastboot is not None:
                argument = fastboot_target[target]
                argv = (fastboot, "-s", device.serial, "reboot") + (
                    (argument,) if argument is not None else ()
                )
            else:
                raise PlanningError(
                    "reboot_transport_unsupported",
                    f"cannot reboot from {device.mode} to {target}",
                )
            requests = (ProcessRequest(argv, timeout_seconds=30.0),)
            postconditions = (
                OperationPostcondition(
                    "device_mode",
                    {"mode": target},
                    "device reconnects in the requested mode",
                ),
            )
        return (
            self._base_plan(
                snapshot,
                device,
                requests,
                label=f"Reboot {device.serial} to {target}",
                risk=OperationRisk.MUTATING,
                postconditions=postconditions,
            ),
            False,
            False,
        )

    def _switch_slot(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
    ) -> tuple[OperationPlan, bool, bool]:
        self._validate_payload(command, {"serial", "slot", "confirmationText"})
        device = self._fastboot_device(command, snapshot)
        slot = self._slot(command.payload.get("slot"))
        fastboot = self._fastboot(snapshot)
        plan = self._base_plan(
            snapshot,
            device,
            (
                ProcessRequest(
                    (fastboot, "-s", device.serial, f"--set-active={slot}"),
                    timeout_seconds=30.0,
                ),
            ),
            label=f"Switch {device.serial} to slot {slot}",
            slots=(slot,),
            data_behavior="switch",
            risk=OperationRisk.DESTRUCTIVE,
            postconditions=(
                OperationPostcondition("active_slot", {"slot": slot}),
            ),
        )
        return plan, True, True

    def _bootloader(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
    ) -> tuple[OperationPlan, bool, bool]:
        self._validate_payload(command, {"serial", "confirmationText"})
        device = self._fastboot_device(command, snapshot)
        action = "unlock" if command.kind.endswith("unlock") else "lock"
        if action == "lock":
            decision = self.bootloader_lock_policy.evaluate(snapshot, device)
            if not decision.allowed:
                raise PlanningError(decision.code, decision.message)
        fastboot = self._fastboot(snapshot)
        plan = self._base_plan(
            snapshot,
            device,
            (
                ProcessRequest(
                    (fastboot, "-s", device.serial, "flashing", action),
                    timeout_seconds=60.0,
                ),
            ),
            label=f"{action.title()} bootloader on {device.serial}",
            data_behavior=f"wipe_{action}",
            risk=OperationRisk.DESTRUCTIVE,
            postconditions=(
                OperationPostcondition(
                    "bootloader_state",
                    {"state": "unlocked" if action == "unlock" else "locked"},
                ),
            ),
        )
        return plan, True, True

    def _boot_flash(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
    ) -> tuple[OperationPlan, bool, bool]:
        self._validate_payload(command, {"serial", "partition", "slot", "confirmationText"})
        device = self._fastboot_device(command, snapshot)
        if device.bootloader.casefold() != "unlocked":
            raise PlanningError(
                "bootloader_unlocked_required",
                "boot image flashing requires an explicitly unlocked bootloader",
            )
        artifact = self._boot_artifact(snapshot)
        source_partition = (
            snapshot.boot.flavor.casefold()
            if snapshot.boot.flavor.casefold() in _FASTBOOT_PARTITIONS
            else "boot"
        )
        raw_partition = command.payload.get("partition", source_partition)
        partition = self._partition(raw_partition)
        if partition != source_partition:
            raise PlanningError(
                "boot_partition_mismatch",
                (
                    f"the selected {source_partition} artifact cannot be flashed "
                    f"to partition {partition}"
                ),
            )
        raw_slot = command.payload.get("slot")
        slot = self._slot(raw_slot) if raw_slot is not None else ""
        fastboot = self._fastboot(snapshot)
        argv = [fastboot, "-s", device.serial]
        if slot:
            argv.append(f"--slot={slot}")
        argv.extend(("flash", partition, artifact.path))
        plan = self._base_plan(
            snapshot,
            device,
            (ProcessRequest(tuple(argv), timeout_seconds=300.0),),
            label=f"Flash {partition} on {device.serial}",
            partitions=(partition,),
            slots=(slot,) if slot else (),
            artifacts=(artifact,),
            risk=OperationRisk.DESTRUCTIVE,
            postconditions=(
                OperationPostcondition(
                    "partition_written",
                    {
                        "partition": partition,
                        "slot": slot,
                        "sha256": artifact.sha256,
                    },
                ),
            ),
        )
        return plan, True, True

    def _boot_live(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
    ) -> tuple[OperationPlan, bool, bool]:
        self._validate_payload(command, {"serial", "confirmationText"})
        device = self._fastboot_device(command, snapshot)
        if device.bootloader.casefold() != "unlocked":
            raise PlanningError(
                "bootloader_unlocked_required",
                "live boot requires an explicitly unlocked bootloader",
            )
        artifact = self._boot_artifact(snapshot)
        source_partition = snapshot.boot.flavor.casefold()
        if source_partition != "boot":
            raise PlanningError(
                "live_boot_partition_unsupported",
                "live boot supports only a canonical boot image",
            )
        fastboot = self._fastboot(snapshot)
        plan = self._base_plan(
            snapshot,
            device,
            (
                ProcessRequest(
                    (fastboot, "-s", device.serial, "boot", artifact.path),
                    timeout_seconds=180.0,
                ),
            ),
            label=f"Live boot {device.serial}",
            artifacts=(artifact,),
            risk=OperationRisk.MUTATING,
            postconditions=(
                OperationPostcondition(
                    "live_boot_active",
                    {"sha256": artifact.sha256},
                    "the device is running the verified temporary boot image",
                ),
            ),
        )
        return plan, False, True

    def _flash(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
    ) -> tuple[OperationPlan, bool, bool]:
        self._validate_payload(command, {"serial", "confirmationText"})
        device = self._device(command, snapshot)
        options = self._normalized_flash_options(snapshot.plan.options)
        if "images" in options:
            raise PlanningError(
                "untrusted_artifact_metadata",
                "image paths and hashes cannot be supplied by the UI plan",
            )
        if options.get("verify") is False:
            raise PlanningError(
                "option_not_supported_for_mode",
                "verify=false is unsupported because backend artifact verification is mandatory",
            )
        mode = snapshot.plan.mode.strip().casefold()
        if mode in _DRY_RUN_MODES:
            mode = "images"
        if mode in _OTA_MODES:
            self._validate_ota_options(options)
            if device.mode != "sideload":
                raise PlanningError(
                    "ota_sideload_required",
                    "OTA execution requires the selected device to already be in sideload mode",
                )
            if snapshot.firmware.type.casefold() != "ota":
                raise PlanningError("ota_firmware_required", "selected firmware is not an OTA package")
            if not snapshot.firmware.verified or not snapshot.firmware.processed:
                raise PlanningError(
                    "firmware_not_processed",
                    "OTA firmware must be verified and processed before sideload",
                )
            artifact = self._firmware_artifact(snapshot, required=True)
            if artifact is None:
                raise PlanningError(
                    "firmware_required",
                    "no canonical OTA firmware is selected",
                )
            adb = self._adb(snapshot)
            requests = [
                ProcessRequest(
                    (adb, "-s", device.serial, "sideload", artifact.path),
                    timeout_seconds=1800.0,
                )
            ]
            if options.get("noReboot") is False:
                requests.append(
                    ProcessRequest(
                        (adb, "-s", device.serial, "reboot"),
                        timeout_seconds=90.0,
                    )
                )
            plan = self._base_plan(
                snapshot,
                device,
                tuple(requests),
                label=f"Sideload OTA on {device.serial}",
                artifacts=(artifact,),
                risk=OperationRisk.DESTRUCTIVE,
                postconditions=(
                    OperationPostcondition(
                        "firmware_applied",
                        {
                            "firmwareSha256": artifact.sha256,
                            "build": snapshot.firmware.build,
                        },
                    ),
                ),
            )
            compiled = (plan, True, True)
        else:
            if mode not in _IMAGE_MODES:
                raise PlanningError("flash_mode_unsupported", f"unsupported flash mode: {snapshot.plan.mode}")
            compiled = self._image_flash(command, snapshot, device, mode, options)
        if snapshot.plan.dry_run:
            return (
                replace(
                    compiled[0],
                    dry_run=True,
                    risk=OperationRisk.READ_ONLY,
                    postconditions=(),
                ),
                False,
                False,
            )
        return compiled

    def _image_flash(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        mode: str,
        options: Mapping[str, object],
    ) -> tuple[OperationPlan, bool, bool]:
        if device.mode != "fastboot":
            raise PlanningError("fastboot_required", "image flashing requires fastboot mode")
        if options.get("downgrade") is True:
            raise PlanningError(
                "option_not_supported_for_mode",
                "downgrade requires a backend-produced downgrade artifact and is not supported for image plans",
            )
        if options.get("temporaryRoot") is True and options.get("noReboot") is True:
            raise PlanningError(
                "flash_option_conflict",
                "temporaryRoot performs the final boot and cannot be combined with noReboot",
            )
        repository_artifacts = self.artifact_repository.resolve(snapshot)
        if not repository_artifacts:
            raise PlanningError(
                "processed_artifacts_unavailable",
                "backend-verified processed image artifacts are unavailable",
            )
        firmware_type = snapshot.firmware.type.casefold()
        if mode == "factory" and firmware_type != "factory":
            raise PlanningError(
                "factory_firmware_required",
                "factory mode requires canonical factory firmware metadata",
            )
        if firmware_type in {"factory", "custom"}:
            if not snapshot.firmware.verified or not snapshot.firmware.processed:
                raise PlanningError(
                    "firmware_not_processed",
                    f"{firmware_type} firmware must be verified and processed first",
                )

        images: dict[str, FileArtifact] = {}
        for artifact in repository_artifacts:
            if not artifact.role.startswith("partition:"):
                continue
            partition = self._partition(artifact.role.partition(":")[2])
            if partition in images:
                raise PlanningError(
                    "processed_artifacts_invalid",
                    f"duplicate backend artifact for partition {partition}",
                )
            issue = self._revalidate_artifact(artifact)
            if issue is not None:
                raise PlanningError(*issue)
            images[partition] = artifact
        if not images:
            raise PlanningError(
                "processed_artifacts_unavailable",
                "backend repository contains no flashable partition artifacts",
            )

        selected_partitions = options.get("partitions")
        if selected_partitions is not None:
            if isinstance(selected_partitions, str) or not isinstance(
                selected_partitions,
                Sequence,
            ):
                raise PlanningError("partition_selection_invalid", "partitions must be an array")
            requested = tuple(
                self._partition(item)
                for item in cast(Sequence[object], selected_partitions)
            )
            if not requested:
                raise PlanningError(
                    "partition_selection_empty",
                    "at least one partition must be selected",
                )
            missing = tuple(item for item in requested if item not in images)
            if missing:
                raise PlanningError(
                    "processed_artifact_missing",
                    f"no backend artifact is available for partition {missing[0]}",
                )
            images = {partition: images[partition] for partition in requested}

        factory_components = {
            partition: images[partition]
            for partition in _FACTORY_COMPONENT_ORDER
            if partition in images
        }
        image_partitions = {
            partition: artifact
            for partition, artifact in images.items()
            if partition not in _FACTORY_COMPONENT_ORDER
        }
        if factory_components and mode != "factory":
            raise PlanningError(
                "factory_component_mode_required",
                "bootloader and radio artifacts may only run in canonical factory mode",
            )
        if factory_components:
            if device.bootloader.casefold() == "locked":
                raise PlanningError(
                    "bootloader_unlocked_required",
                    "factory bootloader and radio stages require an unlocked bootloader",
                )
            if "radio" in factory_components and "bootloader" not in factory_components:
                raise PlanningError(
                    "factory_bootloader_artifact_required",
                    "the factory radio stage requires its verified bootloader artifact",
                )
            if not image_partitions:
                raise PlanningError(
                    "factory_partition_artifact_required",
                    "factory component stages require at least one verified OS partition artifact",
                )

        disable_verity = options.get("disableVerity") is True
        disable_verification = options.get("disableVerification") is True
        if (disable_verity or disable_verification) and "vbmeta" not in images:
            raise PlanningError(
                "option_not_supported_for_mode",
                "disableVerity/disableVerification require a verified vbmeta artifact in the plan",
            )
        fastboot_flags: list[str] = []
        if disable_verity:
            fastboot_flags.append("--disable-verity")
        if disable_verification:
            fastboot_flags.append("--disable-verification")
        if options.get("force") is True:
            fastboot_flags.append("--force")

        fastboot = self._fastboot(snapshot)
        global_slot = options.get("slot")
        if global_slot == "inactive":
            observed_slot = device.slot.strip().casefold()
            if observed_slot not in {"a", "b"}:
                raise PlanningError(
                    "active_slot_unavailable",
                    "inactive slot targeting requires a backend-observed active slot",
                )
            global_slot = "b" if observed_slot == "a" else "a"
        elif global_slot is not None and global_slot != "both":
            global_slot = self._slot(global_slot)
        requests: list[ProcessRequest] = []
        artifacts: list[FileArtifact] = list(
            self._canonical_flash_artifacts(
                snapshot,
                require_firmware=firmware_type == "factory",
            )
        )
        partitions: list[str] = []
        slots: list[str] = []
        for partition in _FACTORY_COMPONENT_ORDER:
            artifact = factory_components.get(partition)
            if artifact is None:
                continue
            artifacts.append(artifact)
            requests.append(
                ProcessRequest(
                    (fastboot, "-s", device.serial, "flash", partition, artifact.path),
                    timeout_seconds=600.0,
                )
            )
            requests.append(
                ProcessRequest(
                    (fastboot, "-s", device.serial, "reboot-bootloader"),
                    timeout_seconds=120.0,
                )
            )
            partitions.append(partition)

        for partition in _FASTBOOT_PARTITION_ORDER:
            artifact = image_partitions.get(partition)
            if artifact is None:
                continue
            artifacts.append(artifact)
            raw_slot = global_slot
            target_slots: tuple[str, ...]
            if raw_slot == "both":
                target_slots = ("a", "b")
            elif raw_slot is None or raw_slot == "":
                target_slots = ("",)
            else:
                target_slots = (self._slot(raw_slot),)
            for slot in target_slots:
                argv = [fastboot, "-s", device.serial]
                if slot:
                    argv.append(f"--slot={slot}")
                    slots.append(slot)
                argv.extend(fastboot_flags)
                argv.extend(("flash", partition, artifact.path))
                requests.append(ProcessRequest(tuple(argv), timeout_seconds=600.0))
            partitions.append(partition)

        behavior = options.get("dataBehavior", options.get("data_behavior", "preserve"))
        wipe = mode in {"wipedata", "wipe"} or options.get("wipe") is True
        if behavior not in {"preserve", "wipe"}:
            raise PlanningError("data_behavior_invalid", "data behavior must be preserve or wipe")
        wipe = wipe or behavior == "wipe"
        if wipe:
            requests.append(
                ProcessRequest((fastboot, "-s", device.serial, "-w"), timeout_seconds=300.0)
            )
        temporary_root = options.get("temporaryRoot") is True
        if temporary_root:
            if not snapshot.boot.patched:
                raise PlanningError(
                    "temporary_root_image_required",
                    "temporaryRoot requires a canonical patched boot image",
                )
            boot_artifact = self._boot_artifact(snapshot)
            artifacts.append(boot_artifact)
            requests.append(
                ProcessRequest(
                    (fastboot, "-s", device.serial, "boot", boot_artifact.path),
                    timeout_seconds=180.0,
                )
            )
        elif options.get("noReboot") is False:
            requests.append(
                ProcessRequest(
                    (fastboot, "-s", device.serial, "reboot"),
                    timeout_seconds=90.0,
                )
            )
        plan = self._base_plan(
            snapshot,
            device,
            tuple(requests),
            label=f"Flash {len(partitions)} image(s) on {device.serial}",
            partitions=tuple(partitions),
            slots=tuple(dict.fromkeys(slots)),
            data_behavior="wipe" if wipe else "preserve",
            artifacts=tuple(artifacts),
            risk=OperationRisk.DESTRUCTIVE,
            postconditions=(
                OperationPostcondition(
                    "flash_applied",
                    {
                        "firmwareSha256": snapshot.firmware.hash,
                        "partitions": tuple(partitions),
                        "slots": tuple(dict.fromkeys(slots)),
                        "dataBehavior": "wipe" if wipe else "preserve",
                        "build": snapshot.firmware.build,
                    },
                ),
            ),
        )
        return plan, True, True

    def _normalized_flash_options(
        self,
        raw_options: Mapping[str, object],
    ) -> dict[str, object]:
        aliases = {
            "disable_verity": "disableVerity",
            "disable_verification": "disableVerification",
            "no_reboot": "noReboot",
            "temporary_root": "temporaryRoot",
            "data_behavior": "dataBehavior",
        }
        allowed = {
            "images",
            "partitions",
            "slot",
            "dataBehavior",
            "wipe",
            "verify",
            "disableVerity",
            "disableVerification",
            "force",
            "noReboot",
            "downgrade",
            "temporaryRoot",
        }
        normalized: dict[str, object] = {}
        for raw_key, value in raw_options.items():
            key = aliases.get(raw_key, raw_key)
            if key not in allowed:
                raise PlanningError(
                    "flash_metadata_unsupported",
                    f"unsupported canonical flash option: {raw_key}",
                )
            if key in normalized and normalized[key] != value:
                raise PlanningError(
                    "flash_option_conflict",
                    f"conflicting values were supplied for {key}",
                )
            normalized[key] = value
        return normalized

    @staticmethod
    def _validate_ota_options(options: Mapping[str, object]) -> None:
        for key in (
            "disableVerity",
            "disableVerification",
            "force",
            "downgrade",
            "temporaryRoot",
            "wipe",
        ):
            if options.get(key) is True:
                raise PlanningError(
                    "option_not_supported_for_mode",
                    f"{key} is not supported for OTA sideload",
                )
        if "slot" in options or "partitions" in options:
            raise PlanningError(
                "option_not_supported_for_mode",
                "partition and slot targeting are not supported for OTA sideload",
            )
        if options.get("dataBehavior", "preserve") != "preserve":
            raise PlanningError(
                "option_not_supported_for_mode",
                "data wiping is not supported as part of OTA sideload",
            )

    def _base_plan(
        self,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        requests: tuple[ProcessRequest, ...],
        *,
        label: str,
        partitions: tuple[str, ...] = (),
        slots: tuple[str, ...] = (),
        data_behavior: str = "preserve",
        artifacts: tuple[FileArtifact, ...] = (),
        dry_run: bool = False,
        risk: OperationRisk = OperationRisk.READ_ONLY,
        postconditions: tuple[OperationPostcondition, ...] = (),
    ) -> OperationPlan:
        created = self.clock()
        return OperationPlan(
            requests=requests,
            label=label,
            created=created,
            expires=created + OPERATION_PLAN_TTL_SECONDS,
            risk=risk,
            postconditions=postconditions,
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
            dry_run=dry_run,
        )

    def _bind_reinforced_confirmation(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        plan: OperationPlan,
        destructive: bool,
        requires_confirmation: bool,
        preview: bool,
    ) -> PlanCompilation:
        semantic = json.dumps(
            {
                "kind": command.kind,
                "revision": snapshot.revision,
                # Lifecycle metadata changes between preview and execute.  The
                # stable execution fingerprint still binds every request,
                # target, hash, risk and postcondition.
                "execution_fingerprint": plan.execution_fingerprint(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        nonce = hmac.new(self._confirmation_secret, semantic, hashlib.sha256).hexdigest()[:32]
        plan = replace(plan, confirmation_nonce=nonce)
        challenge_key = plan.confirmation_challenge()
        text = self._required_confirmation_text(command.kind, plan, snapshot)
        supplied = command.payload.get("confirmationText")

        if preview:
            self._issue_challenge(challenge_key)
            return PlanCompilation(
                plan,
                destructive=destructive,
                requires_confirmation=requires_confirmation,
                confirmation_text=text,
                confirmation_nonce=nonce,
            )

        issued = self._challenge_is_pending(challenge_key)
        if supplied is None:
            self._issue_challenge(challenge_key)
            code = "confirmation_text_required"
            message = "preview the operation and enter the exact confirmation text"
        elif not isinstance(supplied, str) or not hmac.compare_digest(supplied, text):
            self._issue_challenge(challenge_key)
            code = "confirmation_text_mismatch"
            message = "confirmation text did not exactly match the backend challenge"
        elif not issued:
            self._issue_challenge(challenge_key)
            code = "confirmation_preview_required"
            message = "a backend preview is required before reinforced confirmation"
        else:
            # A challenge is consumed before a process-capable plan leaves the
            # compiler. Replaying the same text must require a new preview.
            if not self._consume_challenge(challenge_key):
                self._issue_challenge(challenge_key)
                return PlanCompilation(
                    plan,
                    "confirmation_preview_required",
                    "a backend preview is required before reinforced confirmation",
                    destructive,
                    requires_confirmation,
                    text,
                    nonce,
                )
            token = plan.confirmation_challenge()
            return PlanCompilation(
                replace(plan, confirmation_token=token),
                destructive=destructive,
                requires_confirmation=requires_confirmation,
                confirmation_text=text,
                confirmation_nonce=nonce,
            )
        return PlanCompilation(
            plan,
            code,
            message,
            destructive,
            requires_confirmation,
            text,
            nonce,
        )

    def _bind_batch_confirmation(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        batch: OperationBatch,
        preview: bool,
    ) -> BatchCompilation:
        semantic = json.dumps(
            {
                "kind": command.kind,
                "revision": snapshot.revision,
                "fingerprint": batch.fingerprint,
                "serials": batch.target_serials,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        nonce = hmac.new(self._confirmation_secret, semantic, hashlib.sha256).hexdigest()[:32]
        batch = replace(batch, confirmation_nonce=nonce)
        challenge_key = batch.confirmation_challenge()
        text = batch.required_confirmation_text()
        supplied = command.payload.get("confirmationText")

        if preview:
            self._issue_challenge(challenge_key)
            return BatchCompilation(
                batch,
                confirmation_text=text,
                confirmation_nonce=nonce,
            )
        if supplied is None:
            self._issue_challenge(challenge_key)
            code = "confirmation_text_required"
            message = "preview the batch and enter the exact confirmation text"
        elif not isinstance(supplied, str) or not hmac.compare_digest(supplied, text):
            self._issue_challenge(challenge_key)
            code = "confirmation_text_mismatch"
            message = "batch confirmation text did not exactly match the backend challenge"
        elif not self._challenge_is_pending(challenge_key):
            self._issue_challenge(challenge_key)
            code = "confirmation_preview_required"
            message = "a backend batch preview is required before confirmation"
        elif not self._consume_challenge(challenge_key):
            self._issue_challenge(challenge_key)
            code = "confirmation_preview_required"
            message = "a backend batch preview is required before confirmation"
        else:
            return BatchCompilation(
                replace(batch, confirmation_token=batch.confirmation_challenge()),
                confirmation_text=text,
                confirmation_nonce=nonce,
            )
        return BatchCompilation(
            batch,
            code,
            message,
            confirmation_text=text,
            confirmation_nonce=nonce,
        )

    def bind_reinforced_confirmation(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        plan: OperationPlan,
        *,
        destructive: bool,
        requires_confirmation: bool,
        preview: bool = False,
    ) -> PlanCompilation:
        """Bind a backend-issued challenge to a non-planner service plan."""

        return self._bind_reinforced_confirmation(
            command,
            snapshot,
            plan,
            destructive,
            requires_confirmation,
            preview,
        )

    def _issue_challenge(self, challenge_key: str) -> None:
        now = self._challenge_clock()
        with self._challenge_lock:
            self._prune_challenges_locked(now)
            self._issued_challenges[challenge_key] = now + self.challenge_ttl_seconds
            self._issued_challenges.move_to_end(challenge_key)
            while len(self._issued_challenges) > self.maximum_pending_challenges:
                self._issued_challenges.popitem(last=False)

    def _challenge_is_pending(self, challenge_key: str) -> bool:
        now = self._challenge_clock()
        with self._challenge_lock:
            self._prune_challenges_locked(now)
            expiry = self._issued_challenges.get(challenge_key)
            return expiry is not None and expiry > now

    def _consume_challenge(self, challenge_key: str) -> bool:
        now = self._challenge_clock()
        with self._challenge_lock:
            self._prune_challenges_locked(now)
            expiry = self._issued_challenges.pop(challenge_key, None)
            return expiry is not None and expiry > now

    def _prune_challenges_locked(self, now: float) -> None:
        expired = tuple(
            key for key, expiry in self._issued_challenges.items() if expiry <= now
        )
        for key in expired:
            self._issued_challenges.pop(key, None)

    def _required_confirmation_text(
        self,
        kind: str,
        plan: OperationPlan,
        _snapshot: AppSnapshot,
    ) -> str:
        serial = plan.target_serial or ""
        suffix = confirmation_serial_suffix(serial)
        if kind == "device.switchSlot":
            if not plan.slots:
                raise ValueError("slot confirmation requires a canonical target slot")
            return f"SLOT {plan.slots[0]} {suffix}"
        if kind == "device.bootloader.unlock":
            return f"UNLOCK {suffix}"
        if kind == "device.bootloader.lock":
            return f"LOCK {suffix}"
        if kind == "partitions.erase":
            if not plan.partitions:
                raise ValueError("erase confirmation requires a canonical partition")
            partition = plan.partitions[0]
            return f"ERASE {partition} {suffix}"
        return f"WIPE {suffix}"

    def _device(self, command: AppCommand, snapshot: AppSnapshot) -> DeviceInfo:
        payload_serial = command.payload.get("serial")
        if payload_serial is not None and (
            not isinstance(payload_serial, str) or not payload_serial.strip()
        ):
            raise PlanningError("target_serial_invalid", "payload.serial must be a non-empty string")
        serial = command.target_serial or (
            payload_serial.strip() if isinstance(payload_serial, str) else snapshot.selected_serial
        )
        if not serial:
            raise PlanningError("target_serial_required", "one selected target serial is required")
        if command.target_serial and payload_serial and command.target_serial != payload_serial.strip():
            raise PlanningError("ambiguous_target_serial", "command and payload target different devices")
        if serial not in snapshot.selected_serials:
            raise PlanningError("target_serial_changed", "target serial is not selected")
        device = next((item for item in snapshot.devices if item.serial == serial), None)
        if device is None:
            raise PlanningError("device_disconnected", "target serial is not in the current inventory")
        if not device.online or device.mode in {"offline", "unauthorized"}:
            raise PlanningError("device_disconnected", f"device is not online: {device.mode}")
        return device

    def _fastboot_device(self, command: AppCommand, snapshot: AppSnapshot) -> DeviceInfo:
        device = self._device(command, snapshot)
        if device.mode != "fastboot":
            raise PlanningError("fastboot_required", "operation requires the target in fastboot mode")
        return device

    @staticmethod
    def _adb(snapshot: AppSnapshot) -> str:
        if not snapshot.toolchain.ready or not snapshot.toolchain.adb:
            raise PlanningError("toolchain_not_ready", "validated adb is required")
        return snapshot.toolchain.adb

    @staticmethod
    def _fastboot(snapshot: AppSnapshot) -> str:
        if not snapshot.toolchain.ready or not snapshot.toolchain.fastboot:
            raise PlanningError("toolchain_not_ready", "validated fastboot is required")
        return snapshot.toolchain.fastboot

    def _boot_artifact(self, snapshot: AppSnapshot) -> FileArtifact:
        if not snapshot.boot.path:
            raise PlanningError("boot_image_required", "no canonical boot image is selected")
        if not snapshot.boot.hash:
            raise PlanningError("boot_hash_required", "selected boot image has no verified SHA-256")
        return self._artifact(snapshot.boot.path, snapshot.boot.hash, "boot")

    def _firmware_artifact(self, snapshot: AppSnapshot, *, required: bool) -> FileArtifact | None:
        if not snapshot.firmware.path:
            if required:
                raise PlanningError("firmware_required", "no canonical firmware is selected")
            return None
        if not snapshot.firmware.hash:
            raise PlanningError("firmware_hash_required", "selected firmware has no verified SHA-256")
        return self._artifact(snapshot.firmware.path, snapshot.firmware.hash, "firmware")

    def _canonical_flash_artifacts(
        self,
        snapshot: AppSnapshot,
        *,
        require_firmware: bool,
    ) -> tuple[FileArtifact, ...]:
        firmware = self._firmware_artifact(snapshot, required=require_firmware)
        return (firmware,) if firmware is not None else ()

    def _artifact(self, raw_path: object, raw_hash: object, role: str) -> FileArtifact:
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise PlanningError("artifact_path_required", f"{role} path is required")
        if not isinstance(raw_hash, str) or not raw_hash.strip():
            raise PlanningError("artifact_hash_required", f"{role} SHA-256 is required")
        try:
            artifact = FileArtifact(str(Path(raw_path).expanduser().resolve()), raw_hash, role)
        except (OSError, TypeError, ValueError) as error:
            raise PlanningError("artifact_metadata_invalid", str(error)) from error
        issue = self._revalidate_artifact(artifact)
        if issue is not None:
            raise PlanningError(*issue)
        return artifact

    def _revalidate_artifact(self, artifact: FileArtifact) -> tuple[str, str] | None:
        path = Path(artifact.path)
        if not path.is_file():
            return "artifact_missing", f"artifact no longer exists: {artifact.path}"
        digest = hashlib.sha256()
        try:
            with path.open("rb") as stream:
                while chunk := stream.read(self.hash_chunk_size):
                    digest.update(chunk)
        except OSError as error:
            return "artifact_read_failed", str(error)
        if not hmac.compare_digest(digest.hexdigest(), artifact.sha256):
            return "artifact_hash_mismatch", f"artifact hash changed: {artifact.path}"
        return None

    @staticmethod
    def _partition(raw_partition: object) -> str:
        if not isinstance(raw_partition, str):
            raise PlanningError("partition_invalid", "partition must be a string")
        partition = raw_partition.strip().casefold()
        if partition not in _FASTBOOT_PARTITIONS:
            raise PlanningError("partition_not_allowed", f"partition is not allow-listed: {partition}")
        return partition

    @staticmethod
    def _slot(raw_slot: object) -> str:
        if not isinstance(raw_slot, str) or raw_slot.strip().casefold() not in {"a", "b"}:
            raise PlanningError("slot_invalid", "slot must be exactly a or b")
        return raw_slot.strip().casefold()

    @staticmethod
    def _validate_payload(command: AppCommand, allowed: set[str]) -> None:
        unknown = set(command.payload) - allowed
        if unknown:
            raise PlanningError(
                "invalid_plan_payload",
                f"unsupported semantic field: {sorted(unknown)[0]}",
            )
