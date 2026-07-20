"""Pure safety decisions for headless PixelFlasher commands."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace

from .contracts import (
    AppCommand,
    AppSnapshot,
    CommandKind,
    InteractionKind,
    InteractionRequest,
    OperationBatch,
    OperationRisk,
    SafetyDecision,
)

_HIGH_RISK_ACTIONS = frozenset(
    {"wipe", "erase", "switch", "lock", "unlock", "set_active"}
)
_HIGH_RISK_DATA_BEHAVIORS = frozenset(
    {
        "wipe",
        "erase",
        "switch",
        "lock",
        "unlock",
        "wipe_lock",
        "wipe_unlock",
        "set_active",
    }
)


@dataclass(frozen=True, slots=True)
class SafetyPolicy:
    """Validate optimistic revisions, device identity, and confirmations."""

    revisioned_kinds: frozenset[str] = frozenset(
        {
            CommandKind.DEVICE_SCAN.value,
            CommandKind.DEVICE_SELECT.value,
            CommandKind.FIRMWARE_SELECT.value,
            CommandKind.FLASH_PLAN_UPDATE.value,
            CommandKind.FLASH_EXECUTE.value,
            "platformTools.setup",
            "firmware.process",
            "firmware.catalog.refresh",
            "firmware.download",
            "support.create",
            "flash.plan.preview",
            "device.reboot",
            "device.switchSlot",
            "device.bootloader.lock",
            "device.bootloader.unlock",
            "boot.flash",
            "boot.live",
            "boot.patch",
            "boot.inventory",
            "boot.delete",
            "boot.select",
            "apps.list",
            "apps.action",
            "partitions.list",
            "partitions.read",
            "partitions.write",
            "partitions.erase",
            "tools.logcat",
            "tools.logcat.clear",
            "tools.pushFiles",
            "tools.adbShell",
            "tools.scrcpy",
            "tools.scrcpy.setup",
            "tools.wifi",
            "tools.wifi.status",
            "tools.wifi.discover",
            "tools.avb",
            "tools.xml",
            "tools.keybox",
            "device.inspect",
            "device.openUrl",
            "backups.create",
            "backups.restore",
            "backups.list",
            "backups.delete",
            "root.apps.list",
            "root.apps.install",
            "root.apps.catalog.refresh",
            "root.apps.download",
            "root.modules.list",
            "root.modules.action",
        }
    )
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)

    def is_destructive(self, command: AppCommand) -> bool:
        if command.operation_plan is not None and command.operation_plan.dry_run:
            return False
        return bool(
            command.destructive
            or command.kind == CommandKind.FLASH_EXECUTE.value
            or command.operation_plan is not None
            and command.operation_plan.risk is OperationRisk.DESTRUCTIVE
        )

    def evaluate(self, command: AppCommand, snapshot: AppSnapshot) -> SafetyDecision:
        reinforced = False
        if command.kind == "firmware.process":
            if command.payload:
                return SafetyDecision(
                    False,
                    "invalid_firmware_process_payload",
                    "firmware.process uses the canonical selected firmware and accepts no payload",
                )
            if command.operation_plan is not None:
                return SafetyDecision(
                    False,
                    "untrusted_operation_plan",
                    "firmware processing cannot accept a caller-provided process plan",
                )
            if command.target_serial is not None:
                return SafetyDecision(
                    False,
                    "firmware_process_target_not_allowed",
                    "firmware processing derives compatibility from canonical selected devices",
                )
        if command.kind == "support.create":
            if command.operation_plan is not None:
                return SafetyDecision(
                    False,
                    "untrusted_operation_plan",
                    "support package creation does not accept a process plan",
                )
            if command.target_serial is not None:
                return SafetyDecision(
                    False,
                    "support_target_not_allowed",
                    "support package creation is a local operation",
                )
        if command.kind == "tools.avb":
            if command.operation_plan is not None:
                return SafetyDecision(
                    False,
                    "untrusted_operation_plan",
                    "AVB downgrade preparation does not accept a process plan",
                )
            if command.target_serial is not None:
                return SafetyDecision(
                    False,
                    "avb_target_not_allowed",
                    "AVB downgrade preparation is bound to canonical firmware state",
                )
        if command.kind == "tools.xml":
            if command.operation_plan is not None:
                return SafetyDecision(
                    False,
                    "untrusted_operation_plan",
                    "binary XML decoding does not accept a process plan",
                )
            if command.target_serial is not None:
                return SafetyDecision(
                    False,
                    "xml_target_not_allowed",
                    "binary XML decoding is a local operation",
                )
        if command.kind == "tools.keybox":
            if command.operation_plan is not None:
                return SafetyDecision(
                    False,
                    "untrusted_operation_plan",
                    "keybox analysis does not accept a process plan",
                )
            if command.target_serial is not None:
                return SafetyDecision(
                    False,
                    "keybox_target_not_allowed",
                    "keybox analysis is a local operation",
                )
        if command.kind in {"backups.list", "backups.delete"}:
            if command.operation_plan is not None:
                return SafetyDecision(
                    False,
                    "untrusted_operation_plan",
                    "backup inventory operations do not accept a process plan",
                )
            if command.target_serial is not None:
                return SafetyDecision(
                    False,
                    "backup_inventory_target_not_allowed",
                    "backup inventory operations are local application operations",
                )
        if (
            command.kind == CommandKind.FLASH_EXECUTE.value
            or self.is_destructive(command)
            or (command.operation_plan is not None and command.operation_plan.target_serial is not None)
        ):
            if not snapshot.selected_serials:
                return SafetyDecision(False, "device_not_selected", "no target device is selected")
            plan_target = command.operation_plan.target_serial if command.operation_plan is not None else None
            if not plan_target:
                return SafetyDecision(
                    False,
                    "plan_target_serial_required",
                    "each destructive operation plan must name one target serial",
                )
            if not command.target_serial:
                return SafetyDecision(
                    False,
                    "command_target_serial_required",
                    "the command must name the same individual target as its plan",
                )
            if command.target_serial != plan_target:
                return SafetyDecision(
                    False,
                    "ambiguous_target_serial",
                    "command and operation plan name different target serials",
                )
            if plan_target not in snapshot.selected_serials:
                return SafetyDecision(
                    False,
                    "target_serial_changed",
                    (
                        f"target device {plan_target!r} is no longer selected; "
                        f"selected devices are {snapshot.selected_serials!r}"
                    ),
                )
            plan = command.operation_plan
            assert plan is not None
            now = self.clock()
            if plan.expires <= now:
                return SafetyDecision(
                    False,
                    "plan_expired",
                    "operation plan expired before execution",
                )
            if plan.created > now + 1.0:
                return SafetyDecision(
                    False,
                    "plan_created_in_future",
                    "operation plan creation time is invalid",
                )
            target_device = next(
                (device for device in snapshot.devices if device.serial == plan_target),
                None,
            )
            if target_device is not None and (
                not target_device.online or target_device.mode in {"offline", "unauthorized"}
            ):
                return SafetyDecision(
                    False,
                    "device_disconnected",
                    f"device {plan_target!r} is not online",
                )
            if plan.expected_device_state:
                if target_device is None:
                    return SafetyDecision(
                        False,
                        "device_state_unavailable",
                        f"current state for device {plan_target!r} is unavailable",
                    )
                if target_device.mode != plan.expected_device_state:
                    return SafetyDecision(
                        False,
                        "device_state_changed",
                        (f"device state changed from {plan.expected_device_state!r} to {target_device.mode!r}"),
                    )
            if plan.expected_codename:
                if target_device is None or not target_device.codename:
                    return SafetyDecision(
                        False,
                        "device_codename_unavailable",
                        f"current codename for device {plan_target!r} is unavailable",
                    )
                if target_device.codename.casefold() != plan.expected_codename.casefold():
                    return SafetyDecision(
                        False,
                        "device_codename_changed",
                        "device codename no longer matches the operation plan",
                    )
            if plan.plan_revision != snapshot.plan.revision:
                return SafetyDecision(
                    False,
                    "plan_revision_changed",
                    (f"flash plan revision changed from {plan.plan_revision} to {snapshot.plan.revision}"),
                )
            if plan.fingerprint != snapshot.plan.fingerprint:
                return SafetyDecision(
                    False,
                    "plan_fingerprint_changed",
                    "flash plan fingerprint no longer matches canonical state",
                )
            if plan.firmware_hash != snapshot.firmware.hash:
                return SafetyDecision(
                    False,
                    "firmware_hash_changed",
                    "firmware hash no longer matches the operation plan",
                )
            if plan.boot_hash != snapshot.boot.hash:
                return SafetyDecision(
                    False,
                    "boot_hash_changed",
                    "boot image hash no longer matches the operation plan",
                )
            if plan.snapshot_revision is not None and plan.snapshot_revision != snapshot.revision:
                return SafetyDecision(
                    False,
                    "snapshot_revision_changed",
                    (f"application revision changed from {plan.snapshot_revision} to {snapshot.revision}"),
                )
            reinforced = self.requires_reinforced_confirmation(command)
            if reinforced and not plan.reinforced_confirmation_valid:
                return SafetyDecision(
                    False,
                    "reinforced_confirmation_required",
                    ("wipe, erase, slot switching, and unlock operations require a nonce-bound confirmation token"),
                )

        if command.kind in self.revisioned_kinds:
            if command.expected_revision is None:
                return SafetyDecision(False, "revision_required", "expected_revision is required")
            if command.expected_revision != snapshot.revision:
                return SafetyDecision(
                    False,
                    "stale_revision",
                    (f"state revision changed: expected {command.expected_revision}, current {snapshot.revision}"),
                )

        if self.is_destructive(command) or command.requires_confirmation:
            plan = command.operation_plan
            interaction_target = plan.target_serial if plan is not None else command.target_serial
            destructive = self.is_destructive(command)
            request = InteractionRequest(
                operation_id=command.operation_id,
                kind=InteractionKind.CONFIRM,
                title=(
                    "Confirm high-risk destructive operation"
                    if reinforced
                    else "Confirm destructive operation"
                    if destructive
                    else "Confirm device operation"
                ),
                message=(
                    f"Run {command.kind!r} on device {interaction_target!r}?"
                    if interaction_target
                    else f"Run {command.kind!r}?"
                ),
                expected_revision=snapshot.revision,
                target_serial=interaction_target,
                destructive=destructive,
                reinforced=reinforced,
                confirmation_nonce=plan.confirmation_nonce if plan is not None else None,
            )
            return SafetyDecision(True, "confirmation_required", interaction=request)

        return SafetyDecision(True, "allowed")

    def evaluate_batch(
        self,
        batch: OperationBatch,
        snapshots: Mapping[str, AppSnapshot] | AppSnapshot,
    ) -> SafetyDecision:
        """Revalidate a confirmed flash batch and each device-bound plan."""

        now = self.clock()
        if batch.expires <= now:
            return SafetyDecision(False, "batch_expired", "operation batch expired")
        if batch.created > now + 1.0:
            return SafetyDecision(
                False,
                "batch_created_in_future",
                "operation batch creation time is invalid",
            )
        if batch.fingerprint != batch.compute_fingerprint():
            return SafetyDecision(
                False,
                "batch_fingerprint_changed",
                "operation batch fingerprint no longer matches its ordered plans",
            )
        if not batch.reinforced_confirmation_valid:
            return SafetyDecision(
                False,
                "batch_confirmation_required",
                "the flash batch requires one nonce-bound confirmation",
            )

        for plan in batch.plans:
            if isinstance(snapshots, AppSnapshot):
                snapshot = snapshots
            else:
                snapshot = snapshots.get(plan.target_serial or "")
            if snapshot is None:
                return SafetyDecision(
                    False,
                    "batch_snapshot_unavailable",
                    f"current state is unavailable for {plan.target_serial!r}",
                )
            authorized = replace(
                plan,
                confirmation_nonce=batch.confirmation_nonce,
                confirmation_token=None,
            )
            authorized = replace(
                authorized,
                confirmation_token=authorized.confirmation_challenge(),
            )
            command = AppCommand(
                CommandKind.FLASH_EXECUTE,
                expected_revision=snapshot.revision,
                target_serial=authorized.target_serial,
                operation_plan=authorized,
                operation_id=f"{batch.batch_id}:{authorized.target_serial}",
                destructive=True,
                requires_confirmation=True,
            )
            decision = self.evaluate(command, snapshot)
            if not decision.allowed:
                return SafetyDecision(
                    False,
                    decision.code,
                    f"{authorized.target_serial}: {decision.message}",
                )

        expected_revision = (
            snapshots.revision
            if isinstance(snapshots, AppSnapshot)
            else max(item.revision for item in snapshots.values())
        )
        return SafetyDecision(
            True,
            "confirmation_required",
            interaction=InteractionRequest(
                operation_id=batch.batch_id,
                kind=InteractionKind.CONFIRM,
                title="Confirm destructive flash batch",
                message=batch.required_confirmation_text(),
                expected_revision=expected_revision,
                destructive=True,
                reinforced=True,
                confirmation_nonce=batch.confirmation_nonce,
            ),
        )

    @staticmethod
    def requires_reinforced_confirmation(command: AppCommand) -> bool:
        plan = command.operation_plan
        if plan is None or plan.dry_run:
            return False
        behavior = plan.data_behavior.strip().casefold().replace("-", "_")
        if behavior in _HIGH_RISK_DATA_BEHAVIORS:
            return True
        for request in plan.requests:
            for argument in request.argv:
                token = argument.strip().casefold().lstrip("-").replace("-", "_")
                if token in _HIGH_RISK_ACTIONS or token.startswith("set_active="):
                    return True
        return False
