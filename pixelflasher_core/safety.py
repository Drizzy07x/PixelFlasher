"""Pure safety decisions for headless PixelFlasher commands."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import (
    AppCommand,
    AppSnapshot,
    CommandKind,
    InteractionKind,
    InteractionRequest,
    SafetyDecision,
)


_HIGH_RISK_ACTIONS = frozenset(
    {"wipe", "erase", "switch", "unlock", "set_active", "set-active"}
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
            "support.create",
            "flash.plan.preview",
            "device.reboot",
            "device.switchSlot",
            "device.bootloader.lock",
            "device.bootloader.unlock",
            "boot.flash",
            "boot.live",
            "boot.patch",
            "apps.list",
            "apps.action",
            "partitions.list",
            "partitions.read",
            "partitions.write",
            "partitions.erase",
            "tools.logcat",
            "tools.pushFiles",
            "tools.adbShell",
            "tools.scrcpy",
            "tools.wifi",
            "backups.create",
            "backups.restore",
            "root.apps.list",
            "root.apps.install",
            "root.modules.list",
            "root.modules.action",
        }
    )

    def is_destructive(self, command: AppCommand) -> bool:
        if command.operation_plan is not None and command.operation_plan.dry_run:
            return False
        return command.destructive or command.kind == CommandKind.FLASH_EXECUTE.value

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
        if (
            command.kind == CommandKind.FLASH_EXECUTE.value
            or self.is_destructive(command)
            or (
                command.operation_plan is not None
                and command.operation_plan.target_serial is not None
            )
        ):
            if not snapshot.selected_serials:
                return SafetyDecision(False, "device_not_selected", "no target device is selected")
            plan_target = (
                command.operation_plan.target_serial if command.operation_plan is not None else None
            )
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
            target_device = next(
                (device for device in snapshot.devices if device.serial == plan_target),
                None,
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
                        (
                            f"device state changed from {plan.expected_device_state!r} "
                            f"to {target_device.mode!r}"
                        ),
                    )
            if plan.plan_revision != snapshot.plan.revision:
                return SafetyDecision(
                    False,
                    "plan_revision_changed",
                    (
                        f"flash plan revision changed from {plan.plan_revision} "
                        f"to {snapshot.plan.revision}"
                    ),
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
            reinforced = self.requires_reinforced_confirmation(command)
            if reinforced and not plan.reinforced_confirmation_valid:
                return SafetyDecision(
                    False,
                    "reinforced_confirmation_required",
                    (
                        "wipe, erase, slot switching, and unlock operations require "
                        "a nonce-bound confirmation token"
                    ),
                )

        if command.kind in self.revisioned_kinds:
            if command.expected_revision is None:
                return SafetyDecision(False, "revision_required", "expected_revision is required")
            if command.expected_revision != snapshot.revision:
                return SafetyDecision(
                    False,
                    "stale_revision",
                    (
                        f"state revision changed: expected {command.expected_revision}, "
                        f"current {snapshot.revision}"
                    ),
                )

        if self.is_destructive(command) or command.requires_confirmation:
            plan = command.operation_plan
            interaction_target = plan.target_serial if plan is not None else command.target_serial
            request = InteractionRequest(
                operation_id=command.operation_id,
                kind=InteractionKind.CONFIRM,
                title=(
                    "Confirm high-risk destructive operation"
                    if reinforced
                    else "Confirm destructive operation"
                ),
                message=(
                    f"Run {command.kind!r} on device {interaction_target!r}?"
                    if interaction_target
                    else f"Run {command.kind!r}?"
                ),
                expected_revision=snapshot.revision,
                target_serial=interaction_target,
                destructive=self.is_destructive(command),
                reinforced=reinforced,
                confirmation_nonce=plan.confirmation_nonce if plan is not None else None,
            )
            return SafetyDecision(True, "confirmation_required", interaction=request)

        return SafetyDecision(True, "allowed")

    @staticmethod
    def requires_reinforced_confirmation(command: AppCommand) -> bool:
        plan = command.operation_plan
        if plan is None or plan.dry_run:
            return False
        safety_tokens = [
            plan.data_behavior.lower().replace("-", "_")
        ] + [
            argument.lower().lstrip("-").replace("-", "_")
            for request in plan.requests
            for argument in request.argv
        ]
        return any(
            action in token
            for token in safety_tokens
            for action in _HIGH_RISK_ACTIONS
        )
