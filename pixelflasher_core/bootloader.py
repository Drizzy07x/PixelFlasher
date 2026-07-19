"""Fail-closed bootloader transition policy."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import AppSnapshot, DeviceInfo, OperationStatus

LOCK_STOCK_EVIDENCE_REQUIRED_MESSAGE = (
    "Bootloader locking is blocked because PixelFlasher has not verified a complete "
    "compatible stock factory flash for this device with no subsequent state changes."
)


@dataclass(frozen=True, slots=True)
class BootloaderLockDecision:
    allowed: bool
    code: str
    message: str


class BootloaderLockPolicy:
    """Accept relocking only from canonical, revision-bound stock evidence."""

    _UNSAFE_OPTIONS = frozenset(
        {
            "disableVerity",
            "disableVerification",
            "disable_verity",
            "disable_verification",
            "force",
            "temporaryRoot",
            "temporary_root",
            "downgrade",
        }
    )

    def evaluate(self, snapshot: AppSnapshot, device: DeviceInfo) -> BootloaderLockDecision:
        evidence = next(
            (
                item
                for item in snapshot.bootloader_lock_evidence
                if item.serial == device.serial
            ),
            None,
        )
        if evidence is None:
            return self._deny(
                "bootloader_lock_stock_evidence_required",
                LOCK_STOCK_EVIDENCE_REQUIRED_MESSAGE,
            )
        if evidence.snapshot_revision != snapshot.revision:
            return self._deny(
                "bootloader_lock_state_changed",
                "Canonical state changed after the verified stock flash; locking remains blocked.",
            )
        if not device.codename or device.codename.casefold() != evidence.device_codename.casefold():
            return self._deny(
                "bootloader_lock_device_mismatch",
                "Stock flash evidence does not match the connected device codename.",
            )

        firmware = snapshot.firmware
        if (
            firmware.type.casefold() != "factory"
            or not firmware.verified
            or not firmware.processed
            or not firmware.hash
            or not firmware.build
        ):
            return self._deny(
                "bootloader_lock_factory_firmware_required",
                "Locking requires canonical verified and processed factory firmware.",
            )
        if (
            firmware.hash.casefold() != evidence.firmware_hash
            or firmware.build != evidence.firmware_build
        ):
            return self._deny(
                "bootloader_lock_firmware_mismatch",
                "Canonical firmware no longer matches the verified stock flash evidence.",
            )

        plan = snapshot.plan
        if (
            plan.mode.casefold() != "factory"
            or plan.dry_run
            or plan.fingerprint != evidence.flash_plan_fingerprint
        ):
            return self._deny(
                "bootloader_lock_plan_mismatch",
                "Canonical flash plan no longer proves the completed stock factory flash.",
            )
        options = plan.options
        if options.get("slot") != "both" or "partitions" in options:
            return self._deny(
                "bootloader_lock_factory_flash_incomplete",
                "Locking requires a complete stock factory flash covering both slots.",
            )
        if any(options.get(option) is True for option in self._UNSAFE_OPTIONS):
            return self._deny(
                "bootloader_lock_modified_factory_flash",
                "The completed flash used options that do not prove an unmodified stock state.",
            )

        result = snapshot.last_result
        if (
            result is None
            or result.status is not OperationStatus.SUCCESS
            or result.operation_id != evidence.flash_operation_id
        ):
            return self._deny(
                "bootloader_lock_flash_result_unverified",
                "The successful factory flash result bound to this evidence is unavailable.",
            )
        if not set(evidence.required_partitions).issubset(evidence.flashed_partitions):
            return self._deny(
                "bootloader_lock_factory_flash_incomplete",
                "Verified stock partitions are incomplete; locking remains blocked.",
            )
        if set(evidence.slots) != {"a", "b"}:
            return self._deny(
                "bootloader_lock_factory_flash_incomplete",
                "Verified stock flash evidence does not cover both slots.",
            )
        return BootloaderLockDecision(True, "bootloader_lock_allowed", "")

    @staticmethod
    def _deny(code: str, message: str) -> BootloaderLockDecision:
        return BootloaderLockDecision(False, code, message)
