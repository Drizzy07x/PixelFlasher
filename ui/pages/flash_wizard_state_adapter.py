"""Safe state adapter from the legacy frame to ``WizardSession``.

The adapter only reads already-loaded UI/config state. It intentionally does not
run adb, fastboot, firmware parsing, patching, or flashing operations.

Shared read-only state comes from ``modern_readonly_state`` so Modern UI
surfaces can converge on one safe state model.
"""

from __future__ import annotations

from typing import Any

from ui.pages.flash_wizard_model import (
    DataBehavior,
    PatchChoice,
    SlotBehavior,
    WizardDevice,
    WizardFirmware,
    WizardOptions,
    WizardSession,
)
from ui.pages.modern_readonly_state import ModernReadonlyState, build_readonly_state


def build_wizard_session(frame: Any) -> WizardSession:
    """Build a read-only ``WizardSession`` from the current legacy frame state."""

    config = getattr(frame, "config", None)
    readonly = build_readonly_state(frame, tool_resolver=lambda name: None)
    return WizardSession(
        device=_wizard_device(readonly),
        firmware=_wizard_firmware(readonly, config),
        patch_choice=_read_patch_choice(frame, config),
        options=_read_options(frame, config),
        preflight_passed=False,
        flash_connected=False,
    )


def _wizard_device(readonly: ModernReadonlyState) -> WizardDevice:
    device = readonly.device
    return WizardDevice(
        display_name=device.display_name,
        serial=device.serial,
        adb_ready=device.adb_ready,
        fastboot_ready=device.fastboot_ready,
        bootloader_unlocked=_bootloader_unlocked(device.bootloader_state),
        active_slot=device.active_slot,
    )


def _wizard_firmware(readonly: ModernReadonlyState, config: Any) -> WizardFirmware:
    firmware = readonly.firmware
    return WizardFirmware(
        path=firmware.path,
        package_type=firmware.package_type,
        target_device=firmware.target_device,
        build_id=firmware.build_id,
        has_boot_image=firmware.has_boot_image,
        has_init_boot_image=firmware.has_init_boot_image,
        sha256=_read_sha256(config),
        verified=firmware.verified,
    )


def _read_patch_choice(frame: Any, config: Any) -> PatchChoice:
    if getattr(config, "boot_id", None) or getattr(config, "selected_boot_md5", None):
        return PatchChoice.USE_EXISTING
    return PatchChoice.SKIP


def _read_options(frame: Any, config: Any) -> WizardOptions:
    if bool(getattr(frame, "wipe", False)):
        data_behavior = DataBehavior.WIPE
    else:
        data_behavior = DataBehavior.KEEP

    if bool(getattr(config, "flash_both_slots", False)):
        slot_behavior = SlotBehavior.BOTH
    elif bool(getattr(config, "flash_to_inactive_slot", False)):
        slot_behavior = SlotBehavior.INACTIVE
    else:
        slot_behavior = SlotBehavior.AUTO

    return WizardOptions(
        data_behavior=data_behavior,
        slot_behavior=slot_behavior,
        disable_verity=bool(getattr(config, "disable_verity", False)),
        disable_verification=bool(getattr(config, "disable_verification", False)),
        fastboot_force=bool(getattr(config, "fastboot_force", False)),
        no_reboot=bool(getattr(config, "no_reboot", False)),
    )


def _bootloader_unlocked(value: str) -> bool | None:
    normalized = str(value or "").strip().lower()
    if normalized in {"unlocked", "unlock", "true", "yes"}:
        return True
    if normalized in {"locked", "lock", "false", "no"}:
        return False
    return None


def _read_sha256(config: Any) -> str:
    return str(getattr(config, "firmware_sha256", "") or getattr(config, "rom_sha256", "") or "")
