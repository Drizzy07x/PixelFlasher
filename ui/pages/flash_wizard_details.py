"""Formatting helpers for Flash Wizard step details.

Pure functions only. No wxPython, no adb, no fastboot, no flashing.
"""

from __future__ import annotations

from ui.pages.flash_wizard_model import WizardSession, WizardStepKey


def step_detail_lines(session: WizardSession, step: WizardStepKey | str) -> tuple[str, ...]:
    """Return display lines for one wizard step from the session model."""
    step_key = WizardStepKey(step)
    if step_key == WizardStepKey.DEVICE:
        return _device_lines(session)
    if step_key == WizardStepKey.FIRMWARE:
        return _firmware_lines(session)
    if step_key == WizardStepKey.PATCH:
        return _patch_lines(session)
    if step_key == WizardStepKey.OPTIONS:
        return _option_lines(session)
    if step_key == WizardStepKey.REVIEW:
        return _review_lines(session)
    if step_key == WizardStepKey.FLASH:
        return _flash_lines(session)
    return ()


def warning_lines(session: WizardSession) -> tuple[str, ...]:
    warnings = session.warnings()
    if not warnings:
        return ("No warnings.",)
    return tuple(f"Warning: {warning}" for warning in warnings)


def _device_lines(session: WizardSession) -> tuple[str, ...]:
    device = session.device
    return (
        f"Device: {device.display_name or device.serial or 'not selected'}",
        f"Connection: {device.connection_label}",
        f"ADB ready: {'yes' if device.adb_ready else 'no'}",
        f"Fastboot ready: {'yes' if device.fastboot_ready else 'no'}",
        f"Bootloader unlocked: {_optional_bool(device.bootloader_unlocked)}",
        f"Active slot: {device.active_slot or 'unknown'}",
    )


def _firmware_lines(session: WizardSession) -> tuple[str, ...]:
    firmware = session.firmware
    return (
        f"Firmware: {firmware.filename or 'not selected'}",
        f"Package type: {firmware.package_type}",
        f"Target device: {firmware.target_device or 'unknown'}",
        f"Build ID: {firmware.build_id or 'unknown'}",
        f"SHA-256: {'available' if firmware.sha256 else 'missing'}",
        f"Verified: {'yes' if firmware.verified else 'no'}",
    )


def _patch_lines(session: WizardSession) -> tuple[str, ...]:
    firmware = session.firmware
    return (
        f"Patch choice: {session.patch_choice.value}",
        f"boot.img available: {'yes' if firmware.has_boot_image else 'no'}",
        f"init_boot.img available: {'yes' if firmware.has_init_boot_image else 'no'}",
        f"Patchable image available: {'yes' if firmware.has_patchable_image else 'no'}",
        "Patch execution: requires PixelFlasher confirmation",
    )


def _option_lines(session: WizardSession) -> tuple[str, ...]:
    options = session.options
    return (
        f"Data behavior: {options.data_behavior.value}",
        f"Slot behavior: {options.slot_behavior.value}",
        f"Disable verity: {'yes' if options.disable_verity else 'no'}",
        f"Disable verification: {'yes' if options.disable_verification else 'no'}",
        f"Fastboot force: {'yes' if options.fastboot_force else 'no'}",
        f"No reboot: {'yes' if options.no_reboot else 'no'}",
        f"Dangerous options: {'enabled' if options.dangerous_enabled else 'disabled'}",
    )


def _review_lines(session: WizardSession) -> tuple[str, ...]:
    lines = list(session.review_lines())
    warnings = warning_lines(session)
    if warnings:
        lines.append("")
        lines.extend(warnings)
    return tuple(lines)


def _flash_lines(session: WizardSession) -> tuple[str, ...]:
    return (
        f"Can flash: {'yes' if session.can_flash else 'no'}",
        f"Pre-flight checks: {'passed' if session.preflight_passed else 'not passed'}",
        f"Flash execution connected: {'yes' if session.flash_connected else 'no'}",
        "Final action: available after blocking warnings are resolved",
        "Execution target: guarded PixelFlasher flash flow",
    )


def _optional_bool(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"
