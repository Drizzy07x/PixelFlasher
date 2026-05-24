"""Pure view model for the modern Flash Wizard.

This module contains no wxPython imports and does not call adb, fastboot, patch,
or flash operations. It is safe to unit test and safe to evolve before wiring
real PixelFlasher state into the wizard UI.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable


class WizardStepKey(str, Enum):
    DEVICE = "device"
    FIRMWARE = "firmware"
    PATCH = "patch"
    OPTIONS = "options"
    REVIEW = "review"
    FLASH = "flash"


class PatchChoice(str, Enum):
    SKIP = "skip"
    PATCH_LATER = "patch_later"
    USE_EXISTING = "use_existing"


class DataBehavior(str, Enum):
    KEEP = "keep"
    WIPE = "wipe"


class SlotBehavior(str, Enum):
    AUTO = "auto"
    INACTIVE = "inactive"
    CURRENT = "current"
    BOTH = "both"


@dataclass(frozen=True)
class WizardStepDefinition:
    key: WizardStepKey
    title: str
    description: str


@dataclass(frozen=True)
class WizardDevice:
    display_name: str = ""
    serial: str = ""
    adb_ready: bool = False
    fastboot_ready: bool = False
    bootloader_unlocked: bool | None = None
    active_slot: str = ""

    @property
    def selected(self) -> bool:
        return bool(self.display_name or self.serial)

    @property
    def connection_label(self) -> str:
        if self.adb_ready:
            return "ADB ready"
        if self.fastboot_ready:
            return "Fastboot ready"
        if self.selected:
            return "Selected, connection unknown"
        return "No device selected"


@dataclass(frozen=True)
class WizardFirmware:
    path: str = ""
    package_type: str = "unknown"
    target_device: str = ""
    build_id: str = ""
    has_boot_image: bool = False
    has_init_boot_image: bool = False
    sha256: str = ""
    verified: bool = False

    @property
    def selected(self) -> bool:
        return bool(self.path)

    @property
    def filename(self) -> str:
        return Path(self.path).name if self.path else ""

    @property
    def has_patchable_image(self) -> bool:
        return self.has_boot_image or self.has_init_boot_image


@dataclass(frozen=True)
class WizardOptions:
    data_behavior: DataBehavior = DataBehavior.KEEP
    slot_behavior: SlotBehavior = SlotBehavior.INACTIVE
    disable_verity: bool = False
    disable_verification: bool = False
    fastboot_force: bool = False
    no_reboot: bool = False

    @property
    def dangerous_enabled(self) -> bool:
        return any((
            self.data_behavior == DataBehavior.WIPE,
            self.disable_verity,
            self.disable_verification,
            self.fastboot_force,
        ))


@dataclass(frozen=True)
class WizardSession:
    device: WizardDevice = field(default_factory=WizardDevice)
    firmware: WizardFirmware = field(default_factory=WizardFirmware)
    patch_choice: PatchChoice = PatchChoice.SKIP
    options: WizardOptions = field(default_factory=WizardOptions)
    preflight_passed: bool = False
    flash_connected: bool = False

    def step_complete(self, step: WizardStepKey | str) -> bool:
        step_key = WizardStepKey(step)
        if step_key == WizardStepKey.DEVICE:
            return self.device.selected and (self.device.adb_ready or self.device.fastboot_ready)
        if step_key == WizardStepKey.FIRMWARE:
            return self.firmware.selected and self.firmware.verified
        if step_key == WizardStepKey.PATCH:
            return self.patch_choice in set(PatchChoice)
        if step_key == WizardStepKey.OPTIONS:
            return True
        if step_key == WizardStepKey.REVIEW:
            return self.preflight_passed and not self.blocking_warnings()
        if step_key == WizardStepKey.FLASH:
            return self.can_flash
        return False

    def warnings(self) -> tuple[str, ...]:
        warnings: list[str] = []
        if not self.device.selected:
            warnings.append("No target device selected.")
        elif not (self.device.adb_ready or self.device.fastboot_ready):
            warnings.append("Device connection mode is unknown.")

        if self.device.bootloader_unlocked is False:
            warnings.append("Bootloader appears locked; flashing may fail or wipe data.")
        elif self.device.bootloader_unlocked is None:
            warnings.append("Bootloader lock state is unknown.")

        if not self.firmware.selected:
            warnings.append("No firmware package selected.")
        elif not self.firmware.verified:
            warnings.append("Firmware package has not been verified.")

        if self.patch_choice != PatchChoice.SKIP and not self.firmware.has_patchable_image:
            warnings.append("Patch requested but boot/init_boot image is not available.")

        if self.options.dangerous_enabled:
            warnings.append("Dangerous options are enabled and require explicit confirmation.")

        if not self.preflight_passed:
            warnings.append("Pre-flight checks have not passed.")

        if not self.flash_connected:
            warnings.append("Flash execution is not connected in this build.")
        return tuple(warnings)

    def blocking_warnings(self) -> tuple[str, ...]:
        return tuple(w for w in self.warnings() if w not in {"Flash execution is not connected in this build."})

    @property
    def can_flash(self) -> bool:
        return self.flash_connected and self.preflight_passed and not self.blocking_warnings()

    def review_lines(self) -> tuple[str, ...]:
        return (
            f"Device: {self.device.display_name or self.device.serial or 'not selected'}",
            f"Connection: {self.device.connection_label}",
            f"Firmware: {self.firmware.filename or 'not selected'}",
            f"Firmware verified: {'yes' if self.firmware.verified else 'no'}",
            f"Patch boot/init_boot: {self.patch_choice.value}",
            f"Data behavior: {self.options.data_behavior.value}",
            f"Slot behavior: {self.options.slot_behavior.value}",
            f"Dangerous options: {'enabled' if self.options.dangerous_enabled else 'disabled'}",
            f"Pre-flight checks: {'passed' if self.preflight_passed else 'not passed'}",
            f"Flash enabled: {'yes' if self.can_flash else 'no'}",
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


STEPS: tuple[WizardStepDefinition, ...] = (
    WizardStepDefinition(WizardStepKey.DEVICE, "Device", "Confirm the target device before selecting firmware."),
    WizardStepDefinition(WizardStepKey.FIRMWARE, "Firmware", "Choose an OTA, factory image, or custom ROM package."),
    WizardStepDefinition(WizardStepKey.PATCH, "Patch Boot", "Decide whether boot/init_boot patching is needed."),
    WizardStepDefinition(WizardStepKey.OPTIONS, "Options", "Choose data, slot, and safety behavior."),
    WizardStepDefinition(WizardStepKey.REVIEW, "Review", "Verify the complete plan before any dangerous action."),
    WizardStepDefinition(WizardStepKey.FLASH, "Flash", "Final execution step, intentionally disabled here."),
)


def completed_step_titles(session: WizardSession, steps: Iterable[WizardStepDefinition] = STEPS) -> tuple[str, ...]:
    return tuple(step.title for step in steps if session.step_complete(step.key))
