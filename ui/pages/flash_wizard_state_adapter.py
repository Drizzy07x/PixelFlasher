"""Safe state adapter from the legacy frame to ``WizardSession``.

The adapter only reads already-loaded UI/config state. It intentionally does not
run adb, fastboot, firmware parsing, patching, or flashing operations.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
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


def build_wizard_session(frame: Any) -> WizardSession:
    """Build a read-only ``WizardSession`` from the current legacy frame state."""
    config = getattr(frame, "config", None)
    return WizardSession(
        device=_read_device(frame, config),
        firmware=_read_firmware(frame, config),
        patch_choice=_read_patch_choice(frame, config),
        options=_read_options(frame, config),
        preflight_passed=False,
        flash_connected=False,
    )


def _read_device(frame: Any, config: Any) -> WizardDevice:
    selected = _call_string(getattr(frame, "device_choice", None), "GetStringSelection")
    configured = str(getattr(config, "device", "") or "")
    identifier = selected or configured
    return WizardDevice(
        display_name=identifier or "",
        serial=identifier or "",
        adb_ready=False,
        fastboot_ready=False,
        bootloader_unlocked=None,
        active_slot="",
    )


def _read_firmware(frame: Any, config: Any) -> WizardFirmware:
    path = _call_string(getattr(frame, "firmware_picker", None), "GetPath")
    if not path:
        path = str(getattr(config, "firmware_path", "") or "")

    firmware_is_ota = bool(getattr(config, "firmware_is_ota", False))
    custom_rom = bool(getattr(config, "custom_rom", False))
    package_type = "custom_rom" if custom_rom else ("ota" if firmware_is_ota else "factory")
    target_device = str(getattr(config, "device", "") or "")
    build_id = _infer_build_id(path)
    sha256 = str(getattr(config, "firmware_sha256", "") or getattr(config, "rom_sha256", "") or "")
    verified = bool(path and sha256)

    return WizardFirmware(
        path=path,
        package_type=package_type,
        target_device=target_device,
        build_id=build_id,
        has_boot_image=bool(getattr(config, "boot_id", None) or getattr(config, "selected_boot_md5", None)),
        has_init_boot_image=bool(getattr(config, "firmware_has_init_boot", False) or getattr(config, "rom_has_init_boot", False)),
        sha256=sha256,
        verified=verified,
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


def _call_string(obj: Any, method_name: str) -> str:
    if obj is None:
        return ""
    method = getattr(obj, method_name, None)
    if not callable(method):
        return ""
    with contextlib.suppress(Exception):
        value = method()
        return str(value or "")
    return ""


def _infer_build_id(path: str) -> str:
    if not path:
        return ""
    stem = Path(path).name
    if not stem:
        return ""
    stem = stem.rsplit(".", 1)[0]
    parts = stem.split("-")
    if len(parts) >= 2:
        return "-".join(parts[:2])
    return stem
