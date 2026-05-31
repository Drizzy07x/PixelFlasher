"""Shared read-only state adapter for Modern UI preview surfaces.

This module only reads already-loaded frame/config values. It does not run adb,
fastboot, patching, flashing, firmware parsing, reboot, slot, wipe, or file
mutation operations.
"""

from __future__ import annotations

import contextlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


ToolResolver = Callable[[str], str | None]


@dataclass(frozen=True)
class ModernDeviceState:
    display_name: str = ""
    serial: str = ""
    adb_ready: bool = False
    fastboot_ready: bool = False
    bootloader_state: str = "unknown"
    active_slot: str = ""
    root_status: str = "unknown"
    android_version: str = ""

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
class ModernFirmwareState:
    path: str = ""
    package_type: str = "unknown"
    target_device: str = ""
    build_id: str = ""
    sha256_available: bool = False
    verified: bool = False
    has_boot_image: bool = False
    has_init_boot_image: bool = False

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
class ModernToolState:
    adb_path: str = ""
    fastboot_path: str = ""

    @property
    def adb_available(self) -> bool:
        return bool(self.adb_path)

    @property
    def fastboot_available(self) -> bool:
        return bool(self.fastboot_path)


@dataclass(frozen=True)
class ModernReadonlyState:
    device: ModernDeviceState
    firmware: ModernFirmwareState
    tools: ModernToolState
    warnings: tuple[str, ...]

    @property
    def ready_for_review(self) -> bool:
        return self.device.selected and self.firmware.selected and self.firmware.verified


def build_readonly_state(frame: Any, tool_resolver: ToolResolver | None = None) -> ModernReadonlyState:
    """Build side-effect-free Modern UI state from the current legacy frame."""

    config = getattr(frame, "config", None)
    device = _read_device(frame, config)
    firmware = _read_firmware(frame, config)
    tools = _read_tools(tool_resolver or shutil.which)
    warnings = _warnings(device, firmware)
    return ModernReadonlyState(device=device, firmware=firmware, tools=tools, warnings=warnings)


def _read_device(frame: Any, config: Any) -> ModernDeviceState:
    selected = _call_string(getattr(frame, "device_choice", None), "GetStringSelection")
    configured = str(getattr(config, "device", "") or "")
    identifier = selected or configured

    return ModernDeviceState(
        display_name=identifier,
        serial=identifier,
        adb_ready=bool(selected),
        fastboot_ready=False,
        bootloader_state=str(getattr(config, "bootloader_state", "") or "unknown"),
        active_slot=str(getattr(config, "active_slot", "") or ""),
        root_status=str(getattr(config, "root_status", "") or "unknown"),
        android_version=str(getattr(config, "android_version", "") or ""),
    )


def _read_firmware(frame: Any, config: Any) -> ModernFirmwareState:
    picker_path = _call_string(getattr(frame, "firmware_picker", None), "GetPath")
    firmware_path = picker_path or str(getattr(config, "firmware_path", "") or "")
    custom_rom = bool(getattr(config, "custom_rom", False))
    rom_path = str(getattr(config, "custom_rom_path", "") or getattr(config, "rom_path", "") or "")
    path = rom_path if custom_rom and rom_path else firmware_path

    firmware_is_ota = bool(getattr(config, "firmware_is_ota", False))
    if custom_rom:
        package_type = "custom_rom"
    elif firmware_is_ota:
        package_type = "ota"
    elif path:
        package_type = "factory"
    else:
        package_type = "unknown"

    firmware_sha256 = str(getattr(config, "firmware_sha256", "") or "")
    rom_sha256 = str(getattr(config, "rom_sha256", "") or "")
    sha256 = rom_sha256 if custom_rom else firmware_sha256

    return ModernFirmwareState(
        path=path,
        package_type=package_type,
        target_device=str(getattr(config, "device", "") or ""),
        build_id=_infer_build_id(path),
        sha256_available=bool(sha256),
        verified=bool(path and sha256),
        has_boot_image=bool(getattr(config, "boot_id", None) or getattr(config, "selected_boot_md5", None)),
        has_init_boot_image=bool(getattr(config, "firmware_has_init_boot", False) or getattr(config, "rom_has_init_boot", False)),
    )


def _read_tools(tool_resolver: ToolResolver) -> ModernToolState:
    adb = tool_resolver("adb") or tool_resolver("adb.exe") or ""
    fastboot = tool_resolver("fastboot") or tool_resolver("fastboot.exe") or ""
    return ModernToolState(adb_path=str(adb or ""), fastboot_path=str(fastboot or ""))


def _warnings(device: ModernDeviceState, firmware: ModernFirmwareState) -> tuple[str, ...]:
    warnings: list[str] = []
    if not device.selected:
        warnings.append("No target device selected.")
    if not firmware.selected:
        warnings.append("No firmware package selected.")
    elif not firmware.verified:
        warnings.append("Firmware package has not been verified.")
    return tuple(warnings)


def _call_string(obj: Any, method_name: str) -> str:
    if obj is None:
        return ""
    method = getattr(obj, method_name, None)
    if not callable(method):
        return ""
    with contextlib.suppress(Exception):
        return str(method() or "")
    return ""


def _infer_build_id(path: str) -> str:
    if not path:
        return ""
    stem = Path(path).name.rsplit(".", 1)[0]
    parts = stem.split("-")
    if len(parts) >= 2:
        return "-".join(parts[:2])
    return stem
