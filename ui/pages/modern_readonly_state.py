"""Shared read-only state adapter for Modern UI preview surfaces.

This module only reads already-loaded frame/config values. It does not run adb,
fastboot, patching, flashing, firmware parsing, reboot, slot, wipe, or file
mutation operations.
"""

from __future__ import annotations

import contextlib
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


ToolResolver = Callable[[str], str | None]

PIXEL_CODENAME_NAMES: dict[str, str] = {
    "komodo": "Pixel 9 Pro XL",
    "caiman": "Pixel 9 Pro",
    "tokay": "Pixel 9",
    "akita": "Pixel 8a",
    "husky": "Pixel 8 Pro",
    "shiba": "Pixel 8",
    "felix": "Pixel Fold",
    "tangorpro": "Pixel Tablet",
    "cheetah": "Pixel 7 Pro",
    "panther": "Pixel 7",
    "lynx": "Pixel 7a",
    "raven": "Pixel 6 Pro",
    "oriole": "Pixel 6",
    "bluejay": "Pixel 6a",
    "redfin": "Pixel 5",
    "barbet": "Pixel 5a",
    "bramble": "Pixel 4a 5G",
    "sunfish": "Pixel 4a",
    "coral": "Pixel 4 XL",
    "flame": "Pixel 4",
}


@dataclass(frozen=True)
class ModernDeviceState:
    display_name: str = ""
    serial: str = ""
    codename: str = ""
    product: str = ""
    adb_ready: bool = False
    fastboot_ready: bool = False
    bootloader_state: str = "unknown"
    active_slot: str = ""
    root_status: str = "unknown"
    android_version: str = ""
    build_id: str = ""
    security_patch: str = ""

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
    platform_tools_path: str = ""

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
    flash: "ModernFlashOptionsState" = field(default_factory=lambda: ModernFlashOptionsState())
    backups: "ModernBackupState" = field(default_factory=lambda: ModernBackupState())
    downloads: "ModernDownloadState" = field(default_factory=lambda: ModernDownloadState())
    settings: "ModernSettingsState" = field(default_factory=lambda: ModernSettingsState())

    @property
    def ready_for_review(self) -> bool:
        return self.device.selected and self.firmware.selected and self.firmware.verified


@dataclass(frozen=True)
class ModernFlashOptionsState:
    flash_mode: str = "dryRun"
    data_behavior: str = "Dry run"
    slot_behavior: str = "Default"
    verification: str = "Default"
    verity: str = "Default"
    force: bool = False
    no_reboot: bool = False
    temporary_root: bool = False
    custom_rom: bool = False


@dataclass(frozen=True)
class ModernBackupState:
    total_count: int = 0
    latest_label: str = "not loaded"
    location: str = "not selected"
    restore_mode: str = "guarded legacy only"

    @property
    def has_loaded_backups(self) -> bool:
        return self.total_count > 0


@dataclass(frozen=True)
class ModernDownloadState:
    update_check: bool = False
    module_update_check: bool = False
    image_catalog_status: str = "not loaded"
    update_frequency: str = "not configured"
    last_checked: str = "not checked"


@dataclass(frozen=True)
class ModernSettingsState:
    language: str = "System default"
    advanced_options: bool = False
    verbose: bool = False
    low_memory: bool = False
    notifications: bool = False
    custom_rom_options: bool = False
    phone_path: str = ""


def build_readonly_state(frame: Any, tool_resolver: ToolResolver | None = None) -> ModernReadonlyState:
    """Build side-effect-free Modern UI state from the current legacy frame."""

    config = getattr(frame, "config", None)
    device = _read_device(frame, config)
    firmware = _read_firmware(frame, config)
    tools = _read_tools(config, tool_resolver or shutil.which)
    flash = _read_flash_options(config)
    backups = _read_backups(frame, config)
    downloads = _read_downloads(config)
    settings = _read_settings(config)
    warnings = _warnings(device, firmware)
    return ModernReadonlyState(
        device=device,
        firmware=firmware,
        tools=tools,
        warnings=warnings,
        flash=flash,
        backups=backups,
        downloads=downloads,
        settings=settings,
    )


def _read_device(frame: Any, config: Any) -> ModernDeviceState:
    selected = _call_string(getattr(frame, "device_choice", None), "GetStringSelection")
    configured = str(getattr(config, "device", "") or "")
    phone = _loaded_phone(frame, config)
    props = _loaded_props(phone)
    serial = _first_text(_raw_string(phone, "id"), _serial_from_device_text(selected), configured)
    model = _prop(props, "ro.product.model")
    codename = _first_text(_prop(props, "ro.product.device"), _prop(props, "ro.hardware"), _codename_from_device_text(selected), configured)
    product = _prop(props, "ro.product.name")
    identifier = _first_text(
        _clean_device_model(model),
        _friendly_name_for_codename(codename),
        _device_model_from_text(selected),
        _friendly_name_for_codename(configured),
        _clean_device_label(selected),
        configured,
        serial,
    )
    mode = _read_connection_mode(frame, config, selected)
    adb_ready = _is_adb_mode(mode)
    fastboot_ready = _is_fastboot_mode(mode)

    if selected and not mode:
        adb_ready = True

    return ModernDeviceState(
        display_name=identifier,
        serial=serial or _serial_from_device_text(selected) or identifier,
        codename=codename,
        product=product,
        adb_ready=adb_ready,
        fastboot_ready=fastboot_ready,
        bootloader_state=_first_text(
            getattr(config, "bootloader_state", ""),
            _prop(props, "ro.boot.vbmeta.device_state"),
            _prop(props, "ro.boot.verifiedbootstate"),
            "unknown",
        ),
        active_slot=_normalize_slot(_first_text(getattr(config, "active_slot", ""), _prop(props, "ro.boot.slot_suffix"), _prop(props, "current-slot"))),
        root_status=_read_root_status(phone, config),
        android_version=_first_text(getattr(config, "android_version", ""), _prop(props, "ro.build.version.release")),
        build_id=_first_text(getattr(config, "build_id", ""), _prop(props, "ro.build.id")),
        security_patch=_first_text(getattr(config, "security_patch", ""), _prop(props, "ro.build.version.security_patch")),
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


def _read_tools(config: Any, tool_resolver: ToolResolver) -> ModernToolState:
    configured_path = str(getattr(config, "platform_tools_path", "") or "")
    adb = _configured_tool(configured_path, ("adb.exe", "adb")) or tool_resolver("adb") or tool_resolver("adb.exe") or ""
    fastboot = _configured_tool(configured_path, ("fastboot.exe", "fastboot")) or tool_resolver("fastboot") or tool_resolver("fastboot.exe") or ""
    return ModernToolState(adb_path=str(adb or ""), fastboot_path=str(fastboot or ""), platform_tools_path=configured_path)


def _configured_tool(configured_path: str, names: tuple[str, ...]) -> str:
    if not configured_path:
        return ""
    root = Path(configured_path)
    for name in names:
        candidate = root / name
        if candidate.is_file():
            return str(candidate)
    return ""


def _read_flash_options(config: Any) -> ModernFlashOptionsState:
    mode = str(getattr(config, "flash_mode", "") or "dryRun")
    return ModernFlashOptionsState(
        flash_mode=mode,
        data_behavior=_data_behavior(mode),
        slot_behavior=_slot_behavior(config),
        verification="disabled" if bool(getattr(config, "disable_verification", False)) else "default",
        verity="disabled" if bool(getattr(config, "disable_verity", False)) else "default",
        force=bool(getattr(config, "fastboot_force", False)),
        no_reboot=bool(getattr(config, "no_reboot", False)),
        temporary_root=bool(getattr(config, "temporary_root", False)),
        custom_rom=bool(getattr(config, "custom_rom", False)),
    )


def _read_backups(frame: Any, config: Any) -> ModernBackupState:
    phone = _loaded_phone(frame, config)
    backups = _raw_attr(phone, "backups")
    if not isinstance(backups, dict):
        backups = {}
    latest = _latest_backup_label(backups)
    return ModernBackupState(
        total_count=len(backups),
        latest_label=latest or "not loaded",
        location=str(getattr(config, "phone_path", "") or "not selected"),
    )


def _read_downloads(config: Any) -> ModernDownloadState:
    frequency = getattr(config, "google_images_update_frequency", None)
    last_checked = getattr(config, "google_images_last_checked", None)
    return ModernDownloadState(
        update_check=bool(getattr(config, "update_check", False)),
        module_update_check=bool(getattr(config, "check_module_updates", False)),
        image_catalog_status="loaded" if last_checked else "not loaded",
        update_frequency=_frequency_label(frequency),
        last_checked=_timestamp_label(last_checked),
    )


def _read_settings(config: Any) -> ModernSettingsState:
    return ModernSettingsState(
        language=str(getattr(config, "language", "") or "System default"),
        advanced_options=bool(getattr(config, "advanced_options", False)),
        verbose=bool(getattr(config, "verbose", False)),
        low_memory=bool(getattr(config, "low_mem", False)),
        notifications=bool(getattr(config, "show_notifications", False)),
        custom_rom_options=bool(getattr(config, "show_custom_rom_options", False)),
        phone_path=str(getattr(config, "phone_path", "") or ""),
    )


def _read_connection_mode(frame: Any, config: Any, selected: str) -> str:
    for obj in (_loaded_phone(frame, config), config, frame):
        if obj is None:
            continue
        for attr in ("true_mode", "mode", "device_mode"):
            mode = _normalize_connection_mode(_raw_string(obj, attr) or str(getattr(obj, attr, "") or ""))
            if mode:
                return mode

    return _connection_mode_from_text(selected)


def _connection_mode_from_text(value: str) -> str:
    text = str(value or "").lower()
    if any(token in text for token in ("fastboot", "bootloader", "f.b")):
        return "fastboot"
    if "recovery" in text:
        return "recovery"
    if "adb" in text:
        return "adb"
    return ""


def _serial_from_device_text(value: str) -> str:
    for token in _device_text_tokens(value):
        if ":" in token:
            continue
        compact = token.strip("[]()")
        if 6 <= len(compact) <= 32 and any(ch.isdigit() for ch in compact) and compact.isalnum():
            return compact
    return ""


def _codename_from_device_text(value: str) -> str:
    tokens = _device_text_tokens(value)
    for index, token in enumerate(tokens):
        compact = token.strip("[]()").lower()
        for marker in ("device:", "device=", "product:", "product="):
            if compact.startswith(marker):
                candidate = compact[len(marker) :]
                if candidate in PIXEL_CODENAME_NAMES:
                    return candidate
        if compact in PIXEL_CODENAME_NAMES:
            return compact
        if index > 0 and compact in {"adb", "device", "fastboot", "recovery"}:
            continue
    return ""


def _device_model_from_text(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    for marker in ("model:", "model="):
        lower = text.lower()
        if marker in lower:
            start = lower.index(marker) + len(marker)
            raw = text[start:].split()[0]
            return _clean_device_model(raw)
    if "pixel" in text.lower():
        cleaned = text
        for marker in ("[", "("):
            cleaned = cleaned.split(marker, 1)[0]
        return _clean_device_model(cleaned)
    return ""


def _clean_device_model(value: str) -> str:
    text = str(value or "").strip().strip("[]()")
    if not text:
        return ""
    text = text.replace("_", " ").replace("-", " ")
    cleaned_parts = []
    for part in text.split():
        if part.upper() == part and (any(ch.isdigit() for ch in part) or len(part) <= 3):
            cleaned_parts.append(part)
        else:
            cleaned_parts.append(part.capitalize())
    return " ".join(cleaned_parts)


def _friendly_name_for_codename(value: str) -> str:
    key = str(value or "").strip().lower()
    return PIXEL_CODENAME_NAMES.get(key, "")


def _clean_device_label(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.lower().startswith("x (") or text.lower().startswith("device "):
        return ""
    return text


def _device_text_tokens(value: str) -> tuple[str, ...]:
    return tuple(part.strip(",;") for part in str(value or "").replace("\t", " ").split() if part.strip(",;"))


def _normalize_connection_mode(value: str) -> str:
    mode = str(value or "").strip().lower()
    if mode in {"adb", "device"}:
        return "adb"
    if mode in {"fastboot", "bootloader", "f.b"}:
        return "fastboot"
    if mode == "recovery":
        return "recovery"
    return ""


def _is_adb_mode(mode: str) -> bool:
    return _normalize_connection_mode(mode) == "adb"


def _is_fastboot_mode(mode: str) -> bool:
    return _normalize_connection_mode(mode) == "fastboot"


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


def _loaded_phone(frame: Any, config: Any) -> Any:
    return _raw_attr(frame, "phone") or _raw_attr(config, "phone")


def _loaded_props(phone: Any) -> dict[str, Any]:
    props = _raw_attr(phone, "props")
    prop_dict = _raw_attr(props, "property")
    return prop_dict if isinstance(prop_dict, dict) else {}


def _prop(props: dict[str, Any], key: str) -> str:
    value = props.get(key, "")
    if value == "Property not found":
        return ""
    return str(value or "")


def _raw_attr(obj: Any, name: str) -> Any:
    if obj is None:
        return None
    with contextlib.suppress(Exception):
        return vars(obj).get(name)
    return None


def _raw_string(obj: Any, name: str) -> str:
    value = _raw_attr(obj, name)
    return str(value or "")


def _first_text(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _normalize_slot(value: str) -> str:
    return str(value or "").strip().strip("_")


def _read_root_status(phone: Any, config: Any) -> str:
    configured = str(getattr(config, "root_status", "") or "")
    if configured:
        return configured
    rooted = _raw_attr(phone, "_rooted")
    if rooted is True:
        return "rooted"
    if rooted is False:
        return "not rooted"
    return "unknown"


def _data_behavior(mode: str) -> str:
    return {
        "wipeData": "Wipe selected in legacy config",
        "keepData": "Keep data",
        "dryRun": "Dry run",
        "OTA": "Full OTA",
        "customFlash": "Custom flash",
    }.get(str(mode or ""), str(mode or "unknown"))


def _slot_behavior(config: Any) -> str:
    if bool(getattr(config, "flash_both_slots", False)):
        return "Both slots"
    if bool(getattr(config, "flash_to_inactive_slot", False)):
        return "Inactive slot"
    return "Default"


def _latest_backup_label(backups: dict[Any, Any]) -> str:
    latest = ""
    for key, backup in backups.items():
        date = str(_raw_attr(backup, "date") or "")
        firmware = str(_raw_attr(backup, "firmware") or "")
        label = " · ".join(part for part in (date, firmware) if part) or str(key or "")
        if label > latest:
            latest = label
    return latest


def _frequency_label(value: Any) -> str:
    if value is None or value == "":
        return "not configured"
    with contextlib.suppress(Exception):
        days = int(value)
        if days < 0:
            return "disabled"
        if days == 1:
            return "daily"
        return f"every {days} days"
    return str(value)


def _timestamp_label(value: Any) -> str:
    if not value:
        return "not checked"
    with contextlib.suppress(Exception):
        return str(int(value))
    return str(value)


def _infer_build_id(path: str) -> str:
    if not path:
        return ""
    stem = Path(path).name.rsplit(".", 1)[0]
    parts = stem.split("-")
    if len(parts) >= 2:
        return "-".join(parts[:2])
    return stem
