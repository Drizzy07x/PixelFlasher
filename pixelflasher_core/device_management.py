"""Versioned, UI-independent device scan policy and identity persistence."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import cast

from .config_store import ConfigDocument
from .contracts import (
    MAX_MANAGED_DEVICE_TIMESTAMP,
    DeviceInfo,
    DeviceManagementState,
    ManagedDeviceInfo,
)

DEVICE_MANAGEMENT_KEY = "_pixelflasher_device_management"
DEVICE_MANAGER_POLICY_COMMAND = "device.manager.policy"
DEVICE_MANAGER_UPDATE_COMMAND = "device.manager.update"
DEVICE_MANAGER_REMOVE_COMMAND = "device.manager.remove"
DEVICE_MANAGER_COMMANDS = frozenset(
    {
        DEVICE_MANAGER_POLICY_COMMAND,
        DEVICE_MANAGER_UPDATE_COMMAND,
        DEVICE_MANAGER_REMOVE_COMMAND,
    }
)
_MAX_LEGACY_BYTES = 2 * 1024 * 1024
_STATE_FIELDS = frozenset({"schemaVersion", "scanEnabled", "scanScope", "devices"})
_DEVICE_FIELDS = frozenset(
    {
        "serial",
        "label",
        "enabled",
        "model",
        "codename",
        "connected",
        "mode",
        "firstSeen",
        "lastSeen",
    }
)


class DeviceManagementError(ValueError):
    """Stable validation error for persisted device-management state."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def device_management_from_document(document: ConfigDocument) -> DeviceManagementState:
    if not isinstance(document, ConfigDocument):
        raise TypeError("document must be a ConfigDocument")
    raw = document.values.get(DEVICE_MANAGEMENT_KEY)
    if raw is None:
        return DeviceManagementState()
    return device_management_from_mapping(raw)


def device_management_from_mapping(raw: object) -> DeviceManagementState:
    values = _string_mapping(raw, code="device_management_not_object")
    unknown = set(values) - _STATE_FIELDS
    if unknown:
        raise DeviceManagementError(
            "device_management_field_unknown",
            f"unsupported device-management field: {sorted(unknown)[0]}",
        )
    schema = values.get("schemaVersion", 1)
    enabled = values.get("scanEnabled", True)
    scope = values.get("scanScope", "enabled")
    raw_devices = values.get("devices", ())
    if schema != 1 or isinstance(schema, bool):
        raise DeviceManagementError(
            "device_management_schema_unsupported",
            "device-management schemaVersion must be 1",
        )
    if not isinstance(enabled, bool):
        raise DeviceManagementError(
            "device_management_scan_enabled_invalid",
            "device-management scanEnabled must be a boolean",
        )
    if scope not in {"enabled", "all"}:
        raise DeviceManagementError(
            "device_management_scope_invalid",
            "device-management scanScope must be enabled or all",
        )
    if not isinstance(raw_devices, (tuple, list)):
        raise DeviceManagementError(
            "device_management_devices_invalid",
            "device-management devices must be an array",
        )
    device_values = cast(tuple[object, ...] | list[object], raw_devices)
    if len(device_values) > 256:
        raise DeviceManagementError(
            "device_management_devices_oversized",
            "device-management devices exceeds its limit",
        )
    devices = tuple(_managed_device(item) for item in device_values)
    try:
        return DeviceManagementState(
            schema_version=1,
            scan_enabled=enabled,
            scan_scope=cast(str, scope),
            devices=devices,
        )
    except (TypeError, ValueError) as error:
        raise DeviceManagementError(
            "device_management_invalid",
            str(error),
        ) from error


def document_with_device_management(
    document: ConfigDocument,
    state: DeviceManagementState,
) -> ConfigDocument:
    if not isinstance(document, ConfigDocument):
        raise TypeError("document must be a ConfigDocument")
    if not isinstance(state, DeviceManagementState):
        raise TypeError("state must be a DeviceManagementState")
    if DEVICE_MANAGEMENT_KEY in document.values:
        # Refuse to overwrite a malformed/newer object and accidentally erase
        # information that this release cannot understand.
        device_management_from_mapping(document.values[DEVICE_MANAGEMENT_KEY])
    return document.with_values(**{DEVICE_MANAGEMENT_KEY: state.to_dict()})


def import_legacy_devices(path: str | Path) -> DeviceManagementState:
    """Read the 9.x devices.json format without importing legacy runtime code."""

    source = Path(path)
    if not source.is_file():
        return DeviceManagementState()
    try:
        size = source.stat().st_size
    except OSError as error:
        raise DeviceManagementError(
            "legacy_devices_read_failed",
            "legacy devices metadata could not be inspected",
        ) from error
    if size > _MAX_LEGACY_BYTES:
        raise DeviceManagementError(
            "legacy_devices_oversized",
            "legacy devices metadata exceeds its size limit",
        )
    try:
        raw = json.loads(
            source.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DeviceManagementError(
            "legacy_devices_invalid",
            "legacy devices metadata is not valid UTF-8 JSON",
        ) from error
    root = _string_mapping(raw, code="legacy_devices_invalid")
    if set(root) != {"devices"}:
        raise DeviceManagementError(
            "legacy_devices_invalid",
            "legacy devices metadata must contain only the devices object",
        )
    legacy = _string_mapping(root["devices"], code="legacy_devices_invalid")
    if len(legacy) > 256:
        raise DeviceManagementError(
            "legacy_devices_oversized",
            "legacy devices metadata contains too many entries",
        )
    records: list[ManagedDeviceInfo] = []
    for serial, raw_record in legacy.items():
        record = _string_mapping(raw_record, code="legacy_device_invalid")
        label = record.get("custom_label", "")
        enabled = record.get("enabled", True)
        model = record.get("hardware", "")
        codename = record.get("device_name", "")
        if not all(isinstance(value, str) for value in (label, model, codename)):
            raise DeviceManagementError(
                "legacy_device_invalid",
                f"legacy device {serial} contains invalid identity fields",
            )
        if not isinstance(enabled, bool):
            raise DeviceManagementError(
                "legacy_device_invalid",
                f"legacy device {serial} contains an invalid enabled flag",
            )
        try:
            records.append(
                ManagedDeviceInfo(
                    serial=serial,
                    label=cast(str, label),
                    enabled=enabled,
                    model=cast(str, model),
                    codename=cast(str, codename),
                    connected=False,
                    mode="offline",
                    first_seen=_legacy_timestamp(record.get("first_detected")),
                    last_seen=_legacy_timestamp(record.get("last_seen")),
                )
            )
        except (TypeError, ValueError) as error:
            raise DeviceManagementError(
                "legacy_device_invalid",
                f"legacy device {serial} is invalid",
            ) from error
    return DeviceManagementState(devices=tuple(records))


def backup_legacy_devices(path: str | Path) -> Path | None:
    """Create the immutable 9.x roster backup before canonical import."""

    source = Path(path)
    if not source.is_file():
        return None
    destination = source.with_name(f"{source.name}.v9.bak")
    if destination.exists():
        if destination.is_symlink() or not destination.is_file():
            raise DeviceManagementError(
                "legacy_devices_backup_invalid",
                "legacy devices backup path is not a regular file",
            )
        try:
            matches = _files_match(source, destination)
        except OSError as error:
            raise DeviceManagementError(
                "legacy_devices_backup_failed",
                "legacy devices backup could not be verified",
            ) from error
        if not matches:
            raise DeviceManagementError(
                "legacy_devices_backup_mismatch",
                "legacy devices backup does not match its source",
            )
        return destination

    descriptor = -1
    temporary: Path | None = None
    try:
        source_before = source.stat()
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{source.name}.",
            suffix=".backup.tmp",
            dir=source.parent,
        )
        temporary = Path(temporary_name)
        with source.open("rb") as source_stream, os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            while chunk := source_stream.read(1024 * 1024):
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        source_after = source.stat()
        if (
            source_before.st_size != source_after.st_size
            or source_before.st_mtime_ns != source_after.st_mtime_ns
        ):
            raise DeviceManagementError(
                "legacy_devices_backup_source_changed",
                "legacy devices metadata changed while it was being backed up",
            )
        try:
            os.link(temporary, destination)
        except FileExistsError:
            if destination.is_symlink() or not destination.is_file() or not _files_match(
                source, destination
            ):
                raise DeviceManagementError(
                    "legacy_devices_backup_mismatch",
                    "legacy devices backup does not match its source",
                ) from None
        _fsync_directory(source.parent)
        if not _files_match(source, destination):
            raise DeviceManagementError(
                "legacy_devices_backup_mismatch",
                "legacy devices backup does not match its source",
            )
    except DeviceManagementError:
        raise
    except OSError as error:
        raise DeviceManagementError(
            "legacy_devices_backup_failed",
            "legacy devices metadata could not be backed up",
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination


def _files_match(first: Path, second: Path) -> bool:
    if first.stat().st_size != second.stat().st_size:
        return False
    return _sha256(first) == _sha256(second)


def _sha256(path: Path) -> bytes:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.digest()


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def reconcile_device_management(
    state: DeviceManagementState,
    observed_devices: Sequence[DeviceInfo],
    *,
    observed_at: int | None = None,
) -> tuple[DeviceManagementState, tuple[DeviceInfo, ...]]:
    """Update remembered identities and return policy-visible live devices."""

    if not isinstance(state, DeviceManagementState):
        raise TypeError("state must be a DeviceManagementState")
    if isinstance(observed_devices, (str, bytes)):
        raise TypeError("observed_devices must be a device sequence")
    observed = tuple(observed_devices)
    if any(not isinstance(device, DeviceInfo) for device in observed):
        raise TypeError("observed_devices must contain DeviceInfo values")
    if not state.scan_enabled:
        return paused_device_management(state), ()
    serials = tuple(device.serial for device in observed)
    if len(serials) != len(set(serials)):
        raise ValueError("observed devices must contain unique serials")
    if len(set(serials).union(device.serial for device in state.devices)) > 256:
        raise DeviceManagementError(
            "device_management_devices_oversized",
            "device-management devices exceeds its limit",
        )

    timestamp = int(time.time()) if observed_at is None else observed_at
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0:
        raise ValueError("observed_at must be a non-negative integer")
    previous_records = {device.serial: device for device in state.devices}
    remembered = {
        serial: replace(previous, connected=False, mode="offline")
        for serial, previous in previous_records.items()
    }
    for device in observed:
        previous = previous_records.get(device.serial)
        first_seen = previous.first_seen if previous is not None else timestamp
        if not first_seen:
            first_seen = timestamp
        last_seen = (
            timestamp
            if previous is None or not previous.connected
            else previous.last_seen
        )
        remembered[device.serial] = ManagedDeviceInfo(
            serial=device.serial,
            label=previous.label if previous is not None else "",
            enabled=previous.enabled if previous is not None else True,
            model=device.model or (previous.model if previous is not None else ""),
            codename=device.codename or (previous.codename if previous is not None else ""),
            # Discovery itself proves the transport sees the device; `online`
            # remains a separate operational guard on DeviceInfo.
            connected=True,
            mode=device.mode if device.mode else "offline",
            first_seen=first_seen,
            last_seen=last_seen,
        )
    updated = replace(state, devices=tuple(remembered.values()))
    entries = {device.serial: device for device in updated.devices}
    visible: list[DeviceInfo] = []
    for device in observed:
        entry = entries[device.serial]
        if state.scan_scope == "enabled" and not entry.enabled:
            continue
        visible.append(replace(device, name=entry.label or device.name))
    return updated, tuple(
        sorted(visible, key=lambda device: (device.serial.casefold(), device.serial))
    )


def update_managed_device(
    state: DeviceManagementState,
    serial: str,
    *,
    label: str | None = None,
    enabled: bool | None = None,
) -> DeviceManagementState:
    records = {device.serial: device for device in state.devices}
    current = records.get(serial)
    if current is None:
        raise DeviceManagementError(
            "managed_device_not_found",
            "the managed device is not remembered",
        )
    try:
        records[serial] = replace(
            current,
            label=current.label if label is None else label,
            enabled=current.enabled if enabled is None else enabled,
        )
        return replace(state, devices=tuple(records.values()))
    except (TypeError, ValueError) as error:
        raise DeviceManagementError("managed_device_invalid", str(error)) from error


def remove_managed_device(
    state: DeviceManagementState,
    serial: str,
) -> DeviceManagementState:
    records = {device.serial: device for device in state.devices}
    if serial not in records:
        raise DeviceManagementError(
            "managed_device_not_found",
            "the managed device is not remembered",
        )
    del records[serial]
    return replace(state, devices=tuple(records.values()))


def paused_device_management(state: DeviceManagementState) -> DeviceManagementState:
    return replace(
        state,
        devices=tuple(
            replace(device, connected=False, mode="offline") for device in state.devices
        ),
    )


def _managed_device(raw: object) -> ManagedDeviceInfo:
    values = _string_mapping(raw, code="managed_device_not_object")
    unknown = set(values) - _DEVICE_FIELDS
    if unknown:
        raise DeviceManagementError(
            "managed_device_field_unknown",
            f"unsupported managed-device field: {sorted(unknown)[0]}",
        )
    required = {
        "serial",
        "label",
        "enabled",
        "model",
        "codename",
        "connected",
        "mode",
        "firstSeen",
        "lastSeen",
    }
    missing = required - set(values)
    if missing:
        raise DeviceManagementError(
            "managed_device_field_missing",
            f"managed-device field is missing: {sorted(missing)[0]}",
        )
    try:
        return ManagedDeviceInfo(
            serial=cast(str, values["serial"]),
            label=cast(str, values["label"]),
            enabled=cast(bool, values["enabled"]),
            model=cast(str, values["model"]),
            codename=cast(str, values["codename"]),
            connected=cast(bool, values["connected"]),
            mode=cast(str, values["mode"]),
            first_seen=cast(int, values["firstSeen"]),
            last_seen=cast(int, values["lastSeen"]),
        )
    except (TypeError, ValueError) as error:
        raise DeviceManagementError("managed_device_invalid", str(error)) from error


def _string_mapping(raw: object, *, code: str) -> dict[str, object]:
    if not isinstance(raw, Mapping):
        raise DeviceManagementError(code, "device-management value must be an object")
    values = cast(Mapping[object, object], raw)
    if any(not isinstance(key, str) for key in values):
        raise DeviceManagementError(code, "device-management keys must be strings")
    return {cast(str, key): value for key, value in values.items()}


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DeviceManagementError(
                "legacy_devices_duplicate_key",
                f"legacy devices metadata contains duplicate key: {key}",
            )
        result[key] = value
    return result


def _legacy_timestamp(value: object) -> int:
    # 9.x timestamps were presentation strings. They are optional metadata;
    # malformed values become unknown rather than blocking the whole migration.
    if isinstance(value, int) and not isinstance(value, bool):
        return value if 0 <= value <= MAX_MANAGED_DEVICE_TIMESTAMP else 0
    if not isinstance(value, str) or not value.strip():
        return 0
    try:
        from datetime import datetime

        normalized = value.strip()
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            parsed = datetime.strptime(normalized, "%Y-%m-%d %H:%M:%S")
        timestamp = int(parsed.timestamp())
        return timestamp if 0 <= timestamp <= MAX_MANAGED_DEVICE_TIMESTAMP else 0
    except (OSError, OverflowError, ValueError):
        return 0


__all__ = [
    "DEVICE_MANAGEMENT_KEY",
    "DEVICE_MANAGER_COMMANDS",
    "DEVICE_MANAGER_POLICY_COMMAND",
    "DEVICE_MANAGER_REMOVE_COMMAND",
    "DEVICE_MANAGER_UPDATE_COMMAND",
    "DeviceManagementError",
    "backup_legacy_devices",
    "device_management_from_document",
    "device_management_from_mapping",
    "document_with_device_management",
    "import_legacy_devices",
    "paused_device_management",
    "reconcile_device_management",
    "remove_managed_device",
    "update_managed_device",
]
