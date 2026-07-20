"""Canonical, typed registry for every PixelFlasher WebView v2 command.

This module is the single source of truth for the browser trust boundary.  A
command may be documented for a future milestone without being callable: only
entries that are both ``implemented`` and ``exposed`` enter the production
allow-list.  The TypeScript contract is generated from the same immutable
registry by :mod:`scripts.generate_bridge_contracts`.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, TypedDict, cast

BRIDGE_VERSION = 2


class PayloadKind(StrEnum):
    STRING = "string"
    BOOLEAN = "boolean"
    INTEGER = "integer"
    NUMBER = "number"
    OBJECT = "object"
    ARRAY = "array"
    STRING_ARRAY = "string_array"
    INTEGER_ARRAY = "integer_array"
    FILTER_ARRAY = "filter_array"
    LOGCAT_FILTER_ARRAY = "logcat_filter_array"


class CommandOwner(StrEnum):
    APPLICATION = "application"
    APPLICATIONS = "applications"
    BACKUPS = "backups"
    BOOT_IMAGES = "boot_images"
    BOOTLOADER = "bootloader"
    DEVELOPER_TOOLS = "developer_tools"
    DEVICE = "device"
    DEVICE_TOOLS = "device_tools"
    FIRMWARE = "firmware"
    FLASH = "flash"
    NATIVE_HOST = "native_host"
    PARTITIONS = "partitions"
    PLATFORM_TOOLS = "platform_tools"
    ROOT = "root"
    SETTINGS = "settings"
    SUPPORT = "support"


class CommandMutability(StrEnum):
    READ_ONLY = "read_only"
    MUTATING = "mutating"
    DESTRUCTIVE = "destructive"


class CommandRisk(StrEnum):
    NONE = "none"
    HOST_READ = "host_read"
    HOST_WRITE = "host_write"
    DEVICE_READ = "device_read"
    DEVICE_WRITE = "device_write"
    DESTRUCTIVE = "destructive"


class ExpectedRevision(StrEnum):
    OPTIONAL = "optional"
    REQUIRED = "required"


class ConfirmationPolicy(StrEnum):
    NONE = "none"
    STANDARD = "standard"
    PLAN_FINGERPRINT = "plan_fingerprint"
    LOCK_SERIAL = "lock_serial"
    UNLOCK_SERIAL = "unlock_serial"
    ERASE_PARTITION_SERIAL = "erase_partition_serial"
    SLOT_SERIAL = "slot_serial"


class TargetScope(StrEnum):
    APPLICATION = "application"
    SELECTED_DEVICE = "selected_device"


ANY_DEVICE_STATE = frozenset({"*"})
ADB_DEVICE_STATES = frozenset({"adb", "recovery", "sideload"})
FASTBOOT_DEVICE_STATES = frozenset({"fastboot", "fastbootd"})
CONNECTED_DEVICE_STATES = ADB_DEVICE_STATES | FASTBOOT_DEVICE_STATES


class PayloadSchemaError(ValueError):
    """A payload does not match its closed registry schema."""


@dataclass(frozen=True, slots=True)
class PayloadField:
    kind: PayloadKind
    required: bool = False
    min_items: int | None = None
    max_items: int | None = None

    def __post_init__(self) -> None:
        if (self.min_items is None) != (self.max_items is None):
            raise ValueError("payload item bounds must be provided together")
        minimum = self.min_items
        maximum = self.max_items
        if minimum is None or maximum is None:
            return
        if self.kind not in {
            PayloadKind.ARRAY,
            PayloadKind.FILTER_ARRAY,
            PayloadKind.INTEGER_ARRAY,
            PayloadKind.LOGCAT_FILTER_ARRAY,
            PayloadKind.STRING_ARRAY,
        }:
            raise ValueError("payload item bounds apply only to array fields")
        if not 0 <= minimum <= maximum <= 10_000:
            raise ValueError("payload item bounds are invalid")


@dataclass(frozen=True, slots=True)
class PayloadSchema:
    fields: Mapping[str, PayloadField]

    def __post_init__(self) -> None:
        if any(
            not isinstance(name, str) or not name or not isinstance(field, PayloadField)
            for name, field in self.fields.items()
        ):
            raise ValueError("payload fields must have names and typed definitions")
        normalized = dict(sorted(self.fields.items()))
        object.__setattr__(self, "fields", MappingProxyType(normalized))

    @property
    def allowed_fields(self) -> frozenset[str]:
        return frozenset(self.fields)

    @property
    def required_fields(self) -> frozenset[str]:
        return frozenset(name for name, field in self.fields.items() if field.required)

    def validate(self, payload: Mapping[str, Any]) -> None:
        if any(not isinstance(name, str) for name in payload):
            raise PayloadSchemaError("payload field names must be strings")
        unknown = frozenset(payload) - self.allowed_fields
        if unknown:
            raise PayloadSchemaError(f"payload contains an unsupported field: {sorted(unknown)[0]}")
        missing = self.required_fields - frozenset(payload)
        if missing:
            raise PayloadSchemaError(f"payload is missing a required field: {sorted(missing)[0]}")
        for name, value in payload.items():
            field = self.fields[name]
            if not _matches_payload_kind(value, field.kind):
                raise PayloadSchemaError(f"payload field {name} must be {field.kind.value}")
            minimum = field.min_items
            maximum = field.max_items
            if minimum is not None and maximum is not None and isinstance(value, list):
                values = cast("list[object]", value)
                if minimum <= len(values) <= maximum:
                    continue
                raise PayloadSchemaError(
                    f"payload field {name} must contain between "
                    f"{minimum} and {maximum} items"
                )


@dataclass(frozen=True, slots=True)
class CommandSpec:
    command: str
    typescript_name: str
    payload: PayloadSchema
    owner: CommandOwner
    implemented: bool
    exposed: bool
    mutability: CommandMutability
    expected_revision: ExpectedRevision
    risk: CommandRisk
    valid_device_states: frozenset[str]
    target_scope: TargetScope
    planner: str | None
    timeout_ms: int
    confirmation: ConfirmationPolicy
    postconditions: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.command or not self.typescript_name:
            raise ValueError("registry commands require public and TypeScript names")
        if self.exposed and not self.implemented:
            raise ValueError(f"unimplemented command cannot be exposed: {self.command}")
        if self.implemented and not self.planner:
            raise ValueError(f"implemented command has no execution owner: {self.command}")
        if self.timeout_ms <= 0:
            raise ValueError(f"command timeout must be positive: {self.command}")
        if not self.valid_device_states:
            raise ValueError(f"valid device states must be explicit: {self.command}")
        if self.confirmation is not ConfirmationPolicy.NONE and (self.mutability is CommandMutability.READ_ONLY):
            raise ValueError(f"read-only command cannot require confirmation: {self.command}")


def _matches_payload_kind(value: Any, kind: PayloadKind) -> bool:
    if kind is PayloadKind.STRING:
        return isinstance(value, str)
    if kind is PayloadKind.BOOLEAN:
        return isinstance(value, bool)
    if kind is PayloadKind.INTEGER:
        return isinstance(value, int) and not isinstance(value, bool)
    if kind is PayloadKind.NUMBER:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    if kind is PayloadKind.OBJECT:
        return isinstance(value, Mapping)
    if kind in {PayloadKind.ARRAY, PayloadKind.FILTER_ARRAY}:
        return isinstance(value, list)
    if kind is PayloadKind.STRING_ARRAY:
        return isinstance(value, list) and all(isinstance(item, str) for item in cast("list[object]", value))
    if kind is PayloadKind.INTEGER_ARRAY:
        return isinstance(value, list) and all(
            isinstance(item, int) and not isinstance(item, bool)
            for item in cast("list[object]", value)
        )
    if kind is PayloadKind.LOGCAT_FILTER_ARRAY:
        return isinstance(value, list) and all(
            isinstance(item, Mapping)
            and set(cast("Mapping[object, object]", item)) == {"tag", "priority"}
            and isinstance(cast("Mapping[object, object]", item).get("tag"), str)
            and isinstance(cast("Mapping[object, object]", item).get("priority"), str)
            for item in cast("list[object]", value)
        )
    return False  # pragma: no cover - exhaustive enum guard


def _payload(
    *fields: (
        tuple[str, PayloadKind]
        | tuple[str, PayloadKind, bool]
        | tuple[str, PayloadKind, bool, int, int]
    ),
) -> PayloadSchema:
    definitions: dict[str, PayloadField] = {}
    for definition in fields:
        name, kind = definition[:2]
        required = bool(definition[2]) if len(definition) >= 3 else False
        min_items = int(definition[3]) if len(definition) == 5 else None
        max_items = int(definition[4]) if len(definition) == 5 else None
        if name in definitions:
            raise ValueError(f"duplicate payload field: {name}")
        definitions[name] = PayloadField(kind, required, min_items, max_items)
    return PayloadSchema(definitions)


def _command(
    command: str,
    typescript_name: str,
    payload: PayloadSchema,
    *,
    owner: CommandOwner,
    implemented: bool,
    exposed: bool,
    mutability: CommandMutability,
    expected_revision: ExpectedRevision,
    risk: CommandRisk,
    valid_device_states: frozenset[str],
    target_scope: TargetScope,
    planner: str | None,
    timeout_ms: int = 60_000,
    confirmation: ConfirmationPolicy = ConfirmationPolicy.NONE,
    postconditions: tuple[str, ...] = (),
) -> CommandSpec:
    return CommandSpec(
        command=command,
        typescript_name=typescript_name,
        payload=payload,
        owner=owner,
        implemented=implemented,
        exposed=exposed,
        mutability=mutability,
        expected_revision=expected_revision,
        risk=risk,
        valid_device_states=valid_device_states,
        target_scope=target_scope,
        planner=planner,
        timeout_ms=timeout_ms,
        confirmation=confirmation,
        postconditions=postconditions,
    )


class _LiveArguments(TypedDict):
    implemented: bool
    exposed: bool


class _FutureArguments(TypedDict):
    implemented: bool
    exposed: bool
    planner: None


_FUTURE: _FutureArguments = {
    "implemented": False,
    "exposed": False,
    "planner": None,
}
_LIVE: _LiveArguments = {"implemented": True, "exposed": True}


_COMMAND_SPECS = (
    _command(
        "app.console.export",
        "appConsoleExport",
        _payload(
            ("grant", PayloadKind.STRING, True),
            ("lines", PayloadKind.STRING_ARRAY, True, 1, 200),
        ),
        owner=CommandOwner.APPLICATION,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="native_host.console_export",
        postconditions=("bounded_redacted_console_exported",),
    ),
    _command(
        "app.openFolder",
        "appOpenFolder",
        _payload(("target", PayloadKind.STRING, True)),
        owner=CommandOwner.APPLICATION,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_READ,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="native_host.open_folder",
        postconditions=("backend_owned_directory_open_requested",),
    ),
    _command(
        "app.openLink",
        "appOpenLink",
        _payload(("target", PayloadKind.STRING, True)),
        owner=CommandOwner.APPLICATION,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_READ,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="native_host.open_link",
        postconditions=("allowlisted_https_link_open_requested",),
    ),
    _command(
        "app.exit",
        "appExit",
        _payload(),
        owner=CommandOwner.APPLICATION,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.NONE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="native_host.exit",
        postconditions=("window_close_requested",),
    ),
    _command(
        "app.ready",
        "appReady",
        _payload(),
        owner=CommandOwner.APPLICATION,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.OPTIONAL,
        risk=CommandRisk.NONE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="native_host.lifecycle",
        postconditions=("snapshot_emitted",),
    ),
    _command(
        "snapshot.get",
        "snapshotGet",
        _payload(),
        owner=CommandOwner.APPLICATION,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.OPTIONAL,
        risk=CommandRisk.NONE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="engine.snapshot",
        postconditions=("snapshot_returned",),
    ),
    _command(
        "operation.cancel",
        "operationCancel",
        _payload(("operationId", PayloadKind.STRING, True)),
        owner=CommandOwner.APPLICATION,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.NONE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="engine.cancellation",
        postconditions=("cancellation_acknowledged",),
    ),
    _command(
        "interaction.respond",
        "interactionRespond",
        _payload(
            ("operationId", PayloadKind.STRING, True),
            ("decision", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.APPLICATION,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.NONE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="engine.interaction",
        postconditions=("interaction_acknowledged",),
    ),
    _command(
        "device.scan",
        "deviceScan",
        _payload(
            ("includeProperties", PayloadKind.BOOLEAN),
            ("includeBattery", PayloadKind.BOOLEAN),
        ),
        owner=CommandOwner.DEVICE,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_READ,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="device.scan",
        timeout_ms=10 * 60_000,
        postconditions=("device_inventory_refreshed",),
    ),
    _command(
        "device.select",
        "deviceSelect",
        _payload(("serials", PayloadKind.STRING_ARRAY, True)),
        owner=CommandOwner.DEVICE,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.NONE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="device.selection",
        postconditions=("selected_serials_match",),
    ),
    _command(
        "device.manager.policy",
        "deviceManagerPolicy",
        _payload(
            ("scanEnabled", PayloadKind.BOOLEAN),
            ("scanScope", PayloadKind.STRING),
        ),
        owner=CommandOwner.DEVICE,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="device.manager.policy",
        postconditions=("scan_policy_persisted", "monitor_lifecycle_matches"),
    ),
    _command(
        "device.manager.update",
        "deviceManagerUpdate",
        _payload(
            ("serial", PayloadKind.STRING, True),
            ("label", PayloadKind.STRING),
            ("enabled", PayloadKind.BOOLEAN),
        ),
        owner=CommandOwner.DEVICE,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="device.manager.update",
        postconditions=("managed_device_persisted",),
    ),
    _command(
        "device.manager.remove",
        "deviceManagerRemove",
        _payload(("serial", PayloadKind.STRING, True)),
        owner=CommandOwner.DEVICE,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="device.manager.remove",
        postconditions=("managed_device_removed",),
    ),
    _command(
        "device.reboot",
        "deviceReboot",
        _payload(("serial", PayloadKind.STRING), ("mode", PayloadKind.STRING)),
        owner=CommandOwner.DEVICE,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_WRITE,
        valid_device_states=CONNECTED_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="operation.device_reboot",
        timeout_ms=10 * 60_000,
        confirmation=ConfirmationPolicy.NONE,
        postconditions=("device_reconnected", "expected_mode_observed"),
    ),
    _command(
        "device.switchSlot",
        "deviceSwitchSlot",
        _payload(
            ("serial", PayloadKind.STRING),
            ("slot", PayloadKind.STRING, True),
            ("confirmationText", PayloadKind.STRING),
        ),
        owner=CommandOwner.DEVICE,
        **_LIVE,
        mutability=CommandMutability.DESTRUCTIVE,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DESTRUCTIVE,
        valid_device_states=FASTBOOT_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="operation.slot_switch",
        timeout_ms=10 * 60_000,
        confirmation=ConfirmationPolicy.SLOT_SERIAL,
        postconditions=("active_slot_matches",),
    ),
    _command(
        "device.bootloader.lock",
        "deviceBootloaderLock",
        _payload(("serial", PayloadKind.STRING), ("confirmationText", PayloadKind.STRING)),
        owner=CommandOwner.BOOTLOADER,
        **_LIVE,
        mutability=CommandMutability.DESTRUCTIVE,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DESTRUCTIVE,
        valid_device_states=FASTBOOT_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="operation.bootloader_lock",
        timeout_ms=10 * 60_000,
        confirmation=ConfirmationPolicy.LOCK_SERIAL,
        postconditions=("bootloader_locked", "relock_evidence_consumed"),
    ),
    _command(
        "device.bootloader.unlock",
        "deviceBootloaderUnlock",
        _payload(("serial", PayloadKind.STRING), ("confirmationText", PayloadKind.STRING)),
        owner=CommandOwner.BOOTLOADER,
        **_LIVE,
        mutability=CommandMutability.DESTRUCTIVE,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DESTRUCTIVE,
        valid_device_states=FASTBOOT_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="operation.bootloader_unlock",
        timeout_ms=10 * 60_000,
        confirmation=ConfirmationPolicy.UNLOCK_SERIAL,
        postconditions=("bootloader_unlocked",),
    ),
    _command(
        "platformTools.setup",
        "platformToolsSetup",
        _payload(
            ("source", PayloadKind.STRING, True),
            ("grant", PayloadKind.STRING),
        ),
        owner=CommandOwner.PLATFORM_TOOLS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="toolchain.setup",
        timeout_ms=30 * 60_000,
        postconditions=("adb_fastboot_probed",),
    ),
    _command(
        "firmware.select",
        "firmwareSelect",
        _payload(
            ("grant", PayloadKind.STRING),
            ("firmwareId", PayloadKind.STRING),
            ("expectedKind", PayloadKind.STRING),
        ),
        owner=CommandOwner.FIRMWARE,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_READ,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="firmware.inspect",
        timeout_ms=60 * 60_000,
        postconditions=("firmware_snapshot_matches",),
    ),
    _command(
        "firmware.process",
        "firmwareProcess",
        _payload(),
        owner=CommandOwner.FIRMWARE,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="firmware.process",
        timeout_ms=2 * 60 * 60_000,
        postconditions=("artifacts_hashed", "firmware_repository_updated"),
    ),
    _command(
        "firmware.catalog.refresh",
        "firmwareCatalogRefresh",
        _payload(("device", PayloadKind.STRING), ("channel", PayloadKind.STRING)),
        owner=CommandOwner.FIRMWARE,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="firmware.catalog.refresh",
        timeout_ms=5 * 60_000,
        postconditions=("verified_firmware_catalog_returned",),
    ),
    _command(
        "firmware.download",
        "firmwareDownload",
        _payload(("artifactId", PayloadKind.STRING, True)),
        owner=CommandOwner.FIRMWARE,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="firmware.download",
        timeout_ms=6 * 60 * 60_000,
        postconditions=("firmware_download_verified", "firmware_snapshot_matches"),
    ),
    _command(
        "boot.inventory",
        "bootInventory",
        _payload(),
        owner=CommandOwner.BOOT_IMAGES,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_READ,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="boot_inventory.list",
        timeout_ms=6 * 60 * 60_000,
        postconditions=("boot_metadata_returned",),
    ),
    _command(
        "boot.select",
        "bootSelect",
        _payload(
            ("bootId", PayloadKind.STRING),
            ("grant", PayloadKind.STRING),
            ("partition", PayloadKind.STRING),
        ),
        owner=CommandOwner.BOOT_IMAGES,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="boot_inventory.select",
        timeout_ms=90 * 60_000,
        postconditions=("boot_repository_verified", "boot_snapshot_matches"),
    ),
    _command(
        "boot.delete",
        "bootDelete",
        _payload(("bootId", PayloadKind.STRING, True)),
        owner=CommandOwner.BOOT_IMAGES,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="boot_inventory.delete",
        timeout_ms=10 * 60_000,
        postconditions=("boot_record_absent", "shared_object_preserved"),
    ),
    _command(
        "boot.patch",
        "bootPatch",
        _payload(
            ("serial", PayloadKind.STRING),
            ("flavor", PayloadKind.STRING),
            ("method", PayloadKind.STRING),
            ("appId", PayloadKind.STRING, True),
            ("grant", PayloadKind.STRING, True),
            ("secretGrant", PayloadKind.STRING),
        ),
        owner=CommandOwner.BOOT_IMAGES,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ADB_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="boot.patch",
        timeout_ms=3 * 60 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("patched_artifact_hashed", "boot_repository_updated"),
    ),
    _command(
        "boot.flash",
        "bootFlash",
        _payload(
            ("serial", PayloadKind.STRING),
            ("partition", PayloadKind.STRING),
            ("slot", PayloadKind.STRING),
            ("confirmationText", PayloadKind.STRING),
        ),
        owner=CommandOwner.BOOT_IMAGES,
        **_LIVE,
        mutability=CommandMutability.DESTRUCTIVE,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DESTRUCTIVE,
        valid_device_states=FASTBOOT_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="operation.boot_flash",
        timeout_ms=20 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("partition_write_verified",),
    ),
    _command(
        "boot.live",
        "bootLive",
        _payload(("serial", PayloadKind.STRING), ("confirmationText", PayloadKind.STRING)),
        owner=CommandOwner.BOOT_IMAGES,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_WRITE,
        valid_device_states=FASTBOOT_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="operation.boot_live",
        timeout_ms=10 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("device_reconnected", "boot_completed_observed"),
    ),
    _command(
        "flash.plan.update",
        "flashPlanUpdate",
        _payload(
            ("mode", PayloadKind.STRING),
            ("options", PayloadKind.OBJECT),
            ("dryRun", PayloadKind.BOOLEAN),
        ),
        owner=CommandOwner.FLASH,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.NONE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="flash.intent",
        postconditions=("flash_intent_snapshot_matches",),
    ),
    _command(
        "flash.plan.preview",
        "flashPlanPreview",
        _payload(("serial", PayloadKind.STRING)),
        owner=CommandOwner.FLASH,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_READ,
        valid_device_states=CONNECTED_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="flash.preview",
        postconditions=("immutable_plan_returned",),
    ),
    _command(
        "flash.execute",
        "flashExecute",
        _payload(("serial", PayloadKind.STRING), ("confirmationText", PayloadKind.STRING)),
        owner=CommandOwner.FLASH,
        **_LIVE,
        mutability=CommandMutability.DESTRUCTIVE,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DESTRUCTIVE,
        valid_device_states=CONNECTED_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="operation.flash",
        timeout_ms=4 * 60 * 60_000,
        confirmation=ConfirmationPolicy.PLAN_FINGERPRINT,
        postconditions=("device_reconnected", "build_matches", "slot_matches"),
    ),
    _command(
        "root.apps.catalog.refresh",
        "rootAppsCatalogRefresh",
        _payload(("channel", PayloadKind.STRING)),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="root.apps.catalog.refresh",
        timeout_ms=5 * 60_000,
        postconditions=("verified_root_app_catalog_returned",),
    ),
    _command(
        "root.apps.download",
        "rootAppsDownload",
        _payload(("artifactId", PayloadKind.STRING, True)),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="root.apps.download",
        timeout_ms=30 * 60_000,
        postconditions=("root_app_download_verified", "root_app_inventory_updated"),
    ),
    _command(
        "root.apps.list",
        "rootAppsList",
        _payload(("serial", PayloadKind.STRING)),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_READ,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="root.apps_inventory",
        timeout_ms=60 * 60_000,
        postconditions=("root_apps_returned",),
    ),
    _command(
        "root.apps.install",
        "rootAppsInstall",
        _payload(("serial", PayloadKind.STRING), ("appId", PayloadKind.STRING, True)),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_WRITE,
        valid_device_states=ADB_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="root.app_install",
        timeout_ms=30 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("package_installed",),
    ),
    _command(
        "root.modules.list",
        "rootModulesList",
        _payload(("serial", PayloadKind.STRING)),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_READ,
        valid_device_states=ADB_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="root.modules_inventory",
        timeout_ms=5 * 60_000,
        postconditions=("root_modules_returned",),
    ),
    _command(
        "root.modules.updates",
        "rootModulesUpdates",
        _payload(("serial", PayloadKind.STRING)),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ADB_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="root.modules_updates",
        timeout_ms=30 * 60_000,
        postconditions=("module_update_artifacts_inspected",),
    ),
    _command(
        "root.pif.inventory",
        "rootPifInventory",
        _payload(("serial", PayloadKind.STRING, True)),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_READ,
        valid_device_states=ADB_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="root.pif.inventory",
        timeout_ms=2 * 60_000,
        postconditions=("bounded_pif_inventory_returned",),
    ),
    _command(
        "root.pif.document",
        "rootPifDocument",
        _payload(
            ("serial", PayloadKind.STRING, True),
            ("profileId", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_READ,
        valid_device_states=ADB_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="root.pif.document",
        timeout_ms=2 * 60_000,
        postconditions=("bounded_pif_document_returned",),
    ),
    _command(
        "root.pif.transform",
        "rootPifTransform",
        _payload(
            ("content", PayloadKind.STRING, True),
            ("inputFormat", PayloadKind.STRING, True),
            ("outputFormat", PayloadKind.STRING, True),
            ("normalize", PayloadKind.BOOLEAN, True),
            ("keepUnknown", PayloadKind.BOOLEAN, True),
            ("sortKeys", PayloadKind.BOOLEAN, True),
            ("firstApi", PayloadKind.INTEGER),
        ),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.NONE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="root.pif.transform",
        timeout_ms=30_000,
        postconditions=("bounded_pif_transformation_returned",),
    ),
    _command(
        "root.pif.favorites.list",
        "rootPifFavoritesList",
        _payload(),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.NONE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="root.pif.favorites.list",
        timeout_ms=30_000,
        postconditions=("bounded_pif_favorites_returned",),
    ),
    _command(
        "root.pif.favorites.get",
        "rootPifFavoritesGet",
        _payload(("favoriteId", PayloadKind.STRING, True)),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.NONE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="root.pif.favorites.get",
        timeout_ms=30_000,
        postconditions=("bounded_pif_favorite_returned",),
    ),
    _command(
        "root.pif.favorites.save",
        "rootPifFavoritesSave",
        _payload(
            ("label", PayloadKind.STRING, True),
            ("content", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="root.pif.favorites.save",
        timeout_ms=30_000,
        postconditions=("pif_favorite_persisted",),
    ),
    _command(
        "root.pif.favorites.delete",
        "rootPifFavoritesDelete",
        _payload(("favoriteId", PayloadKind.STRING, True)),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="root.pif.favorites.delete",
        timeout_ms=30_000,
        postconditions=("pif_favorite_deleted",),
    ),
    _command(
        "root.modules.action",
        "rootModulesAction",
        _payload(
            ("serial", PayloadKind.STRING),
            ("action", PayloadKind.STRING, True),
            ("moduleId", PayloadKind.STRING),
            ("grant", PayloadKind.STRING),
            ("artifactId", PayloadKind.STRING),
            ("confirmationText", PayloadKind.STRING),
        ),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.DESTRUCTIVE,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DESTRUCTIVE,
        valid_device_states=ADB_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="root.module_action",
        timeout_ms=30 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("root_module_state_verified",),
    ),
    _command(
        "apps.list",
        "appsList",
        _payload(("serial", PayloadKind.STRING), ("scope", PayloadKind.STRING)),
        owner=CommandOwner.APPLICATIONS,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_READ,
        valid_device_states=ADB_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="apps.inventory",
        timeout_ms=5 * 60_000,
        postconditions=("packages_returned",),
    ),
    _command(
        "apps.action",
        "appsAction",
        _payload(
            ("serial", PayloadKind.STRING),
            ("scope", PayloadKind.STRING),
            ("action", PayloadKind.STRING, True),
            ("package", PayloadKind.STRING),
            ("packages", PayloadKind.STRING_ARRAY),
            ("options", PayloadKind.OBJECT),
            ("grant", PayloadKind.STRING),
        ),
        owner=CommandOwner.APPLICATIONS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_WRITE,
        valid_device_states=ADB_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="apps.action",
        timeout_ms=20 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("package_state_verified",),
    ),
    _command(
        "backups.list",
        "backupsList",
        _payload(("serial", PayloadKind.STRING)),
        owner=CommandOwner.BACKUPS,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_READ,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="backups.inventory",
        timeout_ms=30_000,
        postconditions=("bounded_backup_inventory_returned",),
    ),
    _command(
        "backups.create",
        "backupsCreate",
        _payload(
            ("serial", PayloadKind.STRING),
            ("partition", PayloadKind.STRING, True),
            ("slot", PayloadKind.STRING, True),
            ("grant", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.BACKUPS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=CONNECTED_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="backups.create",
        timeout_ms=30 * 60_000,
        postconditions=("backup_hash_verified",),
    ),
    _command(
        "backups.restore",
        "backupsRestore",
        _payload(
            ("serial", PayloadKind.STRING),
            ("partition", PayloadKind.STRING, True),
            ("slot", PayloadKind.STRING, True),
            ("grant", PayloadKind.STRING),
            ("backupId", PayloadKind.STRING),
        ),
        owner=CommandOwner.BACKUPS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_WRITE,
        valid_device_states=CONNECTED_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="backups.restore",
        timeout_ms=30 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("restore_write_verified",),
    ),
    _command(
        "backups.delete",
        "backupsDelete",
        _payload(
            ("backupId", PayloadKind.STRING, True),
            ("confirmationText", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.BACKUPS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="backups.delete",
        timeout_ms=30_000,
        postconditions=("backup_record_removed",),
    ),
    _command(
        "backups.magisk.list",
        "backupsMagiskList",
        _payload(("serial", PayloadKind.STRING, True)),
        owner=CommandOwner.BACKUPS,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_READ,
        valid_device_states=ADB_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="backups.magisk.list",
        timeout_ms=3 * 60_000,
        postconditions=("bounded_magisk_backup_inventory_returned",),
    ),
    _command(
        "backups.magisk.import",
        "backupsMagiskImport",
        _payload(
            ("serial", PayloadKind.STRING, True),
            ("grant", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.BACKUPS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_WRITE,
        valid_device_states=ADB_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="backups.magisk.import",
        timeout_ms=20 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("magisk_backup_hash_verified",),
    ),
    _command(
        "backups.magisk.delete",
        "backupsMagiskDelete",
        _payload(
            ("serial", PayloadKind.STRING, True),
            ("sha1", PayloadKind.STRING, True),
            ("confirmationText", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.BACKUPS,
        **_LIVE,
        mutability=CommandMutability.DESTRUCTIVE,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DESTRUCTIVE,
        valid_device_states=ADB_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="backups.magisk.delete",
        timeout_ms=5 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("magisk_backup_absence_verified",),
    ),
    _command(
        "partitions.list",
        "partitionsList",
        _payload(("serial", PayloadKind.STRING)),
        owner=CommandOwner.PARTITIONS,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_READ,
        valid_device_states=FASTBOOT_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="partitions.inventory",
        postconditions=("partition_inventory_returned",),
    ),
    _command(
        "partitions.read",
        "partitionsRead",
        _payload(
            ("serial", PayloadKind.STRING),
            ("partition", PayloadKind.STRING, True),
            ("grant", PayloadKind.STRING, True),
            ("overwrite", PayloadKind.BOOLEAN),
        ),
        owner=CommandOwner.PARTITIONS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=FASTBOOT_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="partitions.read",
        timeout_ms=20 * 60_000,
        postconditions=("local_hash_verified",),
    ),
    _command(
        "partitions.write",
        "partitionsWrite",
        _payload(
            ("serial", PayloadKind.STRING),
            ("partition", PayloadKind.STRING, True),
            ("grant", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.PARTITIONS,
        **_LIVE,
        mutability=CommandMutability.DESTRUCTIVE,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DESTRUCTIVE,
        valid_device_states=FASTBOOT_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="partitions.write",
        timeout_ms=20 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("partition_write_verified",),
    ),
    _command(
        "partitions.erase",
        "partitionsErase",
        _payload(
            ("serial", PayloadKind.STRING),
            ("partition", PayloadKind.STRING, True),
            ("confirmationText", PayloadKind.STRING),
        ),
        owner=CommandOwner.PARTITIONS,
        **_LIVE,
        mutability=CommandMutability.DESTRUCTIVE,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DESTRUCTIVE,
        valid_device_states=FASTBOOT_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="partitions.erase",
        timeout_ms=10 * 60_000,
        confirmation=ConfirmationPolicy.ERASE_PARTITION_SERIAL,
        postconditions=("partition_erased_verified",),
    ),
    _command(
        "tools.adbShell",
        "toolsAdbShell",
        _payload(
            ("serial", PayloadKind.STRING, True),
            ("columns", PayloadKind.INTEGER, True),
            ("rows", PayloadKind.INTEGER, True),
        ),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_WRITE,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="native_host.adb_terminal.open",
        timeout_ms=30_000,
        postconditions=("pty_bound_to_serial_revision_and_adb_state",),
    ),
    _command(
        "tools.adbShell.write",
        "toolsAdbShellWrite",
        _payload(
            ("sessionId", PayloadKind.STRING, True),
            ("data", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_WRITE,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.APPLICATION,
        planner="native_host.adb_terminal.write",
        timeout_ms=30_000,
        postconditions=("pty_input_accepted_for_bound_session",),
    ),
    _command(
        "tools.adbShell.resize",
        "toolsAdbShellResize",
        _payload(
            ("sessionId", PayloadKind.STRING, True),
            ("columns", PayloadKind.INTEGER, True),
            ("rows", PayloadKind.INTEGER, True),
        ),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.NONE,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.APPLICATION,
        planner="native_host.adb_terminal.resize",
        timeout_ms=30_000,
        postconditions=("pty_size_updated_for_bound_session",),
    ),
    _command(
        "tools.adbShell.close",
        "toolsAdbShellClose",
        _payload(("sessionId", PayloadKind.STRING, True)),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.NONE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="native_host.adb_terminal.close",
        timeout_ms=30_000,
        postconditions=("pty_session_closed",),
    ),
    _command(
        "tools.scrcpy.setup",
        "toolsScrcpySetup",
        _payload(("source", PayloadKind.STRING)),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="tools.scrcpy.setup",
        timeout_ms=30 * 60_000,
        postconditions=("scrcpy_binary_probed",),
    ),
    _command(
        "tools.scrcpy",
        "toolsScrcpy",
        _payload(
            ("serial", PayloadKind.STRING),
            ("maxSize", PayloadKind.INTEGER, True),
            ("maxFps", PayloadKind.INTEGER, True),
            ("videoBitRateMbps", PayloadKind.INTEGER, True),
            ("fullscreen", PayloadKind.BOOLEAN, True),
            ("alwaysOnTop", PayloadKind.BOOLEAN, True),
            ("stayAwake", PayloadKind.BOOLEAN, True),
            ("turnScreenOff", PayloadKind.BOOLEAN, True),
            ("showTouches", PayloadKind.BOOLEAN, True),
            ("noAudio", PayloadKind.BOOLEAN, True),
        ),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_READ,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="tools.scrcpy",
        timeout_ms=5 * 60_000,
        postconditions=("managed_process_started",),
    ),
    _command(
        "tools.wifi",
        "toolsWifi",
        _payload(
            ("action", PayloadKind.STRING, True),
            ("host", PayloadKind.STRING, True),
            ("port", PayloadKind.INTEGER, True),
            ("secretGrant", PayloadKind.STRING),
        ),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="tools.wifi",
        timeout_ms=5 * 60_000,
        postconditions=("adb_endpoint_observed",),
    ),
    _command(
        "tools.wifi.status",
        "toolsWifiStatus",
        _payload(("serial", PayloadKind.STRING)),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_READ,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="tools.wifi.status",
        postconditions=("adb_device_state_returned",),
    ),
    _command(
        "tools.wifi.discover",
        "toolsWifiDiscover",
        _payload(),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_READ,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="tools.wifi.discover",
        timeout_ms=20_000,
    ),
    _command(
        "tools.logcat",
        "toolsLogcat",
        _payload(
            ("serial", PayloadKind.STRING),
            ("mode", PayloadKind.STRING),
            ("buffers", PayloadKind.STRING_ARRAY, False, 1, 6),
            ("formatEnabled", PayloadKind.BOOLEAN),
            ("formatVerb", PayloadKind.STRING),
            ("formatModifiers", PayloadKind.STRING_ARRAY, False, 0, 7),
            ("filters", PayloadKind.LOGCAT_FILTER_ARRAY, False, 0, 32),
            ("regex", PayloadKind.STRING),
            ("uids", PayloadKind.INTEGER_ARRAY, False, 0, 32),
            ("maxLines", PayloadKind.INTEGER),
            ("timeoutSeconds", PayloadKind.INTEGER),
            ("redaction", PayloadKind.STRING),
            ("grant", PayloadKind.STRING),
        ),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="tools.logcat",
        timeout_ms=3 * 60_000,
        postconditions=("bounded_log_returned",),
    ),
    _command(
        "tools.logcat.clear",
        "toolsLogcatClear",
        _payload(("serial", PayloadKind.STRING)),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.DESTRUCTIVE,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DESTRUCTIVE,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="tools.logcat.clear",
        timeout_ms=3 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("logcat_buffers_cleared",),
    ),
    _command(
        "device.inspect",
        "deviceInspect",
        _payload(
            ("serial", PayloadKind.STRING),
            ("action", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_READ,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="device.inspect",
        timeout_ms=4 * 60_000,
        postconditions=("bounded_typed_report_returned",),
    ),
    _command(
        "device.openUrl",
        "deviceOpenUrl",
        _payload(
            ("serial", PayloadKind.STRING),
            ("url", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_WRITE,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="device.open_url",
        timeout_ms=30_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("view_intent_accepted",),
    ),
    _command(
        "device.ota.status",
        "deviceOtaStatus",
        _payload(("serial", PayloadKind.STRING)),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_READ,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="device.ota.status",
        timeout_ms=45_000,
        postconditions=("bounded_update_engine_status_returned",),
    ),
    _command(
        "device.ota.certificates",
        "deviceOtaCertificates",
        _payload(("serial", PayloadKind.STRING)),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_READ,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="device.ota.certificates",
        timeout_ms=45_000,
        postconditions=("bounded_certificate_inventory_returned",),
    ),
    _command(
        "device.ota.reset",
        "deviceOtaReset",
        _payload(("serial", PayloadKind.STRING)),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_WRITE,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="device.ota.reset",
        timeout_ms=2 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("ota_idle_state",),
    ),
    _command(
        "device.ota.logs",
        "deviceOtaLogs",
        _payload(
            ("serial", PayloadKind.STRING),
            ("maxLines", PayloadKind.INTEGER),
            ("timeoutSeconds", PayloadKind.INTEGER),
        ),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_READ,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="device.ota.logs",
        timeout_ms=3 * 60_000,
        postconditions=("bounded_redacted_logs_returned",),
    ),
    _command(
        "tools.pushFiles",
        "toolsPushFiles",
        _payload(
            ("serial", PayloadKind.STRING),
            ("grants", PayloadKind.STRING_ARRAY, True, 1, 32),
            ("destination", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.DEVICE_TOOLS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_WRITE,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="tools.push_files",
        timeout_ms=6 * 60 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("remote_files_written",),
    ),
    _command(
        "tools.pif",
        "toolsPif",
        _payload(
            ("serial", PayloadKind.STRING, True),
            ("action", PayloadKind.STRING, True),
            ("profileId", PayloadKind.STRING),
            ("targetPackage", PayloadKind.STRING),
            ("targetFormat", PayloadKind.STRING),
            ("checker", PayloadKind.STRING),
            ("content", PayloadKind.STRING),
            ("baseSha256", PayloadKind.STRING),
            ("confirmationText", PayloadKind.STRING, True),
            ("grant", PayloadKind.STRING),
        ),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.DESTRUCTIVE,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DESTRUCTIVE,
        valid_device_states=ADB_DEVICE_STATES,
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="root.pif.action",
        timeout_ms=2 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("pif_or_target_state_verified",),
    ),
    _command(
        "tools.piAnalysis",
        "toolsPiAnalysis",
        _payload(
            ("serial", PayloadKind.STRING, True),
            ("action", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_READ,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="root.pi_analysis",
        timeout_ms=3 * 60_000,
        postconditions=("bounded_redacted_analysis_returned",),
    ),
    _command(
        "tools.sos",
        "toolsSos",
        _payload(
            ("serial", PayloadKind.STRING, True),
            ("action", PayloadKind.STRING, True),
            ("confirmationText", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_WRITE,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="root.recovery.sos",
        timeout_ms=5 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("all_magisk_modules_disabled",),
    ),
    _command(
        "root.dataAdb.backup",
        "rootDataAdbBackup",
        _payload(
            ("serial", PayloadKind.STRING, True),
            ("grant", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="root.data_adb.backup",
        timeout_ms=60 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("data_adb_backup_verified",),
    ),
    _command(
        "root.dataAdb.restore",
        "rootDataAdbRestore",
        _payload(
            ("serial", PayloadKind.STRING, True),
            ("grant", PayloadKind.STRING, True),
            ("confirmationText", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.DESTRUCTIVE,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DESTRUCTIVE,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="root.data_adb.restore",
        timeout_ms=60 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("data_adb_restore_verified",),
    ),
    _command(
        "root.dataAdb.clear",
        "rootDataAdbClear",
        _payload(
            ("serial", PayloadKind.STRING, True),
            ("confirmationText", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.DESTRUCTIVE,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DESTRUCTIVE,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="root.data_adb.clear",
        timeout_ms=10 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("data_adb_empty",),
    ),
    _command(
        "tools.shizuku",
        "toolsShizuku",
        _payload(
            ("serial", PayloadKind.STRING, True),
            ("action", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.ROOT,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DEVICE_WRITE,
        valid_device_states=frozenset({"adb"}),
        target_scope=TargetScope.SELECTED_DEVICE,
        planner="root.recovery.shizuku",
        timeout_ms=5 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("shizuku_process_running",),
    ),
    _command(
        "tools.keybox",
        "toolsKeybox",
        _payload(
            ("action", PayloadKind.STRING, True),
            ("grants", PayloadKind.STRING_ARRAY, True, 1, 32),
        ),
        owner=CommandOwner.DEVELOPER_TOOLS,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_READ,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="keybox.analyze",
        timeout_ms=5 * 60_000,
        postconditions=("bounded_keybox_reports_returned",),
    ),
    _command(
        "tools.xml",
        "toolsXml",
        _payload(
            ("action", PayloadKind.STRING, True),
            ("grant", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.DEVELOPER_TOOLS,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_READ,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="binary_xml.decode",
        timeout_ms=30_000,
        postconditions=("bounded_xml_returned",),
    ),
    _command(
        "tools.avb",
        "toolsAvb",
        _payload(
            ("action", PayloadKind.STRING, True),
            ("currentSecurityPatch", PayloadKind.STRING),
            ("grant", PayloadKind.STRING),
            ("patchFingerprint", PayloadKind.BOOLEAN),
        ),
        owner=CommandOwner.DEVELOPER_TOOLS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="avb_downgrade.patch_service",
        timeout_ms=30 * 60_000,
        postconditions=("downgrade_artifact_registered",),
    ),
    _command(
        "tools.myTools",
        "toolsMyTools",
        _payload(
            ("action", PayloadKind.STRING, True),
            ("toolId", PayloadKind.STRING),
            ("title", PayloadKind.STRING),
            ("grant", PayloadKind.STRING),
            ("arguments", PayloadKind.STRING_ARRAY, False, 0, 128),
            ("enabled", PayloadKind.BOOLEAN),
        ),
        owner=CommandOwner.DEVELOPER_TOOLS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="my_tools.safe_argv",
        timeout_ms=5 * 60_000,
        postconditions=("profile_persisted_or_process_exit_zero",),
    ),
    _command(
        "tools.myTools.legacyPermission",
        "toolsMyToolsLegacyPermission",
        _payload(
            ("toolId", PayloadKind.STRING, True),
            ("granted", PayloadKind.BOOLEAN, True),
            ("confirmationText", PayloadKind.STRING),
        ),
        owner=CommandOwner.DEVELOPER_TOOLS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="my_tools.legacy_permission",
        timeout_ms=30_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("legacy_raw_permission_persisted",),
    ),
    _command(
        "tools.myTools.legacyRun",
        "toolsMyToolsLegacyRun",
        _payload(
            ("toolId", PayloadKind.STRING, True),
            ("confirmationText", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.DEVELOPER_TOOLS,
        **_LIVE,
        mutability=CommandMutability.DESTRUCTIVE,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.DESTRUCTIVE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="my_tools.legacy_raw",
        timeout_ms=5 * 60_000,
        confirmation=ConfirmationPolicy.STANDARD,
        postconditions=("process_exit_zero",),
    ),
    _command(
        "settings.get",
        "settingsGet",
        _payload(),
        owner=CommandOwner.SETTINGS,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.OPTIONAL,
        risk=CommandRisk.HOST_READ,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="runtime.settings_get",
        postconditions=("preferences_returned",),
    ),
    _command(
        "settings.update",
        "settingsUpdate",
        _payload(
            ("theme", PayloadKind.STRING),
            ("locale", PayloadKind.STRING),
            ("highContrast", PayloadKind.BOOLEAN),
            ("reducedMotion", PayloadKind.BOOLEAN),
            ("zoom", PayloadKind.INTEGER),
            ("expertMode", PayloadKind.BOOLEAN),
            ("automaticUpdateCheck", PayloadKind.BOOLEAN),
            ("checkDiskSpace", PayloadKind.BOOLEAN),
            ("checkBootloaderUnlocked", PayloadKind.BOOLEAN),
            ("checkFirmwareHash", PayloadKind.BOOLEAN),
            ("checkModuleUpdates", PayloadKind.BOOLEAN),
            ("showNotifications", PayloadKind.BOOLEAN),
            ("rebootTimeoutSeconds", PayloadKind.INTEGER),
            ("offerPatchMethods", PayloadKind.BOOLEAN),
            ("showRecoveryPatching", PayloadKind.BOOLEAN),
            ("keepPatchTemporaryFiles", PayloadKind.BOOLEAN),
            ("useBusyboxShell", PayloadKind.BOOLEAN),
            ("lowMemoryMode", PayloadKind.BOOLEAN),
            ("extraImageExtracts", PayloadKind.BOOLEAN),
            ("showCustomRomOptions", PayloadKind.BOOLEAN),
            ("keyboxIndex", PayloadKind.BOOLEAN),
            ("customizeFont", PayloadKind.BOOLEAN),
            ("fontFace", PayloadKind.STRING),
            ("fontSize", PayloadKind.INTEGER),
            ("toolbarPosition", PayloadKind.STRING),
            ("toolbarShowDevice", PayloadKind.BOOLEAN),
            ("toolbarShowTheme", PayloadKind.BOOLEAN),
            ("toolbarShowLanguage", PayloadKind.BOOLEAN),
            ("createBootTar", PayloadKind.BOOLEAN),
        ),
        owner=CommandOwner.SETTINGS,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="runtime.settings_update",
        postconditions=("preferences_persisted",),
    ),
    _command(
        "support.create",
        "supportCreate",
        _payload(
            ("grant", PayloadKind.STRING, True),
            ("includeConfig", PayloadKind.BOOLEAN),
            ("includeLogs", PayloadKind.BOOLEAN),
            ("includeState", PayloadKind.BOOLEAN),
            ("includeSystemInfo", PayloadKind.BOOLEAN),
        ),
        owner=CommandOwner.SUPPORT,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="support.package_v2",
        timeout_ms=30 * 60_000,
        postconditions=("encrypted_container_verified",),
    ),
    _command(
        "updates.check",
        "updatesCheck",
        _payload(),
        owner=CommandOwner.SUPPORT,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_READ,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="runtime.update_check",
        postconditions=("signed_manifest_authenticated", "rollback_sequence_persisted"),
    ),
    _command(
        "native.pickFile",
        "nativePickFile",
        _payload(
            ("purpose", PayloadKind.STRING, True),
            ("title", PayloadKind.STRING),
            ("filters", PayloadKind.FILTER_ARRAY),
        ),
        owner=CommandOwner.NATIVE_HOST,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_READ,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="native_host.pick_file",
        postconditions=("path_grant_issued",),
    ),
    _command(
        "native.pickFiles",
        "nativePickFiles",
        _payload(
            ("purpose", PayloadKind.STRING, True),
            ("title", PayloadKind.STRING),
            ("filters", PayloadKind.FILTER_ARRAY),
        ),
        owner=CommandOwner.NATIVE_HOST,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_READ,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="native_host.pick_files",
        postconditions=("path_grants_issued",),
    ),
    _command(
        "native.pickDirectory",
        "nativePickDirectory",
        _payload(
            ("purpose", PayloadKind.STRING, True),
            ("title", PayloadKind.STRING),
        ),
        owner=CommandOwner.NATIVE_HOST,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_READ,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="native_host.pick_directory",
        postconditions=("path_grant_issued",),
    ),
    _command(
        "native.saveFile",
        "nativeSaveFile",
        _payload(
            ("purpose", PayloadKind.STRING, True),
            ("title", PayloadKind.STRING),
            ("defaultName", PayloadKind.STRING),
            ("filters", PayloadKind.FILTER_ARRAY),
        ),
        owner=CommandOwner.NATIVE_HOST,
        **_LIVE,
        mutability=CommandMutability.READ_ONLY,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.HOST_WRITE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="native_host.save_file",
        postconditions=("write_grant_issued",),
    ),
    _command(
        "secret.issue",
        "secretIssue",
        _payload(
            ("purpose", PayloadKind.STRING, True),
            ("secret", PayloadKind.STRING, True),
        ),
        owner=CommandOwner.NATIVE_HOST,
        **_LIVE,
        mutability=CommandMutability.MUTATING,
        expected_revision=ExpectedRevision.REQUIRED,
        risk=CommandRisk.NONE,
        valid_device_states=ANY_DEVICE_STATE,
        target_scope=TargetScope.APPLICATION,
        planner="native_host.secret_grant",
        postconditions=("secret_grant_issued",),
    ),
)


def _build_registry(specs: tuple[CommandSpec, ...]) -> Mapping[str, CommandSpec]:
    registry: dict[str, CommandSpec] = {}
    typescript_names: set[str] = set()
    for spec in specs:
        if spec.command in registry:
            raise RuntimeError(f"duplicate command registry entry: {spec.command}")
        if spec.typescript_name in typescript_names:
            raise RuntimeError(f"duplicate TypeScript command name: {spec.typescript_name}")
        registry[spec.command] = spec
        typescript_names.add(spec.typescript_name)
    return MappingProxyType(dict(sorted(registry.items())))


COMMAND_REGISTRY = _build_registry(_COMMAND_SPECS)
REGISTERED_COMMANDS = frozenset(COMMAND_REGISTRY)
ALLOWED_COMMANDS = frozenset(command for command, spec in COMMAND_REGISTRY.items() if spec.exposed and spec.implemented)
FUTURE_COMMANDS = REGISTERED_COMMANDS - ALLOWED_COMMANDS
REGISTERED_PAYLOAD_FIELDS: Mapping[str, frozenset[str]] = MappingProxyType(
    {command: spec.payload.allowed_fields for command, spec in COMMAND_REGISTRY.items()}
)
PAYLOAD_FIELDS: Mapping[str, frozenset[str]] = MappingProxyType(
    {command: REGISTERED_PAYLOAD_FIELDS[command] for command in sorted(ALLOWED_COMMANDS)}
)
REVISION_OPTIONAL_COMMANDS = frozenset(
    command for command in ALLOWED_COMMANDS if COMMAND_REGISTRY[command].expected_revision is ExpectedRevision.OPTIONAL
)
NATIVE_PICKER_COMMANDS = frozenset(command for command in ALLOWED_COMMANDS if command.startswith("native."))
DESTRUCTIVE_COMMANDS = frozenset(
    command for command in ALLOWED_COMMANDS if COMMAND_REGISTRY[command].mutability is CommandMutability.DESTRUCTIVE
)
CONFIRMATION_COMMANDS = frozenset(
    command for command in ALLOWED_COMMANDS if COMMAND_REGISTRY[command].confirmation is not ConfirmationPolicy.NONE
)
DEVICE_SCOPED_COMMANDS = frozenset(
    command for command in ALLOWED_COMMANDS if COMMAND_REGISTRY[command].target_scope is TargetScope.SELECTED_DEVICE
)


__all__ = [
    "ADB_DEVICE_STATES",
    "ALLOWED_COMMANDS",
    "ANY_DEVICE_STATE",
    "BRIDGE_VERSION",
    "COMMAND_REGISTRY",
    "CONFIRMATION_COMMANDS",
    "CONNECTED_DEVICE_STATES",
    "DESTRUCTIVE_COMMANDS",
    "DEVICE_SCOPED_COMMANDS",
    "FASTBOOT_DEVICE_STATES",
    "FUTURE_COMMANDS",
    "NATIVE_PICKER_COMMANDS",
    "PAYLOAD_FIELDS",
    "REGISTERED_COMMANDS",
    "REGISTERED_PAYLOAD_FIELDS",
    "REVISION_OPTIONAL_COMMANDS",
    "CommandMutability",
    "CommandOwner",
    "CommandRisk",
    "CommandSpec",
    "ConfirmationPolicy",
    "ExpectedRevision",
    "PayloadField",
    "PayloadKind",
    "PayloadSchema",
    "PayloadSchemaError",
    "TargetScope",
]
