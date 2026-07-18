"""Public, UI-agnostic contracts for the PixelFlasher application core."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, ClassVar, Mapping
from uuid import uuid4


JSONScalar = None | bool | int | float | str
JSONValue = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


class SensitiveText:
    """An in-memory secret whose normal representations are always redacted.

    The value is deliberately absent from ``repr()``, ``str()``, and JSON
    serialization.  A bounded backend service must explicitly call
    :meth:`reveal` at the final secret-aware process boundary.
    """

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("sensitive text must be a string")
        self.__value = value

    def reveal(self) -> str:
        return self.__value

    def __repr__(self) -> str:
        return "SensitiveText([REDACTED])"

    def __str__(self) -> str:
        return "[REDACTED]"

    def __reduce__(self) -> object:
        raise TypeError("sensitive text cannot be pickled")


class CommandKind(str, Enum):
    SNAPSHOT_GET = "snapshot.get"
    DEVICE_SCAN = "device.scan"
    DEVICE_SELECT = "device.select"
    FIRMWARE_SELECT = "firmware.select"
    FLASH_PLAN_UPDATE = "flash.plan.update"
    FLASH_EXECUTE = "flash.execute"


class OperationStatus(str, Enum):
    SUCCESS = "success"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ProgressPhase(str, Enum):
    QUEUED = "queued"
    STARTED = "started"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class InteractionKind(str, Enum):
    CONFIRM = "confirm"
    CHOICE = "choice"
    NOTIFY = "notify"


class InteractionDecision(str, Enum):
    ACCEPTED = "accepted"
    CANCELLED = "cancelled"


def _freeze_mapping(values: Mapping[str, Any] | None) -> Mapping[str, Any]:
    return MappingProxyType(
        {str(key): _freeze_value(value) for key, value in (values or {}).items()}
    )


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_value(item) for key, item in value.items()}
        )
    if isinstance(value, (tuple, list)):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_value(item) for item in value)
    return value


def _json_value(value: Any) -> JSONValue:
    if isinstance(value, SensitiveText):
        return "[REDACTED]"
    if isinstance(value, Enum):
        return str(value.value)
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return value.to_dict()
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_json_value(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


@dataclass(frozen=True, slots=True)
class ProcessRequest:
    """An argv-only process request. Shell command strings are intentionally absent."""

    argv: tuple[str, ...]
    cwd: str | None = None
    env: tuple[tuple[str, str], ...] | None = None
    timeout_seconds: float | None = None
    encoding: str = "utf-8"

    def __post_init__(self) -> None:
        if isinstance(self.argv, str):
            raise TypeError("argv must be a sequence of individual arguments")
        object.__setattr__(self, "argv", tuple(self.argv))
        if self.env is not None:
            object.__setattr__(self, "env", tuple(tuple(item) for item in self.env))
        if not self.argv:
            raise ValueError("argv must not be empty")
        if any(not isinstance(arg, str) or "\x00" in arg for arg in self.argv):
            raise ValueError("argv must contain only NUL-free strings")
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.env is not None and any(
            len(item) != 2 or not all(isinstance(value, str) for value in item)
            for item in self.env
        ):
            raise ValueError("env must contain string key/value pairs")
        if not self.encoding:
            raise ValueError("encoding must not be empty")

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "argv": list(self.argv),
            "cwd": self.cwd,
            "env": dict(self.env) if self.env is not None else None,
            "timeout_seconds": self.timeout_seconds,
            "encoding": self.encoding,
        }


@dataclass(frozen=True, slots=True)
class FileArtifact:
    path: str
    sha256: str
    role: str = ""

    def __post_init__(self) -> None:
        if not self.path:
            raise ValueError("artifact path must not be empty")
        normalized = self.sha256.casefold()
        if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
            raise ValueError("artifact sha256 must contain exactly 64 hexadecimal characters")
        object.__setattr__(self, "sha256", normalized)

    def to_dict(self) -> dict[str, JSONValue]:
        return {"path": self.path, "sha256": self.sha256, "role": self.role}


@dataclass(frozen=True, slots=True, init=False)
class OperationPlan:
    requests: tuple[ProcessRequest, ...]
    label: str = ""
    target_serial: str | None = None
    expected_device_state: str = ""
    firmware_hash: str = ""
    boot_hash: str = ""
    partitions: tuple[str, ...] = ()
    slots: tuple[str, ...] = ()
    data_behavior: str = "preserve"
    plan_revision: int = 0
    fingerprint: str = ""
    confirmation_nonce: str | None = None
    confirmation_token: str | None = None
    artifacts: tuple[FileArtifact, ...] = ()
    dry_run: bool = False

    def __init__(
        self,
        requests: tuple[ProcessRequest, ...] | list[ProcessRequest] | ProcessRequest | None = None,
        label: str = "",
        target_serial: str | None = None,
        expected_device_state: str = "",
        firmware_hash: str = "",
        boot_hash: str = "",
        partitions: tuple[str, ...] = (),
        slots: tuple[str, ...] = (),
        data_behavior: str = "preserve",
        plan_revision: int = 0,
        fingerprint: str = "",
        confirmation_nonce: str | None = None,
        confirmation_token: str | None = None,
        artifacts: tuple[FileArtifact, ...] = (),
        dry_run: bool = False,
        *,
        request: ProcessRequest | None = None,
    ) -> None:
        if isinstance(requests, ProcessRequest):
            normalized_requests = (requests,)
        else:
            normalized_requests = tuple(requests or ())
        if request is not None:
            if normalized_requests:
                raise ValueError("provide requests or request, not both")
            normalized_requests = (request,)
        object.__setattr__(self, "requests", normalized_requests)
        object.__setattr__(self, "label", label)
        object.__setattr__(self, "target_serial", target_serial)
        object.__setattr__(self, "expected_device_state", expected_device_state)
        object.__setattr__(self, "firmware_hash", firmware_hash)
        object.__setattr__(self, "boot_hash", boot_hash)
        object.__setattr__(self, "partitions", tuple(partitions))
        object.__setattr__(self, "slots", tuple(slots))
        object.__setattr__(self, "data_behavior", data_behavior)
        object.__setattr__(self, "plan_revision", plan_revision)
        object.__setattr__(self, "fingerprint", fingerprint)
        object.__setattr__(self, "confirmation_nonce", confirmation_nonce)
        object.__setattr__(self, "confirmation_token", confirmation_token)
        object.__setattr__(self, "artifacts", tuple(artifacts))
        object.__setattr__(self, "dry_run", dry_run)
        self.__post_init__()

    def __post_init__(self) -> None:
        if not self.requests and not self.dry_run:
            raise ValueError("requests must contain at least one process request")
        if any(not isinstance(item, ProcessRequest) for item in self.requests):
            raise TypeError("requests must contain only ProcessRequest values")
        if any(not isinstance(item, FileArtifact) for item in self.artifacts):
            raise TypeError("artifacts must contain only FileArtifact values")
        if not isinstance(self.plan_revision, int) or isinstance(self.plan_revision, bool):
            raise TypeError("plan_revision must be an integer")
        if self.plan_revision < 0:
            raise ValueError("plan_revision cannot be negative")
        if any(not isinstance(item, str) or not item for item in self.partitions):
            raise ValueError("partitions cannot contain empty names")
        if any(not isinstance(item, str) or not item for item in self.slots):
            raise ValueError("slots cannot contain empty names")

    @property
    def request(self) -> ProcessRequest:
        """Compatibility accessor for plans containing exactly one command."""

        if len(self.requests) != 1:
            raise AttributeError("a multi-command plan has no singular request")
        return self.requests[0]

    def confirmation_challenge(self) -> str:
        """Bind a reinforced confirmation token to every safety-critical field."""

        material = {
            "requests": [request.to_dict() for request in self.requests],
            "target_serial": self.target_serial,
            "expected_device_state": self.expected_device_state,
            "firmware_hash": self.firmware_hash,
            "boot_hash": self.boot_hash,
            "partitions": self.partitions,
            "slots": self.slots,
            "data_behavior": self.data_behavior,
            "plan_revision": self.plan_revision,
            "fingerprint": self.fingerprint,
            "confirmation_nonce": self.confirmation_nonce,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "dry_run": self.dry_run,
        }
        encoded = json.dumps(material, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @property
    def reinforced_confirmation_valid(self) -> bool:
        return bool(
            self.confirmation_nonce
            and self.confirmation_token
            and self.confirmation_token == self.confirmation_challenge()
        )

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "requests": [request.to_dict() for request in self.requests],
            "request": self.requests[0].to_dict() if len(self.requests) == 1 else None,
            "label": self.label,
            "target_serial": self.target_serial,
            "expected_device_state": self.expected_device_state,
            "firmware_hash": self.firmware_hash,
            "boot_hash": self.boot_hash,
            "partitions": list(self.partitions),
            "slots": list(self.slots),
            "data_behavior": self.data_behavior,
            "plan_revision": self.plan_revision,
            "fingerprint": self.fingerprint,
            "confirmation_nonce": self.confirmation_nonce,
            "confirmation_token": self.confirmation_token,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "dry_run": self.dry_run,
        }


@dataclass(frozen=True, slots=True)
class AppCommand:
    kind: CommandKind | str
    expected_revision: int | None = None
    target_serial: str | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)
    operation_plan: OperationPlan | None = None
    operation_id: str = field(default_factory=lambda: uuid4().hex)
    destructive: bool = False
    requires_confirmation: bool = False

    def __post_init__(self) -> None:
        kind = self.kind.value if isinstance(self.kind, CommandKind) else str(self.kind)
        payload = dict(self.payload)
        # Wireless pairing credentials are accepted only as ephemeral input.
        # Redact them before the command can be represented or serialized by
        # diagnostics, progress observers, or tests.
        if kind == "tools.wifi" and isinstance(payload.get("pairingCode"), str):
            payload["pairingCode"] = SensitiveText(payload["pairingCode"])
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "target_serial", str(self.target_serial) if self.target_serial else None)
        object.__setattr__(self, "payload", _freeze_mapping(payload))
        if not kind:
            raise ValueError("kind must not be empty")
        if self.expected_revision is not None and (
            not isinstance(self.expected_revision, int)
            or isinstance(self.expected_revision, bool)
            or self.expected_revision < 0
        ):
            raise ValueError("expected_revision must be a non-negative integer or null")
        if not self.operation_id:
            raise ValueError("operation_id must not be empty")

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "kind": str(self.kind),
            "expected_revision": self.expected_revision,
            "target_serial": self.target_serial,
            "payload": _json_value(self.payload),
            "operation_plan": self.operation_plan.to_dict() if self.operation_plan else None,
            "operation_id": self.operation_id,
            "destructive": self.destructive,
            "requires_confirmation": self.requires_confirmation,
        }


@dataclass(frozen=True, slots=True)
class OperationResult:
    event_type: ClassVar[str] = "runtime"

    operation_id: str
    status: OperationStatus
    code: str
    message: str = ""
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    value: Any = None

    @property
    def ok(self) -> bool:
        return self.status is OperationStatus.SUCCESS

    @classmethod
    def success(
        cls,
        operation_id: str,
        *,
        code: str = "ok",
        message: str = "",
        exit_code: int | None = 0,
        stdout: str = "",
        stderr: str = "",
        value: Any = None,
    ) -> "OperationResult":
        return cls(operation_id, OperationStatus.SUCCESS, code, message, exit_code, stdout, stderr, value)

    @classmethod
    def cancelled(
        cls,
        operation_id: str,
        *,
        code: str = "cancelled",
        message: str = "",
        stdout: str = "",
        stderr: str = "",
    ) -> "OperationResult":
        return cls(operation_id, OperationStatus.CANCELLED, code, message, None, stdout, stderr)

    @classmethod
    def failed(
        cls,
        operation_id: str,
        *,
        code: str,
        message: str = "",
        exit_code: int | None = None,
        stdout: str = "",
        stderr: str = "",
    ) -> "OperationResult":
        return cls(operation_id, OperationStatus.FAILED, code, message, exit_code, stdout, stderr)

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "event_type": self.event_type,
            "operation_id": self.operation_id,
            "status": self.status.value,
            "code": self.code,
            "message": self.message,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "value": _json_value(self.value),
        }


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    event_type: ClassVar[str] = "progress"

    operation_id: str
    phase: ProgressPhase
    message: str = ""
    percent: int | None = None

    def __post_init__(self) -> None:
        if self.percent is not None and (
            not isinstance(self.percent, int) or isinstance(self.percent, bool)
        ):
            raise TypeError("percent must be an integer or null")
        if self.percent is not None and not 0 <= self.percent <= 100:
            raise ValueError("percent must be between 0 and 100")

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "event_type": self.event_type,
            "operation_id": self.operation_id,
            "phase": self.phase.value,
            "message": self.message,
            "percent": self.percent,
        }


@dataclass(frozen=True, slots=True)
class InteractionRequest:
    event_type: ClassVar[str] = "interaction"

    operation_id: str
    kind: InteractionKind
    title: str
    message: str
    expected_revision: int
    target_serial: str | None = None
    destructive: bool = False
    choices: tuple[str, ...] = ()
    reinforced: bool = False
    confirmation_nonce: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "choices", tuple(self.choices))
        if (
            not isinstance(self.expected_revision, int)
            or isinstance(self.expected_revision, bool)
            or self.expected_revision < 0
        ):
            raise ValueError("expected_revision must be a non-negative integer")

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "event_type": self.event_type,
            "operation_id": self.operation_id,
            "kind": self.kind.value,
            "title": self.title,
            "message": self.message,
            "expected_revision": self.expected_revision,
            "target_serial": self.target_serial,
            "destructive": self.destructive,
            "choices": list(self.choices),
            "reinforced": self.reinforced,
            "confirmation_nonce": self.confirmation_nonce,
        }


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    serial: str
    model: str = ""
    codename: str = ""
    mode: str = ""
    slot: str = ""
    root: bool = False
    online: bool = True
    name: str = ""
    android_version: str = ""
    build: str = ""
    security_patch: str = ""
    bootloader: str = "unknown"
    battery: int | None = None
    connection: str = ""

    def to_dict(self) -> dict[str, JSONValue]:
        display_name = self.name or self.model or self.codename or self.serial
        slot = self.slot if self.slot in {"a", "b"} else "unknown"
        return {
            "serial": self.serial,
            "name": display_name,
            "model": self.model,
            "codename": self.codename,
            "mode": self.mode,
            "androidVersion": self.android_version,
            "android_version": self.android_version,
            "build": self.build,
            "securityPatch": self.security_patch,
            "security_patch": self.security_patch,
            "bootloader": self.bootloader,
            "slot": slot,
            "battery": self.battery,
            "connection": self.connection,
            "root": self.root,
            "rooted": self.root,
            "online": self.online,
        }


@dataclass(frozen=True, slots=True)
class FirmwareInfo:
    path: str = ""
    type: str = ""
    build: str = ""
    hash: str = ""
    verified: bool = False
    processed: bool = False

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "path": self.path,
            "type": self.type,
            "build": self.build,
            "hash": self.hash,
            "verified": self.verified,
            "processed": self.processed,
        }


@dataclass(frozen=True, slots=True)
class BootInfo:
    id: str = ""
    path: str = ""
    hash: str = ""
    flavor: str = ""
    patched: bool = False

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "id": self.id,
            "path": self.path,
            "hash": self.hash,
            "flavor": self.flavor,
            "patched": self.patched,
        }


@dataclass(frozen=True, slots=True)
class BootloaderLockEvidence:
    """Backend-owned proof that one device received a complete stock flash.

    The browser cannot create or update this value.  Presence alone is not
    sufficient to lock: :class:`BootloaderLockPolicy` also binds it to the
    current device, firmware, plan, result, and snapshot revision.
    """

    serial: str
    device_codename: str
    firmware_hash: str
    firmware_build: str
    flash_operation_id: str
    flash_plan_fingerprint: str
    snapshot_revision: int
    required_partitions: tuple[str, ...]
    flashed_partitions: tuple[str, ...]
    slots: tuple[str, ...]

    def __post_init__(self) -> None:
        for field_name in (
            "serial",
            "device_codename",
            "firmware_hash",
            "firmware_build",
            "flash_operation_id",
            "flash_plan_fingerprint",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
            object.__setattr__(self, field_name, value.strip())
        normalized_hash = self.firmware_hash.casefold()
        if len(normalized_hash) != 64 or any(
            character not in "0123456789abcdef" for character in normalized_hash
        ):
            raise ValueError("firmware_hash must contain exactly 64 hexadecimal characters")
        object.__setattr__(self, "firmware_hash", normalized_hash)
        if (
            not isinstance(self.snapshot_revision, int)
            or isinstance(self.snapshot_revision, bool)
            or self.snapshot_revision < 0
        ):
            raise ValueError("snapshot_revision must be a non-negative integer")

        required = _normalized_contract_tokens(self.required_partitions, "required_partitions")
        flashed = _normalized_contract_tokens(self.flashed_partitions, "flashed_partitions")
        slots = _normalized_contract_tokens(self.slots, "slots")
        if not required:
            raise ValueError("required_partitions must not be empty")
        missing = set(required) - set(flashed)
        if missing:
            raise ValueError(
                f"flashed_partitions is missing required partition: {sorted(missing)[0]}"
            )
        if not {"boot", "init_boot"}.intersection(required):
            raise ValueError("stock evidence must include boot or init_boot")
        if "vbmeta" not in required:
            raise ValueError("stock evidence must include vbmeta")
        if set(slots) != {"a", "b"}:
            raise ValueError("stock evidence must cover both slots a and b")
        object.__setattr__(self, "required_partitions", required)
        object.__setattr__(self, "flashed_partitions", flashed)
        object.__setattr__(self, "slots", slots)

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "serial": self.serial,
            "device_codename": self.device_codename,
            "firmware_hash": self.firmware_hash,
            "firmware_build": self.firmware_build,
            "flash_operation_id": self.flash_operation_id,
            "flash_plan_fingerprint": self.flash_plan_fingerprint,
            "snapshot_revision": self.snapshot_revision,
            "required_partitions": list(self.required_partitions),
            "flashed_partitions": list(self.flashed_partitions),
            "slots": list(self.slots),
        }


def _normalized_contract_tokens(values: object, field_name: str) -> tuple[str, ...]:
    if isinstance(values, str) or not isinstance(values, (tuple, list)):
        raise TypeError(f"{field_name} must be an array of strings")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{field_name} must contain non-empty strings")
    return tuple(dict.fromkeys(value.strip().casefold() for value in values))


@dataclass(frozen=True, slots=True)
class FlashPlan:
    mode: str = "images"
    options: Mapping[str, Any] = field(default_factory=dict)
    revision: int = 0
    fingerprint: str = ""
    dry_run: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.mode, str) or not self.mode.strip():
            raise ValueError("mode must be a non-empty string")
        legacy_dry_mode = self.mode.strip().casefold() in {"dryrun", "dry-run", "dry_run"}
        if legacy_dry_mode:
            object.__setattr__(self, "mode", "images")
            object.__setattr__(self, "dry_run", True)
        if not isinstance(self.options, Mapping):
            raise TypeError("options must be a mapping")
        normalized = dict(self.options)
        dry_values = [
            normalized.pop(key)
            for key in ("dryRun", "dry_run")
            if key in normalized
        ]
        if any(not isinstance(value, bool) for value in dry_values):
            raise TypeError("dryRun must be a boolean")
        if len(set(dry_values)) > 1:
            raise ValueError("dryRun aliases disagree")
        if legacy_dry_mode and dry_values and dry_values[0] is False:
            raise ValueError("legacy dryRun mode cannot disable dry run")
        if dry_values:
            object.__setattr__(self, "dry_run", dry_values[0])

        bool_options = {
            "verify",
            "disableVerity",
            "disableVerification",
            "force",
            "noReboot",
            "downgrade",
            "temporaryRoot",
            "wipe",
            # Read-compatible aliases for existing core snapshots.
            "disable_verity",
            "disable_verification",
            "no_reboot",
            "temporary_root",
        }
        allowed_options = bool_options | {
            "slot",
            "partitions",
            "dataBehavior",
            "data_behavior",
            # Kept as a recognized field so the trusted planner can reject UI
            # artifact injection with a specific security error.
            "images",
        }
        unknown = set(normalized) - allowed_options
        if unknown:
            raise ValueError(f"unsupported flash option: {sorted(unknown)[0]}")
        for key in bool_options & set(normalized):
            if not isinstance(normalized[key], bool):
                raise TypeError(f"{key} must be a boolean")
        if "slot" in normalized:
            slot = normalized["slot"]
            if not isinstance(slot, str) or slot.strip().casefold() not in {"a", "b", "both"}:
                raise ValueError("slot must be a, b, or both")
            normalized["slot"] = slot.strip().casefold()
        for key in ("dataBehavior", "data_behavior"):
            if key in normalized:
                behavior = normalized[key]
                if not isinstance(behavior, str) or behavior.strip().casefold() not in {
                    "preserve",
                    "wipe",
                }:
                    raise ValueError(f"{key} must be preserve or wipe")
                normalized[key] = behavior.strip().casefold()
        if "partitions" in normalized:
            partitions = normalized["partitions"]
            if isinstance(partitions, str) or not isinstance(partitions, (tuple, list)):
                raise TypeError("partitions must be an array of strings")
            if not partitions:
                raise ValueError("partitions must not be empty")
            if any(not isinstance(item, str) or not item.strip() for item in partitions):
                raise ValueError("partitions must contain non-empty strings")
        if "images" in normalized and not isinstance(normalized["images"], Mapping):
            raise TypeError("images must be an object")

        object.__setattr__(self, "options", _freeze_mapping(normalized))
        if not isinstance(self.revision, int) or isinstance(self.revision, bool):
            raise TypeError("revision must be an integer")
        if self.revision < 0:
            raise ValueError("revision cannot be negative")
        if not isinstance(self.dry_run, bool):
            raise TypeError("dry_run must be a boolean")

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "mode": self.mode,
            "options": _json_value(self.options),
            "revision": self.revision,
            "fingerprint": self.fingerprint,
            "dry_run": self.dry_run,
        }


@dataclass(frozen=True, slots=True)
class ToolchainInfo:
    adb: str = ""
    fastboot: str = ""
    version: str = ""
    ready: bool = False

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "adb": self.adb,
            "fastboot": self.fastboot,
            "version": self.version,
            "ready": self.ready,
        }


@dataclass(frozen=True, slots=True)
class ActiveOperation:
    operation_id: str
    kind: str
    label: str = ""

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "operation_id": self.operation_id,
            "kind": self.kind,
            "label": self.label,
        }


@dataclass(frozen=True, slots=True)
class AppSnapshot:
    event_type: ClassVar[str] = "snapshot"

    revision: int = 0
    devices: tuple[DeviceInfo, ...] = ()
    selected_serials: tuple[str, ...] = ()
    selected_serial: str | None = None
    firmware: FirmwareInfo = field(default_factory=FirmwareInfo)
    boot: BootInfo = field(default_factory=BootInfo)
    plan: FlashPlan = field(default_factory=FlashPlan)
    toolchain: ToolchainInfo = field(default_factory=ToolchainInfo)
    active_operation: ActiveOperation | None = None
    last_result: OperationResult | None = None
    bootloader_lock_evidence: tuple[BootloaderLockEvidence, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "devices", tuple(self.devices))
        if not isinstance(self.revision, int) or isinstance(self.revision, bool) or self.revision < 0:
            raise ValueError("revision must be a non-negative integer")
        if any(not isinstance(device, DeviceInfo) for device in self.devices):
            raise TypeError("devices must contain only DeviceInfo values")
        object.__setattr__(self, "bootloader_lock_evidence", tuple(self.bootloader_lock_evidence))
        if any(
            not isinstance(evidence, BootloaderLockEvidence)
            for evidence in self.bootloader_lock_evidence
        ):
            raise TypeError(
                "bootloader_lock_evidence must contain only BootloaderLockEvidence values"
            )
        evidence_serials = tuple(evidence.serial for evidence in self.bootloader_lock_evidence)
        if len(evidence_serials) != len(set(evidence_serials)):
            raise ValueError("bootloader_lock_evidence must contain unique serials")
        if isinstance(self.selected_serials, str):
            raise TypeError("selected_serials must be a sequence of serials")
        if any(not isinstance(serial, str) for serial in self.selected_serials):
            raise TypeError("selected_serials must contain only strings")
        serials = tuple(dict.fromkeys(serial for serial in self.selected_serials if serial))
        primary = self.selected_serial
        if primary and primary not in serials:
            serials = (primary, *serials)
        if primary is None and serials:
            primary = serials[0]
        object.__setattr__(self, "selected_serials", serials)
        object.__setattr__(self, "selected_serial", primary)

    @property
    def firmware_path(self) -> str:
        return self.firmware.path

    @property
    def flash_mode(self) -> str:
        return self.plan.mode

    @property
    def flash_options(self) -> Mapping[str, Any]:
        return self.plan.options

    @property
    def active_operations(self) -> tuple[str, ...]:
        if self.active_operation is None:
            return ()
        return (self.active_operation.operation_id,)

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "event_type": self.event_type,
            "revision": self.revision,
            "devices": [device.to_dict() for device in self.devices],
            "selected_serials": list(self.selected_serials),
            "selected_serial": self.selected_serial,
            "firmware": self.firmware.to_dict(),
            "boot": self.boot.to_dict(),
            "plan": self.plan.to_dict(),
            "toolchain": self.toolchain.to_dict(),
            "active_operation": (
                self.active_operation.to_dict() if self.active_operation else None
            ),
            "last_result": self.last_result.to_dict() if self.last_result else None,
            "bootloader_lock_evidence": [
                evidence.to_dict() for evidence in self.bootloader_lock_evidence
            ],
        }


@dataclass(frozen=True, slots=True)
class SafetyDecision:
    allowed: bool
    code: str = "ok"
    message: str = ""
    interaction: InteractionRequest | None = None
