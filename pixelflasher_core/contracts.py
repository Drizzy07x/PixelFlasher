"""Public, UI-agnostic contracts for the PixelFlasher application core."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import ntpath
import posixpath
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from types import MappingProxyType
from typing import Any, ClassVar, Never, cast
from uuid import uuid4

from .cancellation import CancellationReason, CancellationToken

JSONScalar = None | bool | int | float | str
JSONValue = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]

PREFERENCES_SCHEMA_KEY = "schemaVersion"
PREFERENCES_SCHEMA_VERSION = 1
SUPPORTED_THEMES = ("dark", "light")
SUPPORTED_LOCALES = ("en", "es", "fr", "it", "zh_CN", "zh_TW")
MIN_ZOOM = 80
MAX_ZOOM = 200
MAX_MANAGED_DEVICE_TIMESTAMP = 253_402_300_799
_SUPPORTED_THEME_SET = frozenset(SUPPORTED_THEMES)
_SUPPORTED_LOCALE_SET = frozenset(SUPPORTED_LOCALES)
_PREFERENCE_FIELDS = frozenset(
    {
        PREFERENCES_SCHEMA_KEY,
        "theme",
        "locale",
        "highContrast",
        "reducedMotion",
        "zoom",
        "expertMode",
    }
)


class PreferencesError(ValueError):
    """Stable validation failure for public presentation preferences."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModernPreferences:
    """Immutable, UI-independent public presentation configuration."""

    theme: str = "dark"
    locale: str = "en"
    high_contrast: bool = False
    reduced_motion: bool = False
    zoom: int = 100
    expert_mode: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.theme, str) or self.theme not in _SUPPORTED_THEME_SET:
            raise PreferencesError(
                "theme_invalid",
                "theme must be exactly dark or light",
            )
        if not isinstance(self.locale, str) or self.locale not in _SUPPORTED_LOCALE_SET:
            raise PreferencesError(
                "locale_invalid",
                "locale must be one of en, es, fr, it, zh_CN, or zh_TW",
            )
        if not isinstance(self.high_contrast, bool):
            raise PreferencesError(
                "high_contrast_invalid",
                "highContrast must be a boolean",
            )
        if not isinstance(self.reduced_motion, bool):
            raise PreferencesError(
                "reduced_motion_invalid",
                "reducedMotion must be a boolean",
            )
        if not isinstance(self.zoom, int) or isinstance(self.zoom, bool):
            raise PreferencesError(
                "zoom_invalid",
                "zoom must be an integer",
            )
        if not MIN_ZOOM <= self.zoom <= MAX_ZOOM:
            raise PreferencesError(
                "zoom_invalid",
                f"zoom must be between {MIN_ZOOM} and {MAX_ZOOM}",
            )
        if not isinstance(self.expert_mode, bool):
            raise PreferencesError(
                "expert_mode_invalid",
                "expertMode must be a boolean",
            )

    @classmethod
    def from_mapping(
        cls,
        raw: Mapping[str, Any],
        *,
        require_schema: bool = False,
    ) -> ModernPreferences:
        if not isinstance(raw, Mapping):
            raise PreferencesError(
                "preferences_not_object",
                "modern preferences must be an object",
            )
        unknown = set(raw) - _PREFERENCE_FIELDS
        if unknown:
            preference_field = min(
                (repr(value) for value in unknown),
                default="<unknown>",
            )
            raise PreferencesError(
                "unknown_preference_field",
                f"unsupported preference field: {preference_field}",
            )
        if require_schema and PREFERENCES_SCHEMA_KEY not in raw:
            raise PreferencesError(
                "preferences_schema_invalid",
                "persisted modern preferences require schemaVersion",
            )
        schema = raw.get(PREFERENCES_SCHEMA_KEY, PREFERENCES_SCHEMA_VERSION)
        if not isinstance(schema, int) or isinstance(schema, bool):
            raise PreferencesError(
                "preferences_schema_invalid",
                "preference schema version must be an integer",
            )
        if schema != PREFERENCES_SCHEMA_VERSION:
            raise PreferencesError(
                "preferences_schema_unsupported",
                (
                    f"unsupported preference schema {schema}; "
                    f"expected {PREFERENCES_SCHEMA_VERSION}"
                ),
            )
        defaults = cls()
        return cls(
            theme=raw.get("theme", defaults.theme),
            locale=raw.get("locale", defaults.locale),
            high_contrast=raw.get("highContrast", defaults.high_contrast),
            reduced_motion=raw.get("reducedMotion", defaults.reduced_motion),
            zoom=raw.get("zoom", defaults.zoom),
            expert_mode=raw.get("expertMode", defaults.expert_mode),
        )

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            PREFERENCES_SCHEMA_KEY: PREFERENCES_SCHEMA_VERSION,
            "theme": self.theme,
            "locale": self.locale,
            "highContrast": self.high_contrast,
            "reducedMotion": self.reduced_motion,
            "zoom": self.zoom,
            "expertMode": self.expert_mode,
        }


def _empty_object_mapping() -> Mapping[str, object]:
    return {}


_WINDOWS_ABSOLUTE_PATH = re.compile(r"(?i)^[a-z]:[\\/]")
_UNC_ABSOLUTE_PATH = re.compile(r"^\\\\[^\\/]+[\\/][^\\/]+")
_WINDOWS_PATH_IN_TEXT = re.compile(r"(?i)(?:^|[^a-z0-9])(?:[a-z]:[\\/])")
_UNC_PATH_IN_TEXT = re.compile(r"(?:^|[^a-zA-Z0-9])\\\\[^\\/\s]+[\\/][^\s\"']+")
_POSIX_PATH_IN_TEXT = re.compile(r"(?:^|[\s\"'(\[=,;])(/(?!/)[^\s\"'\])},;]+)")
_PUBLIC_ANDROID_PATH_PREFIXES = (
    "/data/",
    "/dev/",
    "/metadata/",
    "/mnt/",
    "/odm/",
    "/proc/",
    "/product/",
    "/sdcard/",
    "/storage/",
    "/sys/",
    "/system/",
    "/vendor/",
)
_PUBLIC_PROGRESS_KIND = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,127}$")
_PUBLIC_PROGRESS_ITEM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PLAIN_TARGET_SERIAL = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_IPV6_TARGET_SERIAL = re.compile(
    r"^\[([0-9A-Fa-f:]{2,64}(?:%[A-Za-z0-9._-]{1,32})?)\]:([0-9]{1,5})$"
)


def is_valid_target_serial(value: object) -> bool:
    """Validate USB/emulator serials and bracketed IPv6 ADB endpoints.

    Scoped link-local endpoints are accepted only inside brackets and with a
    restricted zone identifier. Ports are range-checked instead of relying on
    a permissive decimal regex at the WebView boundary.
    """

    if not isinstance(value, str) or not value:
        return False
    if _PLAIN_TARGET_SERIAL.fullmatch(value) is not None:
        return True
    matched = _IPV6_TARGET_SERIAL.fullmatch(value)
    if matched is None:
        return False
    host, raw_port = matched.groups()
    try:
        address = ipaddress.ip_address(host)
        port = int(raw_port, 10)
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv6Address) and 1 <= port <= 65_535


def _looks_like_host_absolute_path(value: str) -> bool:
    normalized = value.strip()
    if not normalized:
        return False
    if _WINDOWS_ABSOLUTE_PATH.match(normalized) or _UNC_ABSOLUTE_PATH.match(normalized):
        return True
    return normalized.startswith("/") and not any(
        normalized == prefix[:-1] or normalized.startswith(prefix)
        for prefix in _PUBLIC_ANDROID_PATH_PREFIXES
    )


def _message_contains_host_path(value: str) -> bool:
    if (
        _WINDOWS_PATH_IN_TEXT.search(value)
        or _UNC_PATH_IN_TEXT.search(value)
        or "WindowsPath(" in value
        or "PosixPath(" in value
        or "PurePath(" in value
    ):
        return True
    return any(
        _looks_like_host_absolute_path(match.group(1))
        for match in _POSIX_PATH_IN_TEXT.finditer(value)
    )


def _public_basename(value: str) -> str:
    """Return a cross-platform basename without exposing its parent path."""

    return ntpath.basename(posixpath.basename(str(value).replace("\\", "/")))


def _public_message(value: str, *, fallback: str = "") -> str:
    """Reject path-bearing diagnostics at the public serialization boundary."""

    if not isinstance(value, str):
        return fallback
    if _message_contains_host_path(value):
        return fallback
    return value


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

    def meets_policy(
        self,
        min_length: int,
        max_length: int,
        *,
        nul_free: bool = True,
    ) -> bool:
        """Check a closed content policy without exposing the secret value."""

        if (
            not isinstance(min_length, int)
            or isinstance(min_length, bool)
            or not isinstance(max_length, int)
            or isinstance(max_length, bool)
            or min_length < 0
            or max_length < min_length
        ):
            raise ValueError("secret policy bounds are invalid")
        return min_length <= len(self.__value) <= max_length and (
            not nul_free or "\x00" not in self.__value
        )

    def same_value(self, expected: SensitiveText) -> bool:
        """Compare two opaque values without exposing or serializing either."""

        if not isinstance(expected, SensitiveText):
            return False
        return hmac.compare_digest(
            self.__value.encode("utf-8"),
            expected.__value.encode("utf-8"),
        )

    def redact(self, text: str) -> str:
        """Remove this value from untrusted process diagnostics."""

        if not isinstance(text, str):
            raise TypeError("redaction input must be a string")
        if not self.__value:
            return text
        return text.replace(self.__value, "[REDACTED]")

    def __repr__(self) -> str:
        return "SensitiveText([REDACTED])"

    def __str__(self) -> str:
        return "[REDACTED]"

    def __reduce__(self) -> Never:
        raise TypeError("sensitive text cannot be pickled")


class CommandKind(StrEnum):
    SNAPSHOT_GET = "snapshot.get"
    DEVICE_SCAN = "device.scan"
    DEVICE_SELECT = "device.select"
    FIRMWARE_SELECT = "firmware.select"
    FLASH_PLAN_UPDATE = "flash.plan.update"
    FLASH_EXECUTE = "flash.execute"


class OperationStatus(StrEnum):
    SUCCESS = "success"
    CANCELLED = "cancelled"
    FAILED = "failed"


class OperationRisk(StrEnum):
    """Execution risk used by the v2 planner and operation runner."""

    READ_ONLY = "read_only"
    MUTATING = "mutating"
    DESTRUCTIVE = "destructive"


OPERATION_PLAN_TTL_SECONDS = 5 * 60.0


class ProgressPhase(StrEnum):
    QUEUED = "queued"
    STARTED = "started"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class InteractionKind(StrEnum):
    CONFIRM = "confirm"
    CHOICE = "choice"
    NOTIFY = "notify"


class InteractionDecision(StrEnum):
    ACCEPTED = "accepted"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class CommandAck:
    """Explicit acknowledgement for cancellation and interaction responses."""

    accepted: bool
    code: str
    message: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.accepted, bool):
            raise TypeError("accepted must be a boolean")
        if not isinstance(self.code, str) or not self.code.strip():
            raise ValueError("command acknowledgement code must not be empty")
        if not isinstance(self.message, str):
            raise TypeError("command acknowledgement message must be a string")

    def __bool__(self) -> bool:
        return self.accepted

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "accepted": self.accepted,
            "code": self.code,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class InteractionResponse:
    """One revision-bound response to a pending backend interaction."""

    decision: InteractionDecision
    expected_revision: int

    def __post_init__(self) -> None:
        decision = (
            self.decision
            if isinstance(self.decision, InteractionDecision)
            else InteractionDecision(str(self.decision))
        )
        object.__setattr__(self, "decision", decision)
        if (
            not isinstance(self.expected_revision, int)
            or isinstance(self.expected_revision, bool)
            or self.expected_revision < 0
        ):
            raise ValueError("expected_revision must be a non-negative integer")

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "decision": self.decision.value,
            "expected_revision": self.expected_revision,
        }


def _freeze_mapping(
    values: Mapping[str, object] | None,
) -> Mapping[str, object]:
    raw_values = cast(Mapping[object, object], values or {})
    return MappingProxyType(
        {str(key): _freeze_value(value) for key, value in raw_values.items()}
    )


def _freeze_value(value: object) -> object:
    if isinstance(value, Mapping):
        values = cast(Mapping[object, object], value)
        return MappingProxyType(
            {str(key): _freeze_value(item) for key, item in values.items()}
        )
    if isinstance(value, (tuple, list)):
        items = cast(tuple[object, ...] | list[object], value)
        return tuple(_freeze_value(item) for item in items)
    if isinstance(value, (set, frozenset)):
        items = cast(set[object] | frozenset[object], value)
        return frozenset(_freeze_value(item) for item in items)
    return value


def _json_value(value: object) -> JSONValue:
    if isinstance(value, SensitiveText):
        return "[REDACTED]"
    if isinstance(value, Enum):
        return str(cast(object, value.value))
    converter = getattr(value, "to_dict", None)
    if callable(converter):
        converted = cast(Callable[[], object], converter)()
        return _json_value(converted)
    if isinstance(value, Mapping):
        values = cast(Mapping[object, object], value)
        return {str(key): _json_value(item) for key, item in values.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        items = cast(
            tuple[object, ...] | list[object] | set[object] | frozenset[object],
            value,
        )
        return [_json_value(item) for item in items]
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
    stdin_secret_field: str | None = None
    output_limit_bytes: int | None = None

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
        if self.output_limit_bytes is not None and (
            not isinstance(self.output_limit_bytes, int)
            or isinstance(self.output_limit_bytes, bool)
            or not 1_024 <= self.output_limit_bytes <= 64 * 1_024 * 1_024
        ):
            raise ValueError(
                "output_limit_bytes must be between 1024 and 67108864 or null"
            )
        if self.stdin_secret_field is not None and (
            not isinstance(self.stdin_secret_field, str)
            or not self.stdin_secret_field
            or len(self.stdin_secret_field) > 64
            or not self.stdin_secret_field[0].isalpha()
            or not all(
                character.isascii() and (character.isalnum() or character == "_")
                for character in self.stdin_secret_field
            )
        ):
            raise ValueError(
                "stdin_secret_field must be a short ASCII identifier or null"
            )

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "argv": list(self.argv),
            "cwd": self.cwd,
            "env": dict(self.env) if self.env is not None else None,
            "timeout_seconds": self.timeout_seconds,
            "encoding": self.encoding,
            # This is only the backend payload field name. Secret material is
            # deliberately absent from process requests and operation plans.
            "stdin_secret_field": self.stdin_secret_field,
            "output_limit_bytes": self.output_limit_bytes,
        }

    def to_public_dict(
        self,
        *,
        artifact_references: Mapping[str, str] | None = None,
    ) -> dict[str, JSONValue]:
        """Serialize a display-only command without host paths, cwd, or env."""

        references = artifact_references or {}
        argv: list[JSONValue] = []
        for index, argument in enumerate(self.argv):
            reference = references.get(argument)
            if reference is not None:
                argv.append(reference)
            elif index == 0:
                argv.append(_public_basename(argument) or "tool")
            elif _looks_like_host_absolute_path(argument):
                argv.append("@host-resource")
            else:
                argv.append(argument)
        return {
            "argv": argv,
            "timeout_seconds": self.timeout_seconds,
            "encoding": self.encoding,
            "stdin_secret_field": self.stdin_secret_field,
            "output_limit_bytes": self.output_limit_bytes,
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

    def public_reference(self) -> str:
        role = self.role.strip().replace(" ", "-") or "artifact"
        return f"@artifact/{role}/{self.sha256[:12]}"

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "sha256": self.sha256,
            "role": self.role,
            "displayName": self.public_reference(),
        }


_SECRET_FIELD_FRAGMENTS = frozenset(
    {"credential", "pairing", "passphrase", "password", "secret", "token"}
)


def _reject_sensitive_metadata(value: Any, *, path: str = "postcondition") -> None:
    if isinstance(value, SensitiveText):
        raise ValueError(f"{path} must not contain secrets")
    if isinstance(value, Mapping):
        values = cast(Mapping[object, object], value)
        for raw_key, item in values.items():
            if isinstance(raw_key, SensitiveText):
                raise ValueError(f"{path} must not contain secret keys")
            key = str(raw_key)
            normalized = key.casefold().replace("-", "_")
            if any(fragment in normalized for fragment in _SECRET_FIELD_FRAGMENTS):
                raise ValueError(f"{path}.{key} is not allowed to contain secret material")
            _reject_sensitive_metadata(item, path=f"{path}.{key}")
    elif isinstance(value, (tuple, list, set, frozenset)):
        items = cast(
            tuple[object, ...] | list[object] | set[object] | frozenset[object],
            value,
        )
        for index, item in enumerate(items):
            _reject_sensitive_metadata(item, path=f"{path}[{index}]")


@dataclass(frozen=True, slots=True)
class OperationPostcondition:
    """One observable condition that must hold before success is reported."""

    kind: str
    expected: Mapping[str, object] = field(default_factory=dict[str, object])
    description: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not self.kind.strip():
            raise ValueError("postcondition kind must be a non-empty string")
        if not isinstance(self.expected, Mapping):
            raise TypeError("postcondition expected value must be a mapping")
        _reject_sensitive_metadata(self.expected)
        object.__setattr__(self, "kind", self.kind.strip())
        object.__setattr__(self, "expected", _freeze_mapping(self.expected))
        if not isinstance(self.description, str):
            raise TypeError("postcondition description must be a string")

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "kind": self.kind,
            "expected": _json_value(self.expected),
            "description": self.description,
        }

    def to_public_dict(self) -> dict[str, JSONValue]:
        """Expose the observable contract, never backend evidence locations."""

        return {
            "kind": self.kind,
            "description": _public_message(self.description),
        }


def _normalized_operation_risk(value: OperationRisk | str) -> OperationRisk:
    if isinstance(value, OperationRisk):
        return value
    aliases = {
        "none": OperationRisk.READ_ONLY,
        "read": OperationRisk.READ_ONLY,
        "read_only": OperationRisk.READ_ONLY,
        "device_read": OperationRisk.READ_ONLY,
        "mutating": OperationRisk.MUTATING,
        "mutation": OperationRisk.MUTATING,
        "device_write": OperationRisk.MUTATING,
        "destructive": OperationRisk.DESTRUCTIVE,
    }
    normalized = str(value).strip().casefold().replace("-", "_")
    try:
        return aliases[normalized]
    except KeyError as error:
        raise ValueError(f"unsupported operation risk: {value}") from error


def _normalized_postcondition(value: object) -> OperationPostcondition:
    if isinstance(value, OperationPostcondition):
        return value
    if isinstance(value, str):
        return OperationPostcondition(value)
    if isinstance(value, Mapping):
        values = cast(Mapping[object, object], value)
        unknown = set(values) - {"kind", "expected", "description"}
        if unknown:
            raise ValueError(
                f"unsupported postcondition field: {sorted(str(item) for item in unknown)[0]}"
            )
        expected = values.get("expected", {})
        if not isinstance(expected, Mapping):
            raise TypeError("postcondition expected value must be a mapping")
        return OperationPostcondition(
            kind=str(values.get("kind", "")),
            expected=cast(Mapping[str, object], expected),
            description=str(values.get("description", "")),
        )
    raise TypeError("postconditions must contain typed conditions, strings, or mappings")


def confirmation_serial_suffix(serial: str) -> str:
    """Return only the final six serial characters for confirmation text."""

    normalized = str(serial).strip()
    if not normalized:
        raise ValueError("a real target serial is required for confirmation")
    return normalized[-6:]


@dataclass(frozen=True, slots=True, init=False)
class OperationPlan:
    requests: tuple[ProcessRequest, ...]
    label: str = ""
    plan_id: str = ""
    created: float = 0.0
    expires: float = 0.0
    risk: OperationRisk = OperationRisk.READ_ONLY
    postconditions: tuple[OperationPostcondition, ...] = ()
    snapshot_revision: int | None = None
    target_serial: str | None = None
    expected_codename: str = ""
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
        plan_id: str | None = None,
        created: float | None = None,
        expires: float | None = None,
        risk: OperationRisk | str = OperationRisk.READ_ONLY,
        postconditions: tuple[
            OperationPostcondition | str | Mapping[str, object], ...
        ] = (),
        snapshot_revision: int | None = None,
        target_serial: str | None = None,
        expected_codename: str = "",
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
        planId: str | None = None,
    ) -> None:
        if isinstance(requests, ProcessRequest):
            normalized_requests = (requests,)
        else:
            normalized_requests = tuple(requests or ())
        if request is not None:
            if normalized_requests:
                raise ValueError("provide requests or request, not both")
            normalized_requests = (request,)
        if plan_id is not None and planId is not None and plan_id != planId:
            raise ValueError("plan_id and planId aliases disagree")
        normalized_plan_id = plan_id or planId or uuid4().hex
        created_value = time.time() if created is None else float(created)
        expires_value = (
            created_value + OPERATION_PLAN_TTL_SECONDS
            if expires is None
            else float(expires)
        )
        normalized_risk = _normalized_operation_risk(risk)
        if dry_run:
            normalized_risk = OperationRisk.READ_ONLY
        normalized_postconditions = tuple(
            _normalized_postcondition(item) for item in postconditions
        )
        object.__setattr__(self, "requests", normalized_requests)
        object.__setattr__(self, "label", label)
        object.__setattr__(self, "plan_id", normalized_plan_id)
        object.__setattr__(self, "created", created_value)
        object.__setattr__(self, "expires", expires_value)
        object.__setattr__(self, "risk", normalized_risk)
        object.__setattr__(self, "postconditions", normalized_postconditions)
        object.__setattr__(self, "snapshot_revision", snapshot_revision)
        object.__setattr__(self, "target_serial", target_serial)
        object.__setattr__(self, "expected_codename", expected_codename)
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
        if not isinstance(self.plan_id, str) or not self.plan_id.strip():
            raise ValueError("plan_id must be a non-empty string")
        if not math.isfinite(self.created) or not math.isfinite(self.expires):
            raise ValueError("created and expires must be finite timestamps")
        if self.created < 0 or self.expires <= self.created:
            raise ValueError("expires must be later than created")
        if self.expires - self.created > OPERATION_PLAN_TTL_SECONDS + 1e-6:
            raise ValueError("operation plan TTL cannot exceed five minutes")
        if self.risk is not OperationRisk.READ_ONLY and not self.postconditions:
            raise ValueError("mutating plans require at least one postcondition")
        if self.snapshot_revision is not None and (
            not isinstance(self.snapshot_revision, int)
            or isinstance(self.snapshot_revision, bool)
            or self.snapshot_revision < 0
        ):
            raise ValueError("snapshot_revision must be a non-negative integer or null")
        if not isinstance(self.plan_revision, int) or isinstance(self.plan_revision, bool):
            raise TypeError("plan_revision must be an integer")
        if self.plan_revision < 0:
            raise ValueError("plan_revision cannot be negative")
        if any(not isinstance(item, str) or not item for item in self.partitions):
            raise ValueError("partitions cannot contain empty names")
        if any(not isinstance(item, str) or not item for item in self.slots):
            raise ValueError("slots cannot contain empty names")
        if not isinstance(self.expected_codename, str):
            raise TypeError("expected_codename must be a string")

    @property
    def request(self) -> ProcessRequest:
        """Compatibility accessor for plans containing exactly one command."""

        if len(self.requests) != 1:
            raise AttributeError("a multi-command plan has no singular request")
        return self.requests[0]

    @property
    def planId(self) -> str:  # noqa: N802 - public bridge contract spelling
        return self.plan_id

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires

    def execution_fingerprint(self) -> str:
        """Fingerprint stable execution semantics, excluding IDs and clocks."""

        material = {
            "requests": [request.to_dict() for request in self.requests],
            "target_serial": self.target_serial,
            "expected_codename": self.expected_codename,
            "expected_device_state": self.expected_device_state,
            "firmware_hash": self.firmware_hash,
            "boot_hash": self.boot_hash,
            "partitions": self.partitions,
            "slots": self.slots,
            "data_behavior": self.data_behavior,
            "snapshot_revision": self.snapshot_revision,
            "plan_revision": self.plan_revision,
            "fingerprint": self.fingerprint,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "dry_run": self.dry_run,
            "risk": self.risk.value,
            "postconditions": [item.to_dict() for item in self.postconditions],
        }
        encoded = json.dumps(material, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def confirmation_challenge(self) -> str:
        """Bind a reinforced confirmation token to every safety-critical field."""

        material = {
            "execution_fingerprint": self.execution_fingerprint(),
            "confirmation_nonce": self.confirmation_nonce,
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
            "planId": self.plan_id,
            "created": self.created,
            "expires": self.expires,
            "risk": self.risk.value,
            "postconditions": [item.to_dict() for item in self.postconditions],
            "snapshot_revision": self.snapshot_revision,
            "execution_fingerprint": self.execution_fingerprint(),
            "requests": [request.to_dict() for request in self.requests],
            "request": self.requests[0].to_dict() if len(self.requests) == 1 else None,
            "label": self.label,
            "target_serial": self.target_serial,
            "expected_codename": self.expected_codename,
            "expected_device_state": self.expected_device_state,
            "firmware_hash": self.firmware_hash,
            "boot_hash": self.boot_hash,
            "partitions": list(self.partitions),
            "slots": list(self.slots),
            "data_behavior": self.data_behavior,
            "plan_revision": self.plan_revision,
            "fingerprint": self.fingerprint,
            "confirmation_nonce": self.confirmation_nonce,
            # Execution tokens are backend-only and must never cross JSON.
            "confirmation_token": None,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "dry_run": self.dry_run,
        }

    def to_public_dict(self) -> dict[str, JSONValue]:
        artifact_references = {
            artifact.path: artifact.public_reference() for artifact in self.artifacts
        }
        requests = [
            request.to_public_dict(artifact_references=artifact_references)
            for request in self.requests
        ]
        return cast(dict[str, JSONValue], {
            "planId": self.plan_id,
            "created": self.created,
            "expires": self.expires,
            "risk": self.risk.value,
            "postconditions": [item.to_public_dict() for item in self.postconditions],
            "snapshot_revision": self.snapshot_revision,
            "execution_fingerprint": self.execution_fingerprint(),
            "requests": requests,
            "request": requests[0] if len(requests) == 1 else None,
            "label": _public_message(self.label),
            "target_serial": self.target_serial,
            "expected_codename": self.expected_codename,
            "expected_device_state": self.expected_device_state,
            "firmware_hash": self.firmware_hash,
            "boot_hash": self.boot_hash,
            "partitions": list(self.partitions),
            "slots": list(self.slots),
            "data_behavior": self.data_behavior,
            "plan_revision": self.plan_revision,
            "fingerprint": self.fingerprint,
            "confirmation_nonce": self.confirmation_nonce,
            "confirmation_token": None,
            "artifacts": [artifact.to_public_dict() for artifact in self.artifacts],
            "dry_run": self.dry_run,
        })


@dataclass(frozen=True, slots=True, init=False)
class OperationBatch:
    """An immutable, ordered, fail-fast group of flash plans."""

    plans: tuple[OperationPlan, ...]
    kind: str = CommandKind.FLASH_EXECUTE.value
    batch_id: str = ""
    created: float = 0.0
    expires: float = 0.0
    risk: OperationRisk = OperationRisk.DESTRUCTIVE
    fingerprint: str = ""
    confirmation_nonce: str | None = None
    confirmation_token: str | None = None

    def __init__(
        self,
        plans: tuple[OperationPlan, ...] | list[OperationPlan],
        kind: str = CommandKind.FLASH_EXECUTE.value,
        batch_id: str | None = None,
        created: float | None = None,
        expires: float | None = None,
        risk: OperationRisk | str = OperationRisk.DESTRUCTIVE,
        fingerprint: str = "",
        confirmation_nonce: str | None = None,
        confirmation_token: str | None = None,
        *,
        batchId: str | None = None,
    ) -> None:
        normalized_plans = tuple(plans)
        if kind != CommandKind.FLASH_EXECUTE.value:
            raise ValueError("OperationBatch supports only flash.execute")
        if not normalized_plans:
            raise ValueError("batch must contain at least one flash plan")
        if any(not isinstance(plan, OperationPlan) for plan in normalized_plans):
            raise TypeError("batch plans must contain only OperationPlan values")
        if batch_id is not None and batchId is not None and batch_id != batchId:
            raise ValueError("batch_id and batchId aliases disagree")
        serials = tuple(plan.target_serial for plan in normalized_plans)
        if any(not serial for serial in serials):
            raise ValueError("every batch plan must name one target serial")
        if len(serials) != len(set(serials)):
            raise ValueError("batch plans must target unique serials")
        if any(plan.dry_run or plan.risk is not OperationRisk.DESTRUCTIVE for plan in normalized_plans):
            raise ValueError("batch flash plans must be destructive, non-dry-run plans")
        data_behaviors = tuple(
            plan.data_behavior.strip().casefold().replace("-", "_")
            for plan in normalized_plans
        )
        if len(set(data_behaviors)) != 1:
            raise ValueError("batch flash plans must use one canonical data behavior")

        created_value = time.time() if created is None else float(created)
        maximum_expiry = min(plan.expires for plan in normalized_plans)
        expires_value = (
            min(created_value + OPERATION_PLAN_TTL_SECONDS, maximum_expiry)
            if expires is None
            else float(expires)
        )
        normalized_risk = _normalized_operation_risk(risk)
        if normalized_risk is not OperationRisk.DESTRUCTIVE:
            raise ValueError("flash batches must be destructive")
        normalized_batch_id = batch_id or batchId or uuid4().hex

        object.__setattr__(self, "plans", normalized_plans)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "batch_id", normalized_batch_id)
        object.__setattr__(self, "created", created_value)
        object.__setattr__(self, "expires", expires_value)
        object.__setattr__(self, "risk", normalized_risk)
        object.__setattr__(self, "confirmation_nonce", confirmation_nonce)
        object.__setattr__(self, "confirmation_token", confirmation_token)
        computed = self.compute_fingerprint()
        if fingerprint and fingerprint != computed:
            raise ValueError("batch fingerprint does not match its ordered plans")
        object.__setattr__(self, "fingerprint", fingerprint or computed)
        self.__post_init__()

    def __post_init__(self) -> None:
        if not isinstance(self.batch_id, str) or not self.batch_id.strip():
            raise ValueError("batch_id must be a non-empty string")
        if not math.isfinite(self.created) or not math.isfinite(self.expires):
            raise ValueError("batch timestamps must be finite")
        if self.created < 0 or self.expires <= self.created:
            raise ValueError("batch expires must be later than created")
        if self.expires - self.created > OPERATION_PLAN_TTL_SECONDS + 1e-6:
            raise ValueError("operation batch TTL cannot exceed five minutes")
        if self.expires > min(plan.expires for plan in self.plans) + 1e-6:
            raise ValueError("batch cannot outlive one of its plans")

    @property
    def batchId(self) -> str:  # noqa: N802 - public bridge contract spelling
        return self.batch_id

    @property
    def target_serials(self) -> tuple[str, ...]:
        return tuple(plan.target_serial or "" for plan in self.plans)

    def compute_fingerprint(self) -> str:
        material = {
            "kind": self.kind,
            "plans": [
                {
                    "serial": plan.target_serial,
                    "fingerprint": plan.execution_fingerprint(),
                }
                for plan in self.plans
            ],
        }
        encoded = json.dumps(material, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def confirmation_challenge(self) -> str:
        material = {
            "fingerprint": self.fingerprint,
            "confirmation_nonce": self.confirmation_nonce,
            "serials": self.target_serials,
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

    def required_confirmation_text(self) -> str:
        verb = (
            "WIPE"
            if self.plans[0].data_behavior.strip().casefold().replace("-", "_") == "wipe"
            else "FLASH"
        )
        return f"{verb} {len(self.plans)} {self.fingerprint[:8]}"

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "batchId": self.batch_id,
            "kind": self.kind,
            "created": self.created,
            "expires": self.expires,
            "risk": self.risk.value,
            "fingerprint": self.fingerprint,
            "plans": [plan.to_dict() for plan in self.plans],
            "confirmation_nonce": self.confirmation_nonce,
            "confirmation_token": None,
            "required_confirmation_text": self.required_confirmation_text(),
        }

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "batchId": self.batch_id,
            "kind": self.kind,
            "created": self.created,
            "expires": self.expires,
            "risk": self.risk.value,
            "fingerprint": self.fingerprint,
            "plans": [plan.to_public_dict() for plan in self.plans],
            "confirmation_nonce": self.confirmation_nonce,
            "confirmation_token": None,
            "required_confirmation_text": self.required_confirmation_text(),
        }


@dataclass(frozen=True, slots=True, init=False)
class OperationPreviewBatch:
    """An immutable, non-executable group of per-device dry-run plans."""

    plans: tuple[OperationPlan, ...]
    preview_id: str = ""
    created: float = 0.0
    expires: float = 0.0
    fingerprint: str = ""

    def __init__(
        self,
        plans: tuple[OperationPlan, ...] | list[OperationPlan],
        *,
        preview_id: str | None = None,
        created: float | None = None,
        expires: float | None = None,
        fingerprint: str = "",
    ) -> None:
        normalized = tuple(plans)
        if len(normalized) < 2:
            raise ValueError("preview batch requires at least two plans")
        if any(not isinstance(plan, OperationPlan) or not plan.dry_run for plan in normalized):
            raise ValueError("preview batch accepts only dry-run operation plans")
        serials = tuple(plan.target_serial for plan in normalized)
        if any(not serial for serial in serials) or len(serials) != len(set(serials)):
            raise ValueError("preview batch plans must target unique serials")
        created_value = time.time() if created is None else float(created)
        maximum_expiry = min(plan.expires for plan in normalized)
        expires_value = (
            min(created_value + OPERATION_PLAN_TTL_SECONDS, maximum_expiry)
            if expires is None
            else float(expires)
        )
        object.__setattr__(self, "plans", normalized)
        object.__setattr__(self, "preview_id", preview_id or uuid4().hex)
        object.__setattr__(self, "created", created_value)
        object.__setattr__(self, "expires", expires_value)
        computed = self.compute_fingerprint()
        if fingerprint and fingerprint != computed:
            raise ValueError("preview fingerprint does not match its ordered plans")
        object.__setattr__(self, "fingerprint", fingerprint or computed)
        self.__post_init__()

    def __post_init__(self) -> None:
        if not self.preview_id.strip():
            raise ValueError("preview_id must be a non-empty string")
        if not math.isfinite(self.created) or not math.isfinite(self.expires):
            raise ValueError("preview timestamps must be finite")
        if self.created < 0 or self.expires <= self.created:
            raise ValueError("preview expires must be later than created")
        if self.expires - self.created > OPERATION_PLAN_TTL_SECONDS + 1e-6:
            raise ValueError("preview batch TTL cannot exceed five minutes")
        if self.expires > min(plan.expires for plan in self.plans) + 1e-6:
            raise ValueError("preview batch cannot outlive one of its plans")

    @property
    def target_serials(self) -> tuple[str, ...]:
        return tuple(plan.target_serial or "" for plan in self.plans)

    def compute_fingerprint(self) -> str:
        material = {
            "kind": "flash.preview.batch",
            "plans": [
                {"serial": plan.target_serial, "fingerprint": plan.execution_fingerprint()}
                for plan in self.plans
            ],
        }
        encoded = json.dumps(material, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "previewId": self.preview_id,
            "created": self.created,
            "expires": self.expires,
            "fingerprint": self.fingerprint,
            "targetSerials": list(self.target_serials),
            "plans": [plan.to_dict() for plan in self.plans],
            "dry_run": True,
        }

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "previewId": self.preview_id,
            "created": self.created,
            "expires": self.expires,
            "fingerprint": self.fingerprint,
            "targetSerials": list(self.target_serials),
            "plans": [plan.to_public_dict() for plan in self.plans],
            "dry_run": True,
        }


@dataclass(frozen=True, slots=True)
class AppCommand:
    kind: CommandKind | str
    expected_revision: int | None = None
    target_serial: str | None = None
    payload: Mapping[str, object] = field(default_factory=_empty_object_mapping)
    operation_plan: OperationPlan | None = None
    operation_id: str = field(default_factory=lambda: uuid4().hex)
    destructive: bool = False
    requires_confirmation: bool = False
    execution_timeout_seconds: float | None = None
    _accepted_monotonic: float = field(
        default_factory=time.monotonic,
        repr=False,
        compare=False,
    )
    _cancellation_token: CancellationToken = field(
        default_factory=CancellationToken,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        kind = self.kind.value if isinstance(self.kind, CommandKind) else str(self.kind)
        payload_values = self.payload
        payload: dict[str, object] = {
            key: value for key, value in payload_values.items()
        }
        # Wireless pairing credentials are accepted only as ephemeral input.
        # Redact them before the command can be represented or serialized by
        # diagnostics, progress observers, or tests.
        pairing_code = payload.get("pairingCode")
        if kind == "tools.wifi" and isinstance(pairing_code, str):
            payload["pairingCode"] = SensitiveText(pairing_code)
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
        if self.execution_timeout_seconds is not None and (
            isinstance(self.execution_timeout_seconds, bool)
            or not isinstance(self.execution_timeout_seconds, (int, float))
            or not math.isfinite(self.execution_timeout_seconds)
            or self.execution_timeout_seconds <= 0
        ):
            raise ValueError("execution_timeout_seconds must be positive and finite or null")
        if (
            isinstance(self._accepted_monotonic, bool)
            or not isinstance(self._accepted_monotonic, (int, float))
            or not math.isfinite(self._accepted_monotonic)
            or self._accepted_monotonic < 0
        ):
            raise ValueError("accepted monotonic time must be finite and non-negative")
        if not isinstance(self._cancellation_token, CancellationToken):
            raise TypeError("cancellation token must be a CancellationToken")
        if self.execution_timeout_seconds is not None:
            self._cancellation_token.set_deadline_at(
                self._accepted_monotonic + self.execution_timeout_seconds
            )

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
            "execution_timeout_seconds": self.execution_timeout_seconds,
        }

    @property
    def accepted_monotonic(self) -> float:
        return self._accepted_monotonic

    @property
    def cancellation_token(self) -> CancellationToken:
        """Internal one-shot control shared by the accepting host and engine."""

        return self._cancellation_token

    @property
    def cancellation_reason(self) -> CancellationReason | None:
        return self._cancellation_token.reason

    def request_cancellation(self) -> None:
        """Request cancellation without waiting for engine registration."""

        self._cancellation_token.cancel()


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
    ) -> OperationResult:
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
    ) -> OperationResult:
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
    ) -> OperationResult:
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

    def to_public_dict(self) -> dict[str, JSONValue]:
        """Return only terminal metadata safe for snapshots and generic events."""

        return {
            "event_type": self.event_type,
            "operation_id": self.operation_id,
            "status": self.status.value,
            "code": self.code,
            "message": _public_message(
                self.message,
                fallback="The operation could not be completed.",
            ),
            "exit_code": self.exit_code,
        }


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    event_type: ClassVar[str] = "progress"

    operation_id: str
    phase: ProgressPhase
    message: str = ""
    percent: int | None = None
    kind: str = ""
    current: int | None = None
    total: int | None = None
    item: str | None = None
    target_serial: str | None = None

    def __post_init__(self) -> None:
        if self.percent is not None and (
            not isinstance(self.percent, int) or isinstance(self.percent, bool)
        ):
            raise TypeError("percent must be an integer or null")
        if self.percent is not None and not 0 <= self.percent <= 100:
            raise ValueError("percent must be between 0 and 100")
        if not isinstance(self.kind, str):
            raise TypeError("progress kind must be a string")
        if (self.current is None) != (self.total is None):
            raise ValueError("progress current and total must be provided together")
        if self.current is not None and (
            isinstance(self.current, bool)
            or not isinstance(self.current, int)
            or isinstance(self.total, bool)
            or not isinstance(self.total, int)
            or not 1 <= self.current <= self.total <= 10_000
        ):
            raise ValueError("progress current and total are invalid")
        if self.item is not None and (
            not isinstance(self.item, str)
            or not self.item
            or len(self.item) > 256
            or not self.item.isprintable()
            or self.current is None
        ):
            raise ValueError("progress item is invalid")
        if self.target_serial is not None and not isinstance(self.target_serial, str):
            raise TypeError("progress target serial must be a string or null")

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "event_type": self.event_type,
            "operation_id": self.operation_id,
            "phase": self.phase.value,
            "message": self.message,
            "percent": self.percent,
            "kind": self.kind,
            "current": self.current,
            "total": self.total,
            "item": self.item,
            "target_serial": self.target_serial,
        }

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "event_type": self.event_type,
            "operation_id": self.operation_id,
            "phase": self.phase.value,
            "message": _public_message(self.message, fallback="Operation update."),
            "percent": self.percent,
            "kind": (
                self.kind
                if not self.kind or _PUBLIC_PROGRESS_KIND.fullmatch(self.kind)
                else ""
            ),
            "current": self.current,
            "total": self.total,
            "item": (
                self.item
                if self.item is not None
                and _PUBLIC_PROGRESS_ITEM.fullmatch(self.item)
                else None
            ),
            "target_serial": (
                self.target_serial
                if self.target_serial is not None
                and is_valid_target_serial(self.target_serial)
                else None
            ),
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
    _timeout_seconds: float | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "choices", tuple(self.choices))
        if (
            not isinstance(self.expected_revision, int)
            or isinstance(self.expected_revision, bool)
            or self.expected_revision < 0
        ):
            raise ValueError("expected_revision must be a non-negative integer")
        if self._timeout_seconds is not None and (
            isinstance(self._timeout_seconds, bool)
            or not isinstance(self._timeout_seconds, (int, float))
            or not math.isfinite(self._timeout_seconds)
            or self._timeout_seconds < 0
        ):
            raise ValueError("interaction timeout must be finite and non-negative or null")

    @property
    def timeout_seconds(self) -> float | None:
        """Internal wait budget; never serialized into the public bridge event."""

        return self._timeout_seconds

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

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "event_type": self.event_type,
            "operation_id": self.operation_id,
            "kind": self.kind.value,
            "title": _public_message(self.title, fallback="Confirm operation"),
            "message": _public_message(self.message, fallback="Continue?"),
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
class ManagedDeviceInfo:
    """Persisted, non-operational identity used by the device manager.

    Operational facts such as slot, root and bootloader state deliberately do
    not live here: a remembered device can never become evidence for a device
    mutation after it disconnects.
    """

    serial: str
    label: str = ""
    enabled: bool = True
    model: str = ""
    codename: str = ""
    connected: bool = False
    mode: str = "offline"
    first_seen: int = 0
    last_seen: int = 0

    def __post_init__(self) -> None:
        if (
            not isinstance(self.serial, str)
            or not self.serial
            or self.serial != self.serial.strip()
            or len(self.serial) > 256
            or any(not character.isprintable() for character in self.serial)
        ):
            raise ValueError("managed device serial is invalid")
        for field_name, value, maximum in (
            ("label", self.label, 120),
            ("model", self.model, 256),
            ("codename", self.codename, 128),
        ):
            if (
                not isinstance(value, str)
                or len(value) > maximum
                or any(not character.isprintable() for character in value)
            ):
                raise ValueError(f"managed device {field_name} is invalid")
        if not isinstance(self.enabled, bool) or not isinstance(self.connected, bool):
            raise TypeError("managed device flags must be booleans")
        if self.mode not in {
            "adb",
            "fastboot",
            "fastbootd",
            "recovery",
            "sideload",
            "offline",
            "unauthorized",
        }:
            raise ValueError("managed device mode is invalid")
        for field_name, value in (
            ("first_seen", self.first_seen),
            ("last_seen", self.last_seen),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                or value > MAX_MANAGED_DEVICE_TIMESTAMP
            ):
                raise ValueError(f"managed device {field_name} is invalid")
        if self.first_seen and self.last_seen and self.last_seen < self.first_seen:
            raise ValueError("managed device last_seen cannot precede first_seen")

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "serial": self.serial,
            "label": self.label,
            "enabled": self.enabled,
            "model": self.model,
            "codename": self.codename,
            "connected": self.connected,
            "mode": self.mode,
            "firstSeen": self.first_seen,
            "lastSeen": self.last_seen,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementState:
    """Versioned scan policy and remembered device identities."""

    schema_version: int = 1
    scan_enabled: bool = True
    scan_scope: str = "enabled"
    devices: tuple[ManagedDeviceInfo, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported device-management schema")
        if not isinstance(self.scan_enabled, bool):
            raise TypeError("scan_enabled must be a boolean")
        if self.scan_scope not in {"enabled", "all"}:
            raise ValueError("scan_scope must be enabled or all")
        object.__setattr__(self, "devices", tuple(self.devices))
        if any(not isinstance(device, ManagedDeviceInfo) for device in self.devices):
            raise TypeError("managed devices must contain ManagedDeviceInfo values")
        if len(self.devices) > 256:
            raise ValueError("managed devices exceeds its limit")
        serials = tuple(device.serial for device in self.devices)
        if len(serials) != len(set(serials)):
            raise ValueError("managed devices must contain unique serials")
        ordered = tuple(
            sorted(self.devices, key=lambda device: (device.serial.casefold(), device.serial))
        )
        object.__setattr__(self, "devices", ordered)

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "schemaVersion": self.schema_version,
            "scanEnabled": self.scan_enabled,
            "scanScope": self.scan_scope,
            "devices": [device.to_dict() for device in self.devices],
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

    def to_public_dict(self) -> dict[str, JSONValue]:
        kind = self.type.strip().casefold()
        if kind in {"custom_rom", "customrom"}:
            kind = "custom"
        if kind not in {"factory", "ota", "custom"}:
            kind = "factory"
        identity = self.hash or self.build
        return {
            "id": identity,
            "name": self.build or "Selected firmware",
            "build": self.build,
            "kind": kind,
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

    def to_public_dict(self) -> dict[str, JSONValue]:
        flavor = self.flavor or "boot"
        return {
            "id": self.id,
            "image": f"{flavor}.img",
            "hash": self.hash,
            "flavor": flavor,
            "patched": self.patched,
            "verified": bool(self.id and self.hash),
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

    def to_public_dict(self) -> dict[str, JSONValue]:
        """Expose eligibility, not the backend-owned relock proof."""

        return {
            "serial": self.serial,
            "snapshot_revision": self.snapshot_revision,
        }


def _normalized_contract_tokens(values: object, field_name: str) -> tuple[str, ...]:
    if isinstance(values, str) or not isinstance(values, (tuple, list)):
        raise TypeError(f"{field_name} must be an array of strings")
    items = cast(tuple[object, ...] | list[object], values)
    normalized: list[str] = []
    for value in items:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} must contain non-empty strings")
        normalized.append(value.strip().casefold())
    return tuple(dict.fromkeys(normalized))


@dataclass(frozen=True, slots=True)
class FlashPlan:
    mode: str = "images"
    options: Mapping[str, object] = field(default_factory=_empty_object_mapping)
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
        option_values = self.options
        normalized: dict[str, object] = {
            key: value for key, value in option_values.items()
        }
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
            if not isinstance(slot, str) or slot.strip().casefold() not in {
                "a",
                "b",
                "both",
                "inactive",
            }:
                raise ValueError("slot must be a, b, both, or inactive")
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
            partition_items = cast(tuple[object, ...] | list[object], partitions)
            if any(
                not isinstance(item, str) or not item.strip()
                for item in partition_items
            ):
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

    def to_public_dict(self) -> dict[str, JSONValue]:
        public_options = {
            key: value
            for key, value in self.options.items()
            if key != "images"
        }
        return {
            "mode": self.mode,
            "options": _json_value(public_options),
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

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "adb": bool(self.adb),
            "fastboot": bool(self.fastboot),
            "version": self.version,
            "ready": self.ready,
        }


@dataclass(frozen=True, slots=True)
class ActiveOperation:
    operation_id: str
    kind: str
    label: str = ""
    target_serial: str | None = None

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "operation_id": self.operation_id,
            "kind": self.kind,
            "label": self.label,
            "target_serial": self.target_serial,
        }

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "operation_id": self.operation_id,
            "kind": self.kind,
            "label": _public_message(self.label, fallback="Operation in progress"),
            "target_serial": (
                self.target_serial
                if self.target_serial is not None
                and is_valid_target_serial(self.target_serial)
                else None
            ),
        }


@dataclass(frozen=True, slots=True)
class AppSnapshot:
    event_type: ClassVar[str] = "snapshot"

    revision: int = 0
    preferences: ModernPreferences = field(default_factory=ModernPreferences)
    device_management: DeviceManagementState = field(default_factory=DeviceManagementState)
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
        if not isinstance(self.preferences, ModernPreferences):
            raise TypeError("preferences must be a ModernPreferences value")
        if not isinstance(self.device_management, DeviceManagementState):
            raise TypeError("device_management must be a DeviceManagementState value")
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
    def flash_options(self) -> Mapping[str, object]:
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
            "preferences": self.preferences.to_dict(),
            "device_management": self.device_management.to_dict(),
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

    def to_public_dict(self) -> dict[str, JSONValue]:
        has_firmware = bool(
            self.firmware.path
            or self.firmware.hash
            or self.firmware.build
            or self.firmware.type
        )
        has_boot = bool(self.boot.id or self.boot.hash or self.boot.path)
        return {
            "event_type": self.event_type,
            "revision": self.revision,
            "preferences": self.preferences.to_dict(),
            "device_management": self.device_management.to_dict(),
            "devices": [device.to_dict() for device in self.devices],
            "selected_serials": list(self.selected_serials),
            "selected_serial": self.selected_serial,
            "firmware": self.firmware.to_public_dict() if has_firmware else None,
            "boot": self.boot.to_public_dict() if has_boot else None,
            "plan": self.plan.to_public_dict(),
            "toolchain": self.toolchain.to_public_dict(),
            "active_operation": (
                self.active_operation.to_public_dict() if self.active_operation else None
            ),
            "last_result": (
                self.last_result.to_public_dict() if self.last_result else None
            ),
            "bootloader_lock_evidence": [
                evidence.to_public_dict() for evidence in self.bootloader_lock_evidence
            ],
        }


@dataclass(frozen=True, slots=True)
class SnapshotChanged:
    """A canonical-state publication from the application engine."""

    event_type: ClassVar[str] = "snapshot"

    snapshot: AppSnapshot

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, AppSnapshot):
            raise TypeError("snapshot must be an AppSnapshot")

    @property
    def revision(self) -> int:
        return self.snapshot.revision

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "event_type": self.event_type,
            "snapshot": self.snapshot.to_dict(),
        }

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "event_type": self.event_type,
            "snapshot": self.snapshot.to_public_dict(),
        }


@dataclass(frozen=True, slots=True)
class OperationFinished:
    """A terminal, explicit result publication from the application engine."""

    event_type: ClassVar[str] = "runtime"

    result: OperationResult

    def __post_init__(self) -> None:
        if not isinstance(self.result, OperationResult):
            raise TypeError("result must be an OperationResult")

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "event_type": self.event_type,
            "result": self.result.to_dict(),
        }

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "event_type": self.event_type,
            "result": self.result.to_public_dict(),
        }


type AppEvent = (
    SnapshotChanged | ProgressEvent | InteractionRequest | OperationFinished
)


@dataclass(frozen=True, slots=True)
class SafetyDecision:
    allowed: bool
    code: str = "ok"
    message: str = ""
    interaction: InteractionRequest | None = None
