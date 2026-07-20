"""Strict v2 JSON contract shared by the wx WebView host and React UI.

The Edge WebView backend supports one named script-message handler.  Every
request is therefore multiplexed through the single ``pixelflasher`` channel
and validated here before it can reach a command factory or a native picker.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ui.command_registry import (
    ALLOWED_COMMANDS,
    BRIDGE_VERSION,
    COMMAND_REGISTRY,
    NATIVE_PICKER_COMMANDS,
    REVISION_OPTIONAL_COMMANDS,
    PayloadSchemaError,
)
from ui.command_registry import (
    PAYLOAD_FIELDS as PAYLOAD_FIELDS,
)

BRIDGE_CHANNEL = "pixelflasher"
MAX_MESSAGE_BYTES = 256 * 1024
MAX_PAYLOAD_BYTES = 64 * 1024

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_GRANT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_PURPOSE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9.-]{2,127}$")
_SIMPLE_TEXT_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]{1,160}$")
_EXTENSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,15}$")
_LOGCAT_TAG_PATTERN = re.compile(r"^(?:\*|[A-Za-z0-9][A-Za-z0-9_.-]{0,63})$")

_REQUIRED_FIELDS = frozenset({"version", "requestId", "command", "payload", "expectedRevision"})


class BridgeProtocolError(ValueError):
    """Raised when a message does not satisfy the public bridge contract."""

    def __init__(self, code: str, message: str, *, request_id: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.request_id = request_id


class _DuplicateJSONKey(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(key)
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


@dataclass(frozen=True, slots=True)
class BridgeRequest:
    version: int
    request_id: str
    command: str
    # Browser payloads can contain ephemeral secrets (currently Wi-Fi pairing
    # codes), so the representation must never print them.
    payload: Mapping[str, Any] = field(repr=False)
    expected_revision: int | None

    @classmethod
    def from_json(cls, raw: str) -> BridgeRequest:
        if not isinstance(raw, str):
            raise BridgeProtocolError("invalid_message", "Bridge messages must be strings.")
        try:
            raw_size = len(raw.encode("utf-8", errors="strict"))
        except UnicodeError as exc:
            raise BridgeProtocolError("invalid_message", "Bridge message is not valid UTF-8.") from exc
        if raw_size > MAX_MESSAGE_BYTES:
            raise BridgeProtocolError("message_too_large", "Bridge message exceeds the size limit.")

        try:
            value = json.loads(
                raw,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_non_finite,
            )
        except _DuplicateJSONKey as exc:
            raise BridgeProtocolError("invalid_json", f"Bridge message contains a duplicate field: {exc}.") from exc
        except (RecursionError, TypeError, ValueError) as exc:
            raise BridgeProtocolError("invalid_json", "Bridge message is not valid JSON.") from exc

        if not isinstance(value, dict):
            raise BridgeProtocolError("invalid_envelope", "Bridge message must be a JSON object.")

        request_id_value = value.get("requestId", "")
        request_id = request_id_value if isinstance(request_id_value, str) else ""
        keys = frozenset(value)
        if keys != _REQUIRED_FIELDS:
            missing = sorted(_REQUIRED_FIELDS - keys)
            unexpected = sorted(keys - _REQUIRED_FIELDS)
            detail = []
            if missing:
                detail.append(f"missing: {', '.join(missing)}")
            if unexpected:
                detail.append(f"unexpected: {', '.join(unexpected)}")
            raise BridgeProtocolError(
                "invalid_envelope",
                "Bridge envelope fields are invalid" + (f" ({'; '.join(detail)})" if detail else "."),
                request_id=request_id,
            )

        request = cls(
            version=value["version"],
            request_id=request_id,
            command=value["command"],
            payload=value["payload"],
            expected_revision=value["expectedRevision"],
        )
        return request.validate()

    def validate(self) -> BridgeRequest:
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise BridgeProtocolError(
                "invalid_version", "Bridge version must be an integer.", request_id=self.request_id
            )
        if self.version != BRIDGE_VERSION:
            raise BridgeProtocolError(
                "unsupported_version",
                f"Unsupported bridge version {self.version}; expected {BRIDGE_VERSION}.",
                request_id=self.request_id,
            )
        if not isinstance(self.request_id, str) or not _REQUEST_ID_PATTERN.fullmatch(self.request_id):
            raise BridgeProtocolError(
                "invalid_request_id",
                "requestId contains unsupported characters or length.",
                request_id=self.request_id if isinstance(self.request_id, str) else "",
            )
        if not isinstance(self.command, str) or self.command not in ALLOWED_COMMANDS:
            raise BridgeProtocolError(
                "command_not_allowed",
                "The requested command is not allow-listed.",
                request_id=self.request_id,
            )
        if not isinstance(self.payload, Mapping):
            raise BridgeProtocolError(
                "invalid_payload",
                "Bridge payload must be a JSON object.",
                request_id=self.request_id,
            )
        try:
            payload_size = len(
                json.dumps(
                    dict(self.payload),
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
            )
        except (RecursionError, TypeError, ValueError) as exc:
            raise BridgeProtocolError(
                "invalid_payload",
                "Bridge payload must contain only JSON values.",
                request_id=self.request_id,
            ) from exc
        if payload_size > MAX_PAYLOAD_BYTES:
            raise BridgeProtocolError(
                "payload_too_large",
                "Bridge payload exceeds the size limit.",
                request_id=self.request_id,
            )

        try:
            COMMAND_REGISTRY[self.command].payload.validate(self.payload)
        except PayloadSchemaError as exc:
            raise BridgeProtocolError(
                "invalid_payload",
                f"{self.command} {exc}",
                request_id=self.request_id,
            ) from exc
        _validate_payload_values(self.command, self.payload, self.request_id)

        revision = self.expected_revision
        if revision is not None and (isinstance(revision, bool) or not isinstance(revision, int) or revision < 0):
            raise BridgeProtocolError(
                "invalid_revision",
                "expectedRevision must be a non-negative integer or null.",
                request_id=self.request_id,
            )
        if self.command not in REVISION_OPTIONAL_COMMANDS and revision is None:
            raise BridgeProtocolError(
                "revision_required",
                "expectedRevision is required for this command.",
                request_id=self.request_id,
            )
        return self

    def fingerprint(self) -> str:
        """Return the canonical request identity used for idempotent replay."""

        canonical = json.dumps(
            {
                "version": self.version,
                "command": self.command,
                "payload": dict(self.payload),
                "expectedRevision": self.expected_revision,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


def _validate_payload_values(
    command: str,
    payload: Mapping[str, Any],
    request_id: str,
) -> None:
    if "grant" in payload:
        _require_grant(payload["grant"], "grant", request_id)
    if "grants" in payload:
        grants = payload["grants"]
        if not isinstance(grants, list) or not 1 <= len(grants) <= 64:
            _payload_error("grants must contain between 1 and 64 grant tokens", request_id)
        for index, token in enumerate(grants):
            _require_grant(token, f"grants[{index}]", request_id)
    if "secretGrant" in payload:
        _require_grant(payload["secretGrant"], "secretGrant", request_id)

    if command in NATIVE_PICKER_COMMANDS:
        purpose = payload.get("purpose")
        if not isinstance(purpose, str) or not _PURPOSE_PATTERN.fullmatch(purpose):
            _payload_error("native picker purpose is required and invalid", request_id)
        for name in ("title", "defaultName"):
            if name in payload and (
                not isinstance(payload[name], str) or not _SIMPLE_TEXT_PATTERN.fullmatch(payload[name])
            ):
                _payload_error(f"native picker {name} is invalid", request_id)
        if "filters" in payload:
            _validate_filters(payload["filters"], request_id)
    elif command == "secret.issue":
        purpose = payload.get("purpose")
        if not isinstance(purpose, str) or not _PURPOSE_PATTERN.fullmatch(purpose):
            _payload_error("secret purpose is required and invalid", request_id)
        secret = payload.get("secret")
        if not isinstance(secret, str) or not secret or len(secret) > 256 or "\x00" in secret:
            _payload_error("secret value is invalid", request_id)

    if command == "tools.avb":
        if payload.get("action") != "prepareDowngrade":
            _payload_error("tools.avb action is invalid", request_id)
        has_grant = "grant" in payload
        has_security_patch = "currentSecurityPatch" in payload
        if has_grant == has_security_patch:
            _payload_error(
                "tools.avb requires exactly one current boot grant or security patch",
                request_id,
            )
        security_patch = payload.get("currentSecurityPatch")
        if has_security_patch and (
            not isinstance(security_patch, str)
            or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", security_patch)
        ):
            _payload_error("tools.avb security patch must use YYYY-MM-DD", request_id)
        if payload.get("patchFingerprint") is True and not has_grant:
            _payload_error(
                "tools.avb fingerprint patching requires a current boot grant",
                request_id,
            )

    if command == "tools.xml" and payload.get("action") != "decodeBinary":
        _payload_error("tools.xml action is invalid", request_id)

    if command == "interaction.respond":
        if not _nonempty_string(payload.get("operationId"), limit=128):
            _payload_error("interaction.respond operationId is required", request_id)
        if payload.get("decision") not in {"accepted", "cancelled"}:
            _payload_error("interaction.respond decision is invalid", request_id)
    elif command == "operation.cancel":
        if not _nonempty_string(payload.get("operationId"), limit=128):
            _payload_error("operation.cancel operationId is required", request_id)
    elif command == "device.select":
        serials = payload.get("serials")
        if (
            not isinstance(serials, list)
            or len(serials) > 32
            or not all(_nonempty_string(serial, limit=256) for serial in serials)
        ):
            _payload_error("device.select serials must be a bounded string array", request_id)
    elif command == "device.manager.policy":
        if not payload:
            _payload_error("device manager policy requires one field", request_id)
        if "scanScope" in payload and payload["scanScope"] not in {"enabled", "all"}:
            _payload_error("device manager scanScope is invalid", request_id)
    elif command == "device.manager.update":
        serial = payload.get("serial")
        if (
            not _nonempty_string(serial, limit=256)
            or not isinstance(serial, str)
            or serial != serial.strip()
        ):
            _payload_error("device manager serial is invalid", request_id)
        if set(payload) == {"serial"}:
            _payload_error("device manager update requires label or enabled", request_id)
        if "label" in payload:
            label = payload["label"]
            if (
                not isinstance(label, str)
                or len(label) > 120
                or any(not character.isprintable() for character in label)
            ):
                _payload_error("device manager label is invalid", request_id)
    elif command == "device.manager.remove":
        serial = payload.get("serial")
        if (
            not _nonempty_string(serial, limit=256)
            or not isinstance(serial, str)
            or serial != serial.strip()
        ):
            _payload_error("device manager serial is invalid", request_id)
    elif command == "device.inspect":
        if payload.get("action") not in {
            "properties",
            "screenXml",
            "bootloaderVersions",
            "pifPrint",
        }:
            _payload_error("device.inspect action is invalid", request_id)
    elif command == "support.create":
        if "grant" not in payload:
            _payload_error("support.create requires a native grant", request_id)
        for name in ("includeConfig", "includeLogs", "includeState", "includeSystemInfo"):
            if name in payload and not isinstance(payload[name], bool):
                _payload_error(f"support.create {name} must be a boolean", request_id)
    elif command == "firmware.select":
        has_grant = "grant" in payload
        has_id = _nonempty_string(payload.get("firmwareId"), limit=256)
        if has_grant == has_id:
            _payload_error("firmware.select requires one native grant or firmwareId", request_id)
        if payload.get("expectedKind") not in {None, "stock", "custom"}:
            _payload_error("firmware.select expectedKind is invalid", request_id)
    elif command == "boot.delete":
        boot_id = payload.get("bootId")
        if not isinstance(boot_id, str) or re.fullmatch(r"[0-9a-f]{32}", boot_id) is None:
            _payload_error("boot.delete bootId is invalid", request_id)
    elif command == "tools.pushFiles" and "grants" not in payload:
        _payload_error("tools.pushFiles requires native grants", request_id)
    elif command == "firmware.catalog.refresh":
        device = payload.get("device")
        channel = payload.get("channel", "stable")
        if (
            not isinstance(device, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", device.casefold()) is None
            or channel not in {"stable", "beta", "canary"}
        ):
            _payload_error("firmware catalog device or channel is invalid", request_id)
    elif command == "firmware.download":
        artifact_id = payload.get("artifactId")
        if not isinstance(artifact_id, str) or re.fullmatch(r"[0-9a-f]{32}", artifact_id) is None:
            _payload_error("firmware artifactId is invalid", request_id)
    elif command == "root.apps.catalog.refresh":
        if payload.get("channel", "stable") not in {"stable", "beta", "canary"}:
            _payload_error("root-app catalog channel is invalid", request_id)
    elif command == "root.apps.download":
        artifact_id = payload.get("artifactId")
        if not isinstance(artifact_id, str) or re.fullmatch(r"[0-9a-f]{32}", artifact_id) is None:
            _payload_error("root-app artifactId is invalid", request_id)
    elif command == "tools.logcat":
        _validate_logcat_payload(payload, request_id)
    elif command == "boot.patch":
        if "grant" not in payload:
            _payload_error("boot.patch requires a native destination grant", request_id)
        if "flavor" in payload and "method" in payload:
            _payload_error("boot.patch accepts flavor or method, not both", request_id)
        patch_method = payload.get("flavor", payload.get("method"))
        if not _nonempty_string(patch_method, limit=64):
            _payload_error("boot.patch flavor or method is required", request_id)
        if patch_method == "apatch" and "secretGrant" not in payload:
            _payload_error("boot.patch APatch requires a native secretGrant", request_id)
        if patch_method != "apatch" and "secretGrant" in payload:
            _payload_error("boot.patch secretGrant is valid only for APatch", request_id)
    elif command == "tools.wifi":
        action = payload.get("action")
        if action not in {"pair", "connect", "disconnect"}:
            _payload_error(
                "tools.wifi action must be exactly pair, connect, or disconnect",
                request_id,
            )
        if not _valid_wifi_host(payload.get("host")):
            _payload_error("tools.wifi host must be a numeric IP address", request_id)
        port = payload.get("port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            _payload_error("tools.wifi port must be between 1 and 65535", request_id)
        if action == "pair" and "secretGrant" not in payload:
            _payload_error("tools.wifi pair requires a native secretGrant", request_id)
        if action != "pair" and "secretGrant" in payload:
            _payload_error("tools.wifi secretGrant is valid only for pair", request_id)

    if "serial" in payload and not _nonempty_string(payload["serial"], limit=256):
        _payload_error("serial must be a non-empty string", request_id)
    if "confirmationText" in payload and not _nonempty_string(payload["confirmationText"], limit=512):
        _payload_error("confirmationText must be a non-empty string", request_id)


def _validate_logcat_payload(payload: Mapping[str, Any], request_id: str) -> None:
    if "mode" in payload and payload["mode"] not in {"snapshot", "stream"}:
        _payload_error("tools.logcat mode is invalid", request_id)
    if "buffers" in payload:
        buffers = payload["buffers"]
        allowed_buffers = {"main", "system", "radio", "events", "crash", "all"}
        if (
            not isinstance(buffers, list)
            or not 1 <= len(buffers) <= 6
            or any(not isinstance(item, str) or item not in allowed_buffers for item in buffers)
            or len(set(buffers)) != len(buffers)
            or "all" in buffers
            and len(buffers) != 1
        ):
            _payload_error("tools.logcat buffers are invalid or ambiguous", request_id)
    format_enabled = payload.get("formatEnabled", True)
    if not isinstance(format_enabled, bool):
        _payload_error("tools.logcat formatEnabled must be a boolean", request_id)
    if not format_enabled and ({"formatVerb", "formatModifiers"} & set(payload)):
        _payload_error("disabled Logcat formatting cannot include format options", request_id)
    if "formatVerb" in payload and payload["formatVerb"] not in {
        "brief",
        "long",
        "process",
        "raw",
        "tag",
        "thread",
        "threadtime",
        "time",
    }:
        _payload_error("tools.logcat formatVerb is invalid", request_id)
    if "formatModifiers" in payload:
        modifiers = payload["formatModifiers"]
        allowed_modifiers = {
            "color",
            "descriptive",
            "epoch",
            "monotonic",
            "printable",
            "uid",
            "usec",
        }
        if (
            not isinstance(modifiers, list)
            or len(modifiers) > len(allowed_modifiers)
            or any(not isinstance(item, str) or item not in allowed_modifiers for item in modifiers)
            or len(set(modifiers)) != len(modifiers)
            or {"epoch", "monotonic"} <= set(modifiers)
        ):
            _payload_error("tools.logcat formatModifiers are invalid or ambiguous", request_id)
    if "filters" in payload:
        filters = payload["filters"]
        if not isinstance(filters, list) or len(filters) > 32:
            _payload_error("tools.logcat filters are invalid", request_id)
        seen_tags: set[str] = set()
        for item in filters:
            if not isinstance(item, Mapping) or set(item) != {"tag", "priority"}:
                _payload_error("tools.logcat filter fields are invalid", request_id)
            tag = item.get("tag")
            priority = item.get("priority")
            if (
                not isinstance(tag, str)
                or _LOGCAT_TAG_PATTERN.fullmatch(tag) is None
                or not isinstance(priority, str)
                or priority not in {"V", "D", "I", "W", "E", "F", "S"}
                or tag.casefold() in seen_tags
            ):
                _payload_error("tools.logcat filter is invalid or duplicated", request_id)
            seen_tags.add(tag.casefold())
    regex_filter = payload.get("regex")
    if regex_filter is not None and (
        not isinstance(regex_filter, str)
        or not regex_filter
        or regex_filter != regex_filter.strip()
        or len(regex_filter.encode("utf-8")) > 256
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in regex_filter)
    ):
        _payload_error("tools.logcat regex is invalid", request_id)
    if "uids" in payload:
        uids = payload["uids"]
        if (
            not isinstance(uids, list)
            or len(uids) > 32
            or any(
                not isinstance(uid, int)
                or isinstance(uid, bool)
                or not 0 <= uid <= 4_294_967_295
                for uid in uids
            )
            or len(set(uids)) != len(uids)
        ):
            _payload_error("tools.logcat uids are invalid or duplicated", request_id)
    for field_name, minimum, maximum in (
        ("maxLines", 1, 10_000),
        ("timeoutSeconds", 1, 120),
    ):
        value = payload.get(field_name)
        if value is not None and (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not minimum <= value <= maximum
        ):
            _payload_error(
                f"tools.logcat {field_name} is outside its bound", request_id
            )
    if regex_filter is not None and payload.get("timeoutSeconds", 30) > 30:
        _payload_error("regex-filtered Logcat capture is limited to 30 seconds", request_id)
    if "redaction" in payload and payload["redaction"] not in {
        "strict",
        "standard",
        "none",
    }:
        _payload_error("tools.logcat redaction policy is invalid", request_id)


def _validate_filters(value: Any, request_id: str) -> None:
    if not isinstance(value, list) or len(value) > 16:
        _payload_error("native picker filters must be an array of at most 16 entries", request_id)
    for item in value:
        if not isinstance(item, dict) or frozenset(item) != {"label", "extensions"}:
            _payload_error("native picker filter fields are invalid", request_id)
        if not isinstance(item["label"], str) or not _SIMPLE_TEXT_PATTERN.fullmatch(item["label"]):
            _payload_error("native picker filter label is invalid", request_id)
        extensions = item["extensions"]
        if not isinstance(extensions, list) or not 1 <= len(extensions) <= 16:
            _payload_error("native picker filter extensions are invalid", request_id)
        if not all(
            isinstance(extension, str) and _EXTENSION_PATTERN.fullmatch(extension.lstrip("*."))
            for extension in extensions
        ):
            _payload_error("native picker filter extension is invalid", request_id)


def _require_grant(value: Any, field: str, request_id: str) -> None:
    if not isinstance(value, str) or not _GRANT_PATTERN.fullmatch(value):
        _payload_error(f"{field} must be an opaque native grant", request_id)


def _nonempty_string(value: Any, *, limit: int) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= limit and "\x00" not in value


def _valid_wifi_host(value: object) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if any(character in value for character in "[]%"):
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not address.is_unspecified and not address.is_multicast


def _payload_error(message: str, request_id: str) -> None:
    raise BridgeProtocolError("invalid_payload", message, request_id=request_id)


def response_envelope(
    request_id: str,
    *,
    ok: bool,
    result: Mapping[str, Any] | None = None,
    error: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the exact v2 response shape without leaking Python exceptions."""

    if ok:
        return {
            "version": BRIDGE_VERSION,
            "requestId": str(request_id),
            "ok": True,
            "result": dict(result or {}),
        }
    return {
        "version": BRIDGE_VERSION,
        "requestId": str(request_id),
        "ok": False,
        "error": dict(error or {"code": "request_failed", "message": "Request failed."}),
    }


def event_envelope(
    event_type: str,
    payload: Mapping[str, Any],
    *,
    revision: int,
) -> dict[str, Any]:
    if event_type not in {"snapshot", "progress", "interaction", "runtime"}:
        raise ValueError(f"Unsupported bridge event type: {event_type}")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise ValueError("event revision must be a non-negative integer")
    return {
        "version": BRIDGE_VERSION,
        "event": event_type,
        "revision": revision,
        "payload": dict(payload),
    }


def protocol_error_envelope(error: BridgeProtocolError) -> dict[str, Any]:
    return response_envelope(
        error.request_id,
        ok=False,
        error={"code": error.code, "message": str(error)},
    )
