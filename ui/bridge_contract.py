"""Versioned JSON contract shared by the wx WebView host and React UI.

The Edge WebView backend only supports one named script message handler, so
every frontend request is multiplexed through the ``pixelflasher`` channel.
This module deliberately has no wx dependency and can be exercised headlessly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Mapping


BRIDGE_VERSION = 1
BRIDGE_CHANNEL = "pixelflasher"
MAX_MESSAGE_BYTES = 256 * 1024

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_BOOT_PATCH_PAYLOAD_FIELDS = frozenset(
    {"serial", "flavor", "method", "appId", "destination"}
)
_FIRMWARE_PAYLOAD_FIELDS = {
    "firmware.select": frozenset({"path"}),
    "firmware.process": frozenset(),
}
_DEVICE_TOOL_PAYLOAD_FIELDS = {
    "tools.scrcpy": frozenset({"serial"}),
    "tools.wifi": frozenset({"serial", "action", "host", "port", "pairingCode"}),
}
_SUPPORT_PAYLOAD_FIELDS = frozenset(
    {
        "destinationId",
        "includeConfig",
        "includeLogs",
        "includeState",
        "includeSystemInfo",
    }
)
_DESTINATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")

# This is the outer trust boundary. Adding a UI control is intentionally not
# enough to make a backend action callable; its command must also be reviewed
# and added here.
ALLOWED_COMMANDS = frozenset(
    {
        "app.ready",
        "snapshot.get",
        "operation.cancel",
        "interaction.respond",
        "device.scan",
        "device.select",
        "device.reboot",
        "device.switchSlot",
        "device.bootloader.lock",
        "device.bootloader.unlock",
        "platformTools.setup",
        "firmware.pick",
        "firmware.pickCustomRom",
        "firmware.select",
        "firmware.process",
        "firmware.catalog.refresh",
        "boot.select",
        "boot.patch",
        "boot.flash",
        "boot.live",
        "flash.plan.update",
        "flash.plan.preview",
        "flash.execute",
        "root.apps.list",
        "root.apps.install",
        "root.modules.list",
        "root.modules.action",
        "apps.list",
        "apps.action",
        "backups.list",
        "backups.create",
        "backups.restore",
        "backups.delete",
        "partitions.list",
        "partitions.read",
        "partitions.write",
        "partitions.erase",
        "tools.adbShell",
        "tools.scrcpy",
        "tools.wifi",
        "tools.logcat",
        "tools.pushFiles",
        "tools.pif",
        "tools.piAnalysis",
        "tools.sos",
        "tools.dataAdb",
        "tools.shizuku",
        "tools.keybox",
        "tools.xml",
        "tools.avb",
        "tools.myTools",
        "settings.get",
        "settings.update",
        "support.create",
        "updates.check",
        "native.pickFile",
        "native.pickFiles",
        "native.pickDirectory",
        "native.saveFile",
    }
)

_REQUIRED_FIELDS = frozenset(
    {"version", "requestId", "command", "payload", "expectedRevision"}
)


class BridgeProtocolError(ValueError):
    """Raised when a message does not satisfy the public bridge contract."""

    def __init__(self, code: str, message: str, *, request_id: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.request_id = request_id


@dataclass(frozen=True, slots=True)
class BridgeRequest:
    version: int
    request_id: str
    command: str
    # Browser payloads can contain ephemeral secrets (currently Wi-Fi pairing
    # codes), so the envelope representation must never print them.
    payload: Mapping[str, Any] = field(repr=False)
    expected_revision: int | None

    @classmethod
    def from_json(cls, raw: str) -> "BridgeRequest":
        if not isinstance(raw, str):
            raise BridgeProtocolError("invalid_message", "Bridge messages must be strings.")
        if len(raw.encode("utf-8", errors="strict")) > MAX_MESSAGE_BYTES:
            raise BridgeProtocolError("message_too_large", "Bridge message exceeds the size limit.")

        try:
            value = json.loads(raw)
        except (TypeError, ValueError) as exc:
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

        version = value["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise BridgeProtocolError("invalid_version", "Bridge version must be an integer.", request_id=request_id)
        if version != BRIDGE_VERSION:
            raise BridgeProtocolError(
                "unsupported_version",
                f"Unsupported bridge version {version}; expected {BRIDGE_VERSION}.",
                request_id=request_id,
            )

        if not _REQUEST_ID_PATTERN.fullmatch(request_id):
            raise BridgeProtocolError(
                "invalid_request_id",
                "requestId contains unsupported characters or length.",
                request_id=request_id,
            )

        command = value["command"]
        if not isinstance(command, str) or command not in ALLOWED_COMMANDS:
            raise BridgeProtocolError(
                "command_not_allowed",
                "The requested command is not allow-listed.",
                request_id=request_id,
            )

        payload = value["payload"]
        if not isinstance(payload, dict):
            raise BridgeProtocolError(
                "invalid_payload",
                "Bridge payload must be a JSON object.",
                request_id=request_id,
            )
        if command == "boot.patch":
            unknown = frozenset(payload) - _BOOT_PATCH_PAYLOAD_FIELDS
            if unknown:
                raise BridgeProtocolError(
                    "invalid_payload",
                    (
                        "boot.patch payload contains an unsupported field: "
                        f"{sorted(unknown)[0]}"
                    ),
                    request_id=request_id,
                )
        allowed_firmware_fields = _FIRMWARE_PAYLOAD_FIELDS.get(command)
        if allowed_firmware_fields is not None:
            unknown = frozenset(payload) - allowed_firmware_fields
            if unknown:
                raise BridgeProtocolError(
                    "invalid_payload",
                    (
                        f"{command} payload contains an unsupported field: "
                        f"{sorted(unknown)[0]}"
                    ),
                    request_id=request_id,
                )
        allowed_device_tool_fields = _DEVICE_TOOL_PAYLOAD_FIELDS.get(command)
        if allowed_device_tool_fields is not None:
            unknown = frozenset(payload) - allowed_device_tool_fields
            if unknown:
                raise BridgeProtocolError(
                    "invalid_payload",
                    (
                        f"{command} payload contains an unsupported field: "
                        f"{sorted(unknown)[0]}"
                    ),
                    request_id=request_id,
                )
        if command == "support.create":
            unknown = frozenset(payload) - _SUPPORT_PAYLOAD_FIELDS
            if unknown:
                raise BridgeProtocolError(
                    "invalid_payload",
                    (
                        "support.create payload contains an unsupported field: "
                        f"{sorted(unknown)[0]}"
                    ),
                    request_id=request_id,
                )
            destination_id = payload.get("destinationId")
            if not isinstance(destination_id, str) or not _DESTINATION_ID_PATTERN.fullmatch(
                destination_id
            ):
                raise BridgeProtocolError(
                    "invalid_payload",
                    "support.create requires a native destinationId.",
                    request_id=request_id,
                )
            for field in (
                "includeConfig",
                "includeLogs",
                "includeState",
                "includeSystemInfo",
            ):
                if field in payload and not isinstance(payload[field], bool):
                    raise BridgeProtocolError(
                        "invalid_payload",
                        f"support.create {field} must be a boolean.",
                        request_id=request_id,
                    )

        expected_revision = value["expectedRevision"]
        if expected_revision is not None and (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 0
        ):
            raise BridgeProtocolError(
                "invalid_revision",
                "expectedRevision must be a non-negative integer or null.",
                request_id=request_id,
            )

        return cls(
            version=version,
            request_id=request_id,
            command=command,
            payload=payload,
            expected_revision=expected_revision,
        )


def response_envelope(
    request_id: str,
    *,
    ok: bool,
    result: Mapping[str, Any] | None = None,
    error: Mapping[str, Any] | None = None,
    revision: int | None = None,
) -> dict[str, Any]:
    """Build a stable response object without leaking Python exceptions."""

    envelope: dict[str, Any] = {
        "version": BRIDGE_VERSION,
        "type": "response",
        "requestId": request_id,
        "ok": bool(ok),
        "result": dict(result or {}),
        "error": dict(error or {}),
    }
    if revision is not None:
        envelope["revision"] = revision
    return envelope


def event_envelope(event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    if event_type not in {"snapshot", "progress", "interaction", "runtime"}:
        raise ValueError(f"Unsupported bridge event type: {event_type}")
    return {
        "version": BRIDGE_VERSION,
        "type": event_type,
        "payload": dict(payload),
    }


def protocol_error_envelope(error: BridgeProtocolError) -> dict[str, Any]:
    return response_envelope(
        error.request_id,
        ok=False,
        error={"code": error.code, "message": str(error)},
    )
