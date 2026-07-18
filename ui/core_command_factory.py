"""Translate validated bridge requests into typed core commands.

Risk metadata is defined here and in the core SafetyPolicy, never accepted from
the browser payload. The duplicated boundary is intentional defence in depth.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Mapping

from pixelflasher_core import AppCommand, AppSnapshot
from ui.bridge_contract import BridgeRequest


SnapshotProvider = Callable[[], AppSnapshot]

DESTRUCTIVE_COMMANDS = frozenset(
    {
        "flash.execute",
        "boot.flash",
        "partitions.write",
        "partitions.erase",
        "device.bootloader.lock",
        "device.bootloader.unlock",
        "device.switchSlot",
        # Action-specific metadata is recomputed from RootingCompilation by
        # the engine.  The bridge boundary stays conservative because it must
        # not trust a browser-provided action value.
        "root.modules.action",
    }
)

CONFIRMATION_COMMANDS = DESTRUCTIVE_COMMANDS | frozenset(
    {
        "boot.live",
        "boot.patch",
        "device.switchSlot",
        "backups.restore",
        "apps.action",
        "root.apps.install",
        "root.modules.action",
    }
)

DEVICE_SCOPED_COMMANDS = CONFIRMATION_COMMANDS | frozenset(
    {
        "device.reboot",
        "boot.patch",
        "backups.list",
        "backups.create",
        "backups.delete",
        "partitions.list",
        "partitions.read",
        "root.modules.list",
        "apps.list",
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
    }
)

SETTINGS_COMMANDS = frozenset({"settings.get", "settings.update"})
LOCAL_COMMANDS = SETTINGS_COMMANDS | frozenset(
    {"root.apps.list", "firmware.select", "firmware.process", "support.create"}
)
_LOCAL_FIRMWARE_PAYLOAD_FIELDS = {
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


def create_command_factory(snapshot_provider: SnapshotProvider):
    def command_factory(request: BridgeRequest) -> AppCommand:
        snapshot = snapshot_provider()
        payload = dict(request.payload)
        allowed_firmware_fields = _LOCAL_FIRMWARE_PAYLOAD_FIELDS.get(request.command)
        if allowed_firmware_fields is not None:
            unknown = frozenset(payload) - allowed_firmware_fields
            if unknown:
                raise ValueError(
                    f"{request.command} payload contains an unsupported field: "
                    f"{sorted(unknown)[0]}"
                )
        allowed_device_tool_fields = _DEVICE_TOOL_PAYLOAD_FIELDS.get(request.command)
        if allowed_device_tool_fields is not None:
            unknown = frozenset(payload) - allowed_device_tool_fields
            if unknown:
                raise ValueError(
                    f"{request.command} payload contains an unsupported field: "
                    f"{sorted(unknown)[0]}"
                )
        if request.command == "support.create":
            unknown = frozenset(payload) - _SUPPORT_PAYLOAD_FIELDS
            if unknown:
                raise ValueError(
                    "support.create payload contains an unsupported field: "
                    f"{sorted(unknown)[0]}"
                )
        target_serial = (
            None
            if request.command in LOCAL_COMMANDS
            else _target_serial(payload, snapshot, request.command)
        )
        return AppCommand(
            kind=request.command,
            expected_revision=request.expected_revision,
            target_serial=target_serial,
            payload=payload,
            destructive=request.command in DESTRUCTIVE_COMMANDS,
            requires_confirmation=request.command in CONFIRMATION_COMMANDS,
        )

    return command_factory


def _target_serial(
    payload: Mapping[str, Any],
    snapshot: AppSnapshot,
    command: str,
) -> str | None:
    raw = payload.get("serial")
    if raw is not None and (not isinstance(raw, str) or not raw.strip()):
        raise ValueError("payload.serial must be a non-empty string")
    serial = raw.strip() if isinstance(raw, str) else snapshot.selected_serial
    if command in DEVICE_SCOPED_COMMANDS and not serial:
        raise ValueError("A target serial is required for this command")
    return serial
