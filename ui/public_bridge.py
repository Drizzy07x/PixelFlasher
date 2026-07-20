"""Closed, route-free serializers for the WebView trust boundary.

Core contracts intentionally retain host paths because the backend needs them.
Nothing in this module is an execution contract: every value produced here is a
display-only projection selected by the canonical command registry.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import ntpath
import posixpath
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import date, datetime, timedelta
from typing import cast

from pixelflasher_core import AppSnapshot, OperationResult, is_valid_target_serial
from pixelflasher_core.contracts import MAX_MANAGED_DEVICE_TIMESTAMP
from ui.command_registry import ALLOWED_COMMANDS

JSONScalar = None | bool | int | float | str
JSONValue = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
ResultProjector = Callable[[object], JSONValue | None]
_STRICT_STRUCTURED_RESULTS = frozenset(
    {
        "apps.action",
        "device.openUrl",
        "device.inspect",
        "boot.delete",
        "backups.create",
        "backups.delete",
        "backups.list",
        "backups.magisk.list",
        "backups.magisk.import",
        "backups.magisk.delete",
        "backups.restore",
        "firmware.catalog.refresh",
        "firmware.download",
        "firmware.process",
        "firmware.select",
        "root.apps.catalog.refresh",
        "root.apps.download",
        "root.modules.list",
        "root.dataAdb.backup",
        "root.dataAdb.restore",
        "root.dataAdb.clear",
        "tools.shizuku",
        "tools.sos",
        "tools.logcat",
        "tools.logcat.clear",
        "tools.pushFiles",
        "tools.avb",
        "tools.xml",
        "tools.keybox",
        "tools.scrcpy.setup",
        "tools.wifi.discover",
    }
)

_WINDOWS_PATH = re.compile(r"(?i)(?:^|[^a-z0-9])(?:[a-z]:[\\/])")
_UNC_PATH = re.compile(r"(?:^|[^a-zA-Z0-9])\\\\[^\\/\s]+[\\/][^\s'\"]+")
_POSIX_PATH = re.compile(r"(?:^|[\s\"'(\[=,;])(/(?!/)[^\s\"'\])},;]+)")
_ANDROID_PATH_PREFIXES = (
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
_UNSAFE_LOG_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_BOOTLOADER_CODENAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_BOOTLOADER_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")
_BOOTLOADER_FULL_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$")
_LOWERCASE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_ABL_PARTITION_BYTES = 64 * 1024 * 1024
_MDNS_LOCAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class PublicProjectionError(TypeError):
    """A backend value cannot safely enter the browser contract."""


def _is_host_path_string(value: str) -> bool:
    if (
        _WINDOWS_PATH.search(value)
        or _UNC_PATH.search(value)
        or "WindowsPath(" in value
        or "PosixPath(" in value
        or "PurePath(" in value
    ):
        return True
    for match in _POSIX_PATH.finditer(value):
        path = match.group(1)
        if not any(
            path == prefix[:-1] or path.startswith(prefix)
            for prefix in _ANDROID_PATH_PREFIXES
        ):
            return True
    return False


def safe_public_message(value: object, *, fallback: str) -> str:
    """Return one bounded message, replacing strings containing host paths."""

    if not isinstance(value, str):
        return fallback
    message = value.strip()
    if not message or len(message) > 4096:
        return fallback
    if _is_host_path_string(message):
        return fallback
    return message


def ensure_public_json(value: object, *, depth: int = 0) -> JSONValue:
    """Validate JSON recursively without dataclass, Path, enum, or string fallbacks."""

    if depth > 24:
        raise PublicProjectionError("public payload nesting is too deep")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        if _is_host_path_string(value):
            raise PublicProjectionError("public payload contains a host path")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise PublicProjectionError("public payload numbers must be finite")
        return value
    if isinstance(value, Mapping):
        values = cast(Mapping[object, object], value)
        result: dict[str, JSONValue] = {}
        for key, item in values.items():
            if not isinstance(key, str):
                raise PublicProjectionError("public payload keys must be strings")
            result[key] = ensure_public_json(item, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        items = cast(Sequence[object], value)
        return [ensure_public_json(item, depth=depth + 1) for item in items]
    raise PublicProjectionError(f"unsupported public payload type: {type(value).__name__}")


def _public_object(value: object) -> dict[str, JSONValue]:
    public = ensure_public_json(value)
    if not isinstance(public, dict):
        raise PublicProjectionError("public projection must be an object")
    return public


def public_snapshot(value: object) -> dict[str, JSONValue]:
    """Project either an AppSnapshot or its legacy internal mapping."""

    source = _record(value.to_dict() if isinstance(value, AppSnapshot) else value)
    firmware = _public_firmware(source.get("firmware"))
    boot = _public_boot(source.get("boot"))
    active = _public_active_operation(source.get("active_operation", source.get("activeOperation")))
    last_result = _public_result_summary(source.get("last_result", source.get("lastResult")))
    evidence_source = source.get(
        "bootloader_lock_evidence",
        source.get("bootloaderLockEvidence", []),
    )
    evidence = [
        item
        for raw in _array(evidence_source)
        if (item := _public_lock_evidence(raw)) is not None
    ]
    result: dict[str, object] = {
        "event_type": "snapshot",
        "revision": _integer(source.get("revision"), default=0),
        "preferences": _public_preferences(source.get("preferences")),
        "device_management": _public_device_management(
            source.get("device_management", source.get("deviceManagement"))
        ),
        "devices": [_public_device(item) for item in _array(source.get("devices", []))],
        "selected_serials": _strings(source.get("selected_serials", source.get("selectedSerials", []))),
        "selected_serial": _optional_string(source.get("selected_serial", source.get("selectedSerial"))),
        "firmware": firmware,
        "boot": boot,
        "plan": _public_flash_plan(source.get("plan")),
        "toolchain": _public_toolchain(source.get("toolchain")),
        "active_operation": active,
        "last_result": last_result,
        "bootloader_lock_evidence": evidence,
    }
    return _public_object(result)


def project_operation_result(command: str, result: OperationResult) -> dict[str, JSONValue]:
    """Project an OperationResult through the command's explicit allow-list."""

    if not isinstance(result, OperationResult):
        raise PublicProjectionError("operation result must use the public core contract")
    projector = PUBLIC_RESULT_PROJECTORS.get(command)
    if projector is None:
        raise PublicProjectionError(f"command has no public result projector: {command}")

    summary = public_operation_summary(result)
    projected_value: JSONValue | None = None
    if result.ok and command in _STRICT_STRUCTURED_RESULTS and result.value is None:
        raise PublicProjectionError(
            f"successful {command} result is missing its public value"
        )
    if result.value is not None:
        try:
            projected_value = projector(result.value)
            if projected_value is not None:
                projected_value = ensure_public_json(projected_value)
        except (KeyError, TypeError, ValueError, PublicProjectionError) as error:
            if result.ok and command in _STRICT_STRUCTURED_RESULTS:
                raise PublicProjectionError(
                    f"successful {command} result does not match its public contract"
                ) from error
            # Malformed or newly expanded backend values degrade to the stable
            # terminal summary instead of becoming an accidental public API.
            projected_value = None
    if projected_value is not None:
        summary["value"] = projected_value
    public = ensure_public_json(summary)
    if not isinstance(public, dict):  # pragma: no cover - contract guard
        raise PublicProjectionError("operation result projection must be an object")
    return public


def public_operation_summary(result: OperationResult) -> dict[str, JSONValue]:
    """Serialize terminal metadata while independently sanitizing diagnostics."""

    if not isinstance(result, OperationResult):
        raise PublicProjectionError("operation result must use the public core contract")
    summary = result.to_public_dict()
    summary["message"] = safe_public_message(
        result.message,
        fallback="The operation could not be completed.",
    )
    public = ensure_public_json(summary)
    if not isinstance(public, dict):  # pragma: no cover - contract guard
        raise PublicProjectionError("operation summary must be an object")
    return public


def _record(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PublicProjectionError("expected an object")
    values = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in values):
        raise PublicProjectionError("object keys must be strings")
    return cast(Mapping[str, object], values)


def _array(value: object) -> Sequence[object]:
    if not isinstance(value, (list, tuple)):
        raise PublicProjectionError("expected an array")
    return cast(Sequence[object], value)


def _string(value: object, *, default: str = "") -> str:
    return value if isinstance(value, str) else default


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _target_serial(value: object) -> str | None:
    return (
        value
        if isinstance(value, str) and is_valid_target_serial(value)
        else None
    )


def _boolean(value: object, *, default: bool = False) -> bool:
    return value if isinstance(value, bool) else default


def _integer(value: object, *, default: int = 0) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _managed_device_timestamp(value: object) -> int:
    timestamp = _integer(value)
    return timestamp if 0 <= timestamp <= MAX_MANAGED_DEVICE_TIMESTAMP else 0


def _number(value: object, *, default: float = 0.0) -> int | float:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        return value
    return default


def _strings(value: object, *, maximum: int = 2048) -> list[str]:
    return [item for item in _array(value)[:maximum] if isinstance(item, str)]


def _closed_record(
    value: object,
    *,
    fields: frozenset[str],
) -> Mapping[str, object]:
    source = _record(value)
    if frozenset(source) != fields:
        raise PublicProjectionError("public result fields do not match its contract")
    return source


def _closed_bounded_strings(
    value: object,
    *,
    maximum_items: int,
    maximum_item_utf8_bytes: int,
    maximum_utf8_bytes: int,
) -> list[str]:
    if not isinstance(value, list):
        raise PublicProjectionError("public result string array exceeds its item limit")
    items = cast("list[object]", value)
    if len(items) > maximum_items:
        raise PublicProjectionError("public result string array exceeds its item limit")
    result: list[str] = []
    total_utf8_bytes = 0
    for item in items:
        if (
            not isinstance(item, str)
            or "\x00" in item
            or "\r" in item
            or "\n" in item
        ):
            raise PublicProjectionError("public result contains an invalid bounded string")
        item_utf8_bytes = len(item.encode("utf-8"))
        if item_utf8_bytes > maximum_item_utf8_bytes:
            raise PublicProjectionError("public result string exceeds its byte limit")
        total_utf8_bytes += item_utf8_bytes
        if total_utf8_bytes > maximum_utf8_bytes:
            raise PublicProjectionError("public result strings exceed their byte limit")
        result.append(item)
    return result


def _public_preferences(value: object) -> dict[str, JSONValue]:
    source = _record(value)
    return {
        "schemaVersion": _integer(source.get("schemaVersion"), default=1),
        "theme": _string(source.get("theme"), default="dark"),
        "locale": _string(source.get("locale"), default="en"),
        "highContrast": _boolean(source.get("highContrast")),
        "reducedMotion": _boolean(source.get("reducedMotion")),
        "zoom": _integer(source.get("zoom"), default=100),
    }


def _public_device(value: object) -> dict[str, JSONValue]:
    source = _record(value)
    serial = _string(source.get("serial"))
    model = _string(source.get("model"))
    codename = _string(source.get("codename"))
    name = _string(source.get("name"), default=model or codename or serial)
    return {
        "serial": serial,
        "name": name,
        "model": model,
        "codename": codename,
        "mode": _string(source.get("mode"), default="offline"),
        "androidVersion": _string(source.get("androidVersion", source.get("android_version"))),
        "build": _string(source.get("build")),
        "securityPatch": _string(source.get("securityPatch", source.get("security_patch"))),
        "bootloader": _string(source.get("bootloader"), default="unknown"),
        "slot": _string(source.get("slot"), default="unknown"),
        "battery": _integer(source.get("battery")),
        "connection": _string(source.get("connection")),
        "rooted": _boolean(source.get("rooted", source.get("root"))),
        "online": _boolean(source.get("online"), default=True),
    }


def _public_device_management(value: object) -> dict[str, JSONValue]:
    if value is None:
        return {
            "schemaVersion": 1,
            "scanEnabled": True,
            "scanScope": "enabled",
            "devices": [],
        }
    source = _record(value)
    raw_scope = _string(source.get("scanScope"), default="enabled")
    scope = raw_scope if raw_scope in {"enabled", "all"} else "enabled"
    devices: list[JSONValue] = []
    for raw_device in _array(source.get("devices", []))[:256]:
        device = _record(raw_device)
        devices.append(
            {
                "serial": _string(device.get("serial"))[:256],
                "label": _string(device.get("label"))[:120],
                "enabled": _boolean(device.get("enabled"), default=True),
                "model": _string(device.get("model"))[:256],
                "codename": _string(device.get("codename"))[:128],
                "connected": _boolean(device.get("connected")),
                "mode": _string(device.get("mode"), default="offline"),
                "firstSeen": _managed_device_timestamp(device.get("firstSeen")),
                "lastSeen": _managed_device_timestamp(device.get("lastSeen")),
            }
        )
    return {
        "schemaVersion": 1,
        "scanEnabled": _boolean(source.get("scanEnabled"), default=True),
        "scanScope": scope,
        "devices": devices,
    }


def _public_firmware(value: object) -> dict[str, JSONValue] | None:
    if value is None:
        return None
    source = _record(value)
    build = _string(source.get("build"))
    digest = _string(source.get("hash", source.get("sha256")))
    identity = _string(source.get("id"), default=digest or build)
    raw_kind = _string(source.get("kind", source.get("type"))).casefold()
    kind = "custom" if raw_kind in {"custom", "custom_rom", "customrom"} else raw_kind
    if kind not in {"factory", "ota", "custom"}:
        kind = "factory"
    if not any((identity, build, digest, _string(source.get("name")))):
        return None
    return {
        "id": identity,
        "name": _string(source.get("name"), default=build or "Selected firmware"),
        "build": build,
        "kind": kind,
        "hash": digest,
        "verified": _boolean(source.get("verified", source.get("ok"))),
        "processed": _boolean(source.get("processed")),
    }


def _public_boot(value: object) -> dict[str, JSONValue] | None:
    if value is None:
        return None
    source = _record(value)
    identity = _string(source.get("id"))
    digest = _string(source.get("hash", source.get("sha256")))
    flavor = _string(source.get("flavor", source.get("partition")), default="boot")
    if not identity and not digest:
        return None
    return {
        "id": identity,
        "image": _string(source.get("image"), default=f"{flavor}.img"),
        "hash": digest,
        "flavor": flavor,
        "patched": _boolean(source.get("patched")),
        "verified": _boolean(source.get("verified"), default=bool(identity and digest)),
    }


def _public_flash_plan(value: object) -> dict[str, JSONValue]:
    if value is None:
        return {"mode": "images", "options": {}, "revision": 0, "fingerprint": "", "dry_run": True}
    source = _record(value)
    raw_options = source.get("options", {})
    options_source = _record(raw_options)
    allowed = {
        "verify",
        "disableVerity",
        "disableVerification",
        "force",
        "noReboot",
        "downgrade",
        "temporaryRoot",
        "wipe",
        "disable_verity",
        "disable_verification",
        "no_reboot",
        "temporary_root",
        "slot",
        "partitions",
        "dataBehavior",
        "data_behavior",
    }
    options = {
        key: ensure_public_json(item)
        for key, item in options_source.items()
        if key in allowed
    }
    return {
        "mode": _string(source.get("mode"), default="images"),
        "options": options,
        "revision": _integer(source.get("revision")),
        "fingerprint": _string(source.get("fingerprint")),
        "dry_run": _boolean(source.get("dry_run", source.get("dryRun")), default=True),
    }


def _public_toolchain(value: object) -> dict[str, JSONValue]:
    if value is None:
        return {"adb": False, "fastboot": False, "version": "", "ready": False}
    source = _record(value)
    adb = source.get("adb")
    fastboot = source.get("fastboot")
    return {
        "adb": adb if isinstance(adb, bool) else bool(_string(adb)),
        "fastboot": fastboot if isinstance(fastboot, bool) else bool(_string(fastboot)),
        "version": _string(source.get("version")),
        "ready": _boolean(source.get("ready")),
    }


def _public_active_operation(value: object) -> dict[str, JSONValue] | None:
    if value is None:
        return None
    source = _record(value)
    operation_id = _string(source.get("operation_id", source.get("id")))
    if not operation_id:
        return None
    return {
        "operation_id": operation_id,
        "kind": _string(source.get("kind")),
        "label": safe_public_message(source.get("label"), fallback="Operation in progress"),
        "target_serial": _target_serial(
            source.get("target_serial", source.get("targetSerial"))
        ),
    }


def _public_result_summary(value: object) -> dict[str, JSONValue] | None:
    if value is None:
        return None
    if isinstance(value, OperationResult):
        return _public_object(value.to_public_dict())
    source = _record(value)
    raw_exit_code = source.get("exit_code")
    exit_code = (
        raw_exit_code
        if isinstance(raw_exit_code, int) and not isinstance(raw_exit_code, bool)
        else None
    )
    return _public_object({
        "event_type": "runtime",
        "operation_id": _string(source.get("operation_id", source.get("operationId"))),
        "status": _string(source.get("status"), default="failed"),
        "code": _string(source.get("code"), default="operation_failed"),
        "message": safe_public_message(
            source.get("message"),
            fallback="The operation could not be completed.",
        ),
        "exit_code": exit_code,
    })


def _public_lock_evidence(value: object) -> dict[str, JSONValue] | None:
    source = _record(value)
    serial = _string(source.get("serial"))
    revision = source.get("snapshot_revision")
    if not serial or not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        return None
    return {"serial": serial, "snapshot_revision": revision}


def _public_artifact(value: object) -> dict[str, JSONValue] | None:
    if value is None:
        return None
    source = _record(value)
    digest = _string(source.get("sha256"))
    role = _string(source.get("role"), default="artifact")
    if not digest:
        return None
    return {
        "sha256": digest,
        "role": role,
        "displayName": _string(source.get("displayName"), default=f"@artifact/{role}/{digest[:12]}"),
    }


def _public_process_request(
    value: object,
    artifact_references: Mapping[str, str],
) -> dict[str, JSONValue]:
    source = _record(value)
    raw_argv = _strings(source.get("argv", []))
    argv: list[str] = []
    for index, argument in enumerate(raw_argv):
        if argument in artifact_references:
            argv.append(artifact_references[argument])
        elif index == 0:
            argv.append(ntpath.basename(posixpath.basename(argument.replace("\\", "/"))) or "tool")
        elif _is_host_path_string(argument):
            argv.append("@host-resource")
        else:
            argv.append(argument)
    timeout = source.get("timeout_seconds")
    return _public_object({
        "argv": argv,
        "timeout_seconds": timeout if isinstance(timeout, (int, float)) and not isinstance(timeout, bool) else None,
        "encoding": _string(source.get("encoding"), default="utf-8"),
        "stdin_secret_field": _optional_string(source.get("stdin_secret_field")),
    })


def _public_operation_plan(value: object) -> dict[str, JSONValue]:
    source = _record(value)
    raw_artifacts = _array(source.get("artifacts", []))
    artifacts: list[dict[str, JSONValue]] = []
    references: dict[str, str] = {}
    for raw in raw_artifacts:
        artifact_source = _record(raw)
        public = _public_artifact(artifact_source)
        if public is None:
            continue
        artifacts.append(public)
        path = _string(artifact_source.get("path"))
        display = _string(public.get("displayName"))
        if path and display:
            references[path] = display
    requests = [
        _public_process_request(item, references)
        for item in _array(source.get("requests", []))
    ]
    postconditions: list[dict[str, object]] = []
    for raw in _array(source.get("postconditions", [])):
        condition = _record(raw)
        postconditions.append(
            {
                "kind": _string(condition.get("kind")),
                "description": safe_public_message(condition.get("description"), fallback=""),
            }
        )
    return _public_object({
        "planId": _string(source.get("planId", source.get("plan_id"))),
        "created": _number(source.get("created")),
        "expires": _number(source.get("expires")),
        "risk": _string(source.get("risk")),
        "postconditions": postconditions,
        "snapshot_revision": _integer(source.get("snapshot_revision")),
        "execution_fingerprint": _string(source.get("execution_fingerprint")),
        "requests": requests,
        "request": requests[0] if len(requests) == 1 else None,
        "label": safe_public_message(source.get("label"), fallback=""),
        "target_serial": _optional_string(source.get("target_serial")),
        "expected_codename": _optional_string(source.get("expected_codename")),
        "expected_device_state": _optional_string(source.get("expected_device_state")),
        "firmware_hash": _string(source.get("firmware_hash")),
        "boot_hash": _string(source.get("boot_hash")),
        "partitions": _strings(source.get("partitions", [])),
        "slots": _strings(source.get("slots", [])),
        "data_behavior": _string(source.get("data_behavior")),
        "plan_revision": _integer(source.get("plan_revision")),
        "fingerprint": _string(source.get("fingerprint")),
        "confirmation_nonce": _optional_string(source.get("confirmation_nonce")),
        "confirmation_token": None,
        "artifacts": artifacts,
        "dry_run": _boolean(source.get("dry_run")),
    })


def _project_none(value: object) -> None:
    del value
    return None


def _project_snapshot(value: object) -> JSONValue:
    return public_snapshot(value)


def _project_platform_tools_setup(value: object) -> JSONValue:
    """Project the closed setup receipt without exposing installation routes."""

    source = _record(value)
    expected_fields = {"source", "ready", "version", "installation", "revision"}
    if set(source) != expected_fields:
        raise PublicProjectionError("Platform Tools result fields are invalid")

    selected_source = source["source"]
    ready = source["ready"]
    version = source["version"]
    revision = source["revision"]
    if selected_source not in {"official", "directory"}:
        raise PublicProjectionError("Platform Tools source is invalid")
    if not isinstance(ready, bool):
        raise PublicProjectionError("Platform Tools readiness is invalid")
    if not isinstance(version, str) or len(version) > 256:
        raise PublicProjectionError("Platform Tools version is invalid")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise PublicProjectionError("Platform Tools revision is invalid")

    raw_installation = source["installation"]
    installation: dict[str, object] | None = None
    if raw_installation is not None:
        installed = _record(raw_installation)
        expected_installation_fields = {
            "installed",
            "adbAvailable",
            "fastbootAvailable",
            "archiveSha256",
            "archiveSize",
            "version",
        }
        if set(installed) != expected_installation_fields:
            raise PublicProjectionError("Platform Tools installation fields are invalid")
        booleans = (
            installed["installed"],
            installed["adbAvailable"],
            installed["fastbootAvailable"],
        )
        digest = installed["archiveSha256"]
        archive_size = installed["archiveSize"]
        installed_version = installed["version"]
        if not all(isinstance(item, bool) for item in booleans):
            raise PublicProjectionError("Platform Tools installation availability is invalid")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None:
            raise PublicProjectionError("Platform Tools archive digest is invalid")
        if (
            isinstance(archive_size, bool)
            or not isinstance(archive_size, int)
            or archive_size < 0
        ):
            raise PublicProjectionError("Platform Tools archive size is invalid")
        if not isinstance(installed_version, str) or len(installed_version) > 256:
            raise PublicProjectionError("Platform Tools installation version is invalid")
        installation = {
            "installed": installed["installed"],
            "adbAvailable": installed["adbAvailable"],
            "fastbootAvailable": installed["fastbootAvailable"],
            "archiveSha256": digest.casefold(),
            "archiveSize": archive_size,
            "version": installed_version,
        }

    return ensure_public_json(
        {
            "source": selected_source,
            "ready": ready,
            "version": version,
            "installation": installation,
            "revision": revision,
        }
    )


def _project_scrcpy_setup(value: object) -> JSONValue:
    """Expose provenance and integrity, never the installed host path."""

    source = _record(value)
    if set(source) != {"ready", "installation", "revision"}:
        raise PublicProjectionError("Scrcpy setup result fields are invalid")
    ready = source["ready"]
    revision = source["revision"]
    if not isinstance(ready, bool):
        raise PublicProjectionError("Scrcpy readiness is invalid")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise PublicProjectionError("Scrcpy revision is invalid")
    raw_installation = source["installation"]
    installation: dict[str, object] | None = None
    if raw_installation is not None:
        installed = _record(raw_installation)
        expected_fields = {
            "installed",
            "version",
            "platform",
            "architecture",
            "license",
            "provenance",
            "archiveSha256",
            "archiveSize",
        }
        if set(installed) != expected_fields or installed["installed"] is not True:
            raise PublicProjectionError("Scrcpy installation fields are invalid")
        digest = installed["archiveSha256"]
        archive_size = installed["archiveSize"]
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise PublicProjectionError("Scrcpy archive digest is invalid")
        if isinstance(archive_size, bool) or not isinstance(archive_size, int) or archive_size <= 0:
            raise PublicProjectionError("Scrcpy archive size is invalid")
        bounded: dict[str, str] = {}
        for field, maximum in (
            ("version", 128),
            ("platform", 64),
            ("architecture", 64),
            ("license", 256),
            ("provenance", 512),
        ):
            item = installed[field]
            if not isinstance(item, str) or not item or len(item) > maximum:
                raise PublicProjectionError(f"Scrcpy {field} is invalid")
            bounded[field] = item
        installation = {
            "installed": True,
            **bounded,
            "archiveSha256": digest,
            "archiveSize": archive_size,
        }
    return ensure_public_json(
        {"ready": ready, "installation": installation, "revision": revision}
    )


def _project_preferences(value: object) -> JSONValue:
    source = _record(value)
    return ensure_public_json({"preferences": _public_preferences(source.get("preferences"))})


def _project_device_scan(value: object) -> JSONValue:
    source = _record(value)
    scan = _record(source.get("scan", {}))
    return ensure_public_json({
        "snapshot": public_snapshot(source.get("snapshot")),
        "scan": {
            "devices": [_public_device(item) for item in _array(scan.get("devices", []))],
            "successful_sources": _strings(scan.get("successful_sources", [])),
            "cancelled": _boolean(scan.get("cancelled")),
        },
    })


def _project_firmware_inspection(value: object) -> dict[str, JSONValue]:
    source = _closed_record(
        value,
        fields=frozenset(
            {
                "type",
                "sha256",
                "build",
                "device",
                "code",
                "ok",
                "provenance",
                "detectedDevices",
                "expectedDevices",
                "compatibility",
                "evidence",
            }
        ),
    )
    kind = source["type"]
    digest = source["sha256"]
    build = source["build"]
    device = source["device"]
    provenance = source["provenance"]
    compatibility = source["compatibility"]
    if kind not in {"factory", "ota", "custom"}:
        raise PublicProjectionError("firmware inspection type is invalid")
    if not isinstance(digest, str) or _LOWERCASE_SHA256.fullmatch(digest) is None:
        raise PublicProjectionError("firmware inspection digest is invalid")
    if not isinstance(build, str) or len(build) > 512:
        raise PublicProjectionError("firmware inspection build is invalid")
    if not isinstance(device, str) or len(device) > 512:
        raise PublicProjectionError("firmware inspection device is invalid")
    if source["code"] != "ok" or source["ok"] is not True:
        raise PublicProjectionError("firmware inspection result is invalid")
    if provenance not in {"official", "user_supplied"}:
        raise PublicProjectionError("firmware inspection provenance is invalid")
    if compatibility not in {"matched", "unverified", "not_checked"}:
        raise PublicProjectionError("firmware compatibility evidence is invalid")
    detected = _closed_bounded_strings(
        source["detectedDevices"],
        maximum_items=32,
        maximum_item_utf8_bytes=64,
        maximum_utf8_bytes=2_048,
    )
    expected = _closed_bounded_strings(
        source["expectedDevices"],
        maximum_items=32,
        maximum_item_utf8_bytes=64,
        maximum_utf8_bytes=2_048,
    )
    evidence = _closed_bounded_strings(
        source["evidence"],
        maximum_items=8,
        maximum_item_utf8_bytes=64,
        maximum_utf8_bytes=512,
    )
    allowed_evidence = {
        "sha256_computed",
        "archive_paths_validated",
        "archive_members_verified",
        "factory_flash_script",
        "factory_image_archive",
        "ota_metadata",
        "verified_zip",
    }
    if not evidence or any(item not in allowed_evidence for item in evidence):
        raise PublicProjectionError("firmware inspection evidence is invalid")
    return cast(
        dict[str, JSONValue],
        ensure_public_json({**source, "detectedDevices": detected, "expectedDevices": expected, "evidence": evidence}),
    )


def _project_firmware_select(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset({"snapshot", "inspection"}),
    )
    return ensure_public_json({
        "snapshot": public_snapshot(source["snapshot"]),
        "inspection": _project_firmware_inspection(source["inspection"]),
    })


def _project_firmware_process(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset({"processing", "firmware", "boot"}),
    )
    processing = _closed_record(
        source["processing"],
        fields=frozenset(
            {"status", "code", "inspection", "artifacts", "detectedDevices", "registered"}
        ),
    )
    if processing["status"] != "SUCCESS" or processing["code"] != "firmware_artifacts_ready":
        raise PublicProjectionError("firmware processing terminal evidence is invalid")
    if processing["registered"] is not True:
        raise PublicProjectionError("firmware processing registration evidence is invalid")
    raw_artifacts = _array(processing["artifacts"])
    if not raw_artifacts or len(raw_artifacts) > 512:
        raise PublicProjectionError("firmware processing artifacts are invalid")
    artifacts: list[dict[str, JSONValue]] = []
    for raw in raw_artifacts:
        artifact = _closed_record(
            raw,
            fields=frozenset({"sha256", "role", "displayName"}),
        )
        digest = artifact["sha256"]
        role = artifact["role"]
        display_name = artifact["displayName"]
        if not isinstance(digest, str) or _LOWERCASE_SHA256.fullmatch(digest) is None:
            raise PublicProjectionError("firmware artifact digest is invalid")
        if not isinstance(role, str) or not role or len(role) > 128:
            raise PublicProjectionError("firmware artifact role is invalid")
        if (
            not isinstance(display_name, str)
            or display_name != f"@artifact/{role}/{digest[:12]}"
        ):
            raise PublicProjectionError("firmware artifact display name is invalid")
        artifacts.append({"sha256": digest, "role": role, "displayName": display_name})
    detected_devices = _closed_bounded_strings(
        processing["detectedDevices"],
        maximum_items=32,
        maximum_item_utf8_bytes=64,
        maximum_utf8_bytes=2_048,
    )
    return ensure_public_json({
        "processing": {
            "status": _string(processing["status"]),
            "code": _string(processing["code"]),
            "inspection": _project_firmware_inspection(processing["inspection"]),
            "artifacts": artifacts,
            "detectedDevices": detected_devices,
            "registered": True,
        },
        "firmware": _public_firmware(source["firmware"]),
        "boot": _public_boot(source["boot"]),
    })


def _project_confirmation(value: object) -> JSONValue | None:
    source = _record(value)
    confirmation = source.get("confirmation")
    if confirmation is None:
        return None
    details = _record(confirmation)
    required = _string(details.get("required_text"))
    if not required:
        return None
    return ensure_public_json({"confirmation": {"required_text": required}})


def _project_plan_preview(value: object) -> JSONValue:
    source = _record(value)
    compiled = _record(source.get("compiled"))
    raw_plan = compiled.get("plan")
    confirmation = _project_confirmation(compiled)
    projected: dict[str, object] = {
        "revision": _integer(source.get("revision")),
        "canonical_plan": _public_flash_plan(source.get("canonical_plan")),
        "plan": _public_flash_plan(source.get("plan")),
        "selected_serials": _strings(source.get("selected_serials", [])),
        "firmware": _public_firmware(source.get("firmware")),
        "compiled": {
            "ok": _boolean(compiled.get("ok")),
            "code": _string(compiled.get("code")),
            "destructive": _boolean(compiled.get("destructive")),
            "requires_confirmation": _boolean(compiled.get("requires_confirmation")),
            "plan": _public_operation_plan(raw_plan) if raw_plan is not None else None,
            "confirmation": confirmation.get("confirmation") if isinstance(confirmation, dict) else None,
        },
    }
    if source.get("batch") is True:
        raw_batch = compiled.get("preview", compiled.get("batch"))
        projected["batch"] = True
        projected_compiled = cast(dict[str, object], projected["compiled"])
        projected_compiled["batch"] = _public_preview_batch(raw_batch)
    return ensure_public_json(projected)


def _public_preview_batch(value: object) -> dict[str, JSONValue]:
    source = _record(value)
    plans = [_public_operation_plan(item) for item in _array(source.get("plans", []))]
    target_serials = _strings(source.get("targetSerials", []))
    if not target_serials:
        target_serials = [
            str(plan.get("target_serial"))
            for plan in plans
            if isinstance(plan.get("target_serial"), str)
        ]
    if len(plans) < 2 or len(plans) != len(target_serials):
        raise PublicProjectionError("flash preview batch targets are invalid")
    return _public_object({
        "previewId": _string(source.get("previewId", source.get("batchId"))),
        "created": _number(source.get("created")),
        "expires": _number(source.get("expires")),
        "fingerprint": _string(source.get("fingerprint")),
        "targetSerials": target_serials,
        "plans": plans,
        "dry_run": _boolean(source.get("dry_run"), default=False),
    })


def _project_flash_execute(value: object) -> JSONValue | None:
    source = _record(value)
    if source.get("preview") is not None:
        return ensure_public_json({"preview": _public_preview_batch(source.get("preview"))})
    return _project_confirmation(value)


def _project_apps_list(value: object) -> JSONValue:
    source = _record(value)
    packages: list[dict[str, object]] = []
    for raw in _array(source.get("packages", [])):
        package = _record(raw)
        packages.append(
            {
                "package": _string(package.get("package")),
                # Device paths are intentionally public package metadata.
                "apk_path": _string(package.get("apk_path")),
                "uid": package.get("uid") if isinstance(package.get("uid"), int) else None,
            }
        )
    return ensure_public_json({"count": len(packages), "packages": packages})


def _project_apps_action(value: object) -> JSONValue:
    raw = _record(value)
    action = raw.get("action")
    if action not in {
        "enable",
        "disable",
        "uninstall",
        "clearData",
        "forceStop",
        "launch",
        "permissions",
        "denylistAdd",
        "denylistRemove",
        "suPolicy",
        "export",
        "install",
    }:
        raise PublicProjectionError("package action is invalid")
    if action == "permissions":
        source = _closed_record(value, fields=frozenset({"action", "report"}))
        report = _closed_record(
            source["report"],
            fields=frozenset(
                {
                    "package",
                    "requested",
                    "runtimeGranted",
                    "runtimeDenied",
                    "requestedCount",
                    "runtimeCount",
                    "bounded",
                }
            ),
        )
        package = report["package"]
        requested = report["requested"]
        granted = report["runtimeGranted"]
        denied = report["runtimeDenied"]
        counts = (report["requestedCount"], report["runtimeCount"])
        if (
            report["bounded"] is not True
            or not isinstance(package, str)
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", package)
            is None
            or not all(isinstance(items, (list, tuple)) for items in (requested, granted, denied))
            or not all(
                isinstance(item, str)
                and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]{1,255}", item) is not None
                for items in (requested, granted, denied)
                for item in cast("list[object] | tuple[object, ...]", items)
            )
            or any(len(cast("list[object] | tuple[object, ...]", items)) > 512 for items in (requested, granted, denied))
            or any(
                not isinstance(count, int) or isinstance(count, bool) or count < 0
                for count in counts
            )
            or counts[0] != len(cast("list[object] | tuple[object, ...]", requested))
            or counts[1]
            != len(cast("list[object] | tuple[object, ...]", granted))
            + len(cast("list[object] | tuple[object, ...]", denied))
            or set(cast("list[object] | tuple[object, ...]", granted))
            & set(cast("list[object] | tuple[object, ...]", denied))
        ):
            raise PublicProjectionError("package permission report is invalid")
        return ensure_public_json({"action": "permissions", "report": dict(report)})
    if action == "install":
        source = _closed_record(value, fields=frozenset({"action", "apkIdentity"}))
        identity = _closed_record(
            source["apkIdentity"],
            fields=frozenset(
                {"packageName", "sha256", "signerSha256", "schemes", "verified"}
            ),
        )
        signers = identity["signerSha256"]
        schemes = identity["schemes"]
        if (
            identity["verified"] is not True
            or not isinstance(identity["packageName"], str)
            or re.fullmatch(
                r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+",
                identity["packageName"],
            )
            is None
            or not isinstance(identity["sha256"], str)
            or _LOWERCASE_SHA256.fullmatch(identity["sha256"]) is None
            or not isinstance(signers, (list, tuple))
            or not 1 <= len(signers) <= 16
            or any(
                not isinstance(item, str) or _LOWERCASE_SHA256.fullmatch(item) is None
                for item in signers
            )
            or not isinstance(schemes, (list, tuple))
            or not schemes
            or any(item not in {"v1", "v2", "v3", "v4"} for item in schemes)
        ):
            raise PublicProjectionError("installed APK identity is invalid")
        return ensure_public_json({"action": "install", "apkIdentity": dict(identity)})
    if action == "export":
        source = _closed_record(value, fields=frozenset({"action", "export"}))
        receipt = _closed_record(
            source["export"],
            fields=frozenset(
                {
                    "package",
                    "fileName",
                    "sha256",
                    "size",
                    "verified",
                    "remoteCleaned",
                }
            ),
        )
        package = receipt["package"]
        file_name = receipt["fileName"]
        digest = receipt["sha256"]
        size = receipt["size"]
        if (
            receipt["verified"] is not True
            or receipt["remoteCleaned"] is not True
            or not isinstance(package, str)
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", package)
            is None
            or not isinstance(file_name, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,254}\.apk", file_name, re.I)
            is None
            or not isinstance(digest, str)
            or _LOWERCASE_SHA256.fullmatch(digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 1 <= size <= 2 * 1024 * 1024 * 1024
        ):
            raise PublicProjectionError("APK export receipt is invalid")
        return ensure_public_json({"action": "export", "export": dict(receipt)})
    source = _closed_record(value, fields=frozenset({"action"}))
    return ensure_public_json(dict(source))


_BOOT_ENTRY_FIELDS = (
    "bootId",
    "sha256",
    "size",
    "provenance",
    "createdAt",
    "partition",
    "deviceCodenames",
    "patcher",
    "patcherVersion",
    "signature",
    "sourceHash",
    "patched",
    "verified",
)


def _public_boot_entry(value: object) -> dict[str, JSONValue]:
    source = _record(value)
    return _public_object({
        "bootId": _string(source.get("bootId")),
        "sha256": _string(source.get("sha256")),
        "size": _integer(source.get("size")),
        "provenance": _string(source.get("provenance")),
        "createdAt": _integer(source.get("createdAt")),
        "partition": _string(source.get("partition")),
        "deviceCodenames": _strings(source.get("deviceCodenames", [])),
        "patcher": _string(source.get("patcher")),
        "patcherVersion": _string(source.get("patcherVersion")),
        "signature": _string(source.get("signature")),
        "sourceHash": _string(source.get("sourceHash")),
        "patched": _boolean(source.get("patched")),
        "verified": _boolean(source.get("verified")),
    })


def _project_boot_inventory(value: object) -> JSONValue:
    source = _record(value)
    return ensure_public_json({
        "boots": [_public_boot_entry(item) for item in _array(source.get("boots", []))],
        "selectedBootId": _optional_string(source.get("selectedBootId")),
        "revision": _integer(source.get("revision")),
    })


def _project_boot_select(value: object) -> JSONValue:
    source = _record(value)
    return ensure_public_json({
        "selected": _public_boot_entry(source.get("selected")),
        "revision": _integer(source.get("revision")),
    })


def _project_boot_delete(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset(
            {"bootId", "sha256", "objectRetained", "cleanupDeferred", "revision"}
        ),
    )
    boot_id = source["bootId"]
    digest = source["sha256"]
    revision = source["revision"]
    if not isinstance(boot_id, str) or re.fullmatch(r"[0-9a-f]{32}", boot_id) is None:
        raise PublicProjectionError("boot deletion id is invalid")
    if not isinstance(digest, str) or _LOWERCASE_SHA256.fullmatch(digest) is None:
        raise PublicProjectionError("boot deletion digest is invalid")
    if not isinstance(source["objectRetained"], bool) or not isinstance(
        source["cleanupDeferred"], bool
    ):
        raise PublicProjectionError("boot deletion storage evidence is invalid")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise PublicProjectionError("boot deletion revision is invalid")
    return ensure_public_json(source)


def _project_boot_patch(value: object) -> JSONValue:
    source = _record(value)
    patched = _record(source.get("patchedBoot", {}))
    return ensure_public_json({
        "patchedBoot": {
            "artifact": _public_artifact(patched.get("artifact")),
            "sourceSha256": _string(patched.get("sourceSha256")),
            "flavor": _string(patched.get("flavor")),
            "partition": _string(patched.get("partition")),
        },
        "boot": _public_boot(source.get("boot")),
    })


def _public_root_app(value: object) -> dict[str, JSONValue]:
    source = _closed_record(
        value,
        fields=frozenset(
            {
                "id",
                "provider",
                "flavor",
                "version",
                "sha256",
                "provenance",
                "packageName",
                "signerSha256",
                "schemes",
                "architecture",
            }
        ),
    )
    app_id = source["id"]
    digest = source["sha256"]
    signers = _strings(source["signerSha256"])
    schemes = _strings(source["schemes"])
    if not isinstance(app_id, str) or _LOWERCASE_SHA256.fullmatch(app_id) is None:
        raise PublicProjectionError("root app id is invalid")
    if not isinstance(digest, str) or _LOWERCASE_SHA256.fullmatch(digest) is None:
        raise PublicProjectionError("root app digest is invalid")
    if any(_LOWERCASE_SHA256.fullmatch(signer) is None for signer in signers):
        raise PublicProjectionError("root app signer is invalid")
    for name in (
        "provider",
        "flavor",
        "version",
        "provenance",
        "packageName",
        "architecture",
    ):
        if not isinstance(source[name], str) or not source[name]:
            raise PublicProjectionError(f"root app {name} is invalid")
    return _public_object(
        {
            "id": app_id,
            "provider": source["provider"],
            "flavor": source["flavor"],
            "version": source["version"],
            "sha256": digest,
            "provenance": source["provenance"],
            "packageName": source["packageName"],
            "signerSha256": signers,
            "schemes": schemes,
            "architecture": source["architecture"],
        }
    )


def _public_root_app_catalog_entry(value: object) -> dict[str, JSONValue]:
    source = _closed_record(
        value,
        fields=frozenset(
            {
                "artifactId",
                "provider",
                "channel",
                "flavor",
                "version",
                "architecture",
                "packageName",
                "signerSha256",
                "sha256",
                "size",
                "license",
                "provenance",
            }
        ),
    )
    artifact_id = source["artifactId"]
    digest = source["sha256"]
    size = source["size"]
    signers = _strings(source["signerSha256"])
    if not isinstance(artifact_id, str) or re.fullmatch(r"[0-9a-f]{32}", artifact_id) is None:
        raise PublicProjectionError("root-app catalog artifact id is invalid")
    if not isinstance(digest, str) or _LOWERCASE_SHA256.fullmatch(digest) is None:
        raise PublicProjectionError("root-app catalog digest is invalid")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise PublicProjectionError("root-app catalog size is invalid")
    if not signers or any(_LOWERCASE_SHA256.fullmatch(signer) is None for signer in signers):
        raise PublicProjectionError("root-app catalog signer is invalid")
    for name in (
        "provider",
        "channel",
        "flavor",
        "version",
        "architecture",
        "packageName",
        "license",
        "provenance",
    ):
        if not isinstance(source[name], str) or not source[name]:
            raise PublicProjectionError(f"root-app catalog {name} is invalid")
    return _public_object(source)


def _project_root_apps(value: object) -> JSONValue:
    source = _closed_record(value, fields=frozenset({"count", "apps"}))
    apps = [_public_root_app(raw) for raw in _array(source["apps"])]
    if source["count"] != len(apps):
        raise PublicProjectionError("root app inventory count is invalid")
    return ensure_public_json({"count": len(apps), "apps": apps})


def _project_root_app_catalog(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset({"count", "entries", "channel", "revision"}),
    )
    entries = [
        _public_root_app_catalog_entry(raw)
        for raw in _array(source["entries"])
    ]
    if source["count"] != len(entries):
        raise PublicProjectionError("root-app catalog count is invalid")
    if source["channel"] not in {"stable", "beta", "canary"}:
        raise PublicProjectionError("root-app catalog channel is invalid")
    revision = source["revision"]
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise PublicProjectionError("root-app catalog revision is invalid")
    return ensure_public_json(
        {
            "count": len(entries),
            "entries": entries,
            "channel": source["channel"],
            "revision": revision,
        }
    )


def _project_root_app_download(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset({"artifact", "app", "cacheHit", "resumed", "revision"}),
    )
    if not isinstance(source["cacheHit"], bool) or not isinstance(source["resumed"], bool):
        raise PublicProjectionError("root-app download cache evidence is invalid")
    revision = source["revision"]
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise PublicProjectionError("root-app download revision is invalid")
    return ensure_public_json(
        {
            "artifact": _public_root_app_catalog_entry(source["artifact"]),
            "app": _public_root_app(source["app"]),
            "cacheHit": source["cacheHit"],
            "resumed": source["resumed"],
            "revision": revision,
        }
    )


def _project_root_modules(value: object) -> JSONValue:
    source = _closed_record(value, fields=frozenset({"count", "modules"}))
    count = source["count"]
    raw_modules = source["modules"]
    if (
        not isinstance(count, int)
        or isinstance(count, bool)
        or not 0 <= count <= 256
        or not isinstance(raw_modules, list)
        or len(raw_modules) != count
    ):
        raise PublicProjectionError("root module inventory count is invalid")
    fields = frozenset(
        {
            "id", "name", "version", "versionCode", "author", "description",
            "state", "updateMetadata",
        }
    )
    modules: list[dict[str, JSONValue]] = []
    seen: set[str] = set()
    for raw in cast("list[object]", raw_modules):
        module = _closed_record(raw, fields=fields)
        module_id = module["id"]
        version_code = module["versionCode"]
        strings = {
            key: module[key]
            for key in ("name", "version", "author", "description")
        }
        if (
            not isinstance(module_id, str)
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]{0,63}", module_id) is None
            or module_id.casefold() in seen
            or any(not isinstance(item, str) for item in strings.values())
            or len(cast(str, strings["name"])) > 256
            or len(cast(str, strings["version"])) > 128
            or len(cast(str, strings["author"])) > 256
            or len(cast(str, strings["description"])) > 1024
            or any(
                any(ord(character) < 32 for character in cast(str, item))
                for item in strings.values()
            )
            or (
                version_code is not None
                and (
                    not isinstance(version_code, int)
                    or isinstance(version_code, bool)
                    or not 0 <= version_code <= 2_147_483_647
                )
            )
            or module["state"] not in {"enabled", "disabled", "pending_remove", "corrupt"}
            or module["updateMetadata"] not in {"available", "absent"}
        ):
            raise PublicProjectionError("root module inventory record is invalid")
        modules.append(cast(dict[str, JSONValue], ensure_public_json(dict(module))))
        seen.add(module_id.casefold())
    return ensure_public_json({"count": count, "modules": modules})


def _project_root_module_action(value: object) -> JSONValue:
    source = _record(value)
    return ensure_public_json({
        "action": _string(source.get("action")),
        "targetSerial": _optional_string(source.get("targetSerial")),
        "moduleId": _string(source.get("moduleId")),
    })


def _project_root_recovery(value: object, *, expected_action: str) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset({"action", "targetSerial", "verified"}),
    )
    if (
        source["action"] != expected_action
        or not isinstance(source["targetSerial"], str)
        or not is_valid_target_serial(source["targetSerial"])
        or source["verified"] is not True
    ):
        raise PublicProjectionError("root recovery result is invalid")
    return ensure_public_json(dict(source))


def _project_shizuku_recovery(value: object) -> JSONValue:
    return _project_root_recovery(value, expected_action="startShizuku")


def _project_sos_recovery(value: object) -> JSONValue:
    return _project_root_recovery(value, expected_action="disableModules")


def _project_data_adb_backup(value: object) -> JSONValue:
    fields = frozenset(
        {
            "action",
            "targetSerial",
            "fileName",
            "sha256",
            "sizeBytes",
            "payloadSha256",
            "entryCount",
            "contentFingerprint",
            "deviceCodename",
            "verified",
            "remoteCleaned",
        }
    )
    source = _closed_record(value, fields=fields)
    file_name = source["fileName"]
    size = source["sizeBytes"]
    entry_count = source["entryCount"]
    if (
        source["action"] != "backup"
        or not isinstance(source["targetSerial"], str)
        or not is_valid_target_serial(source["targetSerial"])
        or not isinstance(file_name, str)
        or ntpath.basename(posixpath.basename(file_name.replace("\\", "/"))) != file_name
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,191}\.pfdataadb", file_name, re.I)
        is None
        or not isinstance(size, int)
        or isinstance(size, bool)
        or not 1 <= size <= 2 * 1024 * 1024 * 1024 + 32 * 1024 * 1024
        or not isinstance(entry_count, int)
        or isinstance(entry_count, bool)
        or not 0 <= entry_count <= 20_000
        or source["verified"] is not True
        or source["remoteCleaned"] is not True
    ):
        raise PublicProjectionError("/data/adb backup receipt is invalid")
    for field in ("sha256", "payloadSha256", "contentFingerprint"):
        digest = source[field]
        if not isinstance(digest, str) or _LOWERCASE_SHA256.fullmatch(digest) is None:
            raise PublicProjectionError("/data/adb backup digest is invalid")
    if not isinstance(source["deviceCodename"], str) or not source["deviceCodename"]:
        raise PublicProjectionError("/data/adb backup device identity is invalid")
    return ensure_public_json(dict(source))


def _project_data_adb_restore(value: object) -> JSONValue:
    fields = frozenset(
        {
            "action",
            "targetSerial",
            "payloadSha256",
            "entryCount",
            "contentFingerprint",
            "deviceCodename",
            "verified",
            "remoteCleaned",
        }
    )
    source = _closed_record(value, fields=fields)
    entry_count = source["entryCount"]
    if (
        source["action"] != "restore"
        or not isinstance(source["targetSerial"], str)
        or not is_valid_target_serial(source["targetSerial"])
        or not isinstance(entry_count, int)
        or isinstance(entry_count, bool)
        or not 0 <= entry_count <= 20_000
        or not isinstance(source["deviceCodename"], str)
        or not source["deviceCodename"]
        or source["verified"] is not True
        or source["remoteCleaned"] is not True
    ):
        raise PublicProjectionError("/data/adb restore receipt is invalid")
    for field in ("payloadSha256", "contentFingerprint"):
        digest = source[field]
        if not isinstance(digest, str) or _LOWERCASE_SHA256.fullmatch(digest) is None:
            raise PublicProjectionError("/data/adb restore digest is invalid")
    return ensure_public_json(dict(source))


def _project_data_adb_clear(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset({"action", "targetSerial", "empty", "verified"}),
    )
    if (
        source["action"] != "clear"
        or not isinstance(source["targetSerial"], str)
        or not is_valid_target_serial(source["targetSerial"])
        or source["empty"] is not True
        or source["verified"] is not True
    ):
        raise PublicProjectionError("/data/adb clear receipt is invalid")
    return ensure_public_json(dict(source))


def _project_partitions(value: object) -> JSONValue:
    source = _record(value)
    partitions: list[dict[str, object]] = []
    for raw in _array(source.get("partitions", [])):
        partition = _record(raw)
        partitions.append(
            {
                "name": _string(partition.get("name")),
                "size_bytes": _integer(partition.get("size_bytes")),
                "partition_type": _string(partition.get("partition_type")),
            }
        )
    return ensure_public_json({"count": len(partitions), "partitions": partitions})


def _project_wifi_discovery(value: object) -> JSONValue:
    fields = frozenset(
        {"action", "count", "services", "discardedCount", "bounded"}
    )
    source = _closed_record(value, fields=fields)
    if source["action"] != "discover" or source["bounded"] is not True:
        raise PublicProjectionError("Wi-Fi discovery result is not bounded")
    count = source["count"]
    discarded_count = source["discardedCount"]
    raw_services = source["services"]
    if (
        not isinstance(count, int)
        or isinstance(count, bool)
        or count < 0
        or not isinstance(discarded_count, int)
        or isinstance(discarded_count, bool)
        or discarded_count < 0
        or not isinstance(raw_services, list)
        or len(raw_services) > 256
        or count != len(raw_services)
        or count + discarded_count > 256
    ):
        raise PublicProjectionError("Wi-Fi discovery counts are invalid")

    item_fields = frozenset(
        {
            "id",
            "instance",
            "serviceType",
            "host",
            "port",
            "endpoint",
            "addressFamily",
        }
    )
    services: list[dict[str, JSONValue]] = []
    identities: set[tuple[str, str]] = set()
    for raw in cast("list[object]", raw_services):
        service = _closed_record(raw, fields=item_fields)
        service_id = service["id"]
        instance = service["instance"]
        service_type = service["serviceType"]
        host = service["host"]
        port = service["port"]
        endpoint = service["endpoint"]
        if (
            not isinstance(service_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", service_id) is None
            or not isinstance(instance, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", instance) is None
            or service_type not in {"pairing", "connect", "legacy"}
            or not isinstance(host, str)
            or not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65_535
            or endpoint != f"{host}:{port}"
            or service["addressFamily"] != "ipv4"
        ):
            raise PublicProjectionError("Wi-Fi discovery service is invalid")
        try:
            address = ipaddress.IPv4Address(host)
        except ipaddress.AddressValueError as error:
            raise PublicProjectionError("Wi-Fi discovery host is invalid") from error
        if (
            str(address) != host
            or address.is_loopback
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
            or not any(address in network for network in _MDNS_LOCAL_NETWORKS)
        ):
            raise PublicProjectionError("Wi-Fi discovery host is unsafe")
        expected_id = hashlib.sha256(
            f"{service_type}\0{endpoint}".encode("ascii")
        ).hexdigest()
        identity = (cast(str, service_type), cast(str, endpoint))
        if service_id != expected_id or identity in identities:
            raise PublicProjectionError("Wi-Fi discovery identity is invalid")
        identities.add(identity)
        services.append(
            {
                "id": service_id,
                "instance": instance,
                "serviceType": cast(str, service_type),
                "host": host,
                "port": port,
                "endpoint": cast(str, endpoint),
                "addressFamily": "ipv4",
            }
        )
    return ensure_public_json(
        {
            "action": "discover",
            "count": count,
            "services": services,
            "discardedCount": discarded_count,
            "bounded": True,
        }
    )


def _project_push_files(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset({"targetSerial", "count", "files"}),
    )
    target_serial = source["targetSerial"]
    count = source["count"]
    raw_files = source["files"]
    if (
        not isinstance(target_serial, str)
        or _target_serial(target_serial) is None
        or not isinstance(count, int)
        or isinstance(count, bool)
        or not 1 <= count <= 32
        or not isinstance(raw_files, list)
    ):
        raise PublicProjectionError("push result count is invalid")
    file_values = cast("list[object]", raw_files)
    if len(file_values) != count:
        raise PublicProjectionError("push result count is invalid")

    item_fields = frozenset(
        {"displayName", "destination", "sha256", "sizeBytes", "verified"}
    )
    files: list[dict[str, JSONValue]] = []
    destinations: set[str] = set()
    display_names: set[str] = set()
    for raw in file_values:
        item = _closed_record(raw, fields=item_fields)
        display_name = item["displayName"]
        destination = item["destination"]
        digest = item["sha256"]
        size_bytes = item["sizeBytes"]
        if (
            not isinstance(display_name, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", display_name)
            is None
            or not isinstance(destination, str)
            or destination
            not in {
                f"/data/local/tmp/{display_name}",
                f"/sdcard/Download/{display_name}",
            }
            or destination in destinations
            or display_name.casefold() in display_names
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(size_bytes, int)
            or isinstance(size_bytes, bool)
            or size_bytes < 0
            or size_bytes > 9_007_199_254_740_991
            or item["verified"] is not True
        ):
            raise PublicProjectionError("push result file receipt is invalid")
        destinations.add(destination)
        display_names.add(display_name.casefold())
        files.append(
            {
                "displayName": display_name,
                "destination": destination,
                "sha256": digest,
                "sizeBytes": size_bytes,
                "verified": True,
            }
        )
    return ensure_public_json(
        {"targetSerial": target_serial, "count": count, "files": files}
    )


def _project_device_inspect(value: object) -> JSONValue:
    source = _record(value)
    action = _string(source.get("action"))
    result: dict[str, JSONValue] = {
        "action": action,
        "targetSerial": _string(source.get("targetSerial")),
    }
    if action == "properties":
        result.update(
            _public_object({
                "properties": _string_map(source.get("properties", {})),
                "redactedKeys": _strings(source.get("redactedKeys", [])),
                "count": _integer(source.get("count")),
                "summary": _string_map(source.get("summary", {})),
            })
        )
    elif action == "screenXml":
        result.update(
            _public_object({
                "xml": _string(source.get("xml")),
                "sha256": _string(source.get("sha256")),
                "nodeCount": _integer(source.get("nodeCount")),
                "redactedFields": _integer(source.get("redactedFields")),
            })
        )
    elif action == "bootloaderVersions":
        return _project_bootloader_versions(value)
    elif action == "pifPrint":
        result.update(
            _public_object({
                "format": _string(source.get("format")),
                "profile": _string_map(source.get("profile", {})),
            })
        )
    else:
        raise PublicProjectionError("device inspection action is invalid")
    return result


def _project_bootloader_versions(value: object) -> JSONValue:
    fields = frozenset(
        {
            "action",
            "targetSerial",
            "source",
            "current",
            "activeSlot",
            "bootloaderCodename",
            "slots",
            "activeMatchesReported",
        }
    )
    source = _closed_record(value, fields=fields)
    target_serial = source["targetSerial"]
    current = source["current"]
    active_slot = source["activeSlot"]
    bootloader_codename = source["bootloaderCodename"]
    if source["action"] != "bootloaderVersions" or source["source"] != "abl_slots":
        raise PublicProjectionError("bootloader inspection identity is invalid")
    if not isinstance(target_serial, str) or not is_valid_target_serial(target_serial):
        raise PublicProjectionError("bootloader inspection target serial is invalid")
    if active_slot not in {"a", "b"}:
        raise PublicProjectionError("bootloader inspection active slot is invalid")
    if source["activeMatchesReported"] is not True:
        raise PublicProjectionError("bootloader inspection is not verified")
    if (
        not isinstance(bootloader_codename, str)
        or _BOOTLOADER_CODENAME.fullmatch(bootloader_codename) is None
    ):
        raise PublicProjectionError("bootloader inspection codename is invalid")
    if (
        not isinstance(current, str)
        or _BOOTLOADER_FULL_VERSION.fullmatch(current) is None
    ):
        raise PublicProjectionError("reported bootloader version is invalid")

    raw_slots = _closed_record(source["slots"], fields=frozenset({"a", "b"}))
    slots = {
        slot: _project_bootloader_slot(
            raw_slots[slot],
            slot=slot,
            bootloader_codename=bootloader_codename,
        )
        for slot in ("a", "b")
    }
    active = slots[cast("str", active_slot)]
    if current != active["fullVersion"]:
        raise PublicProjectionError("reported bootloader version does not match the active slot")
    return ensure_public_json(
        {
            "action": "bootloaderVersions",
            "targetSerial": target_serial,
            "source": "abl_slots",
            "current": current,
            "activeSlot": active_slot,
            "bootloaderCodename": bootloader_codename,
            "slots": slots,
            "activeMatchesReported": True,
        }
    )


def _project_bootloader_slot(
    value: object,
    *,
    slot: str,
    bootloader_codename: str,
) -> dict[str, JSONValue]:
    source = _closed_record(
        value,
        fields=frozenset(
            {"partition", "version", "fullVersion", "sha256", "sizeBytes"}
        ),
    )
    version = source["version"]
    full_version = source["fullVersion"]
    digest = source["sha256"]
    size_bytes = source["sizeBytes"]
    if source["partition"] != f"abl_{slot}":
        raise PublicProjectionError("bootloader inspection partition is invalid")
    if not isinstance(version, str) or _BOOTLOADER_VERSION.fullmatch(version) is None:
        raise PublicProjectionError("bootloader slot version is invalid")
    if (
        not isinstance(full_version, str)
        or _BOOTLOADER_FULL_VERSION.fullmatch(full_version) is None
        or full_version != f"{bootloader_codename}-{version}"
    ):
        raise PublicProjectionError("bootloader slot full version is invalid")
    if not isinstance(digest, str) or _LOWERCASE_SHA256.fullmatch(digest) is None:
        raise PublicProjectionError("bootloader slot digest is invalid")
    if (
        not isinstance(size_bytes, int)
        or isinstance(size_bytes, bool)
        or not 1 <= size_bytes <= _MAX_ABL_PARTITION_BYTES
    ):
        raise PublicProjectionError("bootloader slot size is invalid")
    return {
        "partition": f"abl_{slot}",
        "version": version,
        "fullVersion": full_version,
        "sha256": digest,
        "sizeBytes": size_bytes,
    }


def _project_device_open_url(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset(
            {
                "action",
                "targetSerial",
                "scheme",
                "host",
                "urlSha256",
                "intentAccepted",
            }
        ),
    )
    target_serial = source["targetSerial"]
    scheme = source["scheme"]
    host = source["host"]
    digest = source["urlSha256"]
    if source["action"] != "openUrl" or source["intentAccepted"] is not True:
        raise PublicProjectionError("browser intent result is not verified")
    if not isinstance(target_serial, str) or not is_valid_target_serial(target_serial):
        raise PublicProjectionError("browser intent target serial is invalid")
    if scheme not in {"http", "https"}:
        raise PublicProjectionError("browser intent scheme is invalid")
    if (
        not isinstance(host, str)
        or not host
        or not host.isascii()
        or host != host.casefold()
        or len(host) > 253
    ):
        raise PublicProjectionError("browser intent host is invalid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if any(_DNS_LABEL.fullmatch(label) is None for label in host.split(".")):
            raise PublicProjectionError("browser intent host is invalid") from None
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise PublicProjectionError("browser intent URL digest is invalid")
    return {
        "action": "openUrl",
        "targetSerial": target_serial,
        "scheme": scheme,
        "host": host,
        "urlSha256": digest,
        "intentAccepted": True,
    }


def _project_ota_status(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset(
            {"action", "state", "progress", "idle", "lastAttemptError", "bounded"}
        ),
    )
    if source["action"] != "status" or source["bounded"] is not True:
        raise PublicProjectionError("OTA status result is not bounded")
    state = source["state"]
    allowed_states = {
        "idle",
        "checking_for_update",
        "update_available",
        "downloading",
        "verifying",
        "finalizing",
        "updated_need_reboot",
        "reporting_error_event",
        "attempting_rollback",
        "disabled",
    }
    if not isinstance(state, str) or state not in allowed_states:
        raise PublicProjectionError("OTA status state is invalid")
    progress = source["progress"]
    if (
        not isinstance(progress, (int, float))
        or isinstance(progress, bool)
        or not 0 <= progress <= 1
    ):
        raise PublicProjectionError("OTA status progress is invalid")
    if source["idle"] is not (state == "idle"):
        raise PublicProjectionError("OTA status idle evidence is inconsistent")
    last_error = source["lastAttemptError"]
    if last_error is not None and (
        not isinstance(last_error, str)
        or re.fullmatch(r"[A-Za-z0-9_.:+-]{1,128}", last_error) is None
    ):
        raise PublicProjectionError("OTA status error evidence is invalid")
    return ensure_public_json({
        "action": "status",
        "state": state,
        "progress": progress,
        "idle": source["idle"],
        "lastAttemptError": last_error,
        "bounded": True,
    })


def _project_firmware_catalog_entry(value: object) -> dict[str, JSONValue]:
    source = _closed_record(
        value,
        fields=frozenset(
            {"artifactId", "device", "channel", "kind", "version", "sha256", "size", "license", "provenance"}
        ),
    )
    artifact_id = source["artifactId"]
    device = source["device"]
    channel = source["channel"]
    kind = source["kind"]
    version = source["version"]
    digest = source["sha256"]
    size = source["size"]
    license_value = source["license"]
    provenance = source["provenance"]
    if not isinstance(artifact_id, str) or re.fullmatch(r"[0-9a-f]{32}", artifact_id) is None:
        raise PublicProjectionError("firmware catalog artifact ID is invalid")
    if not isinstance(device, str) or re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", device) is None:
        raise PublicProjectionError("firmware catalog device is invalid")
    if channel not in {"stable", "beta", "canary"} or kind not in {"factory", "ota"}:
        raise PublicProjectionError("firmware catalog classification is invalid")
    if not isinstance(version, str) or not version or len(version.encode("utf-8")) > 128:
        raise PublicProjectionError("firmware catalog version is invalid")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise PublicProjectionError("firmware catalog digest is invalid")
    if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= 16 * 1024**3:
        raise PublicProjectionError("firmware catalog size is invalid")
    for label, text, maximum in (
        ("license", license_value, 256),
        ("provenance", provenance, 512),
    ):
        if not isinstance(text, str) or not text or len(text.encode("utf-8")) > maximum or not text.isprintable():
            raise PublicProjectionError(f"firmware catalog {label} is invalid")
    return {
        "artifactId": artifact_id,
        "device": device,
        "channel": channel,
        "kind": kind,
        "version": version,
        "sha256": digest,
        "size": size,
        "license": license_value,
        "provenance": provenance,
    }


def _project_firmware_catalog(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset({"count", "entries", "device", "channel", "revision"}),
    )
    entries = source["entries"]
    if not isinstance(entries, list) or len(entries) > 512:
        raise PublicProjectionError("firmware catalog entries are invalid")
    projected = [_project_firmware_catalog_entry(entry) for entry in entries]
    if source["count"] != len(projected):
        raise PublicProjectionError("firmware catalog count does not match")
    if any(entry["device"] != source["device"] or entry["channel"] != source["channel"] for entry in projected):
        raise PublicProjectionError("firmware catalog scope does not match")
    revision = source["revision"]
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise PublicProjectionError("firmware catalog revision is invalid")
    return ensure_public_json({**source, "entries": projected})


def _project_firmware_download(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset({"artifact", "cacheHit", "resumed", "revision", "inspection"}),
    )
    if not isinstance(source["cacheHit"], bool) or not isinstance(source["resumed"], bool):
        raise PublicProjectionError("firmware download cache evidence is invalid")
    revision = source["revision"]
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise PublicProjectionError("firmware download revision is invalid")
    return ensure_public_json({
        "artifact": _project_firmware_catalog_entry(source["artifact"]),
        "cacheHit": source["cacheHit"],
        "resumed": source["resumed"],
        "revision": revision,
        "inspection": _project_firmware_inspection(source["inspection"]),
    })


def _project_ota_certificates(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset(
            {"action", "archivePresent", "count", "entries", "bounded"}
        ),
    )
    if source["action"] != "certificates":
        raise PublicProjectionError("OTA certificate result action is invalid")
    if source["archivePresent"] is not True or source["bounded"] is not True:
        raise PublicProjectionError("OTA certificate result is not bounded")
    count = source["count"]
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise PublicProjectionError("OTA certificate result count is invalid")
    entries = _closed_bounded_strings(
        source["entries"],
        maximum_items=1_024,
        maximum_item_utf8_bytes=256,
        maximum_utf8_bytes=256 * 1_024,
    )
    if count != len(entries):
        raise PublicProjectionError("OTA certificate result count does not match")
    for entry in entries:
        if (
            not entry
            or not entry.isprintable()
            or "\\" in entry
            or entry.startswith("/")
            or any(part in {"", ".", ".."} for part in entry.split("/"))
        ):
            raise PublicProjectionError("OTA certificate entry is invalid")
    return ensure_public_json({
        "action": "certificates",
        "archivePresent": True,
        "count": count,
        "entries": entries,
        "bounded": True,
    })


def _project_ota_logs(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset(
            {"action", "lineCount", "lines", "redactedCount", "bounded"}
        ),
    )
    if source["action"] != "logs" or source["bounded"] is not True:
        raise PublicProjectionError("OTA log result is not a bounded log response")
    line_count = source["lineCount"]
    redacted_count = source["redactedCount"]
    if (
        not isinstance(line_count, int)
        or isinstance(line_count, bool)
        or line_count < 0
        or not isinstance(redacted_count, int)
        or isinstance(redacted_count, bool)
        or not 0 <= redacted_count <= 5_000
    ):
        raise PublicProjectionError("OTA log result counters are invalid")
    lines = _closed_bounded_strings(
        source["lines"],
        maximum_items=5_000,
        maximum_item_utf8_bytes=4_096,
        maximum_utf8_bytes=8 * 1_024 * 1_024,
    )
    if line_count != len(lines):
        raise PublicProjectionError("OTA log result count does not match")
    if any(
        _UNSAFE_LOG_CONTROL.search(line)
        or "update_engine" not in line.casefold()
        for line in lines
    ):
        raise PublicProjectionError("OTA log result contains an invalid line")
    return ensure_public_json({
        "action": "logs",
        "lineCount": line_count,
        "lines": lines,
        "redactedCount": redacted_count,
        "bounded": True,
    })


def _string_map(value: object, *, maximum: int = 4096) -> dict[str, JSONValue]:
    source = _record(value)
    result: dict[str, JSONValue] = {}
    for index, (key, item) in enumerate(source.items()):
        if index >= maximum:
            break
        if isinstance(item, str):
            result[key] = item
    return result


def _project_logcat(value: object) -> JSONValue:
    base_fields = frozenset(
        {
            "targetSerial",
            "mode",
            "lineCount",
            "lines",
            "text",
            "redaction",
            "redactedCount",
            "bounded",
            "truncated",
        }
    )
    raw = _record(value)
    fields = base_fields | ({"export"} if "export" in raw else set())
    source = _closed_record(value, fields=frozenset(fields))

    target_serial = source["targetSerial"]
    if not isinstance(target_serial, str) or not is_valid_target_serial(target_serial):
        raise PublicProjectionError("Logcat result target serial is invalid")
    mode = source["mode"]
    if mode not in {"snapshot", "stream"}:
        raise PublicProjectionError("Logcat result mode is invalid")
    redaction = source["redaction"]
    if redaction not in {"strict", "standard", "none"}:
        raise PublicProjectionError("Logcat result redaction policy is invalid")
    if source["bounded"] is not True or not isinstance(source["truncated"], bool):
        raise PublicProjectionError("Logcat result is not a bounded response")

    line_count = source["lineCount"]
    redacted_count = source["redactedCount"]
    if (
        not isinstance(line_count, int)
        or isinstance(line_count, bool)
        or not 0 <= line_count <= 10_000
        or not isinstance(redacted_count, int)
        or isinstance(redacted_count, bool)
        or not 0 <= redacted_count <= line_count
    ):
        raise PublicProjectionError("Logcat result counters are invalid")
    lines = _closed_bounded_strings(
        source["lines"],
        maximum_items=10_000,
        maximum_item_utf8_bytes=4_096,
        maximum_utf8_bytes=16 * 1_024 * 1_024,
    )
    if line_count != len(lines) or any(_UNSAFE_LOG_CONTROL.search(line) for line in lines):
        raise PublicProjectionError("Logcat result contains invalid lines")
    text = source["text"]
    if not isinstance(text, str) or text != "\n".join(lines):
        raise PublicProjectionError("Logcat result text does not match its lines")
    text_bytes = text.encode("utf-8")
    if len(text_bytes) > 16 * 1_024 * 1_024 + 10_000:
        raise PublicProjectionError("Logcat result text exceeds its byte limit")

    projected: dict[str, object] = {
        "targetSerial": target_serial,
        "mode": mode,
        "lineCount": line_count,
        "lines": lines,
        "text": text,
        "redaction": redaction,
        "redactedCount": redacted_count,
        "bounded": True,
        "truncated": source["truncated"],
    }
    if "export" in source:
        receipt = _closed_record(
            source["export"],
            fields=frozenset({"fileName", "sha256", "size"}),
        )
        file_name = receipt["fileName"]
        digest = receipt["sha256"]
        size = receipt["size"]
        if (
            not isinstance(file_name, str)
            or not 1 <= len(file_name) <= 255
            or not file_name.isprintable()
            or ntpath.basename(posixpath.basename(file_name.replace("\\", "/")))
            != file_name
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or digest != hashlib.sha256(text_bytes).hexdigest()
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size != len(text_bytes)
        ):
            raise PublicProjectionError("Logcat export receipt is invalid")
        projected["export"] = {
            "fileName": file_name,
            "sha256": digest,
            "size": size,
        }
    return ensure_public_json(projected)


def _project_logcat_clear(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset(
            {
                "targetSerial",
                "buffers",
                "clearCommandCompleted",
                "controlCommandVerified",
                "mainBufferSentinelVerified",
                "verificationEntryRetained",
            }
        ),
    )
    target_serial = source["targetSerial"]
    if not isinstance(target_serial, str) or not is_valid_target_serial(target_serial):
        raise PublicProjectionError("Logcat clear target serial is invalid")
    if source["buffers"] != ["all"]:
        raise PublicProjectionError("Logcat clear buffer receipt is invalid")
    if (
        source["clearCommandCompleted"] is not True
        or source["controlCommandVerified"] is not True
        or source["mainBufferSentinelVerified"] is not True
        or source["verificationEntryRetained"] is not True
    ):
        raise PublicProjectionError("Logcat clear receipt is not verified")
    return ensure_public_json(
        {
            "targetSerial": target_serial,
            "buffers": ["all"],
            "clearCommandCompleted": True,
            "controlCommandVerified": True,
            "mainBufferSentinelVerified": True,
            "verificationEntryRetained": True,
        }
    )


def _project_support(value: object) -> JSONValue:
    source = _record(value)
    return ensure_public_json({
        "status": _string(source.get("status")),
        "code": _string(source.get("code")),
        "fileName": ntpath.basename(posixpath.basename(_string(source.get("fileName")).replace("\\", "/"))),
        "sha256": _string(source.get("sha256")),
        "size": _integer(source.get("size")),
        "includedCount": _integer(source.get("includedCount")),
        "omittedCount": _integer(source.get("omittedCount")),
        "schemaVersion": _integer(source.get("schemaVersion"), default=2),
        "keyId": _string(source.get("keyId")),
    })


def _project_avb_downgrade(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset(
            {
                "artifact",
                "currentSecurityPatch",
                "targetSecurityPatch",
                "verified",
            }
        ),
    )
    artifact = _closed_record(
        source["artifact"],
        fields=frozenset({"sha256", "role"}),
    )
    digest = artifact["sha256"]
    current_patch = source["currentSecurityPatch"]
    target_patch = source["targetSecurityPatch"]
    if (
        not isinstance(digest, str)
        or not _LOWERCASE_SHA256.fullmatch(digest)
        or artifact["role"] != "downgrade:boot"
        or source["verified"] is not True
        or not isinstance(current_patch, str)
        or not isinstance(target_patch, str)
    ):
        raise PublicProjectionError("AVB downgrade artifact receipt is invalid")
    try:
        current_date = date.fromisoformat(current_patch)
        target_date = date.fromisoformat(target_patch)
    except ValueError as error:
        raise PublicProjectionError("AVB downgrade security patch is invalid") from error
    if target_date >= current_date:
        raise PublicProjectionError("AVB downgrade security patch order is invalid")
    return ensure_public_json(
        {
            "artifact": {"sha256": digest, "role": "downgrade:boot"},
            "currentSecurityPatch": current_patch,
            "targetSecurityPatch": target_patch,
            "verified": True,
        }
    )


def _project_binary_xml(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset(
            {
                "format",
                "xml",
                "sha256",
                "sizeBytes",
                "elementCount",
                "attributeCount",
                "bounded",
            }
        ),
    )
    xml = source["xml"]
    digest = source["sha256"]
    size = source["sizeBytes"]
    elements = source["elementCount"]
    attributes = source["attributeCount"]
    if (
        source["format"] != "android-binary-xml"
        or source["bounded"] is not True
        or not isinstance(xml, str)
        or not xml.startswith('<?xml version="1.0" encoding="utf-8"?>\n')
        or not xml.endswith("\n")
        or len(xml.encode("utf-8")) > 4 * 1024 * 1024
        or not isinstance(digest, str)
        or not _LOWERCASE_SHA256.fullmatch(digest)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or not 0 < size <= 8 * 1024 * 1024
        or not isinstance(elements, int)
        or isinstance(elements, bool)
        or not 0 < elements <= 100_000
        or not isinstance(attributes, int)
        or isinstance(attributes, bool)
        or not 0 <= attributes <= 200_000
    ):
        raise PublicProjectionError("binary XML decode receipt is invalid")
    return ensure_public_json(
        {
            "format": "android-binary-xml",
            "xml": xml,
            "sha256": digest,
            "sizeBytes": size,
            "elementCount": elements,
            "attributeCount": attributes,
            "bounded": True,
        }
    )


_BACKUP_PARTITIONS = frozenset(
    {
        "boot",
        "dtbo",
        "init_boot",
        "recovery",
        "vbmeta",
        "vbmeta_system",
        "vbmeta_vendor",
        "vendor_boot",
        "vendor_kernel_boot",
    }
)
_BACKUP_INVENTORY_ISSUES = frozenset(
    {
        "backup_cancelled",
        "backup_empty",
        "backup_hash_mismatch",
        "backup_import_failed",
        "backup_import_cancelled",
        "backup_repository_corrupt",
        "backup_source_invalid",
        "backup_source_changed",
        "backup_source_unavailable",
        "backup_too_large",
    }
)


def _project_backup_record(value: object) -> dict[str, JSONValue]:
    source = _closed_record(
        value,
        fields=frozenset(
            {
                "id",
                "sha256",
                "sizeBytes",
                "createdAt",
                "targetSerial",
                "deviceCodename",
                "partition",
                "slot",
                "targetPartition",
                "provenance",
                "available",
                "integrity",
            }
        ),
    )
    backup_id = source["id"]
    digest = source["sha256"]
    size = source["sizeBytes"]
    created = source["createdAt"]
    serial = source["targetSerial"]
    codename = source["deviceCodename"]
    partition = source["partition"]
    slot = source["slot"]
    available = source["available"]
    if (
        not isinstance(backup_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", backup_id) is None
        or not isinstance(digest, str)
        or _LOWERCASE_SHA256.fullmatch(digest) is None
        or not isinstance(size, int)
        or isinstance(size, bool)
        or not 0 < size <= 1024 * 1024 * 1024
        or not isinstance(created, int)
        or isinstance(created, bool)
        or not 0 <= created <= MAX_MANAGED_DEVICE_TIMESTAMP
        or not isinstance(serial, str)
        or not is_valid_target_serial(serial)
        or not isinstance(codename, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", codename) is None
        or partition not in _BACKUP_PARTITIONS
        or slot not in {"a", "b"}
        or source["targetPartition"] != f"{partition}_{slot}"
        or source["provenance"] not in {"created", "user_supplied"}
        or not isinstance(available, bool)
        or source["integrity"] != ("stored" if available else "missing")
    ):
        raise PublicProjectionError("backup record is invalid")
    return cast(dict[str, JSONValue], ensure_public_json(dict(source)))


def _project_backup_inventory(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset(
            {
                "backups",
                "count",
                "totalCount",
                "filteredSerial",
                "revision",
                "bounded",
                "truncated",
            }
        ),
    )
    raw_backups = source["backups"]
    count = source["count"]
    total = source["totalCount"]
    filtered = source["filteredSerial"]
    if (
        source["bounded"] is not True
        or not isinstance(raw_backups, list)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or not 0 <= count <= 1000
        or len(raw_backups) != count
        or not isinstance(total, int)
        or isinstance(total, bool)
        or total < count
        or source["truncated"] is not (total > count)
        or (
            filtered is not None
            and (not isinstance(filtered, str) or not is_valid_target_serial(filtered))
        )
        or not isinstance(source["revision"], int)
        or isinstance(source["revision"], bool)
        or source["revision"] < 0
    ):
        raise PublicProjectionError("backup inventory is invalid")
    backups = [
        _project_backup_record(item)
        for item in cast("list[object]", raw_backups)
    ]
    if filtered is not None and any(
        backup["targetSerial"] != filtered for backup in backups
    ):
        raise PublicProjectionError("filtered backup inventory is invalid")
    return ensure_public_json(
        {
            "backups": backups,
            "count": count,
            "totalCount": total,
            "filteredSerial": filtered,
            "revision": source["revision"],
            "bounded": True,
            "truncated": total > count,
        }
    )


def _project_backup_result(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset(
            {
                "action",
                "targetSerial",
                "partition",
                "slot",
                "backup",
                "inventoryRegistered",
            }
            | ({"inventoryIssue"} if _record(value).get("action") == "restore" else set())
        ),
    )
    action = source["action"]
    serial = source["targetSerial"]
    partition = source["partition"]
    slot = source["slot"]
    registered = source["inventoryRegistered"]
    if (
        action not in {"create", "restore"}
        or not isinstance(serial, str)
        or not is_valid_target_serial(serial)
        or not isinstance(partition, str)
        or re.fullmatch(r"[a-z0-9_]+_[ab]", partition) is None
        or slot not in {"a", "b"}
        or not partition.endswith(f"_{slot}")
        or not isinstance(registered, bool)
    ):
        raise PublicProjectionError("backup operation receipt is invalid")
    backup_value = source["backup"]
    backup = _project_backup_record(backup_value) if backup_value is not None else None
    if action == "create" and (not registered or backup is None):
        raise PublicProjectionError("created backup must enter managed inventory")
    issue = source.get("inventoryIssue")
    if action == "restore" and (
        (registered and (backup is None or issue is not None))
        or (
            not registered
            and (backup is not None or issue not in _BACKUP_INVENTORY_ISSUES)
        )
    ):
        raise PublicProjectionError("restored backup inventory receipt is invalid")
    result: dict[str, JSONValue] = {
        "action": cast(str, action),
        "targetSerial": serial,
        "partition": partition,
        "slot": cast(str, slot),
        "backup": backup,
        "inventoryRegistered": registered,
    }
    if action == "restore":
        result["inventoryIssue"] = cast(str | None, issue)
    return result


def _project_backup_delete(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset(
            {
                "backupId",
                "deleted",
                "objectRemoved",
                "sharedObjectRetained",
                "objectMissing",
                "cleanupDeferred",
                "revision",
            }
        ),
    )
    backup_id = source["backupId"]
    flags = (
        source["objectRemoved"],
        source["sharedObjectRetained"],
        source["objectMissing"],
        source["cleanupDeferred"],
    )
    if (
        not isinstance(backup_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", backup_id) is None
        or source["deleted"] is not True
        or any(not isinstance(flag, bool) for flag in flags)
        or sum(flags) != 1
        or not isinstance(source["revision"], int)
        or isinstance(source["revision"], bool)
        or source["revision"] < 0
    ):
        raise PublicProjectionError("backup deletion receipt is invalid")
    return ensure_public_json(dict(source))


def _project_magisk_backup_inventory(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset({"action", "targetSerial", "count", "backups", "bounded"}),
    )
    serial = source["targetSerial"]
    raw_backups = source["backups"]
    count = source["count"]
    if (
        source["action"] != "list"
        or not isinstance(serial, str)
        or not is_valid_target_serial(serial)
        or source["bounded"] is not True
        or not isinstance(raw_backups, list)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or not 0 <= count <= 256
        or len(raw_backups) != count
    ):
        raise PublicProjectionError("Magisk backup inventory is invalid")
    backups: list[dict[str, JSONValue]] = []
    seen: set[str] = set()
    for raw in cast("list[object]", raw_backups):
        item = _closed_record(
            raw,
            fields=frozenset({"sha1", "sizeBytes", "createdAt", "integrity"}),
        )
        sha1 = item["sha1"]
        size = item["sizeBytes"]
        created = item["createdAt"]
        if (
            not isinstance(sha1, str)
            or re.fullmatch(r"[0-9a-f]{40}", sha1) is None
            or sha1 in seen
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= 1024 * 1024 * 1024
            or not isinstance(created, int)
            or isinstance(created, bool)
            or not 0 <= created <= 4_294_967_295
            or item["integrity"] not in {"verified", "corrupt"}
        ):
            raise PublicProjectionError("Magisk backup record is invalid")
        backups.append(cast(dict[str, JSONValue], ensure_public_json(dict(item))))
        seen.add(sha1)
    return ensure_public_json(
        {
            "action": "list",
            "targetSerial": serial,
            "count": count,
            "backups": backups,
            "bounded": True,
        }
    )


def _project_magisk_backup_mutation(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset({"action", "targetSerial", "sha1", "verified"}),
    )
    if (
        source["action"] not in {"import", "delete"}
        or not isinstance(source["targetSerial"], str)
        or not is_valid_target_serial(source["targetSerial"])
        or not isinstance(source["sha1"], str)
        or re.fullmatch(r"[0-9a-f]{40}", source["sha1"]) is None
        or source["verified"] is not True
    ):
        raise PublicProjectionError("Magisk backup mutation receipt is invalid")
    return ensure_public_json(dict(source))


_KEYBOX_STATUSES = frozenset(
    {"valid", "unverified", "revoked", "expired", "software_attestation", "invalid"}
)
_KEYBOX_ISSUES = frozenset(
    {
        "algorithm_key_type_mismatch",
        "certificate_count_mismatch",
        "certificate_expired_or_not_yet_valid",
        "certificate_expiring_soon",
        "certificate_hash_algorithm_invalid",
        "certificate_issuer_mismatch",
        "certificate_revoked",
        "certificate_signature_invalid",
        "file_too_large",
        "invalid_certificate",
        "invalid_certificate_count",
        "invalid_certificate_structure",
        "invalid_chain_attributes",
        "invalid_device_id",
        "invalid_key_attributes",
        "invalid_keybox_children",
        "invalid_keybox_count",
        "invalid_keybox_structure",
        "invalid_pem_encoding",
        "invalid_pem_size",
        "invalid_private_key",
        "invalid_root",
        "missing_or_duplicate_algorithms",
        "missing_pem",
        "missing_private_key_or_chain",
        "private_key_mismatch",
        "revocation_evidence_invalid",
        "revocation_evidence_unavailable",
        "root_not_self_issued",
        "software_attestation_detected",
        "source_not_bytes",
        "unsafe_or_empty_xml",
        "unsupported_algorithm",
        "unsupported_certificate_key",
        "xml_node_limit_exceeded",
        "xml_parse_failed",
    }
)


def _project_keybox_analysis(value: object) -> JSONValue:
    source = _closed_record(
        value,
        fields=frozenset({"reports", "count", "summary", "revocationEvidence", "bounded"}),
    )
    reports_value = source["reports"]
    count = source["count"]
    if (
        source["bounded"] is not True
        or not isinstance(count, int)
        or isinstance(count, bool)
        or not 1 <= count <= 32
        or not isinstance(reports_value, list)
        or len(reports_value) != count
    ):
        raise PublicProjectionError("keybox analysis receipt is invalid")
    report_values = cast("list[object]", reports_value)
    reports: list[dict[str, JSONValue]] = []
    computed = {status: 0 for status in _KEYBOX_STATUSES}
    for value_item in report_values:
        item = _closed_record(
            value_item,
            fields=frozenset(
                {
                    "displayName",
                    "sha256",
                    "sizeBytes",
                    "status",
                    "structureValid",
                    "cryptographicValid",
                    "keyboxCount",
                    "algorithms",
                    "certificateCount",
                    "expired",
                    "expiringSoon",
                    "softwareAttestation",
                    "revocationStatus",
                    "issues",
                }
            ),
        )
        display_name = item["displayName"]
        status = item["status"]
        algorithms = item["algorithms"]
        issues = item["issues"]
        if (
            not isinstance(display_name, str)
            or not display_name
            or len(display_name) > 255
            or ntpath.basename(posixpath.basename(display_name.replace("\\", "/"))) != display_name
            or not display_name.isprintable()
            or not isinstance(item["sha256"], str)
            or not _LOWERCASE_SHA256.fullmatch(item["sha256"])
            or not isinstance(item["sizeBytes"], int)
            or isinstance(item["sizeBytes"], bool)
            or not 0 <= item["sizeBytes"] <= 4 * 1024 * 1024
            or status not in _KEYBOX_STATUSES
            or not isinstance(item["structureValid"], bool)
            or not isinstance(item["cryptographicValid"], bool)
            or not isinstance(item["keyboxCount"], int)
            or isinstance(item["keyboxCount"], bool)
            or not 0 <= item["keyboxCount"] <= 16
            or not isinstance(algorithms, list)
            or algorithms not in ([], ["ecdsa", "rsa"])
            or not isinstance(item["certificateCount"], int)
            or isinstance(item["certificateCount"], bool)
            or not 0 <= item["certificateCount"] <= 192
            or not isinstance(item["expired"], bool)
            or not isinstance(item["expiringSoon"], bool)
            or not isinstance(item["softwareAttestation"], bool)
            or item["revocationStatus"] not in {"clear", "revoked", "unverified"}
            or not isinstance(issues, list)
            or len(cast("list[object]", issues)) > 32
            or any(
                issue not in _KEYBOX_ISSUES for issue in cast("list[object]", issues)
            )
        ):
            raise PublicProjectionError("keybox report is invalid")
        computed[cast(str, status)] += 1
        reports.append(cast(dict[str, JSONValue], ensure_public_json(dict(item))))

    summary = _closed_record(
        source["summary"],
        fields=frozenset(
            {"valid", "unverified", "revoked", "expired", "softwareAttestation", "invalid"}
        ),
    )
    expected_summary = {
        "valid": computed["valid"],
        "unverified": computed["unverified"],
        "revoked": computed["revoked"],
        "expired": computed["expired"],
        "softwareAttestation": computed["software_attestation"],
        "invalid": computed["invalid"],
    }
    if summary != expected_summary:
        raise PublicProjectionError("keybox summary is invalid")

    evidence_value = source["revocationEvidence"]
    evidence: dict[str, JSONValue] | None = None
    if evidence_value is not None:
        raw_evidence = _closed_record(
            evidence_value,
            fields=frozenset({"sourceId", "keyId", "issuedAt", "expiresAt", "authenticated"}),
        )
        source_id = raw_evidence["sourceId"]
        key_id = raw_evidence["keyId"]
        if (
            raw_evidence["authenticated"] is not True
            or not isinstance(source_id, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", source_id)
            or not isinstance(key_id, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", key_id)
        ):
            raise PublicProjectionError("keybox revocation evidence is invalid")
        try:
            issued_at = datetime.fromisoformat(_string(raw_evidence["issuedAt"]))
            expires_at = datetime.fromisoformat(_string(raw_evidence["expiresAt"]))
        except ValueError as error:
            raise PublicProjectionError("keybox revocation evidence is invalid") from error
        if (
            issued_at.tzinfo is None
            or expires_at.tzinfo is None
            or expires_at <= issued_at
            or expires_at - issued_at > timedelta(days=31)
        ):
            raise PublicProjectionError("keybox revocation evidence is invalid")
        evidence = cast(dict[str, JSONValue], ensure_public_json(dict(raw_evidence)))
    elif expected_summary["valid"] or expected_summary["revoked"]:
        raise PublicProjectionError("verified keybox status requires revocation evidence")
    return ensure_public_json(
        {
            "reports": reports,
            "count": count,
            "summary": expected_summary,
            "revocationEvidence": evidence,
            "bounded": True,
        }
    )
def _project_native_grant(value: object) -> JSONValue:
    source = _record(value)
    data = source.get("data", source)
    if isinstance(data, Mapping):
        values = _record(cast(object, data))
        if "grants" in values:
            return {"grants": [_public_grant(item) for item in _array(values.get("grants", []))]}
        if "grant" in values:
            return {"grant": _public_grant(values.get("grant"))}
    return None


def _public_grant(value: object) -> dict[str, JSONValue]:
    source = _record(value)
    raw_expiry = source.get("expiresInSeconds")
    expiry = raw_expiry if isinstance(raw_expiry, int) and not isinstance(raw_expiry, bool) else None
    return _public_object({
        "grant": _string(source.get("grant")),
        "purpose": _string(source.get("purpose")),
        "target": _string(source.get("target")),
        "access": _string(source.get("access")),
        "consumeOnce": _boolean(source.get("consumeOnce")),
        "expiresInSeconds": expiry,
        "displayName": ntpath.basename(posixpath.basename(_string(source.get("displayName")).replace("\\", "/"))),
    })


# Every callable command has an explicit owner at the output boundary.  Reusing
# a projector is deliberate; adding a registry command without choosing one is
# an import-time error in CI and production.
PUBLIC_RESULT_PROJECTORS: dict[str, ResultProjector] = {
    "app.ready": _project_none,
    "apps.action": _project_apps_action,
    "apps.list": _project_apps_list,
    "backups.create": _project_backup_result,
    "backups.delete": _project_backup_delete,
    "backups.list": _project_backup_inventory,
    "backups.magisk.list": _project_magisk_backup_inventory,
    "backups.magisk.import": _project_magisk_backup_mutation,
    "backups.magisk.delete": _project_magisk_backup_mutation,
    "backups.restore": _project_backup_result,
    "boot.flash": _project_confirmation,
    "boot.delete": _project_boot_delete,
    "boot.inventory": _project_boot_inventory,
    "boot.live": _project_confirmation,
    "boot.patch": _project_boot_patch,
    "boot.select": _project_boot_select,
    "device.bootloader.lock": _project_confirmation,
    "device.bootloader.unlock": _project_confirmation,
    "device.inspect": _project_device_inspect,
    "device.manager.policy": _project_snapshot,
    "device.manager.remove": _project_snapshot,
    "device.manager.update": _project_snapshot,
    "device.openUrl": _project_device_open_url,
    "device.ota.certificates": _project_ota_certificates,
    "device.ota.logs": _project_ota_logs,
    "device.ota.status": _project_ota_status,
    "firmware.catalog.refresh": _project_firmware_catalog,
    "firmware.download": _project_firmware_download,
    "device.reboot": _project_none,
    "device.scan": _project_device_scan,
    "device.select": _project_snapshot,
    "device.switchSlot": _project_confirmation,
    "firmware.process": _project_firmware_process,
    "firmware.select": _project_firmware_select,
    "flash.execute": _project_flash_execute,
    "flash.plan.preview": _project_plan_preview,
    "flash.plan.update": _project_snapshot,
    "interaction.respond": _project_none,
    "native.pickDirectory": _project_native_grant,
    "native.pickFile": _project_native_grant,
    "native.pickFiles": _project_native_grant,
    "native.saveFile": _project_native_grant,
    "operation.cancel": _project_none,
    "partitions.erase": _project_confirmation,
    "partitions.list": _project_partitions,
    "partitions.read": _project_none,
    "partitions.write": _project_none,
    "platformTools.setup": _project_platform_tools_setup,
    "root.apps.install": _project_none,
    "root.apps.catalog.refresh": _project_root_app_catalog,
    "root.apps.download": _project_root_app_download,
    "root.apps.list": _project_root_apps,
    "root.dataAdb.backup": _project_data_adb_backup,
    "root.dataAdb.restore": _project_data_adb_restore,
    "root.dataAdb.clear": _project_data_adb_clear,
    "root.modules.action": _project_root_module_action,
    "root.modules.list": _project_root_modules,
    "secret.issue": _project_native_grant,
    "settings.get": _project_preferences,
    "settings.update": _project_preferences,
    "snapshot.get": _project_snapshot,
    "support.create": _project_support,
    "tools.logcat": _project_logcat,
    "tools.logcat.clear": _project_logcat_clear,
    "tools.pushFiles": _project_push_files,
    "tools.avb": _project_avb_downgrade,
    "tools.xml": _project_binary_xml,
    "tools.keybox": _project_keybox_analysis,
    "tools.shizuku": _project_shizuku_recovery,
    "tools.sos": _project_sos_recovery,
    "tools.scrcpy": _project_none,
    "tools.scrcpy.setup": _project_scrcpy_setup,
    "tools.wifi": _project_none,
    "tools.wifi.status": _project_none,
    "tools.wifi.discover": _project_wifi_discovery,
}

if frozenset(PUBLIC_RESULT_PROJECTORS) != ALLOWED_COMMANDS:
    missing = sorted(ALLOWED_COMMANDS - frozenset(PUBLIC_RESULT_PROJECTORS))
    extra = sorted(frozenset(PUBLIC_RESULT_PROJECTORS) - ALLOWED_COMMANDS)
    raise RuntimeError(f"public bridge projector registry mismatch: missing={missing}, extra={extra}")


__all__ = [
    "PUBLIC_RESULT_PROJECTORS",
    "PublicProjectionError",
    "ensure_public_json",
    "project_operation_result",
    "public_operation_summary",
    "public_snapshot",
    "safe_public_message",
]
