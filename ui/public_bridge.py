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
from typing import cast

from pixelflasher_core import AppSnapshot, OperationResult, is_valid_target_serial
from ui.command_registry import ALLOWED_COMMANDS

JSONScalar = None | bool | int | float | str
JSONValue = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
ResultProjector = Callable[[object], JSONValue | None]
_STRICT_STRUCTURED_RESULTS = frozenset(
    {
        "tools.logcat",
        "tools.logcat.clear",
        "tools.pushFiles",
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


def _project_firmware_select(value: object) -> JSONValue:
    source = _record(value)
    inspection = _record(source.get("inspection", {}))
    return ensure_public_json({
        "snapshot": public_snapshot(source.get("snapshot")),
        "inspection": {
            "type": _string(inspection.get("type")),
            "sha256": _string(inspection.get("sha256")),
            "build": _string(inspection.get("build")),
            "device": _string(inspection.get("device")),
            "code": _string(inspection.get("code")),
            "ok": _boolean(inspection.get("ok")),
        },
    })


def _project_firmware_process(value: object) -> JSONValue:
    source = _record(value)
    processing = _record(source.get("processing", {}))
    inspection = _record(processing.get("inspection", {}))
    artifacts = [
        item
        for raw in _array(processing.get("artifacts", []))
        if (item := _public_artifact(raw)) is not None
    ]
    return ensure_public_json({
        "processing": {
            "status": _string(processing.get("status")),
            "code": _string(processing.get("code")),
            "inspection": {
                "type": _string(inspection.get("type")),
                "sha256": _string(inspection.get("sha256")),
                "build": _string(inspection.get("build")),
                "device": _string(inspection.get("device")),
                "code": _string(inspection.get("code")),
                "ok": _boolean(inspection.get("ok")),
            },
            "artifacts": artifacts,
            "detectedDevices": _strings(processing.get("detectedDevices", [])),
            "registered": _boolean(processing.get("registered")),
        },
        "firmware": _public_firmware(source.get("firmware")),
        "boot": _public_boot(source.get("boot")),
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
    return ensure_public_json({
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
    })


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
    source = _record(value)
    result: dict[str, JSONValue] = {"action": _string(source.get("action"))}
    if source.get("apkIdentity") is not None:
        identity = _record(source.get("apkIdentity"))
        result["apkIdentity"] = ensure_public_json({
            "packageName": _string(identity.get("packageName")),
            "sha256": _string(identity.get("sha256")),
            "signerSha256": _strings(identity.get("signerSha256", [])),
            "schemes": _strings(identity.get("schemes", [])),
            "verified": _boolean(identity.get("verified")),
        })
    return result


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


def _project_root_apps(value: object) -> JSONValue:
    source = _record(value)
    apps: list[dict[str, object]] = []
    for raw in _array(source.get("apps", [])):
        app = _record(raw)
        apps.append(
            {
                "id": _string(app.get("id")),
                "provider": _string(app.get("provider")),
                "flavor": _string(app.get("flavor")),
                "version": _string(app.get("version")),
                "sha256": _string(app.get("sha256")),
                "provenance": _string(app.get("provenance")),
            }
        )
    return ensure_public_json({"count": len(apps), "apps": apps})


def _project_root_modules(value: object) -> JSONValue:
    source = _record(value)
    modules = [
        {"id": _string(_record(raw).get("id"))}
        for raw in _array(source.get("modules", []))
    ]
    return ensure_public_json({"count": len(modules), "modules": modules})


def _project_root_module_action(value: object) -> JSONValue:
    source = _record(value)
    return ensure_public_json({
        "action": _string(source.get("action")),
        "targetSerial": _optional_string(source.get("targetSerial")),
        "moduleId": _string(source.get("moduleId")),
    })


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
        result.update(
            _public_object({
                "source": _string(source.get("source")),
                "current": _string(source.get("current")),
                "slot": _string(source.get("slot")),
                "versions": _string_map(source.get("versions", {})),
            })
        )
    elif action == "pifPrint":
        result.update(
            _public_object({
                "format": _string(source.get("format")),
                "profile": _string_map(source.get("profile", {})),
            })
        )
    return result


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
    "backups.create": _project_none,
    "backups.restore": _project_none,
    "boot.flash": _project_confirmation,
    "boot.inventory": _project_boot_inventory,
    "boot.live": _project_confirmation,
    "boot.patch": _project_boot_patch,
    "boot.select": _project_boot_select,
    "device.bootloader.lock": _project_confirmation,
    "device.bootloader.unlock": _project_confirmation,
    "device.inspect": _project_device_inspect,
    "device.ota.certificates": _project_ota_certificates,
    "device.ota.logs": _project_ota_logs,
    "device.reboot": _project_none,
    "device.scan": _project_device_scan,
    "device.select": _project_snapshot,
    "device.switchSlot": _project_confirmation,
    "firmware.process": _project_firmware_process,
    "firmware.select": _project_firmware_select,
    "flash.execute": _project_confirmation,
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
    "root.apps.list": _project_root_apps,
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
    "tools.scrcpy": _project_none,
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
