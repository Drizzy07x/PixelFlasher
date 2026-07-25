"""Dependency-free schemas for packaged smoke receipts.

This module intentionally supports the Python 3.10 runtime shipped by Ubuntu
22.04 so release artifacts can be verified in a clean system container without
importing the Python 3.12+ application runtime.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

PTY_SMOKE_SCHEMA_VERSION = 1
PTY_SMOKE_MAXIMUM_OUTPUT_BYTES = 64 * 1024
LEGACY_RAW_SMOKE_SCHEMA_VERSION = 2
LEGACY_RAW_SMOKE_MAXIMUM_OUTPUT_BYTES = 64 * 1024


class PtySmokeError(ValueError):
    """The packaged PTY probe or its closed receipt is invalid."""


class LegacyRawSmokeError(ValueError):
    """The packaged Legacy Raw probe or its receipt is invalid."""


def _load_json_object(path: Path, *, error_type: type[ValueError], label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise error_type(f"{label} is missing or invalid JSON") from exc
    if not isinstance(value, dict):
        raise error_type(f"{label} must be a JSON object")
    return cast(dict[str, Any], value)


def _valid_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def validate_pty_smoke_receipt(
    receipt: dict[str, Any],
    *,
    expected_platform: str | None = None,
    expected_architecture: str | None = None,
) -> dict[str, Any]:
    expected_keys = {
        "schemaVersion",
        "status",
        "applicationVersion",
        "platform",
        "architecture",
        "processBits",
        "backend",
        "probeExecutable",
        "outputBytes",
        "outputSha256",
        "exitCode",
        "outputObserved",
        "cleanShutdown",
    }
    if set(receipt) != expected_keys:
        raise PtySmokeError("PTY receipt fields do not match the closed schema")
    if receipt.get("schemaVersion") != PTY_SMOKE_SCHEMA_VERSION or receipt.get("status") != "passed":
        raise PtySmokeError("PTY receipt status or schema is invalid")
    if not isinstance(receipt.get("applicationVersion"), str) or not receipt["applicationVersion"]:
        raise PtySmokeError("PTY receipt application version is invalid")
    if receipt.get("processBits") not in {32, 64}:
        raise PtySmokeError("PTY receipt process width is invalid")
    platform_name = receipt.get("platform")
    backend = receipt.get("backend")
    executable = receipt.get("probeExecutable")
    if platform_name == "windows":
        if backend != "conpty" or executable != "whoami.exe":
            raise PtySmokeError("Windows PTY receipt did not prove ConPTY")
    elif platform_name in {"macos", "linux"}:
        if backend != "posix-pty" or executable != "id":
            raise PtySmokeError("POSIX PTY receipt did not prove the native PTY")
    else:
        raise PtySmokeError("PTY receipt platform is invalid")
    size = receipt.get("outputBytes")
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or not 1 <= size <= PTY_SMOKE_MAXIMUM_OUTPUT_BYTES
        or not _valid_digest(receipt.get("outputSha256"))
    ):
        raise PtySmokeError("PTY receipt output evidence is invalid")
    if receipt.get("exitCode") != 0 or receipt.get("outputObserved") is not True:
        raise PtySmokeError("PTY process completion was not proven")
    if receipt.get("cleanShutdown") is not True:
        raise PtySmokeError("PTY clean shutdown was not proven")
    if expected_platform is not None and platform_name != expected_platform:
        raise PtySmokeError(f"expected platform {expected_platform!r}, got {platform_name!r}")
    if expected_architecture is not None and receipt.get("architecture") != expected_architecture:
        raise PtySmokeError(
            f"expected architecture {expected_architecture!r}, got {receipt.get('architecture')!r}"
        )
    return dict(receipt)


def load_pty_smoke_receipt(path: Path) -> dict[str, Any]:
    return _load_json_object(path, error_type=PtySmokeError, label="PTY smoke receipt")


def validate_legacy_raw_smoke_receipt(
    receipt: dict[str, Any],
    *,
    expected_platform: str | None = None,
    expected_architecture: str | None = None,
) -> dict[str, Any]:
    expected_keys = {
        "schemaVersion",
        "status",
        "applicationVersion",
        "platform",
        "architecture",
        "processBits",
        "shell",
        "probeExecutable",
        "outputBytes",
        "outputSha256",
        "safeArgvProbe",
        "safeArgvOutputBytes",
        "safeArgvOutputSha256",
        "safeArgvProfileReloaded",
        "safeArgvNoShell",
        "safeArgvCompleted",
        "persistentPermission",
        "incorrectPermissionRejected",
        "incorrectRunRejected",
        "exactRunCompleted",
        "cleanShutdown",
    }
    if set(receipt) != expected_keys:
        raise LegacyRawSmokeError("Legacy Raw receipt fields do not match the closed schema")
    if (
        receipt.get("schemaVersion") != LEGACY_RAW_SMOKE_SCHEMA_VERSION
        or receipt.get("status") != "passed"
        or not isinstance(receipt.get("applicationVersion"), str)
        or not receipt["applicationVersion"]
        or receipt.get("processBits") not in {32, 64}
    ):
        raise LegacyRawSmokeError("Legacy Raw receipt identity is invalid")
    platform_name = receipt.get("platform")
    expected_shell = "cmd" if platform_name == "windows" else "zsh" if platform_name == "macos" else "sh"
    if platform_name not in {"windows", "macos", "linux"}:
        raise LegacyRawSmokeError("Legacy Raw receipt platform is invalid")
    if (
        receipt.get("shell") != expected_shell
        or receipt.get("probeExecutable") != ("whoami.exe" if platform_name == "windows" else "id")
    ):
        raise LegacyRawSmokeError("Legacy Raw receipt did not prove the native host shell")
    if receipt.get("safeArgvProbe") != (
        "whoami-user" if platform_name == "windows" else "id-effective-user"
    ):
        raise LegacyRawSmokeError("personal tools receipt did not prove the native safe argv probe")
    for size_field, digest_field, label in (
        ("outputBytes", "outputSha256", "Legacy Raw receipt"),
        ("safeArgvOutputBytes", "safeArgvOutputSha256", "safe argv receipt"),
    ):
        size = receipt.get(size_field)
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 1 <= size <= LEGACY_RAW_SMOKE_MAXIMUM_OUTPUT_BYTES
            or not _valid_digest(receipt.get(digest_field))
        ):
            raise LegacyRawSmokeError(f"{label} output evidence is invalid")
    for field in (
        "safeArgvProfileReloaded",
        "safeArgvNoShell",
        "safeArgvCompleted",
        "persistentPermission",
        "incorrectPermissionRejected",
        "incorrectRunRejected",
        "exactRunCompleted",
        "cleanShutdown",
    ):
        if receipt.get(field) is not True:
            raise LegacyRawSmokeError(f"Legacy Raw receipt did not prove {field}")
    if expected_platform is not None and platform_name != expected_platform:
        raise LegacyRawSmokeError(f"expected platform {expected_platform!r}, got {platform_name!r}")
    if expected_architecture is not None and receipt.get("architecture") != expected_architecture:
        raise LegacyRawSmokeError(
            f"expected architecture {expected_architecture!r}, got {receipt.get('architecture')!r}"
        )
    return dict(receipt)


def load_legacy_raw_smoke_receipt(path: Path) -> dict[str, Any]:
    return _load_json_object(
        path,
        error_type=LegacyRawSmokeError,
        label="Legacy Raw smoke receipt",
    )

