"""Closed receipt contract for packaged PixelFlasher UI smoke tests."""

from __future__ import annotations

import json
import os
import platform
import struct
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from constants import VERSION

UI_SMOKE_SCHEMA_VERSION = 2
UI_SMOKE_BRIDGE_VERSION = 2
UI_SMOKE_TASK_ROUTES = (
    "dashboard",
    "device",
    "flash",
    "firmware",
    "root",
    "apps",
    "backups",
    "tools",
    "settings",
)


class UiSmokeReceiptError(ValueError):
    """Raised when a UI smoke receipt is missing or violates its contract."""


def normalized_platform() -> str:
    value = platform.system().casefold()
    if value == "windows":
        return "windows"
    if value == "darwin":
        return "macos"
    if value == "linux":
        return "linux"
    return value or "unknown"


def normalized_architecture() -> str:
    value = platform.machine().strip().casefold().replace("-", "_")
    if value in {"amd64", "x86_64", "x64"}:
        return "x86_64"
    if value in {"arm64", "aarch64"}:
        return "arm64"
    return value or "unknown"


def create_ui_smoke_receipt(
    *,
    bridge_revision: int,
    journey: Mapping[str, Any],
) -> dict[str, Any]:
    if isinstance(bridge_revision, bool) or not isinstance(bridge_revision, int):
        raise UiSmokeReceiptError("bridge revision must be an integer")
    journey_fields = {
        "taskRoutes",
        "keyboardRouteNavigation",
        "focusTransferredToHeading",
        "persistentDocument",
    }
    if set(journey) != journey_fields:
        raise UiSmokeReceiptError("UI journey fields do not match the closed schema")
    routes = journey.get("taskRoutes")
    if not isinstance(routes, (list, tuple)) or tuple(routes) != UI_SMOKE_TASK_ROUTES:
        raise UiSmokeReceiptError("UI journey did not visit every task route in order")
    for field in (
        "keyboardRouteNavigation",
        "focusTransferredToHeading",
        "persistentDocument",
    ):
        if journey.get(field) is not True:
            raise UiSmokeReceiptError(f"UI journey did not prove {field}")
    return {
        "schemaVersion": UI_SMOKE_SCHEMA_VERSION,
        "status": "ready",
        "applicationVersion": VERSION,
        "bridgeVersion": UI_SMOKE_BRIDGE_VERSION,
        "bridgeRevision": bridge_revision,
        "platform": normalized_platform(),
        "architecture": normalized_architecture(),
        "processBits": struct.calcsize("P") * 8,
        "frontend": "bundled-react",
        "webviewReady": True,
        "taskRoutes": list(UI_SMOKE_TASK_ROUTES),
        "keyboardRouteNavigation": True,
        "focusTransferredToHeading": True,
        "persistentDocument": True,
        "cleanShutdown": True,
    }


def validate_ui_smoke_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_platform: str | None = None,
    expected_architecture: str | None = None,
) -> dict[str, Any]:
    expected_keys = {
        "schemaVersion",
        "status",
        "applicationVersion",
        "bridgeVersion",
        "bridgeRevision",
        "platform",
        "architecture",
        "processBits",
        "frontend",
        "webviewReady",
        "taskRoutes",
        "keyboardRouteNavigation",
        "focusTransferredToHeading",
        "persistentDocument",
        "cleanShutdown",
    }
    if set(receipt) != expected_keys:
        raise UiSmokeReceiptError("receipt fields do not match the closed schema")
    if receipt.get("schemaVersion") != UI_SMOKE_SCHEMA_VERSION:
        raise UiSmokeReceiptError("unsupported UI smoke receipt schema")
    if receipt.get("status") != "ready":
        raise UiSmokeReceiptError("React did not reach the ready state")
    if receipt.get("bridgeVersion") != UI_SMOKE_BRIDGE_VERSION:
        raise UiSmokeReceiptError("bridge v2 handshake was not proven")
    revision = receipt.get("bridgeRevision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise UiSmokeReceiptError("bridge revision is invalid")
    if not isinstance(receipt.get("applicationVersion"), str) or not receipt["applicationVersion"]:
        raise UiSmokeReceiptError("application version is missing")
    if receipt.get("frontend") != "bundled-react":
        raise UiSmokeReceiptError("bundled React frontend was not proven")
    if receipt.get("webviewReady") is not True:
        raise UiSmokeReceiptError("WebView readiness was not proven")
    routes = receipt.get("taskRoutes")
    if not isinstance(routes, list) or tuple(routes) != UI_SMOKE_TASK_ROUTES:
        raise UiSmokeReceiptError("all task routes were not proven")
    if receipt.get("keyboardRouteNavigation") is not True:
        raise UiSmokeReceiptError("keyboard route navigation was not proven")
    if receipt.get("focusTransferredToHeading") is not True:
        raise UiSmokeReceiptError("route focus transfer was not proven")
    if receipt.get("persistentDocument") is not True:
        raise UiSmokeReceiptError("persistent React document was not proven")
    if receipt.get("cleanShutdown") is not True:
        raise UiSmokeReceiptError("clean shutdown was not proven")
    if receipt.get("processBits") not in {32, 64}:
        raise UiSmokeReceiptError("process architecture width is invalid")
    if expected_platform is not None and receipt.get("platform") != expected_platform:
        raise UiSmokeReceiptError(
            f"expected platform {expected_platform!r}, got {receipt.get('platform')!r}"
        )
    if expected_architecture is not None and receipt.get("architecture") != expected_architecture:
        raise UiSmokeReceiptError(
            f"expected architecture {expected_architecture!r}, got {receipt.get('architecture')!r}"
        )
    return dict(receipt)


def load_ui_smoke_receipt(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UiSmokeReceiptError("UI smoke receipt is missing or invalid JSON") from exc
    if not isinstance(payload, dict):
        raise UiSmokeReceiptError("UI smoke receipt must be a JSON object")
    return payload


def write_ui_smoke_receipt(
    path: Path,
    *,
    bridge_revision: int,
    journey: Mapping[str, Any],
) -> dict[str, Any]:
    destination = path.expanduser().absolute()
    parent = destination.parent
    if destination.exists() and destination.is_symlink():
        raise UiSmokeReceiptError("UI smoke receipt destination cannot be a symlink")
    if not parent.is_dir() or parent.is_symlink():
        raise UiSmokeReceiptError("UI smoke receipt parent must be a real directory")

    receipt = create_ui_smoke_receipt(
        bridge_revision=bridge_revision,
        journey=journey,
    )
    payload = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        try:
            directory_descriptor = os.open(parent, os.O_RDONLY)
        except OSError:
            directory_descriptor = None
        if directory_descriptor is not None:
            try:
                os.fsync(directory_descriptor)
            except OSError:
                pass
            finally:
                os.close(directory_descriptor)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return receipt


__all__ = [
    "UI_SMOKE_BRIDGE_VERSION",
    "UI_SMOKE_SCHEMA_VERSION",
    "UI_SMOKE_TASK_ROUTES",
    "UiSmokeReceiptError",
    "create_ui_smoke_receipt",
    "load_ui_smoke_receipt",
    "normalized_architecture",
    "normalized_platform",
    "validate_ui_smoke_receipt",
    "write_ui_smoke_receipt",
]
