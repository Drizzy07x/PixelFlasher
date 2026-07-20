"""Closed, hardware-free packaged firmware smoke for PixelFlasher 10."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import struct
import tempfile
import zipfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from constants import VERSION
from pixelflasher_core import ApplicationRuntime, InteractionDecision
from ui.bridge_contract import BRIDGE_VERSION, BridgeRequest
from ui.core_command_factory import create_command_factory
from ui_smoke_contract import normalized_architecture, normalized_platform

FIRMWARE_SMOKE_SCHEMA_VERSION = 1


class FirmwareSmokeError(RuntimeError):
    """Raised when the packaged firmware cycle cannot prove every boundary."""


def _archive(entries: tuple[tuple[str, bytes], ...]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    return stream.getvalue()


def _write_factory_fixture(path: Path) -> str:
    inner = _archive(
        (
            ("boot.img", b"ANDROID!packaged smoke boot"),
            ("init_boot.img", b"ANDROID!packaged smoke init boot"),
            ("vbmeta.img", b"packaged smoke vbmeta"),
        )
    )
    payload = _archive(
        (
            ("flash-all.sh", b"never execute fixture scripts"),
            ("image-husky-SMOKE.10.0.0.zip", inner),
        )
    )
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _request(
    command: str,
    *,
    request_id: str,
    revision: int,
    payload: Mapping[str, object] | None = None,
) -> BridgeRequest:
    return BridgeRequest.from_json(
        json.dumps(
            {
                "version": BRIDGE_VERSION,
                "requestId": request_id,
                "command": command,
                "payload": dict(payload or {}),
                "expectedRevision": revision,
            },
            separators=(",", ":"),
        )
    )


def create_firmware_smoke_receipt(
    *,
    firmware_sha256: str,
    select_code: str,
    process_code: str,
    trust_status: str,
    boot_flavor: str,
    boot_sha256: str,
) -> dict[str, Any]:
    receipt = {
        "schemaVersion": FIRMWARE_SMOKE_SCHEMA_VERSION,
        "status": "ready",
        "applicationVersion": VERSION,
        "bridgeVersion": BRIDGE_VERSION,
        "platform": normalized_platform(),
        "architecture": normalized_architecture(),
        "processBits": struct.calcsize("P") * 8,
        "fixture": "generated-factory-zip",
        "grantBoundary": True,
        "confirmationBound": True,
        "selectCode": select_code,
        "processCode": process_code,
        "trustStatus": trust_status,
        "firmwareSha256": firmware_sha256,
        "firmwareProcessed": True,
        "bootFlavor": boot_flavor,
        "bootSha256": boot_sha256,
        "cleanShutdown": True,
    }
    return validate_firmware_smoke_receipt(receipt)


def validate_firmware_smoke_receipt(
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
        "platform",
        "architecture",
        "processBits",
        "fixture",
        "grantBoundary",
        "confirmationBound",
        "selectCode",
        "processCode",
        "trustStatus",
        "firmwareSha256",
        "firmwareProcessed",
        "bootFlavor",
        "bootSha256",
        "cleanShutdown",
    }
    if set(receipt) != expected_keys:
        raise FirmwareSmokeError("receipt fields do not match the closed schema")
    if receipt.get("schemaVersion") != FIRMWARE_SMOKE_SCHEMA_VERSION:
        raise FirmwareSmokeError("unsupported firmware smoke receipt schema")
    if receipt.get("status") != "ready" or receipt.get("fixture") != "generated-factory-zip":
        raise FirmwareSmokeError("the generated firmware cycle was not proven")
    if receipt.get("bridgeVersion") != BRIDGE_VERSION:
        raise FirmwareSmokeError("bridge v2 was not proven")
    if receipt.get("grantBoundary") is not True or receipt.get("confirmationBound") is not True:
        raise FirmwareSmokeError("grant or confirmation boundary was not proven")
    if receipt.get("selectCode") != "firmware_selected":
        raise FirmwareSmokeError("firmware selection was not proven")
    if receipt.get("processCode") != "firmware_processed":
        raise FirmwareSmokeError("firmware processing was not proven")
    if receipt.get("trustStatus") != "user_confirmed":
        raise FirmwareSmokeError("hash-bound local firmware trust was not proven")
    if receipt.get("firmwareProcessed") is not True or receipt.get("bootFlavor") != "init_boot":
        raise FirmwareSmokeError("processed firmware or boot promotion was not proven")
    for field in ("firmwareSha256", "bootSha256"):
        value = receipt.get(field)
        if not isinstance(value, str) or len(value) != 64:
            raise FirmwareSmokeError(f"{field} is not a SHA-256 digest")
        try:
            int(value, 16)
        except ValueError as exc:
            raise FirmwareSmokeError(f"{field} is not a SHA-256 digest") from exc
    if not isinstance(receipt.get("applicationVersion"), str) or not receipt["applicationVersion"]:
        raise FirmwareSmokeError("application version is missing")
    if receipt.get("processBits") not in {32, 64} or receipt.get("cleanShutdown") is not True:
        raise FirmwareSmokeError("native process or shutdown proof is invalid")
    if expected_platform is not None and receipt.get("platform") != expected_platform:
        raise FirmwareSmokeError("firmware smoke platform does not match")
    if expected_architecture is not None and receipt.get("architecture") != expected_architecture:
        raise FirmwareSmokeError("firmware smoke architecture does not match")
    return dict(receipt)


def _write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    destination = path.expanduser().absolute()
    if destination.exists() and destination.is_symlink():
        raise FirmwareSmokeError("firmware smoke report cannot be a symlink")
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise FirmwareSmokeError("firmware smoke report parent must be a real directory")
    payload = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def run_packaged_firmware_smoke(report_path: Path) -> dict[str, Any]:
    runtime: ApplicationRuntime | None = None
    clean_shutdown = False
    with tempfile.TemporaryDirectory(prefix="pixelflasher-firmware-smoke-") as directory:
        root = Path(directory)
        fixture = root / "factory-smoke.zip"
        firmware_sha256 = _write_factory_fixture(fixture)
        expected_confirmation = f"TRUST FIRMWARE {firmware_sha256[:8].upper()}"
        confirmations: list[str] = []

        def interaction(request: object) -> InteractionDecision:
            nonce = getattr(request, "confirmation_nonce", None)
            reinforced = getattr(request, "reinforced", False)
            if reinforced is True and isinstance(nonce, str) and nonce == expected_confirmation:
                confirmations.append(nonce)
                return InteractionDecision.ACCEPTED
            return InteractionDecision.CANCELLED

        try:
            runtime = ApplicationRuntime.open(
                root / "config.json",
                interaction_handler=interaction,
                enable_device_monitor=False,
                legacy_database_path=root / "legacy.db",
            )
            factory = create_command_factory(runtime.engine.snapshot)
            revision = runtime.engine.snapshot().revision
            picker = _request(
                "native.pickFile",
                request_id="firmware-smoke-picker",
                revision=revision,
                payload={"purpose": "firmware.select", "title": "Firmware smoke"},
            )
            public_grant = factory.issue_native_grants(picker, (fixture,))
            token = public_grant.get("grant")
            if not isinstance(token, str) or "path" in public_grant:
                raise FirmwareSmokeError("native firmware grant was not opaque")
            selected = runtime.engine.execute(
                factory(
                    _request(
                        "firmware.select",
                        request_id="firmware-smoke-select",
                        revision=revision,
                        payload={"grant": token, "expectedKind": "stock"},
                    )
                )
            )
            if not selected.ok or selected.code != "firmware_selected":
                raise FirmwareSmokeError(f"firmware selection failed: {selected.code}")
            if confirmations != [expected_confirmation]:
                raise FirmwareSmokeError("firmware confirmation was not exactly hash-bound")
            revision = runtime.engine.snapshot().revision
            processed = runtime.engine.execute(
                factory(
                    _request(
                        "firmware.process",
                        request_id="firmware-smoke-process",
                        revision=revision,
                    )
                )
            )
            if not processed.ok or processed.code != "firmware_processed":
                raise FirmwareSmokeError(f"firmware processing failed: {processed.code}")
            snapshot = runtime.engine.snapshot()
            record = runtime.firmware_repository.resolve_selection(sha256=firmware_sha256)
            if record is None or record.metadata.get("packageSignature") != "user_confirmed":
                raise FirmwareSmokeError("firmware trust receipt was not persisted")
            if (
                not snapshot.firmware.processed
                or snapshot.firmware.hash != firmware_sha256
                or not snapshot.boot.hash
                or snapshot.boot.flavor != "init_boot"
            ):
                raise FirmwareSmokeError("processed firmware was not promoted canonically")
            runtime.shutdown()
            clean_shutdown = True
            runtime = None
            receipt = create_firmware_smoke_receipt(
                firmware_sha256=firmware_sha256,
                select_code=selected.code,
                process_code=processed.code,
                trust_status="user_confirmed",
                boot_flavor=snapshot.boot.flavor,
                boot_sha256=snapshot.boot.hash,
            )
            _write_receipt(report_path, receipt)
            return receipt
        finally:
            if runtime is not None:
                runtime.shutdown()
            if not clean_shutdown and report_path.exists() and not report_path.is_symlink():
                report_path.unlink()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware-smoke-report", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = run_packaged_firmware_smoke(args.firmware_smoke_report)
    except Exception as exc:
        print(f"PixelFlasher packaged firmware smoke failed: {exc}")
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


__all__ = [
    "FIRMWARE_SMOKE_SCHEMA_VERSION",
    "FirmwareSmokeError",
    "create_firmware_smoke_receipt",
    "main",
    "run_packaged_firmware_smoke",
    "validate_firmware_smoke_receipt",
]
