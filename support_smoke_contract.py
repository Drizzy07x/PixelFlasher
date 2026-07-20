"""Closed, hardware-free packaged Support Package v1/v2 smoke."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import struct
import sys
import tempfile
import zipfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa

from constants import VERSION
from pixelflasher_core.support_v2 import (
    SUPPORT_V2_MAGIC,
    SupportPackageReader,
    SupportPackageV2Writer,
    SupportSourceEntry,
    SupportV2Error,
)
from ui_smoke_contract import normalized_architecture, normalized_platform

SUPPORT_SMOKE_SCHEMA_VERSION = 1
_SHA256_LENGTH = 64
_SENSITIVE = (
    "9A22123456789012",
    "PACKAGED-SUPPORT-TOKEN",
    "C:\\Users\\Private Person\\Downloads\\factory.zip",
    "private@example.com",
)


class SupportSmokeError(RuntimeError):
    """Raised when packaged support interoperability is not fully proven."""


def _deterministic_zip(entries: Mapping[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 0
            info.external_attr = 0o600 << 16
            archive.writestr(info, entries[name])
    return stream.getvalue()


def _legacy_v1_fixture() -> bytes:
    payload = b"packaged legacy support log\n"
    digest = hashlib.sha256(payload).hexdigest()
    manifest = {
        "schemaVersion": 1,
        "format": "pixelflasher-redacted-support",
        "createdUtc": "2026-07-20T00:00:00+00:00",
        "applicationVersion": "9.x-packaged-fixture",
        "redaction": "mandatory",
        "options": {"includeLogs": True},
        "included": [
            {
                "entry": "logs/log_001.txt",
                "category": "logs",
                "source": "packaged-v1-fixture",
                "bytes": len(payload),
                "sha256": digest,
                "redacted": True,
                "truncated": False,
            }
        ],
        "omitted": [],
        "manifestEntry": "manifest.json",
    }
    return _deterministic_zip(
        {
            "logs/log_001.txt": payload,
            "manifest.json": json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(),
        }
    )


def _v2_envelope(document: bytes) -> dict[str, object]:
    prefix = len(SUPPORT_V2_MAGIC)
    if not document.startswith(SUPPORT_V2_MAGIC) or len(document) < prefix + 4:
        raise SupportSmokeError("v2 magic or envelope length was not proven")
    header_size = struct.unpack(">I", document[prefix : prefix + 4])[0]
    start = prefix + 4
    end = start + header_size
    try:
        value: object = json.loads(document[start:end].decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SupportSmokeError("v2 envelope was not valid JSON") from exc
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise SupportSmokeError("v2 envelope was not an object")
    return value


def create_support_smoke_receipt(
    *,
    container_sha256: str,
    manifest_sha256: str,
    included_count: int,
) -> dict[str, Any]:
    receipt = {
        "schemaVersion": SUPPORT_SMOKE_SCHEMA_VERSION,
        "status": "ready",
        "applicationVersion": VERSION,
        "platform": normalized_platform(),
        "architecture": normalized_architecture(),
        "processBits": struct.calcsize("P") * 8,
        "fixture": "generated-support-v1-v2",
        "keyId": "packaged-smoke-ephemeral",
        "v2Write": True,
        "v2Read": True,
        "v1Read": True,
        "rsaOaepSha256": True,
        "aes256Gcm": True,
        "redactionVerified": True,
        "tamperRejected": True,
        "includedCount": included_count,
        "containerSha256": container_sha256,
        "manifestSha256": manifest_sha256,
        "routeFree": True,
        "processComplete": True,
    }
    return validate_support_smoke_receipt(receipt)


def validate_support_smoke_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_platform: str | None = None,
    expected_architecture: str | None = None,
) -> dict[str, Any]:
    expected_keys = {
        "schemaVersion", "status", "applicationVersion", "platform", "architecture",
        "processBits", "fixture", "keyId", "v2Write", "v2Read", "v1Read",
        "rsaOaepSha256", "aes256Gcm", "redactionVerified", "tamperRejected",
        "includedCount", "containerSha256", "manifestSha256", "routeFree",
        "processComplete",
    }
    if set(receipt) != expected_keys:
        raise SupportSmokeError("receipt fields do not match the closed schema")
    if receipt.get("schemaVersion") != SUPPORT_SMOKE_SCHEMA_VERSION:
        raise SupportSmokeError("unsupported support smoke receipt schema")
    if receipt.get("status") != "ready" or receipt.get("fixture") != "generated-support-v1-v2":
        raise SupportSmokeError("support interoperability was not proven")
    if receipt.get("keyId") != "packaged-smoke-ephemeral":
        raise SupportSmokeError("ephemeral support key identity was not proven")
    for field in (
        "v2Write", "v2Read", "v1Read", "rsaOaepSha256", "aes256Gcm",
        "redactionVerified", "tamperRejected", "routeFree", "processComplete",
    ):
        if receipt.get(field) is not True:
            raise SupportSmokeError(f"{field} was not proven")
    if receipt.get("includedCount") != 2:
        raise SupportSmokeError("the exact support entry count was not proven")
    for field in ("containerSha256", "manifestSha256"):
        value = receipt.get(field)
        if not isinstance(value, str) or len(value) != _SHA256_LENGTH:
            raise SupportSmokeError(f"{field} is not a SHA-256 digest")
        try:
            int(value, 16)
        except ValueError as exc:
            raise SupportSmokeError(f"{field} is not a SHA-256 digest") from exc
    if not isinstance(receipt.get("applicationVersion"), str) or not receipt["applicationVersion"]:
        raise SupportSmokeError("application version is missing")
    if receipt.get("processBits") not in {32, 64}:
        raise SupportSmokeError("native process width is invalid")
    if expected_platform is not None and receipt.get("platform") != expected_platform:
        raise SupportSmokeError("support smoke platform does not match")
    if expected_architecture is not None and receipt.get("architecture") != expected_architecture:
        raise SupportSmokeError("support smoke architecture does not match")
    return dict(receipt)


def _write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    destination = path.expanduser().absolute()
    if destination.exists() and destination.is_symlink():
        raise SupportSmokeError("support smoke report cannot be a symlink")
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise SupportSmokeError("support smoke report parent must be a real directory")
    payload = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent,
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


def run_packaged_support_smoke(report_path: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="pixelflasher-support-smoke-") as directory:
        root = Path(directory)
        print("Support smoke: generating ephemeral recipient key", file=sys.stderr, flush=True)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        print("Support smoke: writing encrypted v2 package", file=sys.stderr, flush=True)
        destination = root / "support-v2.pfsupport"
        writer = SupportPackageV2Writer(
            private_key.public_key(), key_id="packaged-smoke-ephemeral",
        )
        write = writer.write(
            destination,
            (
                SupportSourceEntry.json(
                    "config/PixelFlasher.json",
                    "configuration",
                    {
                        "serial": _SENSITIVE[0], "api_token": _SENSITIVE[1],
                        "firmware_path": _SENSITIVE[2], "owner": _SENSITIVE[3],
                    },
                ),
                SupportSourceEntry.text(
                    "logs/log_001.txt",
                    "logs",
                    f"adb -s {_SENSITIVE[0]} shell\ntoken={_SENSITIVE[1]}\n{_SENSITIVE[2]}\n{_SENSITIVE[3]}",
                ),
            ),
            application_version=VERSION,
            sensitive_values=_SENSITIVE,
        )
        document = destination.read_bytes()
        envelope = _v2_envelope(document)
        if envelope.get("keyWrapAlgorithm") != "RSA-OAEP-SHA256":
            raise SupportSmokeError("RSA-OAEP-SHA256 was not proven")
        if envelope.get("contentEncryption") != "AES-256-GCM":
            raise SupportSmokeError("AES-256-GCM was not proven")
        print("Support smoke: reading and authenticating v2 package", file=sys.stderr, flush=True)
        read_v2 = SupportPackageReader(private_key).read(destination, sensitive_values=_SENSITIVE)
        if read_v2.schema_version != 2 or not read_v2.redaction_verified or len(read_v2.entries) != 2:
            raise SupportSmokeError("v2 readback did not prove the expected package")
        combined = b"\n".join(entry.payload for entry in read_v2.entries)
        if any(value.encode() in combined for value in _SENSITIVE):
            raise SupportSmokeError("v2 readback exposed a seeded sensitive value")
        tampered = bytearray(document)
        tampered[-1] ^= 1
        try:
            SupportPackageReader(private_key).read(bytes(tampered), sensitive_values=_SENSITIVE)
        except SupportV2Error:
            pass
        else:
            raise SupportSmokeError("tampered v2 authentication was not rejected")
        print("Support smoke: reading legacy v1 fixture", file=sys.stderr, flush=True)
        legacy_fixture = _legacy_v1_fixture()
        read_v1 = SupportPackageReader().read(legacy_fixture)
        if read_v1.schema_version != 1 or not read_v1.redaction_verified or len(read_v1.entries) != 1:
            raise SupportSmokeError("v1 compatibility was not proven")
        receipt = create_support_smoke_receipt(
            container_sha256=write.sha256,
            manifest_sha256=write.manifest_sha256,
            included_count=write.included_count,
        )
        serialized = json.dumps(receipt)
        if str(root) in serialized or str(destination) in serialized:
            raise SupportSmokeError("support receipt exposed a host route")
        _write_receipt(report_path, receipt)
        print("Support smoke: complete", file=sys.stderr, flush=True)
        return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--support-smoke-report", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = run_packaged_support_smoke(args.support_smoke_report)
    except Exception as exc:
        print(f"PixelFlasher packaged support smoke failed: {exc}")
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


__all__ = [
    "SUPPORT_SMOKE_SCHEMA_VERSION",
    "SupportSmokeError",
    "create_support_smoke_receipt",
    "main",
    "run_packaged_support_smoke",
    "validate_support_smoke_receipt",
]
