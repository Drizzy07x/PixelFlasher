from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa

from pixelflasher_core.support import (
    SupportPackageError,
    SupportPackageLimits,
    SupportPackageResult,
    SupportPackageStatus,
)
from pixelflasher_core.support_v2 import SUPPORT_V2_MAGIC, SupportPackageReader, SupportV2Error
from pixelflasher_core.support_v2_service import (
    SupportPackageV2Result,
    SupportPackageV2Service,
)

SERIAL = "9A22123456789012"
TOKEN = "SERVICE-TOKEN-SECRET"
PRIVATE_PATH = "C:\\Users\\Private Person\\Downloads\\factory.zip"
NOW = datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)


class FakeDevice:
    def __init__(self, serial: str) -> None:
        self.serial = serial


class FakeSnapshot:
    selected_serials = (SERIAL,)
    selected_serial = SERIAL
    devices = (FakeDevice(SERIAL),)

    def to_dict(self) -> dict[str, object]:
        return {
            "revision": 7,
            "devices": [{"serial": SERIAL, "mode": "adb"}],
            "selected_serials": [SERIAL],
            "selected_serial": SERIAL,
            "firmware": {"path": PRIVATE_PATH, "sha256": "a" * 64},
            "boot": {"path": PRIVATE_PATH, "hash": "b" * 64},
            "plan": {"mode": "factory", "serial": SERIAL},
            "toolchain": {"adb": PRIVATE_PATH},
            "active_operation": None,
            "last_result": {
                "operation_id": "op-1",
                "status": "failed",
                "code": "test",
                "message": f"device {SERIAL} at {PRIVATE_PATH}",
                "exit_code": 1,
            },
        }


class MutableCancellation:
    def __init__(self, cancelled: bool = False) -> None:
        self.cancelled = cancelled


class SupportPackageV2ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()

    def _fixture(self, root: Path, *, database: bool = True) -> Path:
        config = root / "PixelFlasher.json"
        config.write_text(
            json.dumps(
                {
                    "device": SERIAL,
                    "api_token": TOKEN,
                    "firmware_path": PRIVATE_PATH,
                    "safe": "preserved",
                }
            ),
            encoding="utf-8",
        )
        (root / "labels.json").write_text(
            json.dumps({"serial": SERIAL, "owner": "private@example.com"}),
            encoding="utf-8",
        )
        logs = root / "logs"
        logs.mkdir()
        (logs / "run.log").write_text(
            f"adb -s {SERIAL} shell getprop\ntoken={TOKEN}\npath {PRIVATE_PATH}\n",
            encoding="utf-8",
        )
        (logs / "structured.json").write_text(
            json.dumps({"serial": SERIAL, "secret": TOKEN}),
            encoding="utf-8",
        )
        (logs / "ignored.apk").write_bytes(b"not-allow-listed")
        diagrams = root / "puml"
        diagrams.mkdir()
        (diagrams / "trace.puml").write_text(
            f"serial={SERIAL}\nsecret={TOKEN}",
            encoding="utf-8",
        )
        if database:
            connection = sqlite3.connect(root / "PixelFlasher.db")
            try:
                connection.executescript(
                    """
                    CREATE TABLE PACKAGE (
                        id INTEGER,
                        boot_hash TEXT,
                        type TEXT,
                        package_sig TEXT,
                        file_path TEXT,
                        epoch INTEGER
                    );
                    CREATE TABLE PRIVATE_VALUES (serial TEXT, token TEXT, path TEXT);
                    """
                )
                connection.execute(
                    "INSERT INTO PACKAGE VALUES (?, ?, ?, ?, ?, ?)",
                    (1, "a" * 40, "firmware", "factory", PRIVATE_PATH, 1234),
                )
                connection.execute(
                    "INSERT INTO PRIVATE_VALUES VALUES (?, ?, ?)",
                    (SERIAL, TOKEN, PRIVATE_PATH),
                )
                connection.commit()
            finally:
                connection.close()
        return config

    def _service(self, config: Path, **kwargs: object) -> SupportPackageV2Service:
        return SupportPackageV2Service(
            config,
            self.public_key,
            key_id="support-prod-2026",
            app_version="10.0-test",
            clock=lambda: NOW,
            **kwargs,
        )

    def test_backend_compatible_service_writes_only_v2_and_exposes_no_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._fixture(root)
            destination = root / "support-modern.zip"
            service = self._service(config)
            destination_id = service.register_destination(destination)

            result = service.create({"destinationId": destination_id}, snapshot=FakeSnapshot())

            self.assertIsInstance(result, SupportPackageResult)
            self.assertIsInstance(result, SupportPackageV2Result)
            self.assertEqual(SupportPackageStatus.SUCCESS, result.status)
            self.assertEqual("support_package_created", result.code)
            self.assertEqual("support-modern.zip", result.file_name)
            self.assertEqual(hashlib.sha256(destination.read_bytes()).hexdigest(), result.sha256)
            self.assertTrue(destination.read_bytes().startswith(SUPPORT_V2_MAGIC))
            public = result.to_dict()
            self.assertEqual(2, public["schemaVersion"])
            self.assertEqual("support-prod-2026", public["keyId"])
            self.assertNotIn("path", {key.casefold() for key in public})
            self.assertNotIn(str(root), json.dumps(public))

            read = SupportPackageReader(self.private_key).read(
                destination,
                sensitive_values=(SERIAL, TOKEN, PRIVATE_PATH),
            )
            names = {entry.archive_name for entry in read.entries}
            self.assertTrue(
                {
                    "config/PixelFlasher.json",
                    "config/labels.json",
                    "state/app_snapshot.json",
                    "system/system_info.json",
                    "database/PixelFlasher.sqlite3",
                }.issubset(names)
            )
            self.assertTrue(any(name.startswith("logs/log_") for name in names))
            self.assertTrue(any(name.startswith("diagrams/trace_") for name in names))
            combined = b"\n".join(entry.payload for entry in read.entries)
            for private in (SERIAL.encode(), TOKEN.encode(), PRIVATE_PATH.encode()):
                self.assertNotIn(private, combined)

    def test_destination_grant_is_backend_owned_one_use_and_payload_is_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._fixture(root, database=False)
            service = self._service(config)

            forged = service.create(
                {
                    "destinationId": "x" * 43,
                    "path": str(root / "browser-controlled.zip"),
                },
                snapshot=FakeSnapshot(),
            )
            self.assertEqual(SupportPackageStatus.FAILED, forged.status)
            self.assertEqual("invalid_support_payload", forged.code)
            self.assertFalse((root / "browser-controlled.zip").exists())

            destination = root / "one-use.zip"
            destination_id = service.register_destination(destination)
            created = service.create({"destinationId": destination_id}, snapshot=FakeSnapshot())
            repeated = service.create({"destinationId": destination_id}, snapshot=FakeSnapshot())
            self.assertTrue(created.ok)
            self.assertEqual("support_destination_not_granted", repeated.code)
            self.assertEqual(SupportPackageStatus.FAILED, repeated.status)

            with self.assertRaises(SupportPackageError):
                service.register_destination(root / "invalid.zip", allow_overwrite="yes")  # type: ignore[arg-type]

    def test_cancellation_before_consumption_preserves_grant_and_before_commit_leaves_no_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._fixture(root, database=False)
            service = self._service(config)
            destination = root / "retry.zip"
            destination_id = service.register_destination(destination)
            cancellation = MutableCancellation(True)

            cancelled = service.create(
                {"destinationId": destination_id},
                snapshot=FakeSnapshot(),
                cancellation=cancellation,
            )
            self.assertEqual(SupportPackageStatus.CANCELLED, cancelled.status)
            self.assertFalse(destination.exists())
            cancellation.cancelled = False
            retried = service.create(
                {"destinationId": destination_id},
                snapshot=FakeSnapshot(),
                cancellation=cancellation,
            )
            self.assertTrue(retried.ok)

            commit_destination = root / "cancel-at-commit.zip"
            commit_id = service.register_destination(commit_destination)
            commit_cancellation = MutableCancellation(False)
            original_fsync = os.fsync

            def cancel_after_fsync(descriptor: int) -> None:
                original_fsync(descriptor)
                commit_cancellation.cancelled = True

            with patch("pixelflasher_core.support_v2.os.fsync", side_effect=cancel_after_fsync):
                commit_result = service.create(
                    {"destinationId": commit_id},
                    snapshot=FakeSnapshot(),
                    cancellation=commit_cancellation,
                )

            self.assertEqual(SupportPackageStatus.CANCELLED, commit_result.status)
            self.assertEqual("support_package_cancelled", commit_result.code)
            self.assertFalse(commit_destination.exists())
            self.assertEqual([], list(root.glob(".cancel-at-commit.zip.*.tmp")))

    def test_corrupt_database_is_safely_omitted_and_collection_limits_are_manifested(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._fixture(root, database=False)
            (root / "PixelFlasher.db").write_bytes(b"not a sqlite database")
            logs = root / "logs"
            for index in range(5):
                (logs / f"extra-{index}.log").write_text("safe log", encoding="utf-8")
            service = self._service(
                config,
                collection_limits=SupportPackageLimits(
                    max_config_bytes=10_000,
                    max_log_bytes=1_000,
                    max_log_files=2,
                    max_total_bytes=100_000,
                    max_log_depth=2,
                ),
            )
            destination = root / "bounded.zip"
            destination_id = service.register_destination(destination)

            result = service.create({"destinationId": destination_id}, snapshot=FakeSnapshot())

            self.assertTrue(result.ok)
            read = SupportPackageReader(self.private_key).read(destination)
            self.assertNotIn(
                "database/PixelFlasher.sqlite3",
                {entry.archive_name for entry in read.entries},
            )
            reasons = {item.reason for item in read.omissions}
            self.assertIn("support_database_sanitization_failed", reasons)
            self.assertIn("file_count_limit", reasons)

    def test_constructor_has_no_default_or_test_recipient_key(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "PixelFlasher.json"
            config.write_text("{}", encoding="utf-8")
            with self.assertRaises(TypeError):
                SupportPackageV2Service(config, key_id="support-prod-2026")  # type: ignore[call-arg]
            with self.assertRaises(SupportV2Error) as raised:
                SupportPackageV2Service(
                    config,
                    b"not-a-public-key",
                    key_id="support-prod-2026",
                )
            self.assertEqual("support_public_key_invalid", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
