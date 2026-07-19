from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import struct
import tempfile
import unittest
import zipfile
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pixelflasher_core.support import SupportPackageService
from pixelflasher_core.support_v2 import (
    SUPPORT_V2_FORMAT,
    SUPPORT_V2_MAGIC,
    SupportPackageOmission,
    SupportPackageReader,
    SupportPackageV2Writer,
    SupportSourceEntry,
    SupportV2Error,
    SupportV2Limits,
)

SERIAL = "9A22123456789012"
SECRET = "support-secret-value-123"
SOURCE_PATH = "C:\\Users\\Private Person\\Downloads\\factory.zip"
NOW = datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)


def zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


class SupportPackageV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()
        cls.other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _database(self, path: Path) -> None:
        connection = sqlite3.connect(path)
        try:
            connection.executescript(
                """
                CREATE TABLE PACKAGE (
                    id INTEGER PRIMARY KEY,
                    boot_hash TEXT,
                    type TEXT,
                    package_sig TEXT,
                    file_path TEXT,
                    epoch INTEGER,
                    full_ota INTEGER,
                    api_token TEXT
                );
                CREATE TABLE BOOT (
                    id INTEGER PRIMARY KEY,
                    boot_hash TEXT,
                    file_path TEXT,
                    is_patched INTEGER,
                    magisk_version TEXT,
                    hardware TEXT,
                    epoch INTEGER,
                    patch_method TEXT
                );
                CREATE TABLE PACKAGE_BOOT (
                    package_id INTEGER,
                    boot_id INTEGER,
                    epoch INTEGER
                );
                CREATE TABLE SECRET_DATA (token TEXT, serial TEXT, path TEXT);
                """
            )
            connection.execute(
                "INSERT INTO PACKAGE VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (1, "a" * 40, "firmware", SECRET, SOURCE_PATH, 1234, 1, "database-token"),
            )
            connection.execute(
                "INSERT INTO BOOT VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (1, "b" * 40, SOURCE_PATH, 0, "27.0", "panther", 1234, "stock"),
            )
            connection.execute("INSERT INTO PACKAGE_BOOT VALUES (1, 1, 1234)")
            connection.execute(
                "INSERT INTO SECRET_DATA VALUES (?, ?, ?)",
                (SECRET, SERIAL, SOURCE_PATH),
            )
            connection.commit()
        finally:
            connection.close()

    def _entries(self, database: Path):
        return (
            SupportSourceEntry.json(
                "config/PixelFlasher.json",
                "configuration",
                {
                    "api_token": SECRET,
                    "serial": SERIAL,
                    "firmware_path": SOURCE_PATH,
                    "username": "Private Person",
                    "safe": "kept",
                },
                logical_source="active-configuration",
            ),
            SupportSourceEntry.text(
                "logs/log_001.txt",
                "logs",
                (
                    f"adb -s {SERIAL} shell getprop\n"
                    f"token={SECRET}\n"
                    f"firmware {SOURCE_PATH}\n"
                    "contact private@example.com at 192.168.1.50\n"
                ),
                logical_source="runtime-log-001",
            ),
            SupportSourceEntry.sqlite(database),
        )

    def test_v2_round_trip_encrypts_and_verifies_redacted_entries_and_sqlite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "PixelFlasher.db"
            self._database(database)
            destination = root / "support.pfsupport"
            writer = SupportPackageV2Writer(
                self.public_key,
                key_id="support-2026",
                clock=lambda: NOW,
            )

            written = writer.write(
                destination,
                self._entries(database),
                application_version="10.0.0-test",
                sensitive_values=(SERIAL, SECRET, SOURCE_PATH, "Private Person"),
                omissions=(
                    SupportPackageOmission("binary-log", "logs", "binary_not_allowed"),
                ),
            )

            container = destination.read_bytes()
            self.assertTrue(container.startswith(SUPPORT_V2_MAGIC))
            self.assertFalse(zipfile.is_zipfile(destination))
            self.assertNotIn(SERIAL.encode(), container)
            self.assertNotIn(SECRET.encode(), container)
            self.assertNotIn(SOURCE_PATH.encode(), container)
            self.assertEqual(hashlib.sha256(container).hexdigest(), written.sha256)
            self.assertEqual(2, written.schema_version)
            self.assertTrue(written.redaction_verified)

            header_size = struct.unpack(
                ">I",
                container[len(SUPPORT_V2_MAGIC) : len(SUPPORT_V2_MAGIC) + 4],
            )[0]
            header_start = len(SUPPORT_V2_MAGIC) + 4
            header = json.loads(container[header_start : header_start + header_size])
            self.assertEqual("AES-256-GCM", header["contentEncryption"])
            self.assertEqual("RSA-OAEP-SHA256", header["keyWrapAlgorithm"])
            self.assertEqual(written.manifest_sha256, header["manifestSha256"])

            read = SupportPackageReader(self.private_key).read(
                destination,
                sensitive_values=(SERIAL, SECRET, SOURCE_PATH, "Private Person"),
            )
            self.assertEqual(2, read.schema_version)
            self.assertEqual(SUPPORT_V2_FORMAT, read.format)
            self.assertEqual("10.0.0-test", read.application_version)
            self.assertEqual("support-2026", read.key_id)
            self.assertTrue(read.redaction_verified)
            self.assertFalse(read.legacy_encrypted)
            self.assertEqual(written.manifest_sha256, read.manifest_sha256)
            self.assertEqual(1, len(read.omissions))

            config = json.loads(read.entry("config/PixelFlasher.json").payload)
            self.assertEqual("kept", config["safe"])
            self.assertEqual("<redacted>", config["api_token"])
            self.assertEqual("<serial-redacted>", config["serial"])
            self.assertEqual("<path-redacted>", config["firmware_path"])
            combined = b"\n".join(item.payload for item in read.entries)
            for private in (SERIAL.encode(), SECRET.encode(), SOURCE_PATH.encode(), b"private@example.com"):
                self.assertNotIn(private, combined)

            sanitized = root / "sanitized.sqlite3"
            sanitized.write_bytes(read.entry("database/PixelFlasher.sqlite3").payload)
            connection = sqlite3.connect(sanitized)
            try:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                self.assertEqual({"PACKAGE", "BOOT", "PACKAGE_BOOT"}, tables)
                package = connection.execute(
                    "SELECT package_sig, file_path FROM PACKAGE"
                ).fetchone()
                boot_path = connection.execute("SELECT file_path FROM BOOT").fetchone()[0]
            finally:
                connection.close()
            self.assertEqual("<sensitive-redacted>", package[0])
            self.assertEqual("<path-redacted>", package[1])
            self.assertEqual("<path-redacted>", boot_path)

    def test_ciphertext_header_and_wrong_key_tampering_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "support.zip"
            SupportPackageV2Writer(
                self.public_key,
                key_id="support-2026",
                clock=lambda: NOW,
            ).write(
                destination,
                (SupportSourceEntry.text("logs/log_001.txt", "logs", "safe log"),),
                application_version="10-test",
            )
            original = destination.read_bytes()

            tampered_ciphertext = bytearray(original)
            tampered_ciphertext[-1] ^= 0x01
            with self.assertRaises(SupportV2Error) as raised:
                SupportPackageReader(self.private_key).read(bytes(tampered_ciphertext))
            self.assertEqual("support_authentication_failed", raised.exception.code)

            header_size = struct.unpack(
                ">I",
                original[len(SUPPORT_V2_MAGIC) : len(SUPPORT_V2_MAGIC) + 4],
            )[0]
            header_start = len(SUPPORT_V2_MAGIC) + 4
            header = json.loads(original[header_start : header_start + header_size])
            header["manifestSha256"] = "0" * 64
            replacement = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
            self.assertEqual(header_size, len(replacement))
            tampered_header = (
                original[:header_start]
                + replacement
                + original[header_start + header_size :]
            )
            with self.assertRaises(SupportV2Error) as raised:
                SupportPackageReader(self.private_key).read(tampered_header)
            self.assertEqual("support_authentication_failed", raised.exception.code)

            with self.assertRaises(SupportV2Error) as raised:
                SupportPackageReader(self.other_private_key).read(original)
            self.assertEqual("support_key_unwrap_failed", raised.exception.code)

    def test_strict_entry_allowlist_counts_sizes_and_atomic_destination(self):
        limits = SupportV2Limits()
        writer = SupportPackageV2Writer(
            self.public_key,
            key_id="support-2026",
            limits=limits,
            clock=lambda: NOW,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                (
                    (SupportSourceEntry.text("arbitrary/secret.txt", "logs", "safe"),),
                    writer,
                    "support_entry_not_allowed",
                ),
                (
                    (
                        SupportSourceEntry.text("logs/log_001.txt", "logs", "one"),
                        SupportSourceEntry.text("logs/log_002.txt", "logs", "two"),
                    ),
                    SupportPackageV2Writer(
                        self.public_key,
                        key_id="support-2026",
                        limits=replace(limits, max_entries=1),
                        clock=lambda: NOW,
                    ),
                    "support_entry_count_limit",
                ),
                (
                    (SupportSourceEntry.text("logs/log_001.txt", "logs", "12345"),),
                    SupportPackageV2Writer(
                        self.public_key,
                        key_id="support-2026",
                        limits=replace(limits, max_entry_bytes=4),
                        clock=lambda: NOW,
                    ),
                    "support_entry_size_limit",
                ),
            )
            for index, (entries, active_writer, code) in enumerate(cases):
                with self.subTest(code=code):
                    destination = root / f"blocked-{index}.pfsupport"
                    with self.assertRaises(SupportV2Error) as raised:
                        active_writer.write(
                            destination,
                            entries,
                            application_version="10-test",
                        )
                    self.assertEqual(code, raised.exception.code)
                    self.assertFalse(destination.exists())

            existing = root / "existing.pfsupport"
            existing.write_bytes(b"original")
            with self.assertRaises(SupportV2Error) as raised:
                writer.write(
                    existing,
                    (SupportSourceEntry.text("logs/log_001.txt", "logs", "safe"),),
                    application_version="10-test",
                )
            self.assertEqual("support_destination_exists", raised.exception.code)
            self.assertEqual(b"original", existing.read_bytes())

            failed = root / "atomic-failure.pfsupport"
            with patch("pixelflasher_core.support_v2.os.link", side_effect=OSError("blocked")):
                with self.assertRaises(SupportV2Error) as raised:
                    writer.write(
                        failed,
                        (SupportSourceEntry.text("logs/log_001.txt", "logs", "safe"),),
                        application_version="10-test",
                    )
            self.assertEqual("support_write_failed", raised.exception.code)
            self.assertFalse(failed.exists())
            self.assertEqual([], list(root.glob(".atomic-failure.pfsupport.*.tmp")))

    def test_reader_accepts_the_current_schema_v1_service_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            config.write_text(
                json.dumps({"serial": SERIAL, "api_token": SECRET}),
                encoding="utf-8",
            )
            destination = root / "current-v1.zip"
            service = SupportPackageService(config, app_version="9-current")
            destination_id = service.register_destination(destination)
            result = service.create(
                {
                    "destinationId": destination_id,
                    "includeConfig": True,
                    "includeLogs": False,
                    "includeState": False,
                    "includeSystemInfo": False,
                },
                snapshot=object(),
            )
            self.assertTrue(result.ok)

            read = SupportPackageReader().read(
                destination,
                sensitive_values=(SERIAL, SECRET),
            )

            self.assertEqual(1, read.schema_version)
            self.assertEqual("9-current", read.application_version)
            self.assertEqual(
                {"config/PixelFlasher.json"},
                {entry.archive_name for entry in read.entries},
            )

    def test_reads_current_manifest_v1_without_adding_a_v1_writer(self):
        payload = json.dumps({"serial": "<serial-redacted>", "safe": True}).encode()
        digest = hashlib.sha256(payload).hexdigest()
        manifest = {
            "schemaVersion": 1,
            "format": "pixelflasher-redacted-support",
            "createdUtc": "2026-07-18T12:00:00+00:00",
            "applicationVersion": "9.9-test",
            "redaction": "mandatory",
            "options": {"includeConfig": True},
            "included": [
                {
                    "entry": "config/PixelFlasher.json",
                    "category": "configuration",
                    "source": "active-configuration",
                    "bytes": len(payload),
                    "sha256": digest,
                    "redacted": True,
                    "truncated": False,
                }
            ],
            "omitted": [],
            "manifestEntry": "manifest.json",
        }
        package = zip_bytes(
            {
                "config/PixelFlasher.json": payload,
                "manifest.json": json.dumps(manifest).encode(),
            }
        )

        read = SupportPackageReader().read(package)

        self.assertEqual(1, read.schema_version)
        self.assertEqual("9.9-test", read.application_version)
        self.assertFalse(read.legacy_encrypted)
        self.assertEqual(payload, read.entry("config/PixelFlasher.json").payload)
        self.assertEqual(64, len(read.manifest_sha256))

    def test_reads_legacy_fernet_v1_with_oaep_sha256(self):
        inner = zip_bytes({"PixelFlasher.json": b"{}", "logs/run.log": b"safe log"})
        session_key = Fernet.generate_key()
        encrypted = Fernet(session_key).encrypt(inner)
        wrapped = self.public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        package = zip_bytes({"support.pf": encrypted, "pf.dat": wrapped})

        read = SupportPackageReader(self.private_key).read(package)

        self.assertEqual(1, read.schema_version)
        self.assertTrue(read.legacy_encrypted)
        self.assertEqual(
            {"PixelFlasher.json", "logs/run.log"},
            {entry.archive_name for entry in read.entries},
        )
        with self.assertRaises(SupportV2Error) as raised:
            SupportPackageReader().read(package)
        self.assertEqual("support_private_key_required", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
