from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pixelflasher_core.platform_tools_distribution import (
    load_platform_tools_distribution,
)
from scripts.build_platform_tools_catalog import CatalogBuildError, build_catalog
from scripts.verify_platform_tools_catalog import verify


def _pe_x86() -> bytes:
    content = bytearray(128)
    content[:2] = b"MZ"
    content[60:64] = (64).to_bytes(4, "little")
    content[64:68] = b"PE\x00\x00"
    content[68:70] = (0x014C).to_bytes(2, "little")
    return bytes(content)


def _elf_x64() -> bytes:
    content = bytearray(64)
    content[:4] = b"\x7fELF"
    content[4] = 2
    content[5] = 1
    content[18:20] = (62).to_bytes(2, "little")
    return bytes(content)


def _universal_macho() -> bytes:
    content = bytearray(48)
    content[:4] = b"\xca\xfe\xba\xbe"
    content[4:8] = (2).to_bytes(4, "big")
    content[8:12] = (0x01000007).to_bytes(4, "big")
    content[28:32] = (0x0100000C).to_bytes(4, "big")
    return bytes(content)


def _archive(path: Path, *, platform: str) -> dict[str, object]:
    if platform == "windows":
        binary = _pe_x86()
        names = ("adb.exe", "fastboot.exe")
        binary_architectures = ["x86"]
        host_architectures = ["x86_64", "arm64"]
    elif platform == "darwin":
        binary = _universal_macho()
        names = ("adb", "fastboot")
        binary_architectures = ["x86_64", "arm64"]
        host_architectures = ["x86_64", "arm64"]
    else:
        binary = _elf_x64()
        names = ("adb", "fastboot")
        binary_architectures = ["x86_64"]
        host_architectures = ["x86_64"]
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("platform-tools/source.properties", "Pkg.UserSrc=false\nPkg.Revision=37.0.0\n")
        for name in names:
            archive.writestr(f"platform-tools/{name}", binary)
    content = path.read_bytes()
    return {
        "platform": platform,
        "hostArchitectures": host_architectures,
        "binaryArchitectures": binary_architectures,
        "url": f"https://dl.google.com/android/repository/{path.name}",
        "size": len(content),
        "sha1": hashlib.sha1(content, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _inputs(root: Path) -> tuple[Path, Path, Path, dict[str, bytes]]:
    archives = root / "archives"
    output = root / "output"
    archives.mkdir()
    output.mkdir()
    locked = [
        _archive(archives / "platform-tools_r37.0.0-win.zip", platform="windows"),
        _archive(archives / "platform-tools_r37.0.0-darwin.zip", platform="darwin"),
        _archive(archives / "platform-tools_r37.0.0-linux.zip", platform="linux"),
    ]
    source = {
        "schemaVersion": 1,
        "sourceMetadataUrl": "https://dl.google.com/android/repository/repository2-1.xml",
        "releaseChannel": "stable",
        "version": "37.0.0",
        "license": "Android-SDK-License",
        "provenance": "Google Android SDK Platform Tools stable repository",
        "archives": locked,
    }
    source_path = root / "source-lock.json"
    source_path.write_text(json.dumps(source), encoding="utf-8")
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    private_path = root / "private.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return source_path, private_path, output, {"platform-tools-release": public}


class BuildPlatformToolsCatalogTests(unittest.TestCase):
    def test_verified_archives_generate_the_complete_authenticated_matrix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-build-platform-catalog-") as directory:
            root = Path(directory)
            source, private, output, trusted_keys = _inputs(root)

            catalog = build_catalog(
                source_lock_path=source,
                private_key_path=private,
                key_id="platform-tools-release",
                archives_directory=root / "archives",
                output_directory=output,
                expires_at=(datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                trusted_public_keys=trusted_keys,
            )
            distribution = load_platform_tools_distribution(
                output,
                trusted_public_keys=trusted_keys,
            )

            self.assertEqual(5, len(catalog["manifests"]))
            self.assertEqual(
                {
                    ("windows", "x86_64"),
                    ("windows", "arm64"),
                    ("darwin", "x86_64"),
                    ("darwin", "arm64"),
                    ("linux", "x86_64"),
                },
                set(distribution.targets),
            )
            self.assertFalse(any(output.glob(".*.tmp")))
            self.assertEqual(
                "Verified 5 signed Platform Tools targets with 1 pinned key(s).",
                verify(output, trusted_public_keys=trusted_keys),
            )

    def test_unpinned_key_and_changed_archive_fail_before_writing_a_catalog(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-build-platform-catalog-bad-") as directory:
            root = Path(directory)
            source, private, output, _trusted_keys = _inputs(root)

            with self.assertRaisesRegex(CatalogBuildError, "does not match"):
                build_catalog(
                    source_lock_path=source,
                    private_key_path=private,
                    key_id="platform-tools-release",
                    archives_directory=root / "archives",
                    output_directory=output,
                    expires_at=(datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    trusted_public_keys={"platform-tools-release": b"x" * 32},
                )
            self.assertFalse((output / "catalog.json").exists())


if __name__ == "__main__":
    unittest.main()
