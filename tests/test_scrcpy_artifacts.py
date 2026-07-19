from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import tarfile
import tempfile
import zipfile
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from unittest import TestCase

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pixelflasher_core.artifact_downloads import (
    ArtifactDownloader,
    ArtifactDownloadPolicy,
    ArtifactManifestVerifier,
    PinnedEd25519Keyring,
    canonical_manifest_bytes,
)
from pixelflasher_core.scrcpy_artifacts import ScrcpyInstaller, ScrcpyStatus


def pe_binary(architecture: int = 0x8664) -> bytes:
    content = bytearray(256)
    content[:2] = b"MZ"
    content[60:64] = (128).to_bytes(4, "little")
    content[128:132] = b"PE\x00\x00"
    content[132:134] = architecture.to_bytes(2, "little")
    content[160:166] = b"scrcpy"
    return bytes(content)


def elf_binary(machine: int = 62) -> bytes:
    content = bytearray(128)
    content[:4] = b"\x7fELF"
    content[4] = 2
    content[5] = 1
    content[18:20] = machine.to_bytes(2, "little")
    content[32:38] = b"scrcpy"
    return bytes(content)


def zip_archive(*, executable: bytes | None = None, extra: Mapping[str, bytes] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("scrcpy-release/scrcpy.exe", executable or pe_binary())
        archive.writestr("scrcpy-release/SDL2.dll", b"dependency")
        for name, contents in (extra or {}).items():
            archive.writestr(name, contents)
    return buffer.getvalue()


def tar_archive() -> bytes:
    buffer = io.BytesIO()
    binary = elf_binary()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        directory = tarfile.TarInfo("scrcpy-release")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        executable = tarfile.TarInfo("scrcpy-release/scrcpy")
        executable.size = len(binary)
        executable.mode = 0o755
        archive.addfile(executable, io.BytesIO(binary))
    return buffer.getvalue()


def successful_probe(version: str = "3.3.3"):
    def run(argv: tuple[str, ...], timeout: float):
        assert argv[-1] == "--version"
        assert timeout == 10.0

        class Completed:
            returncode = 0
            stdout = f"scrcpy {version}\n"
            stderr = ""

        return Completed()

    return run


class FakeResponse:
    status_code = 200

    def __init__(self, content: bytes) -> None:
        self.content = content
        self.headers: Mapping[str, str] = {
            "Content-Length": str(len(content)),
            "ETag": '"scrcpy-release"',
        }
        self.closed = False

    def iter_content(self, chunk_size: int) -> Iterable[bytes]:
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset : offset + chunk_size]

    def close(self) -> None:
        self.closed = True


class FakeSession:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append((url, kwargs))
        return self.response


def signed_manifest(private_key: Ed25519PrivateKey, content: bytes) -> bytes:
    fields: dict[str, object] = {
        "keyId": "scrcpy-2026",
        "version": "3.3.3",
        "platform": "windows",
        "arch": "x86_64",
        "license": "Apache-2.0",
        "provenance": "Genymobile scrcpy GitHub release",
        "url": "https://github.example/scrcpy-win64.zip",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "expiresAt": "2030-01-01T00:00:00Z",
    }
    signature = private_key.sign(canonical_manifest_bytes(fields))
    return json.dumps(
        {**fields, "signature": base64.b64encode(signature).decode("ascii")},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


class ScrcpyArtifactTests(TestCase):
    def test_signed_zip_install_verifies_target_version_and_promotes_atomically(self) -> None:
        content = zip_archive()
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        response = FakeResponse(content)
        session = FakeSession(response)
        downloader = ArtifactDownloader(
            ArtifactManifestVerifier(
                PinnedEd25519Keyring({"scrcpy-2026": public_key}),
                ArtifactDownloadPolicy(frozenset({"github.example"})),
                clock=lambda: datetime(2026, 7, 19, tzinfo=UTC),
            ),
            session=session,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = ScrcpyInstaller(probe_runner=successful_probe()).install_from_manifest(
                signed_manifest(private_key, content),
                downloader=downloader,
                cache_directory=root / "cache",
                install_root=root / "install",
                expected_platform="win32",
                expected_arch="AMD64",
            )

            self.assertTrue(result.ok)
            self.assertIs(ScrcpyStatus.SUCCESS, result.status)
            assert result.installation is not None
            self.assertEqual("3.3.3", result.installation.version)
            self.assertEqual("x86_64", result.installation.architecture)
            self.assertTrue(result.installation.executable.is_file())
            metadata = json.loads(
                (result.installation.root / ".pixelflasher-scrcpy.json").read_text()
            )
            self.assertEqual(hashlib.sha256(content).hexdigest(), metadata["archiveSha256"])
            self.assertEqual("scrcpy-release/scrcpy.exe", metadata["executable"])
            self.assertEqual(1, len(session.calls))
            self.assertFalse(session.calls[0][1]["allow_redirects"])
            self.assertTrue(response.closed)
            self.assertFalse(any(".staging" in path.name for path in (root / "install").iterdir()))

    def test_linux_tar_install_is_supported_and_executable(self) -> None:
        content = tar_archive()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "scrcpy.tar.gz"
            archive.write_bytes(content)
            result = ScrcpyInstaller(probe_runner=successful_probe()).install_archive(
                archive,
                install_root=root / "install",
                expected_sha256=hashlib.sha256(content).hexdigest(),
                expected_size=len(content),
                expected_version="v3.3.3",
                platform="linux",
                expected_arch="x86_64",
                license_value="Apache-2.0",
                provenance="Genymobile release",
            )

            self.assertTrue(result.ok)
            assert result.installation is not None
            self.assertTrue(result.installation.executable.is_file())
            if os.name != "nt":
                self.assertTrue(result.installation.executable.stat().st_mode & 0o100)

    def test_hash_architecture_and_version_mismatches_fail_without_activation(self) -> None:
        scenarios = (
            (zip_archive(), "0" * 64, "x86_64", "3.3.3", "scrcpy_archive_hash_mismatch"),
            (zip_archive(executable=pe_binary(0xAA64)), None, "x86_64", "3.3.3", "scrcpy_arch_mismatch"),
            (zip_archive(), None, "x86_64", "3.4.0", "scrcpy_manifest_version_mismatch"),
        )
        for content, digest, architecture, version, expected_code in scenarios:
            with self.subTest(code=expected_code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / "scrcpy.zip"
                archive.write_bytes(content)
                result = ScrcpyInstaller(probe_runner=successful_probe()).install_archive(
                    archive,
                    install_root=root / "install",
                    expected_sha256=digest or hashlib.sha256(content).hexdigest(),
                    expected_size=len(content),
                    expected_version=version,
                    platform="windows",
                    expected_arch=architecture,
                    license_value="Apache-2.0",
                    provenance="Genymobile release",
                )
                self.assertIs(ScrcpyStatus.FAILED, result.status)
                self.assertEqual(expected_code, result.code)
                self.assertFalse((root / "install" / "scrcpy").exists())

    def test_traversal_links_and_duplicate_executables_are_rejected(self) -> None:
        unsafe_archives: list[tuple[bytes, str]] = []
        for name in ("../escape", "/absolute"):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr(name, b"bad")
            unsafe_archives.append((buffer.getvalue(), "scrcpy_archive_traversal"))
        duplicate = zip_archive(extra={"other/scrcpy.exe": pe_binary()})
        unsafe_archives.append((duplicate, "scrcpy_executable_ambiguous"))

        for content, expected_code in unsafe_archives:
            with self.subTest(code=expected_code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / "scrcpy.zip"
                archive.write_bytes(content)
                result = ScrcpyInstaller(probe_runner=successful_probe()).install_archive(
                    archive,
                    install_root=root / "install",
                    expected_sha256=hashlib.sha256(content).hexdigest(),
                    expected_size=len(content),
                    expected_version="3.3.3",
                    platform="windows",
                    expected_arch="x86_64",
                    license_value="Apache-2.0",
                    provenance="Genymobile release",
                )
                self.assertIs(ScrcpyStatus.FAILED, result.status)
                self.assertEqual(expected_code, result.code)

    def test_zip_special_entries_are_rejected(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            special = zipfile.ZipInfo("scrcpy-release/device.pipe")
            special.create_system = 3
            special.external_attr = (stat.S_IFIFO | 0o600) << 16
            archive.writestr(special, b"")
        content = buffer.getvalue()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "scrcpy.zip"
            archive.write_bytes(content)
            result = ScrcpyInstaller(probe_runner=successful_probe()).install_archive(
                archive,
                install_root=root / "install",
                expected_sha256=hashlib.sha256(content).hexdigest(),
                expected_size=len(content),
                expected_version="3.3.3",
                platform="windows",
                expected_arch="x86_64",
                license_value="Apache-2.0",
                provenance="Genymobile release",
            )

            self.assertIs(ScrcpyStatus.FAILED, result.status)
            self.assertEqual("scrcpy_archive_link_forbidden", result.code)

    def test_cancellation_never_replaces_an_existing_installation(self) -> None:
        content = zip_archive()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "scrcpy.zip"
            archive.write_bytes(content)
            active = root / "install" / "scrcpy"
            active.mkdir(parents=True)
            marker = active / "existing.txt"
            marker.write_text("preserve")
            result = ScrcpyInstaller(probe_runner=successful_probe()).install_archive(
                archive,
                install_root=root / "install",
                expected_sha256=hashlib.sha256(content).hexdigest(),
                expected_size=len(content),
                expected_version="3.3.3",
                platform="windows",
                expected_arch="x86_64",
                license_value="Apache-2.0",
                provenance="Genymobile release",
                cancelled=lambda: True,
            )

            self.assertIs(ScrcpyStatus.CANCELLED, result.status)
            self.assertEqual("preserve", marker.read_text())
