from __future__ import annotations

import base64
import hashlib
import io
import json
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
from pixelflasher_core.platform_tools import (
    PlatformToolsInstaller,
    PlatformToolsStatus,
)


class FakeResponse:
    status_code = 200

    def __init__(self, content: bytes) -> None:
        self.content = content
        self.headers: Mapping[str, str] = {
            "Content-Length": str(len(content)),
            "ETag": '"platform-tools-release"',
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


def pe_binary(marker: bytes) -> bytes:
    content = bytearray(128)
    content[:2] = b"MZ"
    content[60:64] = (64).to_bytes(4, "little")
    content[64:68] = b"PE\x00\x00"
    content[68:70] = (0x8664).to_bytes(2, "little")
    content[80 : 80 + len(marker)] = marker
    return bytes(content)


def platform_tools_archive() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("platform-tools/", b"")
        archive.writestr("platform-tools/adb.exe", pe_binary(b"adb"))
        archive.writestr("platform-tools/fastboot.exe", pe_binary(b"fastboot"))
    return buffer.getvalue()


def signed_manifest(
    private_key: Ed25519PrivateKey,
    content: bytes,
    *,
    version: str = "36.0.0",
) -> bytes:
    fields: dict[str, object] = {
        "keyId": "platform-tools-2026",
        "version": version,
        "platform": "windows",
        "arch": "x86_64",
        "license": "Apache-2.0",
        "provenance": "Google Android SDK Platform Tools",
        "url": "https://dl.google.example/platform-tools.zip",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "expiresAt": "2030-01-01T00:00:00Z",
    }
    signature = private_key.sign(canonical_manifest_bytes(fields))
    return json.dumps(
        {**fields, "signature": base64.b64encode(signature).decode("ascii")},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def successful_probe(argv: tuple[str, ...], timeout: float):
    del timeout

    class Completed:
        returncode = 0
        stderr = ""
        stdout = (
            "Android Debug Bridge version 1.0.41\nVersion 36.0.0"
            if argv[-1] == "version"
            else "fastboot version 36.0.0"
        )

    return Completed()


class PlatformToolsManifestInstallTests(TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.verifier = ArtifactManifestVerifier(
            PinnedEd25519Keyring({"platform-tools-2026": public_key}),
            ArtifactDownloadPolicy(frozenset({"dl.google.example"})),
            clock=lambda: datetime(2026, 7, 18, tzinfo=UTC),
        )

    def test_manifest_install_normalizes_host_platform_and_architecture(self) -> None:
        content = platform_tools_archive()
        response = FakeResponse(content)
        session = FakeSession(response)
        downloader = ArtifactDownloader(self.verifier, session=session)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = PlatformToolsInstaller(probe_runner=successful_probe).install_from_manifest(
                signed_manifest(self.private_key, content),
                downloader=downloader,
                cache_directory=root / "cache",
                install_root=root / "install",
                expected_platform="win32",
                expected_arch="AMD64",
            )

            self.assertEqual(PlatformToolsStatus.SUCCESS, result.status)
            self.assertEqual(1, len(session.calls))
            self.assertFalse(session.calls[0][1]["allow_redirects"])
            self.assertTrue(response.closed)

    def test_cancelled_manifest_download_does_not_open_the_transport(self) -> None:
        content = platform_tools_archive()
        session = FakeSession(FakeResponse(content))
        downloader = ArtifactDownloader(self.verifier, session=session)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = PlatformToolsInstaller(probe_runner=successful_probe).install_from_manifest(
                signed_manifest(self.private_key, content),
                downloader=downloader,
                cache_directory=root / "cache",
                install_root=root / "install",
                expected_platform="windows",
                expected_arch="x86_64",
                cancelled=lambda: True,
            )

            self.assertEqual(PlatformToolsStatus.CANCELLED, result.status)
            self.assertEqual("artifact_download_cancelled", result.code)
            self.assertEqual([], session.calls)
            self.assertFalse((root / "install" / "platform-tools").exists())

    def test_signed_version_must_match_both_staged_binaries_before_activation(self) -> None:
        content = platform_tools_archive()
        session = FakeSession(FakeResponse(content))
        downloader = ArtifactDownloader(self.verifier, session=session)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = PlatformToolsInstaller(probe_runner=successful_probe).install_from_manifest(
                signed_manifest(self.private_key, content, version="37.0.0"),
                downloader=downloader,
                cache_directory=root / "cache",
                install_root=root / "install",
                expected_platform="windows",
                expected_arch="x86_64",
            )

            self.assertEqual(PlatformToolsStatus.FAILED, result.status)
            self.assertEqual("toolchain_manifest_version_mismatch", result.code)
            self.assertFalse((root / "install" / "platform-tools").exists())
