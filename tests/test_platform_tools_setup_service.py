from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pixelflasher_core.artifact_downloads import (
    ArtifactDownloader,
    ArtifactDownloadPolicy,
    ArtifactManifestVerifier,
    PinnedEd25519Keyring,
)
from pixelflasher_core.executor import (
    CancellationToken,
    FakeProcessTransport,
    TransportOutcome,
)
from pixelflasher_core.platform_tools import PlatformToolsInstaller, PlatformToolsStatus
from pixelflasher_core.platform_tools_setup import (
    MappingPlatformToolsManifestCatalog,
    PlatformToolsSetupService,
)
from pixelflasher_core.toolchain import ToolchainService
from tests.test_platform_tools_manifest_install import (
    FakeResponse,
    FakeSession,
    pe_binary,
    platform_tools_archive,
    signed_manifest,
    successful_probe,
)

ADB_VERSION = "Android Debug Bridge version 1.0.41\nVersion 36.0.0"
FASTBOOT_VERSION = "fastboot version 36.0.0"


def fake_toolchain_service() -> ToolchainService:
    return ToolchainService(
        FakeProcessTransport(
            [
                TransportOutcome(0, ADB_VERSION),
                TransportOutcome(0, FASTBOOT_VERSION),
            ]
        )
    )


def write_local_toolchain(directory: Path) -> None:
    (directory / "adb.exe").write_bytes(pe_binary(b"adb"))
    (directory / "fastboot.exe").write_bytes(pe_binary(b"fastboot"))


class PlatformToolsSetupServiceTests(TestCase):
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

    def test_directory_source_validates_without_exposing_the_granted_path(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "chosen-platform-tools"
            selected.mkdir()
            write_local_toolchain(selected)
            progress: list[tuple[str, int | None]] = []
            service = PlatformToolsSetupService(
                fake_toolchain_service(),
                cache_directory=root / "cache",
                install_directory=root / "install",
                platform="windows",
                architecture="x86_64",
            )

            result = service.setup(
                source="directory",
                directory=selected,
                cancellation=CancellationToken(),
                progress=lambda phase, _message, percent: progress.append(
                    (phase.value, percent)
                ),
            )

            self.assertTrue(result.ok)
            self.assertEqual("toolchain_ready", result.code)
            self.assertEqual("36.0.0", result.toolchain.version if result.toolchain else "")
            self.assertNotIn(str(root), repr(result.to_public_dict()))
            self.assertEqual(("started", 0), progress[0])
            self.assertEqual(("completed", 100), progress[-1])

    def test_unprovisioned_official_catalog_fails_without_network_or_files(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            service = PlatformToolsSetupService(
                fake_toolchain_service(),
                cache_directory=root / "cache",
                install_directory=root / "install",
            )

            result = service.setup(
                source="official",
                directory=None,
                cancellation=CancellationToken(),
            )

            self.assertEqual(PlatformToolsStatus.FAILED, result.status)
            self.assertEqual("platform_tools_catalog_unavailable", result.code)
            self.assertFalse((root / "cache").exists())
            self.assertFalse((root / "install").exists())

    def test_official_source_installs_into_hash_version_and_reprobes_before_activation(self) -> None:
        content = platform_tools_archive()
        document = signed_manifest(self.private_key, content)
        response = FakeResponse(content)
        session = FakeSession(response)
        downloader = ArtifactDownloader(self.verifier, session=session)
        catalog = MappingPlatformToolsManifestCatalog(
            {("windows", "x86_64"): document}
        )

        with TemporaryDirectory() as directory:
            root = Path(directory)
            service = PlatformToolsSetupService(
                fake_toolchain_service(),
                cache_directory=root / "cache",
                install_directory=root / "install",
                catalog=catalog,
                downloader=downloader,
                installer=PlatformToolsInstaller(probe_runner=successful_probe),
                platform="win32",
                architecture="AMD64",
            )

            result = service.setup(
                source="official",
                directory=None,
                cancellation=CancellationToken(),
            )

            digest = hashlib.sha256(content).hexdigest()
            installed = root / "install" / "versions" / digest / "platform-tools"
            self.assertTrue(result.ok)
            self.assertEqual("platform_tools_installed", result.code)
            self.assertTrue((installed / "adb.exe").is_file())
            self.assertTrue((installed / "fastboot.exe").is_file())
            self.assertEqual("36.0.0", result.toolchain.version if result.toolchain else "")
            self.assertEqual(1, len(session.calls))
            self.assertNotIn(str(root), repr(result.to_public_dict()))

    def test_cancellation_before_official_setup_does_not_resolve_catalog(self) -> None:
        class ExplodingCatalog:
            def manifest_for(self, *, platform: str, architecture: str) -> bytes:
                del platform, architecture
                raise AssertionError("catalog must not be opened")

        with TemporaryDirectory() as directory:
            root = Path(directory)
            token = CancellationToken()
            token.cancel()
            service = PlatformToolsSetupService(
                fake_toolchain_service(),
                cache_directory=root / "cache",
                install_directory=root / "install",
                catalog=ExplodingCatalog(),
            )

            result = service.setup(
                source="official",
                directory=None,
                cancellation=token,
            )

            self.assertEqual(PlatformToolsStatus.CANCELLED, result.status)
            self.assertFalse((root / "cache").exists())
            self.assertFalse((root / "install").exists())

    def test_source_contract_rejects_aliases_and_ambiguous_directory(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            service = PlatformToolsSetupService(
                fake_toolchain_service(),
                cache_directory=root / "cache",
                install_directory=root / "install",
            )

            alias = service.setup(
                source="download",
                directory=None,
                cancellation=CancellationToken(),
            )
            ambiguous = service.setup(
                source="official",
                directory=root,
                cancellation=CancellationToken(),
            )

            self.assertEqual("platform_tools_source_invalid", alias.code)
            self.assertEqual("platform_tools_source_ambiguous", ambiguous.code)


if __name__ == "__main__":
    import unittest

    unittest.main()
