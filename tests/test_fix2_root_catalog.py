"""Regression coverage for the architecture-aware root-app inventory identity."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pixelflasher_core.executor import CancellationToken
from pixelflasher_core.root_app_catalog import RootAppCatalogSource
from pixelflasher_core.rooting import RootAppSource, RootingService
from tests.apk_test_helpers import FakeVerifiedApkInspector
from tests.test_root_app_catalog import apk_bytes, catalog_service, signed_manifest


def _source(path: Path, *, architecture: str) -> RootAppSource:
    return RootAppSource(
        path=str(path),
        provider="SukiSU Ultra",
        flavor="stable",
        version="4.1.3",
        provenance="verified-download",
        expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        package_name="org.pixelflasher.test",
        expected_signer_sha256=("a" * 64,),
        architecture=architecture,
    )


class ArchitectureAwareInventoryTests(unittest.TestCase):
    """BUG-32/BUG-41: one release may exist locally for several architectures."""

    def make_service(self) -> RootingService:
        return RootingService(
            apk_inspector=FakeVerifiedApkInspector("org.pixelflasher.test")
        )

    def test_per_architecture_builds_of_one_release_coexist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arm = root / "arm.apk"
            arm.write_bytes(b"arm build")
            arm64 = root / "arm64.apk"
            arm64.write_bytes(b"arm64 build")
            service = self.make_service()

            service.register_verified_source(_source(arm, architecture="arm"))
            service.register_verified_source(_source(arm64, architecture="arm64"))

            inventory = service.root_app_inventory()
            self.assertEqual(
                {"arm", "arm64"},
                {app.architecture for app in inventory},
            )
            self.assertEqual(2, len({app.id for app in inventory}))

    def test_one_universal_apk_staged_per_architecture_gets_distinct_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arm = root / "arm" / "universal.apk"
            arm.parent.mkdir()
            arm.write_bytes(b"universal build")
            arm64 = root / "arm64" / "universal.apk"
            arm64.parent.mkdir()
            arm64.write_bytes(b"universal build")
            service = self.make_service()

            first = service.register_verified_source(_source(arm, architecture="arm"))
            second = service.register_verified_source(
                _source(arm64, architecture="arm64")
            )

            self.assertEqual(first.sha256, second.sha256)
            self.assertNotEqual(first.id, second.id)


class CatalogDownloadIdentityTests(unittest.TestCase):
    """The catalog download of a second architecture keeps a distinct identity."""

    def test_second_architecture_download_replaces_the_first_identity(self) -> None:
        content = apk_bytes()
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        signer = ("a" * 64,)
        sources = tuple(
            RootAppCatalogSource(
                "SukiSU Ultra",
                "stable",
                "stable",
                "org.pixelflasher.test",
                signer,
                signed_manifest(key, content, architecture=architecture),
            )
            for architecture in ("armeabi-v7a", "arm64-v8a")
        )
        directory, service, _session, rooting = catalog_service(content, sources)
        self.addCleanup(directory.cleanup)
        refreshed = service.refresh(channel="stable", cancellation=CancellationToken())
        self.assertTrue(refreshed.ok)
        entries = {entry.architecture: entry for entry in refreshed.entries}

        first = service.download(
            entries["armeabi-v7a"].artifact_id,
            cancellation=CancellationToken(),
        )
        second = service.download(
            entries["arm64-v8a"].artifact_id,
            cancellation=CancellationToken(),
        )

        self.assertTrue(first.ok, first.message)
        self.assertTrue(second.ok, second.message)
        assert first.app is not None and second.app is not None
        self.assertEqual(first.app.sha256, second.app.sha256)
        # The recorded identity follows the architecture the row was published
        # under, so the Root page can tell the two catalog rows apart.
        self.assertNotEqual(first.app.id, second.app.id)
        self.assertEqual(
            ("arm64-v8a",),
            tuple(app.architecture for app in rooting.root_app_inventory()),
        )


if __name__ == "__main__":  # pragma: no cover - manual execution
    unittest.main()
