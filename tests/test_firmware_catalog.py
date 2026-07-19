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

from pixelflasher_core import AppCommand, ApplicationRuntime, ArtifactProvenance, OperationStatus
from pixelflasher_core.artifact_downloads import (
    ArtifactDownloader,
    ArtifactDownloadPolicy,
    ArtifactManifestVerifier,
    PinnedEd25519Keyring,
    canonical_manifest_bytes,
)
from pixelflasher_core.executor import CancellationToken
from pixelflasher_core.firmware_catalog import (
    FirmwareCatalogService,
    FirmwareCatalogSource,
    FirmwareCatalogStatus,
    MappingFirmwareManifestCatalog,
)
from ui.public_bridge import project_operation_result


class Response:
    status_code = 200

    def __init__(self, content: bytes) -> None:
        self.content = content
        self.headers: Mapping[str, str] = {
            "Content-Length": str(len(content)),
            "ETag": '"firmware-v1"',
        }

    def iter_content(self, chunk_size: int) -> Iterable[bytes]:
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset : offset + chunk_size]

    def close(self) -> None:
        pass


class Session:
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.calls: list[str] = []

    def get(self, url: str, **_kwargs: object) -> Response:
        self.calls.append(url)
        return Response(self.content)


def manifest(private_key: Ed25519PrivateKey, content: bytes, *, arch: str = "akita") -> bytes:
    fields: dict[str, object] = {
        "keyId": "firmware-2026",
        "version": "AP4A.260719.001",
        "platform": "android",
        "arch": arch,
        "license": "Google Terms",
        "provenance": "Google Pixel official images",
        "url": "https://downloads.example/akita-factory.zip",
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


def service(content: bytes, source: FirmwareCatalogSource):
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    session = Session(content)
    downloader = ArtifactDownloader(
        ArtifactManifestVerifier(
            PinnedEd25519Keyring({"firmware-2026": public_key}),
            ArtifactDownloadPolicy(frozenset({"downloads.example"})),
            clock=lambda: datetime(2026, 7, 19, tzinfo=UTC),
        ),
        session=session,
    )
    directory = tempfile.TemporaryDirectory()
    catalog = MappingFirmwareManifestCatalog({("akita", "stable"): (source,)})
    return (
        directory,
        FirmwareCatalogService(
            cache_directory=Path(directory.name) / "cache",
            catalog=catalog,
            downloader=downloader,
        ),
        session,
    )


class FirmwareCatalogTests(TestCase):
    def setUp(self) -> None:
        self.content = b"PK\x03\x04verified-firmware"
        self.private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        self.document = manifest(self.private_key, self.content)

    def test_refresh_verifies_scope_and_returns_closed_entries(self) -> None:
        source = FirmwareCatalogSource("akita", "stable", "factory", self.document)
        directory, catalog, session = service(self.content, source)
        self.addCleanup(directory.cleanup)

        result = catalog.refresh(
            device="AKITA",
            channel="stable",
            cancellation=CancellationToken(),
        )

        self.assertTrue(result.ok)
        self.assertEqual(1, len(result.entries))
        entry = result.entries[0]
        self.assertRegex(entry.artifact_id, r"^[0-9a-f]{32}$")
        self.assertEqual("factory", entry.kind)
        self.assertEqual("akita", entry.device)
        self.assertNotIn("url", entry.to_public_dict())
        self.assertEqual([], session.calls)

    def test_refresh_rejects_scope_kind_signature_and_unknown_target(self) -> None:
        scenarios = (
            (FirmwareCatalogSource("panther", "stable", "factory", self.document), "firmware_catalog_scope_mismatch"),
            (FirmwareCatalogSource("akita", "stable", "custom", self.document), "firmware_catalog_kind_invalid"),
            (FirmwareCatalogSource("akita", "stable", "factory", self.document[:-1] + b"x"), "manifest_json_invalid"),
        )
        for source, code in scenarios:
            with self.subTest(code=code):
                directory, catalog, _session = service(self.content, source)
                try:
                    result = catalog.refresh(
                        device="akita",
                        channel="stable",
                        cancellation=CancellationToken(),
                    )
                    self.assertIs(FirmwareCatalogStatus.FAILED, result.status)
                    self.assertEqual(code, result.code)
                finally:
                    directory.cleanup()

        directory, catalog, _session = service(
            self.content,
            FirmwareCatalogSource("akita", "stable", "factory", self.document),
        )
        self.addCleanup(directory.cleanup)
        empty = catalog.refresh(
            device="akita",
            channel="beta",
            cancellation=CancellationToken(),
        )
        self.assertTrue(empty.ok)
        self.assertEqual((), empty.entries)

    def test_download_requires_refreshed_opaque_id_and_verifies_cache(self) -> None:
        source = FirmwareCatalogSource("akita", "stable", "factory", self.document)
        directory, catalog, session = service(self.content, source)
        self.addCleanup(directory.cleanup)
        unknown = catalog.download("0" * 32, cancellation=CancellationToken())
        self.assertEqual("firmware_artifact_unknown", unknown.code)
        refreshed = catalog.refresh(
            device="akita",
            channel="stable",
            cancellation=CancellationToken(),
        )
        artifact_id = refreshed.entries[0].artifact_id

        first = catalog.download(artifact_id, cancellation=CancellationToken())
        second = catalog.download(artifact_id, cancellation=CancellationToken())

        self.assertTrue(first.ok)
        self.assertFalse(first.cache_hit)
        self.assertTrue(second.ok)
        self.assertTrue(second.cache_hit)
        self.assertEqual(1, len(session.calls))
        assert first.path is not None
        self.assertEqual(self.content, first.path.read_bytes())

    def test_failed_refresh_invalidates_previous_catalog_ids(self) -> None:
        source = FirmwareCatalogSource("akita", "stable", "factory", self.document)
        directory, catalog, _session = service(self.content, source)
        self.addCleanup(directory.cleanup)
        refreshed = catalog.refresh(
            device="akita",
            channel="stable",
            cancellation=CancellationToken(),
        )
        artifact_id = refreshed.entries[0].artifact_id

        failed = catalog.refresh(
            device="invalid device",
            channel="stable",
            cancellation=CancellationToken(),
        )
        stale = catalog.download(artifact_id, cancellation=CancellationToken())

        self.assertIs(FirmwareCatalogStatus.FAILED, failed.status)
        self.assertEqual("firmware_artifact_unknown", stale.code)

    def test_cancellation_never_downloads_or_replaces_catalog(self) -> None:
        source = FirmwareCatalogSource("akita", "stable", "factory", self.document)
        directory, catalog, session = service(self.content, source)
        self.addCleanup(directory.cleanup)
        token = CancellationToken()
        token.cancel()
        refreshed = catalog.refresh(device="akita", channel="stable", cancellation=token)
        downloaded = catalog.download("0" * 32, cancellation=token)

        self.assertIs(FirmwareCatalogStatus.CANCELLED, refreshed.status)
        self.assertEqual("firmware_artifact_unknown", downloaded.code)
        self.assertEqual([], session.calls)

    def test_default_service_fails_closed_without_catalog_or_downloader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            catalog = FirmwareCatalogService(cache_directory=directory)
            result = catalog.refresh(
                device="akita",
                channel="stable",
                cancellation=CancellationToken(),
            )
        self.assertIs(FirmwareCatalogStatus.FAILED, result.status)
        self.assertEqual("firmware_catalog_verifier_unavailable", result.code)

    def test_runtime_download_inspects_persists_and_selects_official_firmware(self) -> None:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(
                "META-INF/com/android/metadata",
                "ota-type=AB\npre-device=akita\npost-build-incremental=AP4A.260719.001\n",
            )
            archive.writestr("META-INF/com/google/android/update-binary", b"not executed")
        content = stream.getvalue()
        document = manifest(self.private_key, content)
        public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        session = Session(content)
        downloader = ArtifactDownloader(
            ArtifactManifestVerifier(
                PinnedEd25519Keyring({"firmware-2026": public_key}),
                ArtifactDownloadPolicy(frozenset({"downloads.example"})),
                clock=lambda: datetime(2026, 7, 19, tzinfo=UTC),
            ),
            session=session,
        )
        catalog = MappingFirmwareManifestCatalog(
            {
                ("akita", "stable"): (
                    FirmwareCatalogSource("akita", "stable", "ota", document),
                )
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            runtime = ApplicationRuntime.open(
                Path(directory) / "config.json",
                firmware_catalog=catalog,
                firmware_downloader=downloader,
            )
            try:
                refreshed = runtime.execute(
                    AppCommand(
                        "firmware.catalog.refresh",
                        expected_revision=runtime.snapshot().revision,
                        payload={"device": "akita", "channel": "stable"},
                    )
                )
                self.assertIs(OperationStatus.SUCCESS, refreshed.status)
                public_catalog = project_operation_result("firmware.catalog.refresh", refreshed)
                artifact_id = public_catalog["value"]["entries"][0]["artifactId"]

                downloaded = runtime.execute(
                    AppCommand(
                        "firmware.download",
                        expected_revision=runtime.snapshot().revision,
                        payload={"artifactId": artifact_id},
                    )
                )

                self.assertIs(OperationStatus.SUCCESS, downloaded.status)
                public_download = project_operation_result("firmware.download", downloaded)
                self.assertEqual(artifact_id, public_download["value"]["artifact"]["artifactId"])
                self.assertNotIn('"path":', json.dumps(public_download))
                snapshot = runtime.snapshot()
                self.assertEqual("ota", snapshot.firmware.type)
                self.assertEqual(hashlib.sha256(content).hexdigest(), snapshot.firmware.hash)
                record = runtime.firmware_repository.resolve_selection(
                    sha256=snapshot.firmware.hash
                )
                self.assertIsNotNone(record)
                assert record is not None
                self.assertIs(ArtifactProvenance.OFFICIAL, record.provenance)
            finally:
                runtime.shutdown()
