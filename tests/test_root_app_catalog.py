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
from pixelflasher_core.contracts import AppCommand, AppSnapshot, OperationStatus
from pixelflasher_core.executor import CancellationToken
from pixelflasher_core.root_app_catalog import (
    MappingRootAppManifestCatalog,
    RootAppCatalogService,
    RootAppCatalogSource,
    RootAppCatalogStatus,
)
from pixelflasher_core.rooting import RootingService
from pixelflasher_core.store import AppStateStore
from tests.apk_test_helpers import FakeVerifiedApkInspector
from tests.command_engine_factory import make_test_command_engine
from ui.public_bridge import project_operation_result


class Response:
    status_code = 200

    def __init__(self, content: bytes) -> None:
        self.content = content
        self.headers: Mapping[str, str] = {
            "Content-Length": str(len(content)),
            "ETag": '"root-app-v1"',
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


def apk_bytes() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "AndroidManifest.xml",
            b'<manifest package="org.pixelflasher.test" />',
        )
        archive.writestr("classes.dex", b"dex")
    return stream.getvalue()


def signed_manifest(
    private_key: Ed25519PrivateKey,
    content: bytes,
    *,
    version: str = "1.0.0",
    architecture: str = "arm64-v8a",
) -> bytes:
    fields: dict[str, object] = {
        "keyId": "root-apps-2026",
        "version": version,
        "platform": "android",
        "arch": architecture,
        "license": "GPL-3.0",
        "provenance": "Official provider release",
        "url": "https://downloads.example/root-app.apk",
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


def catalog_service(
    content: bytes,
    sources: tuple[RootAppCatalogSource, ...],
    *,
    rooting: RootingService | None = None,
):
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    session = Session(content)
    downloader = ArtifactDownloader(
        ArtifactManifestVerifier(
            PinnedEd25519Keyring({"root-apps-2026": public_key}),
            ArtifactDownloadPolicy(
                frozenset({"downloads.example"}),
                maximum_artifact_bytes=256 * 1024 * 1024,
            ),
            clock=lambda: datetime(2026, 7, 19, tzinfo=UTC),
        ),
        session=session,
    )
    directory = tempfile.TemporaryDirectory()
    rooting = rooting or RootingService(
        apk_inspector=FakeVerifiedApkInspector("org.pixelflasher.test")
    )
    service = RootAppCatalogService(
        cache_directory=Path(directory.name) / "cache",
        rooting_service=rooting,
        catalog=MappingRootAppManifestCatalog({"stable": sources}),
        downloader=downloader,
    )
    return directory, service, session, rooting


class RootAppCatalogTests(TestCase):
    def setUp(self) -> None:
        self.content = apk_bytes()
        self.private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        self.document = signed_manifest(self.private_key, self.content)

    def source(
        self,
        provider: str = "Magisk",
        *,
        channel: str = "stable",
        package_name: str = "org.pixelflasher.test",
        signer: str = "a" * 64,
        document: bytes | None = None,
    ) -> RootAppCatalogSource:
        return RootAppCatalogSource(
            provider,
            channel,
            channel,
            package_name,
            (signer,),
            document if document is not None else self.document,
        )

    def test_refresh_verifies_all_supported_provider_families(self) -> None:
        providers = (
            "Magisk",
            "APatch",
            "KernelSU",
            "KernelSU Next",
            "SukiSU Ultra",
            "Wild_KSU",
            "KernelSU Legacy",
        )
        sources = tuple(self.source(provider) for provider in providers)
        directory, service, session, _rooting = catalog_service(self.content, sources)
        self.addCleanup(directory.cleanup)

        result = service.refresh(channel="stable", cancellation=CancellationToken())

        self.assertTrue(result.ok)
        self.assertEqual(set(providers), {entry.provider for entry in result.entries})
        self.assertTrue(all(entry.channel == "stable" for entry in result.entries))
        self.assertTrue(all(entry.architecture == "arm64-v8a" for entry in result.entries))
        self.assertTrue(all(entry.signer_sha256 == ("a" * 64,) for entry in result.entries))
        self.assertTrue(all(len(entry.artifact_id) == 32 for entry in result.entries))
        self.assertEqual([], session.calls)
        self.assertNotIn("url", json.dumps(result.to_public_dict()).casefold())

    def test_refresh_rejects_scope_provider_signature_package_and_signer(self) -> None:
        cases = (
            (self.source(channel="beta"), "root_app_catalog_scope_mismatch"),
            (self.source("UnknownRoot"), "root_app_provider_invalid"),
            (
                self.source(document=self.document[:-1] + b"x"),
                "manifest_json_invalid",
            ),
            (
                self.source(package_name="not-a-package"),
                "root_app_package_name_invalid",
            ),
            (self.source(signer="bad"), "root_app_signer_invalid"),
        )
        for source, code in cases:
            with self.subTest(code=code):
                directory, service, _session, _rooting = catalog_service(
                    self.content,
                    (source,),
                )
                try:
                    result = service.refresh(
                        channel="stable",
                        cancellation=CancellationToken(),
                    )
                    self.assertIs(RootAppCatalogStatus.FAILED, result.status)
                    self.assertEqual(code, result.code)
                finally:
                    directory.cleanup()

    def test_download_uses_opaque_id_cache_and_promotes_verified_identity(self) -> None:
        directory, service, session, rooting = catalog_service(
            self.content,
            (self.source(),),
        )
        self.addCleanup(directory.cleanup)
        unknown = service.download("0" * 32, cancellation=CancellationToken())
        self.assertEqual("root_app_artifact_unknown", unknown.code)
        refreshed = service.refresh(channel="stable", cancellation=CancellationToken())
        artifact_id = refreshed.entries[0].artifact_id

        first = service.download(artifact_id, cancellation=CancellationToken())
        second = service.download(artifact_id, cancellation=CancellationToken())

        self.assertTrue(first.ok)
        self.assertFalse(first.cache_hit)
        self.assertTrue(second.ok)
        self.assertTrue(second.cache_hit)
        self.assertEqual(1, len(session.calls))
        self.assertEqual(1, len(rooting.root_app_inventory()))
        app = rooting.root_app_inventory()[0]
        self.assertEqual("org.pixelflasher.test", app.package_name)
        self.assertEqual(("a" * 64,), app.signer_sha256)
        self.assertEqual("arm64-v8a", app.architecture)
        self.assertEqual("verified-download", app.provenance)

    def test_corrupt_cache_is_replaced_before_inventory_promotion(self) -> None:
        directory, service, session, rooting = catalog_service(
            self.content,
            (self.source(),),
        )
        self.addCleanup(directory.cleanup)
        refreshed = service.refresh(channel="stable", cancellation=CancellationToken())
        entry = refreshed.entries[0]
        service.cache_directory.mkdir(parents=True, exist_ok=True)
        cached = service.cache_directory / f"{entry.sha256}.apk"
        cached.write_bytes(b"corrupt-cache")

        result = service.download(
            entry.artifact_id,
            cancellation=CancellationToken(),
        )

        self.assertTrue(result.ok)
        self.assertFalse(result.cache_hit)
        self.assertEqual(self.content, cached.read_bytes())
        self.assertEqual(1, len(session.calls))
        self.assertEqual(1, len(rooting.root_app_inventory()))

    def test_package_or_signer_mismatch_never_enters_inventory(self) -> None:
        cases = (
            (self.source(package_name="com.example.wrong"), "root_app_package_mismatch"),
            (self.source(signer="b" * 64), "root_app_signer_mismatch"),
        )
        for source, code in cases:
            with self.subTest(code=code):
                directory, service, _session, rooting = catalog_service(
                    self.content,
                    (source,),
                )
                try:
                    refreshed = service.refresh(
                        channel="stable",
                        cancellation=CancellationToken(),
                    )
                    result = service.download(
                        refreshed.entries[0].artifact_id,
                        cancellation=CancellationToken(),
                    )
                    self.assertIs(RootAppCatalogStatus.FAILED, result.status)
                    self.assertEqual(code, result.code)
                    self.assertEqual((), rooting.root_app_inventory())
                finally:
                    directory.cleanup()

    def test_cancelled_refresh_and_download_do_not_promote(self) -> None:
        directory, service, session, rooting = catalog_service(
            self.content,
            (self.source(),),
        )
        self.addCleanup(directory.cleanup)
        token = CancellationToken()
        token.cancel()
        cancelled_refresh = service.refresh(channel="stable", cancellation=token)
        self.assertIs(RootAppCatalogStatus.CANCELLED, cancelled_refresh.status)

        refreshed = service.refresh(channel="stable", cancellation=CancellationToken())
        cancelled_download = service.download(
            refreshed.entries[0].artifact_id,
            cancellation=token,
        )
        self.assertIs(RootAppCatalogStatus.CANCELLED, cancelled_download.status)
        self.assertEqual([], session.calls)
        self.assertEqual((), rooting.root_app_inventory())

    def test_engine_refresh_download_and_list_form_one_revisioned_flow(self) -> None:
        rooting = RootingService(
            apk_inspector=FakeVerifiedApkInspector("org.pixelflasher.test")
        )
        directory, catalog, _session, _rooting = catalog_service(
            self.content,
            (self.source(),),
            rooting=rooting,
        )
        self.addCleanup(directory.cleanup)
        store = AppStateStore(AppSnapshot(revision=4))
        engine = make_test_command_engine(
            store=store,
            rooting_service=rooting,
            root_app_catalog_service=catalog,
        )

        refreshed = engine.execute(
            AppCommand(
                "root.apps.catalog.refresh",
                expected_revision=4,
                payload={"channel": "stable"},
            )
        )
        artifact_id = refreshed.value["entries"][0]["artifactId"]
        downloaded = engine.execute(
            AppCommand(
                "root.apps.download",
                expected_revision=4,
                payload={"artifactId": artifact_id},
            )
        )
        listed = engine.execute(
            AppCommand("root.apps.list", expected_revision=5)
        )

        self.assertIs(OperationStatus.SUCCESS, refreshed.status)
        self.assertIs(OperationStatus.SUCCESS, downloaded.status)
        self.assertEqual("root_app_download_registered", downloaded.code)
        self.assertEqual(5, downloaded.value["revision"])
        self.assertEqual(6, store.snapshot().revision)
        self.assertEqual(1, listed.value["count"])
        public = project_operation_result("root.apps.download", downloaded)
        self.assertEqual(artifact_id, public["value"]["artifact"]["artifactId"])
        self.assertNotIn("path", json.dumps(public).casefold())
        engine.shutdown()

    def test_engine_rolls_back_registered_source_after_revision_race(self) -> None:
        rooting = RootingService(
            apk_inspector=FakeVerifiedApkInspector("org.pixelflasher.test")
        )
        store = AppStateStore(AppSnapshot(revision=4))

        class RacingCatalog(RootAppCatalogService):
            def download(self, *args, **kwargs):
                result = super().download(*args, **kwargs)
                if result.ok:
                    store.update(
                        expected_revision=4,
                        preferences=store.snapshot().preferences,
                    )
                return result

        directory, base, _session, _rooting = catalog_service(
            self.content,
            (self.source(),),
            rooting=rooting,
        )
        self.addCleanup(directory.cleanup)
        catalog = RacingCatalog(
            cache_directory=base.cache_directory,
            rooting_service=rooting,
            catalog=base.catalog,
            downloader=base.downloader,
        )
        engine = make_test_command_engine(
            store=store,
            rooting_service=rooting,
            root_app_catalog_service=catalog,
        )
        refreshed = engine.execute(
            AppCommand(
                "root.apps.catalog.refresh",
                expected_revision=4,
                payload={"channel": "stable"},
            )
        )

        result = engine.execute(
            AppCommand(
                "root.apps.download",
                expected_revision=4,
                payload={"artifactId": refreshed.value["entries"][0]["artifactId"]},
            )
        )

        self.assertIs(OperationStatus.FAILED, result.status)
        self.assertEqual("stale_revision", result.code)
        self.assertEqual((), rooting.root_app_inventory())
        engine.shutdown()
