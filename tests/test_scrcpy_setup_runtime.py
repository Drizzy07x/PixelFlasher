from __future__ import annotations

import tempfile
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
)
from pixelflasher_core.config_store import ConfigStore
from pixelflasher_core.contracts import AppCommand, OperationStatus
from pixelflasher_core.runtime import ApplicationRuntime
from pixelflasher_core.scrcpy_artifacts import ScrcpyInstaller
from pixelflasher_core.scrcpy_setup import MappingScrcpyManifestCatalog
from tests.test_scrcpy_artifacts import (
    FakeResponse,
    FakeSession,
    signed_manifest,
    successful_probe,
    zip_archive,
)
from ui.public_bridge import project_operation_result


class ScrcpyRuntimeSetupTests(TestCase):
    def _runtime(self, config_path: Path, content: bytes):
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        session = FakeSession(FakeResponse(content))
        downloader = ArtifactDownloader(
            ArtifactManifestVerifier(
                PinnedEd25519Keyring({"scrcpy-2026": public_key}),
                ArtifactDownloadPolicy(frozenset({"github.example"})),
                clock=lambda: datetime(2026, 7, 19, tzinfo=UTC),
            ),
            session=session,
        )
        runtime = ApplicationRuntime.open(
            config_path,
            scrcpy_catalog=MappingScrcpyManifestCatalog(
                {("windows", "x86_64"): signed_manifest(private_key, content)}
            ),
            scrcpy_downloader=downloader,
            scrcpy_installer=ScrcpyInstaller(probe_runner=successful_probe()),
            scrcpy_platform="windows",
            scrcpy_architecture="x86_64",
        )
        return runtime, session

    def test_official_setup_persists_managed_executable_and_public_receipt_has_no_path(self) -> None:
        content = zip_archive()
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            runtime, session = self._runtime(config_path, content)
            try:
                result = runtime.execute(
                    AppCommand(
                        "tools.scrcpy.setup",
                        expected_revision=runtime.snapshot().revision,
                        payload={"source": "official"},
                    )
                )

                self.assertIs(OperationStatus.SUCCESS, result.status)
                self.assertEqual("scrcpy_installed", result.code)
                configured = runtime.command_engine.device_tools_service.scrcpy_executable
                assert configured is not None
                self.assertTrue(configured.is_file())
                managed_root = runtime._scrcpy_install_path(config_path).resolve()
                configured.resolve().relative_to(managed_root)
                saved = ConfigStore(config_path).load()
                self.assertEqual(str(configured.resolve()), saved.values["scrcpy"]["path"])
                public = project_operation_result("tools.scrcpy.setup", result)
                rendered = str(public)
                self.assertNotIn(str(configured), rendered)
                self.assertEqual("3.3.3", public["value"]["installation"]["version"])
                self.assertEqual(1, len(session.calls))
            finally:
                runtime.shutdown()

    def test_stale_revision_and_invalid_source_fail_before_network(self) -> None:
        content = zip_archive()
        with tempfile.TemporaryDirectory() as directory:
            runtime, session = self._runtime(Path(directory) / "config.json", content)
            try:
                stale = runtime.execute(
                    AppCommand(
                        "tools.scrcpy.setup",
                        expected_revision=runtime.snapshot().revision + 1,
                        payload={"source": "official"},
                    )
                )
                invalid = runtime.execute(
                    AppCommand(
                        "tools.scrcpy.setup",
                        expected_revision=runtime.snapshot().revision,
                        payload={"source": "directory"},
                    )
                )
                self.assertIs(OperationStatus.FAILED, stale.status)
                self.assertEqual("stale_revision", stale.code)
                self.assertIs(OperationStatus.FAILED, invalid.status)
                self.assertEqual("invalid_command", invalid.code)
                self.assertEqual([], session.calls)
            finally:
                runtime.shutdown()

    def test_unprovisioned_build_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = ApplicationRuntime.open(Path(directory) / "config.json")
            try:
                result = runtime.execute(
                    AppCommand(
                        "tools.scrcpy.setup",
                        expected_revision=runtime.snapshot().revision,
                        payload={"source": "official"},
                    )
                )
                self.assertIs(OperationStatus.FAILED, result.status)
                self.assertEqual("scrcpy_catalog_unavailable", result.code)
            finally:
                runtime.shutdown()

