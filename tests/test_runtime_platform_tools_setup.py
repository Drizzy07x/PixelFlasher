from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pixelflasher_core.artifact_downloads import (
    ArtifactDownloader,
    ArtifactDownloadPolicy,
    ArtifactManifestVerifier,
    PinnedEd25519Keyring,
)
from pixelflasher_core.contracts import AppCommand, OperationStatus
from pixelflasher_core.executor import FakeProcessTransport, TransportOutcome
from pixelflasher_core.platform_tools import PlatformToolsInstaller
from pixelflasher_core.platform_tools_setup import (
    MappingPlatformToolsManifestCatalog,
)
from pixelflasher_core.runtime import ApplicationRuntime
from tests.test_headless_services import (
    ADB_VERSION,
    FASTBOOT_VERSION,
    make_toolchain_files,
)
from tests.test_platform_tools_manifest_install import (
    FakeResponse,
    FakeSession,
    platform_tools_archive,
    signed_manifest,
    successful_probe,
)


def versioned_config(path: Path) -> None:
    path.write_text(
        json.dumps({"_pixelflasher_core_schema": 1}),
        encoding="utf-8",
    )


def probe_transport() -> FakeProcessTransport:
    return FakeProcessTransport(
        [
            TransportOutcome(0, ADB_VERSION),
            TransportOutcome(0, FASTBOOT_VERSION),
        ]
    )


class RuntimePlatformToolsSetupTests(TestCase):
    def test_expired_setup_deadline_is_failed_not_user_cancelled(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            versioned_config(config)
            selected = root / "platform-tools-selected"
            selected.mkdir()
            runtime = ApplicationRuntime.open(config)

            result = runtime.execute(
                AppCommand(
                    "platformTools.setup",
                    expected_revision=0,
                    payload={"source": "directory", "path": str(selected)},
                    execution_timeout_seconds=0.01,
                    _accepted_monotonic=time.monotonic() - 1,
                )
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("timed_out", result.code)
            self.assertEqual(0, runtime.snapshot().revision)
            runtime.shutdown()

    def test_directory_activation_is_durable_and_public_result_is_pathless(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            versioned_config(config)
            selected = root / "platform-tools-selected"
            selected.mkdir()
            adb, fastboot = make_toolchain_files(selected)
            runtime = ApplicationRuntime.open(
                config,
                transport=probe_transport(),
                platform_tools_platform="windows",
                platform_tools_architecture="x86_64",
            )

            result = runtime.execute(
                AppCommand(
                    "platformTools.setup",
                    expected_revision=0,
                    payload={"source": "directory", "path": str(selected)},
                )
            )

            self.assertEqual(OperationStatus.SUCCESS, result.status)
            self.assertEqual("toolchain_ready", result.code)
            self.assertNotIn(str(root), repr(result.value))
            self.assertEqual(str(adb), runtime.snapshot().toolchain.adb)
            self.assertEqual(str(fastboot), runtime.snapshot().toolchain.fastboot)
            persisted = runtime.config_store.load()
            self.assertEqual(str(selected.resolve()), persisted.values["platform_tools_path"])
            runtime.shutdown()

            reopened = ApplicationRuntime.open(config)
            self.assertEqual(str(adb), reopened.snapshot().toolchain.adb)
            self.assertEqual(str(fastboot), reopened.snapshot().toolchain.fastboot)
            self.assertFalse(reopened.snapshot().toolchain.ready)
            reopened.shutdown()

    def test_config_failure_does_not_promote_or_activate_verified_pair(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            versioned_config(config)
            selected = root / "platform-tools-selected"
            selected.mkdir()
            make_toolchain_files(selected)
            runtime = ApplicationRuntime.open(
                config,
                transport=probe_transport(),
                platform_tools_platform="windows",
                platform_tools_architecture="x86_64",
            )

            with patch.object(
                runtime.config_store,
                "save",
                side_effect=OSError("injected config failure"),
            ):
                result = runtime.execute(
                    AppCommand(
                        "platformTools.setup",
                        expected_revision=0,
                        payload={"source": "directory", "path": str(selected)},
                    )
                )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("toolchain_activation_save_failed", result.code)
            self.assertEqual(0, runtime.snapshot().revision)
            self.assertFalse(runtime.snapshot().toolchain.ready)
            self.assertIsNone(runtime.command_engine.toolchain_service.configured_path)
            runtime.shutdown()

    def test_signed_official_install_is_versioned_then_atomically_selected(
        self,
    ) -> None:
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        content = platform_tools_archive()
        document = signed_manifest(private_key, content)
        session = FakeSession(FakeResponse(content))
        verifier = ArtifactManifestVerifier(
            PinnedEd25519Keyring({"platform-tools-2026": public_key}),
            ArtifactDownloadPolicy(frozenset({"dl.google.example"})),
            clock=lambda: datetime(2026, 7, 18, tzinfo=UTC),
        )

        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            versioned_config(config)
            runtime = ApplicationRuntime.open(
                config,
                transport=probe_transport(),
                platform_tools_catalog=MappingPlatformToolsManifestCatalog({("windows", "x86_64"): document}),
                platform_tools_downloader=ArtifactDownloader(
                    verifier,
                    session=session,
                ),
                platform_tools_installer=PlatformToolsInstaller(
                    probe_runner=successful_probe,
                ),
                platform_tools_platform="windows",
                platform_tools_architecture="x86_64",
            )

            with patch("pixelflasher_core.toolchain.os.access", return_value=True):
                result = runtime.execute(
                    AppCommand(
                        "platformTools.setup",
                        expected_revision=0,
                        payload={"source": "official"},
                    )
                )

            digest = hashlib.sha256(content).hexdigest()
            expected_root = (
                root / ".PixelFlasher.json.cache" / "platform-tools" / "versions" / digest / "platform-tools"
            )
            self.assertEqual(OperationStatus.SUCCESS, result.status)
            self.assertEqual("platform_tools_installed", result.code)
            self.assertEqual(expected_root.resolve(), Path(runtime.snapshot().toolchain.adb).parent)
            self.assertEqual(1, len(session.calls))
            self.assertNotIn(str(root), repr(result.value))
            runtime.shutdown()


if __name__ == "__main__":
    import unittest

    unittest.main()
