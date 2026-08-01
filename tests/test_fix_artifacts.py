"""Regression tests for the artifacts defect packet."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import shutil
import tempfile
import unittest
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pixelflasher_core.artifact_downloads import (
    ArtifactDownloader,
    ArtifactDownloadPolicy,
    ArtifactManifestVerifier,
    ArtifactPolicyError,
    ArtifactTransportError,
    PinnedEd25519Keyring,
    canonical_manifest_bytes,
)
from pixelflasher_core.executor import CancellationToken
from pixelflasher_core.platform_tools import (
    PlatformToolsInstaller,
    PlatformToolsStatus,
    binary_architecture_is_compatible,
)
from pixelflasher_core.root_app_catalog import (
    MappingRootAppManifestCatalog,
    RootAppCatalogService,
    RootAppCatalogSource,
    RootAppCatalogStatus,
)
from pixelflasher_core.rooting import RootingService
from pixelflasher_core.scrcpy_artifacts import ScrcpyInstaller, ScrcpyStatus, probe_scrcpy
from tests.apk_test_helpers import FakeVerifiedApkInspector

REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
REAL_SCRCPY_BANNER = (
    "scrcpy 4.1 <https://github.com/Genymobile/scrcpy>\n"
    "\n"
    "Dependencies (compiled / linked):\n"
    " - SDL 3.2.4 / 3.2.4\n"
)


def public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


@dataclass
class _Completed:
    returncode: int
    stdout: str
    stderr: str = ""


def banner_probe(banner: str):
    def run(argv: tuple[str, ...], timeout: float) -> _Completed:
        del argv, timeout
        return _Completed(0, banner)

    return run


def platform_tools_probe(argv: tuple[str, ...], timeout: float) -> _Completed:
    del timeout
    if argv[-1] == "version":
        return _Completed(0, "Android Debug Bridge version 1.0.41\nVersion 36.0.0")
    return _Completed(0, "fastboot version 36.0.0")


def pe_binary(machine: int, marker: bytes = b"scrcpy") -> bytes:
    content = bytearray(256)
    content[:2] = b"MZ"
    content[60:64] = (128).to_bytes(4, "little")
    content[128:132] = b"PE\x00\x00"
    content[132:134] = machine.to_bytes(2, "little")
    content[160 : 160 + len(marker)] = marker
    return bytes(content)


def elf_binary(machine: int) -> bytes:
    content = bytearray(128)
    content[:4] = b"\x7fELF"
    content[4] = 2
    content[5] = 1
    content[18:20] = machine.to_bytes(2, "little")
    return bytes(content)


def write_scrcpy_zip(path: Path, *, executable_name: str, executable: bytes) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"scrcpy-release/{executable_name}", executable)
        archive.writestr("scrcpy-release/SDL2.dll", b"dependency")


def write_platform_tools_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("platform-tools/", b"")
        archive.writestr("platform-tools/adb.exe", pe_binary(0x8664, b"new-adb"))
        archive.writestr("platform-tools/fastboot.exe", pe_binary(0x8664, b"new-fastboot"))


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ScrcpyVersionProbeTests(unittest.TestCase):
    """BUG-09: the version probe must match the banner scrcpy really prints."""

    def test_real_scrcpy_banner_is_recognised(self) -> None:
        probe = probe_scrcpy(Path("scrcpy"), runner=banner_probe(REAL_SCRCPY_BANNER))

        self.assertIs(ScrcpyStatus.SUCCESS, probe.status)
        self.assertEqual("4.1.0", probe.version)

    def test_trailing_suffix_never_truncates_the_reported_version(self) -> None:
        cases = (
            ("scrcpy 4.10 <https://github.com/Genymobile/scrcpy>\n", "4.10.0"),
            ("scrcpy 3.3.3 <https://github.com/Genymobile/scrcpy>\n", "3.3.3"),
            ("scrcpy 4.1-beta1 <https://github.com/Genymobile/scrcpy>\n", "4.1.0"),
            ("scrcpy 3.3.3\n", "3.3.3"),
        )
        for banner, expected in cases:
            with self.subTest(banner=banner):
                probe = probe_scrcpy(Path("scrcpy"), runner=banner_probe(banner))

                self.assertIs(ScrcpyStatus.SUCCESS, probe.status)
                self.assertEqual(expected, probe.version)

    def test_version_smuggled_inside_a_line_is_still_rejected(self) -> None:
        probe = probe_scrcpy(
            Path("scrcpy"),
            runner=banner_probe("hostile output claiming scrcpy 9.9 is installed\n"),
        )

        self.assertIs(ScrcpyStatus.FAILED, probe.status)
        self.assertEqual("scrcpy_version_unverified", probe.code)


class ScrcpyCatalogHostTests(unittest.TestCase):
    """BUG-10: the packaged catalog must allow the GitHub asset redirect host."""

    def test_packaged_catalog_allows_the_release_asset_redirect_hosts(self) -> None:
        catalog = json.loads(
            (REPO_ROOT / "resources" / "scrcpy" / "runtime" / "catalog.json").read_text(
                encoding="utf-8"
            )
        )
        hosts = catalog["allowedHosts"]

        self.assertIn("github.com", hosts)
        self.assertIn("release-assets.githubusercontent.com", hosts)

        policy = ArtifactDownloadPolicy(frozenset(hosts))
        policy.validate_url(
            "https://github.com/Genymobile/scrcpy/releases/download/v4.1/scrcpy-win64-v4.1.zip"
        )
        policy.validate_url(
            "https://release-assets.githubusercontent.com/github-production-release-asset/1/2"
        )
        with self.assertRaises(ArtifactPolicyError):
            policy.validate_url("https://downloads.example.test/scrcpy.zip")


class ScrcpyArchitectureTests(unittest.TestCase):
    """BUG-49: Windows on ARM emulates x64, so the win64 archive must install."""

    def test_windows_arm64_target_accepts_the_x86_64_archive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-fix-scrcpy-arm64-") as temporary:
            root = Path(temporary)
            archive = root / "scrcpy.zip"
            write_scrcpy_zip(archive, executable_name="scrcpy.exe", executable=pe_binary(0x8664))

            result = ScrcpyInstaller(
                probe_runner=banner_probe(REAL_SCRCPY_BANNER)
            ).install_archive(
                archive,
                install_root=root / "install",
                expected_sha256=sha256_of(archive),
                expected_size=archive.stat().st_size,
                expected_version="4.1",
                platform="windows",
                expected_arch="arm64",
                license_value="Apache-2.0",
                provenance="Genymobile scrcpy release",
            )

            self.assertEqual(ScrcpyStatus.SUCCESS, result.status)
            self.assertIsNotNone(result.installation)

    def test_posix_targets_keep_the_strict_architecture_rule(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-fix-scrcpy-linux-") as temporary:
            root = Path(temporary)
            archive = root / "scrcpy.zip"
            write_scrcpy_zip(archive, executable_name="scrcpy", executable=elf_binary(62))

            result = ScrcpyInstaller(
                probe_runner=banner_probe(REAL_SCRCPY_BANNER)
            ).install_archive(
                archive,
                install_root=root / "install",
                expected_sha256=sha256_of(archive),
                expected_size=archive.stat().st_size,
                expected_version="4.1",
                platform="linux",
                expected_arch="arm64",
                license_value="Apache-2.0",
                provenance="Genymobile scrcpy release",
            )

            self.assertEqual(ScrcpyStatus.FAILED, result.status)
            self.assertEqual("scrcpy_arch_mismatch", result.code)

    def test_compatibility_rule_stays_windows_only(self) -> None:
        self.assertTrue(
            binary_architecture_is_compatible(
                platform="windows",
                requested_arch="arm64",
                observed_arches=frozenset({"x86_64"}),
            )
        )
        self.assertFalse(
            binary_architecture_is_compatible(
                platform="linux",
                requested_arch="arm64",
                observed_arches=frozenset({"x86_64"}),
            )
        )
        self.assertFalse(
            binary_architecture_is_compatible(
                platform="windows",
                requested_arch="x86_64",
                observed_arches=frozenset({"arm64"}),
            )
        )
        self.assertFalse(
            binary_architecture_is_compatible(
                platform="windows",
                requested_arch="arm64",
                observed_arches=frozenset({"arm"}),
            )
        )


class PlatformToolsBackupCleanupTests(unittest.TestCase):
    """BUG-30: a locked backup must not fail an already committed activation."""

    def test_locked_backup_directory_does_not_fail_a_committed_install(self) -> None:
        real_rmtree = shutil.rmtree
        observed: list[bool] = []

        def guarded_rmtree(path, ignore_errors=False, **kwargs):  # type: ignore[no-untyped-def]
            observed.append(bool(ignore_errors))
            if not ignore_errors:
                raise PermissionError(
                    32,
                    "The process cannot access the file because it is being used by another process",
                )
            return real_rmtree(path, ignore_errors=True, **kwargs)

        with tempfile.TemporaryDirectory(prefix="pf-fix-tools-backup-") as temporary:
            root = Path(temporary)
            archive = root / "platform-tools.zip"
            install_root = root / "install"
            existing = install_root / "platform-tools"
            existing.mkdir(parents=True)
            (existing / "adb.exe").write_bytes(b"old-adb")
            (existing / "fastboot.exe").write_bytes(b"old-fastboot")
            write_platform_tools_zip(archive)

            with patch("pixelflasher_core.platform_tools.shutil.rmtree", guarded_rmtree):
                result = PlatformToolsInstaller(probe_runner=platform_tools_probe).install_archive(
                    archive,
                    install_root=install_root,
                    expected_sha256=sha256_of(archive),
                    expected_size=archive.stat().st_size,
                    platform="windows",
                    expected_arch="x86_64",
                )

            self.assertEqual(PlatformToolsStatus.SUCCESS, result.status)
            self.assertIsNotNone(result.installation)
            assert result.installation is not None
            self.assertEqual(
                pe_binary(0x8664, b"new-adb"),
                result.installation.adb_path.read_bytes(),
            )
            self.assertTrue(observed)
            self.assertTrue(all(observed))


def apk_bytes() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "AndroidManifest.xml",
            b'<manifest package="org.pixelflasher.test" />',
        )
        archive.writestr("classes.dex", b"dex")
    return stream.getvalue()


def root_app_manifest(content: bytes, *, architecture: str) -> bytes:
    fields: dict[str, object] = {
        "keyId": "root-apps-2026",
        "version": "1.0.0",
        "platform": "android",
        "arch": architecture,
        "license": "GPL-3.0",
        "provenance": "Official provider release",
        "url": "https://downloads.example/root-app.apk",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "expiresAt": "2030-01-01T00:00:00Z",
    }
    signature = PRIVATE_KEY.sign(canonical_manifest_bytes(fields))
    return json.dumps(
        {**fields, "signature": base64.b64encode(signature).decode("ascii")},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class RootAppResponse:
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


class RootAppSession:
    def __init__(self, content: bytes) -> None:
        self.content = content

    def get(self, url: str, **_kwargs: object) -> RootAppResponse:
        del url
        return RootAppResponse(self.content)


def root_app_source(
    *,
    provider: str = "KernelSU",
    channel: str = "stable",
    document: bytes,
) -> RootAppCatalogSource:
    return RootAppCatalogSource(
        provider,
        channel,
        "kernelsu",
        "org.pixelflasher.test",
        ("a" * 64,),
        document,
    )


def root_app_catalog_service(
    content: bytes,
    entries: Mapping[str, tuple[RootAppCatalogSource, ...]],
    directory: Path,
) -> tuple[RootAppCatalogService, RootingService]:
    downloader = ArtifactDownloader(
        ArtifactManifestVerifier(
            PinnedEd25519Keyring({"root-apps-2026": public_bytes(PRIVATE_KEY)}),
            ArtifactDownloadPolicy(
                frozenset({"downloads.example"}),
                maximum_artifact_bytes=256 * 1024 * 1024,
            ),
            clock=lambda: datetime(2026, 7, 19, tzinfo=UTC),
        ),
        session=RootAppSession(content),
    )
    rooting = RootingService(apk_inspector=FakeVerifiedApkInspector("org.pixelflasher.test"))
    service = RootAppCatalogService(
        cache_directory=directory / "cache",
        rooting_service=rooting,
        catalog=MappingRootAppManifestCatalog(dict(entries)),
        downloader=downloader,
    )
    return service, rooting


class RootAppCatalogRefreshTests(unittest.TestCase):
    """BUG-33: a refresh must not report empty success nor destroy live state."""

    def setUp(self) -> None:
        self.content = apk_bytes()
        self.document = root_app_manifest(self.content, architecture="arm64-v8a")
        self.directory = tempfile.TemporaryDirectory(prefix="pf-fix-root-apps-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_unprovisioned_channel_fails_and_keeps_previous_entries(self) -> None:
        service, _rooting = root_app_catalog_service(
            self.content,
            {"stable": (root_app_source(document=self.document),)},
            self.root,
        )
        refreshed = service.refresh(channel="stable", cancellation=CancellationToken())
        self.assertIs(RootAppCatalogStatus.SUCCESS, refreshed.status)
        artifact_id = refreshed.entries[0].artifact_id

        beta = service.refresh(channel="beta", cancellation=CancellationToken())

        self.assertIs(RootAppCatalogStatus.FAILED, beta.status)
        self.assertEqual("root_app_catalog_channel_unprovisioned", beta.code)
        self.assertEqual((), beta.entries)

        downloaded = service.download(artifact_id, cancellation=CancellationToken())
        self.assertTrue(downloaded.ok)

    def test_failed_refresh_leaves_resolved_entries_downloadable(self) -> None:
        service, _rooting = root_app_catalog_service(
            self.content,
            {"stable": (root_app_source(document=self.document),)},
            self.root,
        )
        refreshed = service.refresh(channel="stable", cancellation=CancellationToken())
        artifact_id = refreshed.entries[0].artifact_id

        service.catalog = MappingRootAppManifestCatalog(
            {"stable": (root_app_source(document=self.document[:-1] + b"x"),)}
        )
        failed = service.refresh(channel="stable", cancellation=CancellationToken())

        self.assertIs(RootAppCatalogStatus.FAILED, failed.status)

        downloaded = service.download(artifact_id, cancellation=CancellationToken())
        self.assertNotEqual("root_app_artifact_unknown", downloaded.code)
        self.assertTrue(downloaded.ok)

    def test_empty_default_channel_remains_a_legitimate_success(self) -> None:
        service, _rooting = root_app_catalog_service(self.content, {"stable": ()}, self.root)

        result = service.refresh(channel="stable", cancellation=CancellationToken())

        self.assertIs(RootAppCatalogStatus.SUCCESS, result.status)
        self.assertEqual((), result.entries)


class RootAppArchitectureVariantTests(unittest.TestCase):
    """BUG-32: one universal APK listed under two architectures must register."""

    def test_second_architecture_variant_replaces_the_first_registration(self) -> None:
        content = apk_bytes()
        with tempfile.TemporaryDirectory(prefix="pf-fix-root-arch-") as temporary:
            service, rooting = root_app_catalog_service(
                content,
                {
                    "stable": (
                        root_app_source(
                            document=root_app_manifest(content, architecture="arm64-v8a")
                        ),
                        root_app_source(
                            document=root_app_manifest(content, architecture="x86_64")
                        ),
                    )
                },
                Path(temporary),
            )
            refreshed = service.refresh(channel="stable", cancellation=CancellationToken())
            self.assertEqual(2, len(refreshed.entries))
            by_arch = {entry.architecture: entry.artifact_id for entry in refreshed.entries}

            first = service.download(by_arch["arm64-v8a"], cancellation=CancellationToken())
            second = service.download(by_arch["x86_64"], cancellation=CancellationToken())

            self.assertTrue(first.ok)
            self.assertTrue(second.ok)
            assert second.app is not None
            self.assertEqual("x86_64", second.app.architecture)
            inventory = rooting.root_app_inventory()
            self.assertEqual(1, len(inventory))
            self.assertEqual("x86_64", inventory[0].architecture)


def platform_tools_manifest(content: bytes) -> bytes:
    fields: dict[str, object] = {
        "keyId": "release-2026",
        "version": "36.0.2",
        "platform": "windows",
        "arch": "x86_64",
        "license": "Apache-2.0",
        "provenance": "Google Android SDK Platform Tools",
        "url": "https://downloads.example.test/platform-tools.zip",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "expiresAt": "2030-01-01T00:00:00Z",
    }
    signature = PRIVATE_KEY.sign(canonical_manifest_bytes(fields))
    return json.dumps(
        {**fields, "signature": base64.b64encode(signature).decode("ascii")},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class DownloadResponse:
    def __init__(
        self,
        status_code: int,
        *,
        headers: Mapping[str, str] | None = None,
        events: list[bytes | BaseException] | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.events = list(events or [])
        self.closed = False

    def iter_content(self, chunk_size: int):  # type: ignore[no-untyped-def]
        del chunk_size
        for event in self.events:
            if isinstance(event, BaseException):
                raise event
            yield event

    def close(self) -> None:
        self.closed = True


class DownloadSession:
    def __init__(self, *responses: DownloadResponse) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get(self, url: str, **kwargs: object) -> DownloadResponse:
        self.calls.append((url, kwargs))
        if not self.responses:
            raise AssertionError("unexpected network request")
        return self.responses.pop(0)


class ArtifactResumeRefusedTests(unittest.TestCase):
    """BUG-43: a refused Range request must not poison every later attempt."""

    def downloader(self, session: DownloadSession) -> ArtifactDownloader:
        return ArtifactDownloader(
            ArtifactManifestVerifier(
                PinnedEd25519Keyring({"release-2026": public_bytes(PRIVATE_KEY)}),
                ArtifactDownloadPolicy(
                    frozenset({"downloads.example.test"}),
                    maximum_artifact_bytes=1024 * 1024,
                    chunk_size=4,
                ),
                clock=lambda: datetime(2026, 7, 18, tzinfo=UTC),
            ),
            session=session,
        )

    def test_refused_resume_recovers_on_the_same_attempt(self) -> None:
        content = b"verified-download"
        prefix = content[:6]
        session = DownloadSession(
            DownloadResponse(
                200,
                headers={"Content-Length": str(len(content)), "ETag": '"stable"'},
                events=[prefix, requests.ConnectionError("interrupted")],
            ),
            DownloadResponse(416, headers={"Content-Range": f"bytes */{len(content)}"}),
            DownloadResponse(
                200,
                headers={"Content-Length": str(len(content)), "ETag": '"stable"'},
                events=[content],
            ),
        )
        downloader = self.downloader(session)
        document = platform_tools_manifest(content)

        with tempfile.TemporaryDirectory(prefix="pf-fix-resume-") as temporary:
            destination = Path(temporary) / "platform-tools.zip"
            with self.assertRaises(ArtifactTransportError):
                downloader.download(document, destination)
            self.assertNotEqual([], list(Path(temporary).glob(".*.part")))

            result = downloader.download(document, destination)

            self.assertFalse(result.resumed)
            self.assertEqual(content, destination.read_bytes())
            self.assertIn("Range", session.calls[1][1]["headers"])
            self.assertNotIn("Range", session.calls[2][1]["headers"])
            self.assertEqual([], list(Path(temporary).glob(".*.part")))
            self.assertEqual([], list(Path(temporary).glob(".*.resume.json")))

    def test_transient_failure_still_keeps_the_resumable_partial(self) -> None:
        content = b"verified-download"
        prefix = content[:6]
        session = DownloadSession(
            DownloadResponse(
                200,
                headers={"Content-Length": str(len(content)), "ETag": '"stable"'},
                events=[prefix, requests.ConnectionError("interrupted")],
            ),
            DownloadResponse(503),
        )
        downloader = self.downloader(session)
        document = platform_tools_manifest(content)

        with tempfile.TemporaryDirectory(prefix="pf-fix-resume-5xx-") as temporary:
            destination = Path(temporary) / "platform-tools.zip"
            with self.assertRaises(ArtifactTransportError):
                downloader.download(document, destination)
            with self.assertRaises(ArtifactTransportError):
                downloader.download(document, destination)

            self.assertNotEqual([], list(Path(temporary).glob(".*.part")))
            self.assertNotEqual([], list(Path(temporary).glob(".*.resume.json")))


if __name__ == "__main__":
    unittest.main()
