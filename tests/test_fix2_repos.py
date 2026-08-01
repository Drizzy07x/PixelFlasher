from __future__ import annotations

import hashlib
import unittest
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from pixelflasher_core.avb_downgrade import (
    DowngradePatchCode,
    DowngradePatchService,
    DowngradePatchStatus,
)
from pixelflasher_core.contracts import FileArtifact
from pixelflasher_core.persistent_artifacts import PersistentProcessedArtifactRepository
from pixelflasher_core.planner import ProcessedArtifactRepository
from pixelflasher_core.repositories import ArtifactRepository, FirmwareRepository


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def avb_metadata(*, security_patch: str, fingerprint: str) -> dict[str, str]:
    return {
        "Image Size": "4096",
        "Partition Name": "boot",
        "Salt": "00" * 32,
        "Rollback Index": "0",
        "Algorithm": "SHA256_RSA4096",
        "Hash Algorithm": "sha256",
        "com.android.build.boot.os_version": "16.0.0",
        "com.android.build.boot.fingerprint": fingerprint,
        "com.android.build.boot.security_patch": security_patch,
    }


class ContentAwareAvbTool:
    """Fake AVB tool whose patched output differs with the patched properties."""

    def inspect(self, image: Path) -> Mapping[str, str]:
        content = image.read_bytes()
        if content.startswith(b"patched|"):
            _, security_patch, fingerprint = content.decode().split("|", 2)
            return avb_metadata(security_patch=security_patch, fingerprint=fingerprint)
        if content.startswith(b"current|"):
            security_patch = content.decode().split("|", 1)[1]
            return avb_metadata(
                security_patch=security_patch,
                fingerprint=f"current/{security_patch}",
            )
        if content == b"target":
            return avb_metadata(
                security_patch="2025-01-05",
                fingerprint="target/fingerprint",
            )
        raise ValueError("unknown fake AVB image")

    def patch(
        self,
        image: Path,
        *,
        target_info: Mapping[str, str],
        security_patch: str,
        fingerprint: str,
    ) -> None:
        if target_info["Partition Name"] != "boot":
            raise AssertionError("unexpected partition")
        image.write_bytes(f"patched|{security_patch}|{fingerprint}".encode())


class AdditiveArtifactRepository(ProcessedArtifactRepository):
    """A repository that appends to a key instead of rebinding it."""

    def register(
        self,
        artifacts: Sequence[FileArtifact],
        *,
        firmware_hash: str = "",
        plan_fingerprint: str = "",
    ) -> None:
        key = (firmware_hash.casefold(), plan_fingerprint)
        with self._lock:
            existing = self._artifacts.get(key, ())
            self._artifacts[key] = existing + tuple(
                item for item in artifacts if item not in existing
            )


@contextmanager
def persistent_workspace() -> Iterator[tuple[Path, PersistentProcessedArtifactRepository]]:
    """Yield a scratch root plus a repository closed before the root is removed."""

    with TemporaryDirectory() as directory:
        root = Path(directory)
        artifacts = ArtifactRepository(root / "content")
        try:
            yield root, PersistentProcessedArtifactRepository(
                FirmwareRepository(artifacts)
            )
        finally:
            artifacts.close()


class PersistentRegisterReplacesTheKeyTests(unittest.TestCase):
    def test_registering_a_new_downgrade_evicts_the_superseded_record(self) -> None:
        with persistent_workspace() as (root, repository):
            boot = root / "boot.img"
            first_downgrade = root / "downgrade-1.img"
            second_downgrade = root / "downgrade-2.img"
            boot.write_bytes(b"boot")
            first_downgrade.write_bytes(b"downgrade one")
            second_downgrade.write_bytes(b"downgrade two")
            firmware_hash = "b" * 64
            stock = FileArtifact(str(boot), digest(boot), "partition:boot")

            repository.register((stock,), firmware_hash=firmware_hash)
            repository.register(
                (
                    stock,
                    FileArtifact(
                        str(first_downgrade),
                        digest(first_downgrade),
                        "downgrade:boot",
                    ),
                ),
                firmware_hash=firmware_hash,
            )
            repository.register(
                (
                    stock,
                    FileArtifact(
                        str(second_downgrade),
                        digest(second_downgrade),
                        "downgrade:boot",
                    ),
                ),
                firmware_hash=firmware_hash,
            )

            bound = repository.resolve_binding(firmware_hash=firmware_hash)
            self.assertEqual(
                ["downgrade:boot", "partition:boot"],
                sorted(artifact.role for artifact in bound),
            )
            downgrade = next(
                artifact for artifact in bound if artifact.role == "downgrade:boot"
            )
            self.assertEqual(digest(second_downgrade), downgrade.sha256)

    def test_rolling_back_a_replacement_never_leaves_two_downgrade_artifacts(
        self,
    ) -> None:
        # Rebinding the key discards the superseded record, and its content is
        # not resurrected by a rollback.  Losing a downgrade artifact only
        # costs the user a re-patch, while an ambiguous binding blocks every
        # flash mode for the firmware, so the binding is what is protected.
        with persistent_workspace() as (root, repository):
            boot = root / "boot.img"
            first = root / "downgrade-1.img"
            second = root / "downgrade-2.img"
            boot.write_bytes(b"boot")
            first.write_bytes(b"downgrade one")
            second.write_bytes(b"downgrade two")
            firmware_hash = "c" * 64
            stock = FileArtifact(str(boot), digest(boot), "partition:boot")
            repository.register(
                (stock, FileArtifact(str(first), digest(first), "downgrade:boot")),
                firmware_hash=firmware_hash,
            )

            checkpoint = repository.checkpoint(firmware_hash=firmware_hash)
            repository.register(
                (stock, FileArtifact(str(second), digest(second), "downgrade:boot")),
                firmware_hash=firmware_hash,
            )
            repository.rollback(checkpoint)

            bound = repository.resolve_binding(firmware_hash=firmware_hash)
            self.assertEqual(
                ["partition:boot"],
                [artifact.role for artifact in bound],
            )


class DowngradeBindingStaysUnambiguousTests(unittest.TestCase):
    def _prepare(self, root: Path) -> tuple[Path, str, FileArtifact, FileArtifact]:
        root.mkdir(parents=True, exist_ok=True)
        target = root / "target-boot.img"
        target.write_bytes(b"target")
        first_current = root / "current-boot-1.img"
        first_current.write_bytes(b"current|2026-07-05")
        second_current = root / "current-boot-2.img"
        second_current.write_bytes(b"current|2026-08-05")
        firmware_hash = "a" * 64
        return (
            target,
            firmware_hash,
            FileArtifact(str(first_current), digest(first_current), "partition:boot"),
            FileArtifact(str(second_current), digest(second_current), "partition:boot"),
        )

    def test_a_second_downgrade_replaces_the_first_in_the_persistent_repository(
        self,
    ) -> None:
        with persistent_workspace() as (root, repository):
            target, firmware_hash, first, second = self._prepare(root)
            repository.register(
                (FileArtifact(str(target), digest(target), "partition:boot"),),
                firmware_hash=firmware_hash,
            )
            service = DowngradePatchService(
                repository,
                root / "outputs",
                ContentAwareAvbTool(),
            )

            self.assertEqual(
                DowngradePatchStatus.SUCCESS,
                service.create(
                    firmware_hash=firmware_hash,
                    current_boot=first,
                    patch_fingerprint=True,
                ).status,
            )
            second_result = service.create(
                firmware_hash=firmware_hash,
                current_boot=second,
                patch_fingerprint=True,
            )

            self.assertEqual(DowngradePatchStatus.SUCCESS, second_result.status)
            bound = repository.resolve_binding(firmware_hash=firmware_hash)
            self.assertEqual(
                ["downgrade:boot", "partition:boot"],
                sorted(artifact.role for artifact in bound),
            )
            assert second_result.artifact is not None
            downgrade = next(
                artifact for artifact in bound if artifact.role == "downgrade:boot"
            )
            self.assertEqual(second_result.artifact.sha256, downgrade.sha256)

    def test_an_appending_repository_fails_the_downgrade_instead_of_duplicating_it(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target, firmware_hash, first, second = self._prepare(root)
            repository = AdditiveArtifactRepository()
            repository.register(
                (FileArtifact(str(target), digest(target), "partition:boot"),),
                firmware_hash=firmware_hash,
            )
            service = DowngradePatchService(
                repository,
                root / "outputs",
                ContentAwareAvbTool(),
            )

            first_result = service.create(
                firmware_hash=firmware_hash,
                current_boot=first,
                patch_fingerprint=True,
            )
            self.assertEqual(DowngradePatchStatus.SUCCESS, first_result.status)
            second_result = service.create(
                firmware_hash=firmware_hash,
                current_boot=second,
                patch_fingerprint=True,
            )

            self.assertEqual(DowngradePatchStatus.FAILED, second_result.status)
            self.assertEqual(
                DowngradePatchCode.REGISTRATION_FAILED,
                second_result.code,
            )
            bound = repository.resolve_binding(firmware_hash=firmware_hash)
            self.assertEqual(
                1,
                sum(1 for artifact in bound if artifact.role == "downgrade:boot"),
            )
            assert first_result.artifact is not None
            self.assertTrue(Path(first_result.artifact.path).exists())
            self.assertEqual(
                1,
                len(tuple((root / "outputs").glob("*.img"))),
            )


if __name__ == "__main__":
    unittest.main()
