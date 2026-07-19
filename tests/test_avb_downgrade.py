from __future__ import annotations

import hashlib
import sys
import unittest
from collections.abc import Mapping
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

import avbtool
from pixelflasher_core.avb_downgrade import (
    BundledAvbDowngradeTool,
    DowngradePatchCode,
    DowngradePatchService,
    DowngradePatchStatus,
)
from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    FileArtifact,
    FirmwareInfo,
    FlashPlan,
    ToolchainInfo,
)
from pixelflasher_core.executor import CancellationToken
from pixelflasher_core.planner import OperationPlanner, ProcessedArtifactRepository


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metadata(*, security_patch: str, fingerprint: str) -> dict[str, str]:
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


class FakeAvbTool:
    def __init__(self, *, mismatch: bool = False) -> None:
        self.mismatch = mismatch
        self.patch_calls: list[tuple[str, str]] = []

    def inspect(self, image: Path) -> dict[str, str]:
        content = image.read_bytes()
        if content == b"target":
            return metadata(security_patch="2025-01-05", fingerprint="target/fingerprint")
        if content == b"current":
            return metadata(security_patch="2026-07-05", fingerprint="current/fingerprint")
        if content == b"patched":
            security_patch, fingerprint = self.patch_calls[-1]
            if self.mismatch:
                security_patch = "2025-01-05"
            return metadata(security_patch=security_patch, fingerprint=fingerprint)
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
        self.patch_calls.append((security_patch, fingerprint))
        image.write_bytes(b"patched")


class FailingArtifactRepository(ProcessedArtifactRepository):
    fail_registration = False

    def register(self, *args, **kwargs) -> None:
        if self.fail_registration:
            raise RuntimeError("injected registration failure")
        super().register(*args, **kwargs)


class AvbDowngradeTests(unittest.TestCase):
    def make_service(
        self,
        root: Path,
        *,
        tool: FakeAvbTool | None = None,
    ) -> tuple[
        DowngradePatchService,
        ProcessedArtifactRepository,
        str,
        FileArtifact,
    ]:
        root.mkdir(parents=True, exist_ok=True)
        target = root / "target-boot.img"
        current = root / "current-boot.img"
        factory = root / "factory.zip"
        target.write_bytes(b"target")
        current.write_bytes(b"current")
        factory.write_bytes(b"factory firmware")
        firmware_hash = digest(factory)
        repository = ProcessedArtifactRepository()
        repository.register(
            (FileArtifact(str(target), digest(target), "partition:boot"),),
            firmware_hash=firmware_hash,
        )
        service = DowngradePatchService(
            repository,
            root / "outputs",
            tool or FakeAvbTool(),
        )
        return (
            service,
            repository,
            firmware_hash,
            FileArtifact(str(current), digest(current), "partition:boot"),
        )

    def test_verified_current_boot_produces_bound_artifact_and_planner_uses_it(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            service, repository, firmware_hash, current = self.make_service(root)

            result = service.create(
                firmware_hash=firmware_hash,
                current_boot=current,
                patch_fingerprint=True,
            )

            self.assertEqual(DowngradePatchStatus.SUCCESS, result.status)
            self.assertEqual(DowngradePatchCode.READY, result.code)
            self.assertEqual("2026-07-05", result.current_security_patch)
            self.assertEqual("2025-01-05", result.target_security_patch)
            self.assertIsNotNone(result.artifact)
            assert result.artifact is not None
            self.assertEqual("downgrade:boot", result.artifact.role)
            self.assertEqual(b"patched", Path(result.artifact.path).read_bytes())
            self.assertEqual(b"target", (root / "target-boot.img").read_bytes())
            registered = repository.resolve_binding(firmware_hash=firmware_hash)
            self.assertEqual(
                {"partition:boot", "downgrade:boot"},
                {artifact.role for artifact in registered},
            )

            snapshot = AppSnapshot(
                revision=0,
                devices=(
                    DeviceInfo(
                        serial="SERIAL-A",
                        mode="fastboot",
                        codename="akita",
                        bootloader="unlocked",
                    ),
                ),
                selected_serial="SERIAL-A",
                firmware=FirmwareInfo(
                    str(root / "factory.zip"),
                    "factory",
                    "old-build",
                    firmware_hash,
                    True,
                    True,
                ),
                plan=FlashPlan(
                    "keepData",
                    {"downgrade": True, "noReboot": True},
                    dry_run=False,
                ),
                toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
            )
            compilation = OperationPlanner(artifact_repository=repository).compile(
                AppCommand(
                    "flash.execute", expected_revision=0, target_serial="SERIAL-A"
                ),
                snapshot,
                preview=True,
            )
            self.assertTrue(compilation.ok)
            assert compilation.plan is not None
            self.assertEqual(result.artifact.path, compilation.plan.requests[0].argv[-1])

    def test_manual_security_patch_cannot_claim_current_fingerprint(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            service, _repository, firmware_hash, _current = self.make_service(root)

            rejected = service.create(
                firmware_hash=firmware_hash,
                current_security_patch="2026-07-05",
                patch_fingerprint=True,
            )
            accepted = service.create(
                firmware_hash=firmware_hash,
                current_security_patch="2026-07-05",
                patch_fingerprint=False,
            )

            self.assertEqual(DowngradePatchCode.FINGERPRINT_UNAVAILABLE, rejected.code)
            self.assertEqual(DowngradePatchStatus.SUCCESS, accepted.status)

    def test_non_downgrade_tampering_mismatch_and_cancellation_fail_closed(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            service, _repository, firmware_hash, current = self.make_service(root)
            not_downgrade = service.create(
                firmware_hash=firmware_hash,
                current_security_patch="2024-12-05",
            )
            self.assertEqual(DowngradePatchCode.NOT_A_DOWNGRADE, not_downgrade.code)

            current_path = Path(current.path)
            current_path.write_bytes(b"changed")
            tampered = service.create(firmware_hash=firmware_hash, current_boot=current)
            self.assertEqual(DowngradePatchCode.CURRENT_INVALID, tampered.code)

            mismatch_service, _repository, mismatch_hash, mismatch_current = self.make_service(
                root / "mismatch", tool=FakeAvbTool(mismatch=True)
            )
            mismatch = mismatch_service.create(
                firmware_hash=mismatch_hash,
                current_boot=mismatch_current,
            )
            self.assertEqual(DowngradePatchCode.POSTCONDITION_MISMATCH, mismatch.code)

            cancelled_service, _repository, cancelled_hash, _current = self.make_service(
                root / "cancelled"
            )
            token = CancellationToken()
            token.cancel()
            cancelled = cancelled_service.create(
                firmware_hash=cancelled_hash,
                current_security_patch="2026-07-05",
                cancellation=token,
            )
            self.assertEqual(DowngradePatchStatus.CANCELLED, cancelled.status)
            self.assertEqual(DowngradePatchCode.CANCELLED, cancelled.code)

    def test_registration_failure_removes_new_service_output(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "boot.img"
            target.write_bytes(b"target")
            firmware_hash = hashlib.sha256(b"firmware").hexdigest()
            repository = FailingArtifactRepository()
            repository.register(
                (FileArtifact(str(target), digest(target), "partition:boot"),),
                firmware_hash=firmware_hash,
            )
            repository.fail_registration = True
            output_root = root / "outputs"
            service = DowngradePatchService(repository, output_root, FakeAvbTool())

            result = service.create(
                firmware_hash=firmware_hash,
                current_security_patch="2026-07-05",
            )

            self.assertEqual(DowngradePatchCode.REGISTRATION_FAILED, result.code)
            self.assertEqual([], list(output_root.glob("*.img")))

    def test_bundled_avbtool_no_longer_imports_legacy_runtime(self):
        sys.modules.pop("runtime", None)
        tool = avbtool.AvbTool(verbose=False)

        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            tool.run(["avbtool.py"])

        self.assertNotIn("runtime", sys.modules)

    def test_bundled_tool_rewrites_real_avb_image_and_verifies_key_hash(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "boot.img"
            image.write_bytes(bytes(4096))
            key = Path(__file__).resolve().parents[1] / "testkey_rsa4096.pem"
            signing_key = FileArtifact(str(key), digest(key), "avb-signing-key")
            tool = BundledAvbDowngradeTool(signing_key)
            argv = [
                "avbtool.py",
                "add_hash_footer",
                "--image",
                str(image),
                "--partition_size",
                str(256 * 1024),
                "--partition_name",
                "boot",
                "--key",
                str(key),
                "--algorithm",
                "SHA256_RSA4096",
                "--hash_algorithm",
                "sha256",
                "--prop",
                "com.android.build.boot.os_version:16.0.0",
                "--prop",
                "com.android.build.boot.fingerprint:target/fingerprint",
                "--prop",
                "com.android.build.boot.security_patch:2025-01-05",
            ]
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                avbtool.AvbTool(verbose=False).run(argv)
            before = tool.inspect(image)

            tool.patch(
                image,
                target_info=before,
                security_patch="2026-07-05",
                fingerprint="current/fingerprint",
            )
            after = tool.inspect(image)

            self.assertEqual(
                "2026-07-05",
                after["com.android.build.boot.security_patch"],
            )
            self.assertEqual(
                "current/fingerprint",
                after["com.android.build.boot.fingerprint"],
            )
            self.assertEqual("boot", after["Partition Name"])


if __name__ == "__main__":
    unittest.main()
