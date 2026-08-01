"""Regression tests for the flash planner and firmware artifact packet."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory

from pixelflasher_core.avb_downgrade import (
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
from pixelflasher_core.firmware import FirmwareKind
from pixelflasher_core.firmware_artifacts import (
    SUPER_EMPTY_ROLE,
    FirmwareArtifactService,
)
from pixelflasher_core.planner import OperationPlanner, ProcessedArtifactRepository
from tests.test_firmware_artifact_service import write_archive, zip_bytes
from tests.test_payload_processing import (
    StrictPayloadExtractor,
    minimal_payload,
    payload_properties,
    write_zip,
)


def digest(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def snapshot_for(plan: FlashPlan, firmware: FirmwareInfo) -> AppSnapshot:
    return AppSnapshot(
        devices=(
            DeviceInfo(
                "SERIAL-A",
                codename="akita",
                mode="fastboot",
                online=True,
                bootloader="unlocked",
            ),
        ),
        selected_serial="SERIAL-A",
        firmware=firmware,
        plan=plan,
        toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
    )


def flash_command() -> AppCommand:
    return AppCommand(
        "flash.execute",
        expected_revision=0,
        target_serial="SERIAL-A",
    )


def compile_flash(
    root: Path,
    *,
    mode: str,
    options: dict[str, object],
    partition_images: tuple[str, ...],
    firmware_type: str = "factory",
):
    package = root / f"{firmware_type}.zip"
    package.write_bytes(b"firmware package")
    paths = {name: root / f"{name}.img" for name in partition_images}
    for name, path in paths.items():
        path.write_bytes(name.encode("ascii"))
    firmware = FirmwareInfo(
        str(package),
        firmware_type,
        "AP4A.260705.001",
        digest(package),
        True,
        True,
    )
    repository = ProcessedArtifactRepository()
    repository.register(
        tuple(
            FileArtifact(str(paths[name].resolve()), digest(paths[name]), f"partition:{name}")
            for name in partition_images
        ),
        firmware_hash=firmware.hash,
    )
    plan = FlashPlan(mode, options, fingerprint=f"fix-{mode}", dry_run=True)
    snapshot = snapshot_for(plan, firmware)
    compilation = OperationPlanner(artifact_repository=repository).compile(
        flash_command(),
        snapshot,
    )
    return compilation, paths


class WipeModeWithFactoryComponentsTests(unittest.TestCase):
    """BUG-05: wipe mode must be plannable with canonical factory firmware."""

    def test_wipe_mode_plans_the_factory_stage_and_appends_the_wipe(self):
        with TemporaryDirectory() as directory:
            compilation, _paths = compile_flash(
                Path(directory),
                mode="wipe",
                options={"verify": True, "wipe": True, "dataBehavior": "wipe"},
                partition_images=("bootloader", "radio", "boot"),
            )

            self.assertTrue(compilation.ok, compilation.to_dict())
            plan = compilation.plan
            assert plan is not None
            self.assertEqual(("bootloader", "radio", "boot"), plan.partitions)
            self.assertEqual("wipe", plan.data_behavior)
            argvs = [request.argv for request in plan.requests]
            self.assertIn(("FASTBOOT", "-s", "SERIAL-A", "-w"), argvs)
            self.assertEqual(
                argvs[-1],
                ("FASTBOOT", "-s", "SERIAL-A", "-w"),
                "the userdata wipe must run after every image has been written",
            )

    def test_keep_data_mode_also_plans_the_factory_stage(self):
        with TemporaryDirectory() as directory:
            compilation, _paths = compile_flash(
                Path(directory),
                mode="keepdata",
                options={"verify": True},
                partition_images=("bootloader", "radio", "boot"),
            )

            self.assertTrue(compilation.ok, compilation.to_dict())
            assert compilation.plan is not None
            self.assertEqual("preserve", compilation.plan.data_behavior)

    def test_partial_image_modes_still_refuse_the_factory_stage(self):
        with TemporaryDirectory() as directory:
            compilation, _paths = compile_flash(
                Path(directory),
                mode="images",
                options={"verify": True},
                partition_images=("bootloader", "boot"),
            )

            self.assertFalse(compilation.ok)
            self.assertEqual("factory_component_mode_required", compilation.code)

    def test_custom_firmware_never_runs_the_factory_stage(self):
        with TemporaryDirectory() as directory:
            compilation, _paths = compile_flash(
                Path(directory),
                mode="wipe",
                options={"verify": True, "wipe": True, "dataBehavior": "wipe"},
                partition_images=("bootloader", "radio", "boot"),
                firmware_type="custom",
            )

            self.assertFalse(compilation.ok)
            self.assertEqual("factory_component_mode_required", compilation.code)


class FactoryStageWaitsForDeviceTests(unittest.TestCase):
    """BUG-07: every reboot-bootloader must be paired with wait-for-device."""

    def test_each_factory_reboot_is_followed_by_a_wait(self):
        with TemporaryDirectory() as directory:
            compilation, paths = compile_flash(
                Path(directory),
                mode="factory",
                options={"verify": True},
                partition_images=("bootloader", "radio", "boot"),
            )

            self.assertTrue(compilation.ok, compilation.to_dict())
            plan = compilation.plan
            assert plan is not None
            argvs = [request.argv for request in plan.requests]
            self.assertEqual(
                [
                    ("FASTBOOT", "-s", "SERIAL-A", "flash", "bootloader", str(paths["bootloader"].resolve())),
                    ("FASTBOOT", "-s", "SERIAL-A", "reboot-bootloader"),
                    ("FASTBOOT", "-s", "SERIAL-A", "wait-for-device"),
                    ("FASTBOOT", "-s", "SERIAL-A", "flash", "radio", str(paths["radio"].resolve())),
                    ("FASTBOOT", "-s", "SERIAL-A", "reboot-bootloader"),
                    ("FASTBOOT", "-s", "SERIAL-A", "wait-for-device"),
                    ("FASTBOOT", "-s", "SERIAL-A", "flash", "boot", str(paths["boot"].resolve())),
                ],
                argvs,
            )
            waits = [
                index
                for index, argv in enumerate(argvs)
                if argv[-1] == "reboot-bootloader"
            ]
            for index in waits:
                self.assertEqual(
                    "wait-for-device",
                    argvs[index + 1][-1],
                    "a bootloader reboot must never be followed by an unguarded command",
                )


class UnslottedSuperTests(unittest.TestCase):
    """BUG-47: `super` is shared between slots and must not be fanned out."""

    def test_super_is_flashed_once_without_a_slot_argument(self):
        with TemporaryDirectory() as directory:
            compilation, paths = compile_flash(
                Path(directory),
                mode="images",
                options={"verify": True, "slot": "both"},
                partition_images=("boot", "super"),
                firmware_type="custom",
            )

            self.assertTrue(compilation.ok, compilation.to_dict())
            plan = compilation.plan
            assert plan is not None
            argvs = [request.argv for request in plan.requests]
            self.assertEqual(
                [
                    (
                        "FASTBOOT", "-s", "SERIAL-A", "--slot=a", "flash", "boot",
                        str(paths["boot"].resolve()),
                    ),
                    (
                        "FASTBOOT", "-s", "SERIAL-A", "--slot=b", "flash", "boot",
                        str(paths["boot"].resolve()),
                    ),
                    (
                        "FASTBOOT", "-s", "SERIAL-A", "flash", "super",
                        str(paths["super"].resolve()),
                    ),
                ],
                argvs,
            )
            self.assertEqual(("a", "b"), plan.slots)


class FakeAvbTool:
    def inspect(self, image: Path) -> dict[str, str]:
        content = image.read_bytes()
        security_patch = {
            b"target": "2025-01-05",
            b"current": "2026-07-05",
        }.get(content, "2026-07-05")
        return {
            "Image Size": "4096",
            "Partition Name": "boot",
            "Salt": "00" * 32,
            "Rollback Index": "0",
            "Algorithm": "SHA256_RSA4096",
            "Hash Algorithm": "sha256",
            "com.android.build.boot.os_version": "16.0.0",
            "com.android.build.boot.fingerprint": "target/fingerprint",
            "com.android.build.boot.security_patch": security_patch,
        }

    def patch(
        self,
        image: Path,
        *,
        target_info: Mapping[str, str],
        security_patch: str,
        fingerprint: str,
    ) -> None:
        image.write_bytes(b"patched")


class DowngradeBindingTests(unittest.TestCase):
    """BUG-25: the downgrade artifact belongs to the firmware, not to a plan."""

    def test_downgrade_stays_reachable_after_any_flash_option_change(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target-boot.img"
            package = root / "factory.zip"
            target.write_bytes(b"target")
            package.write_bytes(b"factory firmware")
            firmware_hash = digest(package)
            repository = ProcessedArtifactRepository()
            repository.register(
                (FileArtifact(str(target), digest(target), "partition:boot"),),
                firmware_hash=firmware_hash,
            )
            service = DowngradePatchService(repository, root / "outputs", FakeAvbTool())

            result = service.create(
                firmware_hash=firmware_hash,
                plan_fingerprint="fingerprint-at-prepare-time",
                current_security_patch="2026-07-05",
            )

            self.assertEqual(DowngradePatchStatus.SUCCESS, result.status, result.message)
            for fingerprint in ("", "fingerprint-at-prepare-time", "fingerprint-after-toggle"):
                with self.subTest(fingerprint=fingerprint):
                    registered = repository.resolve_binding(
                        firmware_hash=firmware_hash,
                        plan_fingerprint=fingerprint,
                    )
                    self.assertEqual(
                        {"partition:boot", "downgrade:boot"},
                        {artifact.role for artifact in registered},
                    )

    def test_rollback_restores_the_firmware_binding(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target-boot.img"
            package = root / "factory.zip"
            target.write_bytes(b"target")
            package.write_bytes(b"factory firmware")
            firmware_hash = digest(package)
            repository = ProcessedArtifactRepository()
            repository.register(
                (FileArtifact(str(target), digest(target), "partition:boot"),),
                firmware_hash=firmware_hash,
            )
            service = DowngradePatchService(repository, root / "outputs", FakeAvbTool())

            result = service.create(
                firmware_hash=firmware_hash,
                plan_fingerprint="some-plan",
                current_security_patch="2026-07-05",
            )
            self.assertEqual(DowngradePatchStatus.SUCCESS, result.status, result.message)
            assert result.registration_checkpoint is not None
            repository.rollback(result.registration_checkpoint)

            self.assertEqual(
                ("partition:boot",),
                tuple(
                    artifact.role
                    for artifact in repository.resolve_binding(firmware_hash=firmware_hash)
                ),
            )


class SuperEmptyExtractionTests(unittest.TestCase):
    """BUG-06 (extraction half): super_empty.img must survive processing."""

    def test_factory_super_empty_is_extracted_under_a_non_partition_role(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / "husky-factory.zip"
            inner = zip_bytes(
                [
                    ("boot.img", b"verified boot image"),
                    ("super_empty.img", b"verified super metadata"),
                ]
            )
            write_archive(
                firmware,
                [
                    ("flash-all.sh", b"never execute this"),
                    ("bootloader-husky-version.img", b"verified bootloader"),
                    ("radio-husky-version.img", b"verified radio"),
                    ("image-husky-AP4A.260705.001.zip", inner),
                ],
            )
            repository = ProcessedArtifactRepository()
            service = FirmwareArtifactService(repository, root / "processed")

            result = service.process(firmware, expected_devices=("husky",))

            self.assertTrue(result.ok, result.message)
            roles = {artifact.role for artifact in result.artifacts}
            self.assertIn(SUPER_EMPTY_ROLE, roles)
            self.assertNotIn("partition:super_empty", roles)
            self.assertIn(
                "super_empty.img",
                {item.name for item in Path(result.output_directory).iterdir()},
            )

            # The extra artifact must stay invisible to the planner's partition
            # vocabulary: registering it may never break a factory flash.
            snapshot = snapshot_for(
                FlashPlan("factory", {"verify": True}, fingerprint="super-empty", dry_run=True),
                result.firmware,
            )
            compilation = OperationPlanner(artifact_repository=repository).compile(
                flash_command(),
                snapshot,
            )
            self.assertTrue(compilation.ok, compilation.to_dict())
            assert compilation.plan is not None
            self.assertEqual(
                ("bootloader", "radio", "boot"),
                compilation.plan.partitions,
            )


class OtaPayloadAllowListTests(unittest.TestCase):
    """BUG-28: an OTA payload is expanded to the boot chain only."""

    def _archive(self, root: Path, name: str, payload: bytes, *, ota: bool) -> Path:
        archive = root / f"{name}.zip"
        entries: list[tuple[str, bytes]] = []
        if ota:
            entries.append(
                (
                    "META-INF/com/android/metadata",
                    b"ota-type=AB\npre-device=husky\npost-build-incremental=123\n",
                )
            )
        entries.extend(
            [
                ("payload.bin", payload),
                ("payload_properties.txt", payload_properties(payload)),
            ]
        )
        write_zip(archive, entries)
        return archive

    def test_ota_skips_the_logical_partitions_a_custom_rom_still_extracts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = minimal_payload(
                {
                    "boot": b"verified stock boot",
                    "system": b"multi gigabyte system image",
                    "product": b"multi gigabyte product image",
                }
            )

            ota_extractor = StrictPayloadExtractor()
            ota_service = FirmwareArtifactService(
                ProcessedArtifactRepository(),
                root / "processed-ota",
                payload_extractor=ota_extractor,
            )
            ota = ota_service.process(
                self._archive(root, "ota", payload, ota=True),
                expected_devices=("husky",),
            )

            self.assertTrue(ota.ok, ota.message)
            self.assertEqual(FirmwareKind.OTA, ota.inspection.kind)
            self.assertEqual(
                ["firmware", "partition:boot"],
                [artifact.role for artifact in ota.artifacts],
            )
            self.assertEqual(
                {"boot.img"},
                {item.name for item in Path(ota.output_directory).iterdir()},
            )
            self.assertEqual(1, len(ota_extractor.calls))
            self.assertEqual(
                ("boot",),
                tuple(partition.name for partition in ota_extractor.calls[0].partitions),
            )

            custom_extractor = StrictPayloadExtractor()
            custom_service = FirmwareArtifactService(
                ProcessedArtifactRepository(),
                root / "processed-custom",
                payload_extractor=custom_extractor,
            )
            custom = custom_service.process(
                self._archive(root, "custom", payload, ota=False),
                expected_devices=("husky",),
            )

            self.assertTrue(custom.ok, custom.message)
            self.assertEqual(
                ["firmware", "partition:boot", "partition:product", "partition:system"],
                [artifact.role for artifact in custom.artifacts],
            )


if __name__ == "__main__":
    unittest.main()
