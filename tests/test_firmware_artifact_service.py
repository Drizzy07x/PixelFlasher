from __future__ import annotations

import hashlib
import io
import stat
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    FlashPlan,
    ToolchainInfo,
)
from pixelflasher_core.executor import CancellationToken
from pixelflasher_core.firmware import FirmwareKind
from pixelflasher_core.firmware_artifacts import (
    FirmwareArtifactLimits,
    FirmwareArtifactService,
    FirmwareProcessingCode,
    FirmwareProcessingStatus,
)
from pixelflasher_core.planner import OperationPlanner, ProcessedArtifactRepository


def zip_bytes(
    entries: list[tuple[str | zipfile.ZipInfo, bytes]],
    *,
    compression: int = zipfile.ZIP_STORED,
) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return stream.getvalue()


def write_archive(
    path: Path,
    entries: list[tuple[str | zipfile.ZipInfo, bytes]],
    *,
    compression: int = zipfile.ZIP_STORED,
) -> None:
    path.write_bytes(zip_bytes(entries, compression=compression))


class FirmwareArtifactServiceTests(unittest.TestCase):
    def make_service(
        self,
        output: Path,
        *,
        limits: FirmwareArtifactLimits = FirmwareArtifactLimits(),
    ) -> tuple[FirmwareArtifactService, ProcessedArtifactRepository]:
        repository = ProcessedArtifactRepository()
        return FirmwareArtifactService(repository, output, limits=limits), repository

    def test_factory_images_are_extracted_to_fixed_names_hashed_and_registered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / "husky-factory.zip"
            inner = zip_bytes(
                [
                    ("boot.img", b"verified boot image"),
                    ("IMAGES/init_boot.img", b"verified init boot image"),
                    ("not-flashable.txt", b"ignored"),
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
            service, repository = self.make_service(root / "processed")

            result = service.process(firmware, expected_devices=("husky",))

            self.assertTrue(result.ok)
            self.assertEqual(FirmwareProcessingStatus.SUCCESS, result.status)
            self.assertEqual(FirmwareProcessingCode.READY, result.code)
            self.assertEqual(FirmwareKind.FACTORY, result.inspection.kind)
            self.assertEqual("AP4A.260705.001", result.firmware.build)
            self.assertEqual(("husky",), result.detected_devices)
            self.assertTrue(result.firmware.verified)
            self.assertTrue(result.firmware.processed)
            self.assertEqual(
                {
                    "firmware",
                    "partition:boot",
                    "partition:bootloader",
                    "partition:init_boot",
                    "partition:radio",
                },
                {artifact.role for artifact in result.artifacts},
            )
            output = Path(result.output_directory)
            self.assertEqual(
                {"boot.img", "bootloader.img", "init_boot.img", "radio.img"},
                {item.name for item in output.iterdir()},
            )
            boot = next(item for item in result.artifacts if item.role == "partition:boot")
            self.assertEqual(
                hashlib.sha256(Path(boot.path).read_bytes()).hexdigest(),
                boot.sha256,
            )
            self.assertEqual(
                result.artifacts,
                repository.resolve(AppSnapshot(firmware=result.firmware)),
            )
            snapshot = AppSnapshot(
                devices=(DeviceInfo("SERIAL", codename="husky", mode="fastboot"),),
                selected_serial="SERIAL",
                firmware=result.firmware,
                plan=FlashPlan(
                    "factory",
                    {"verify": True},
                    fingerprint="processed-factory",
                    dry_run=True,
                ),
                toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
            )
            compilation = OperationPlanner(
                artifact_repository=repository
            ).compile(
                AppCommand(
                    "flash.execute",
                    expected_revision=0,
                    target_serial="SERIAL",
                ),
                snapshot,
            )
            self.assertTrue(compilation.ok)
            self.assertEqual(
                {
                    "partition:boot",
                    "partition:bootloader",
                    "partition:init_boot",
                    "partition:radio",
                },
                {
                    artifact.role
                    for artifact in compilation.plan.artifacts
                    if artifact.role.startswith("partition:")
                },
            )
            self.assertEqual("firmware_artifacts_ready", result.to_dict()["code"])

    def test_ota_registers_the_verified_source_without_extracting_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / "ota.zip"
            write_archive(
                firmware,
                [
                    (
                        "META-INF/com/android/metadata",
                        b"ota-type=AB\npre-device=akita|husky\npost-build-incremental=12345\n",
                    ),
                    ("payload.bin", b"opaque signed payload"),
                ],
            )
            service, repository = self.make_service(root / "processed")

            result = service.process(firmware, expected_devices=("husky",))

            self.assertTrue(result.ok)
            self.assertEqual(FirmwareKind.OTA, result.inspection.kind)
            self.assertEqual(("akita", "husky"), result.detected_devices)
            self.assertEqual("", result.output_directory)
            self.assertEqual(["firmware"], [artifact.role for artifact in result.artifacts])
            self.assertEqual(
                hashlib.sha256(firmware.read_bytes()).hexdigest(),
                result.artifacts[0].sha256,
            )
            self.assertEqual(
                result.artifacts,
                repository.resolve(AppSnapshot(firmware=result.firmware)),
            )
            self.assertFalse((root / "processed").exists())

    def test_custom_direct_images_use_android_info_for_compatibility(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / "custom.zip"
            write_archive(
                firmware,
                [
                    ("META/android-info.txt", b"require board=shiba|husky\n"),
                    ("images/vendor_boot.img", b"vendor boot"),
                    ("boot.img", b"boot"),
                ],
            )
            service, _repository = self.make_service(root / "processed")

            result = service.process(firmware, expected_devices=("shiba",))

            self.assertTrue(result.ok)
            self.assertEqual(FirmwareKind.CUSTOM, result.inspection.kind)
            self.assertEqual(("husky", "shiba"), result.detected_devices)
            self.assertEqual(
                ["partition:boot", "partition:vendor_boot"],
                sorted(
                    artifact.role
                    for artifact in result.artifacts
                    if artifact.role.startswith("partition:")
                ),
            )

    def test_non_ota_without_boot_or_init_boot_fails_before_registration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / "custom-without-stock-boot.zip"
            write_archive(
                firmware,
                [("images/vendor_boot.img", b"vendor boot only")],
            )
            service, repository = self.make_service(root / "processed")

            result = service.process(firmware)

            self.assertEqual(FirmwareProcessingStatus.FAILED, result.status)
            self.assertEqual(FirmwareProcessingCode.STOCK_BOOT_REQUIRED, result.code)
            self.assertFalse(result.registered)
            self.assertEqual((), result.artifacts)
            self.assertEqual((), repository.resolve(AppSnapshot(firmware=result.firmware)))
            output_root = root / "processed"
            if output_root.exists():
                self.assertEqual([], list(output_root.iterdir()))

    def test_device_mismatch_fails_without_registration_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / "custom.zip"
            write_archive(
                firmware,
                [("android-info.txt", b"require product=husky\n"), ("boot.img", b"boot")],
            )
            service, repository = self.make_service(root / "processed")

            result = service.process(firmware, expected_devices=("shiba",))

            self.assertFalse(result.ok)
            self.assertEqual(FirmwareProcessingCode.DEVICE_MISMATCH, result.code)
            self.assertEqual(FirmwareProcessingStatus.FAILED, result.status)
            self.assertFalse(result.firmware.processed)
            self.assertEqual((), result.artifacts)
            self.assertEqual((), repository.resolve(AppSnapshot(firmware=result.firmware)))
            self.assertFalse((root / "processed").exists())

    def test_outer_and_nested_traversal_and_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases: list[tuple[str, bytes]] = []
            outer = root / "outer.zip"
            write_archive(outer, [("../escaped.img", b"owned")])
            cases.append(("outer", outer.read_bytes()))

            nested_traversal = zip_bytes([("../boot.img", b"owned")])
            factory_traversal = root / "factory-traversal.zip"
            write_archive(
                factory_traversal,
                [("flash-all.sh", b""), ("image-husky-build.zip", nested_traversal)],
            )
            cases.append(("nested traversal", factory_traversal.read_bytes()))

            link = zipfile.ZipInfo("boot.img")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            nested_symlink = zip_bytes([(link, b"../../escaped.img")])
            factory_symlink = root / "factory-symlink.zip"
            write_archive(
                factory_symlink,
                [("flash-all.sh", b""), ("image-husky-build.zip", nested_symlink)],
            )
            cases.append(("nested symlink", factory_symlink.read_bytes()))

            for case_name, content in cases:
                with self.subTest(case=case_name):
                    firmware = root / f"case-{case_name.replace(' ', '-')}.zip"
                    firmware.write_bytes(content)
                    output = root / f"processed-{case_name.replace(' ', '-')}"
                    service, _repository = self.make_service(output)

                    result = service.process(firmware)

                    self.assertFalse(result.ok)
                    self.assertIn(
                        result.code,
                        {
                            FirmwareProcessingCode.UNSAFE_PATH,
                            FirmwareProcessingCode.UNSAFE_FILE_TYPE,
                        },
                    )
                    self.assertFalse((root / "escaped.img").exists())
                    if output.exists():
                        self.assertEqual([], list(output.iterdir()))

    def test_duplicate_paths_and_duplicate_partition_aliases_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate_path = root / "duplicate.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                write_archive(
                    duplicate_path,
                    [("boot.img", b"first"), ("BOOT.IMG", b"second")],
                )
            duplicate_partition = root / "duplicate-partition.zip"
            write_archive(
                duplicate_partition,
                [("a/boot.img", b"first"), ("b/boot.img", b"second")],
            )

            service, _repository = self.make_service(root / "processed-a")
            duplicate_result = service.process(duplicate_path)
            partition_service, _repository = self.make_service(root / "processed-b")
            partition_result = partition_service.process(duplicate_partition)

            self.assertEqual(FirmwareProcessingCode.DUPLICATE_ENTRY, duplicate_result.code)
            self.assertEqual(
                FirmwareProcessingCode.DUPLICATE_PARTITION,
                partition_result.code,
            )

    def test_member_entry_total_and_compression_limits_are_enforced_pre_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            member = root / "member.zip"
            write_archive(member, [("boot.img", b"1234")])
            entries = root / "entries.zip"
            write_archive(entries, [("boot.img", b"1"), ("vendor_boot.img", b"2")])
            total = root / "total.zip"
            write_archive(total, [("boot.img", b"123"), ("vendor_boot.img", b"456")])
            ratio = root / "ratio.zip"
            write_archive(
                ratio,
                [("boot.img", b"\0" * 4096)],
                compression=zipfile.ZIP_DEFLATED,
            )
            cases = (
                (
                    member,
                    FirmwareArtifactLimits(maximum_member_bytes=3),
                    FirmwareProcessingCode.MEMBER_TOO_LARGE,
                ),
                (
                    entries,
                    FirmwareArtifactLimits(maximum_entries=1),
                    FirmwareProcessingCode.TOO_MANY_ENTRIES,
                ),
                (
                    total,
                    FirmwareArtifactLimits(maximum_uncompressed_bytes=5),
                    FirmwareProcessingCode.EXPANDED_SIZE_EXCEEDED,
                ),
                (
                    ratio,
                    FirmwareArtifactLimits(maximum_compression_ratio=2),
                    FirmwareProcessingCode.SUSPICIOUS_COMPRESSION,
                ),
            )
            for index, (firmware, limits, code) in enumerate(cases):
                with self.subTest(code=code):
                    output = root / f"processed-{index}"
                    service, _repository = self.make_service(output, limits=limits)

                    result = service.process(firmware)

                    self.assertEqual(code, result.code)
                    self.assertFalse(result.ok)
                    self.assertFalse(output.exists())

    def test_payload_only_custom_rom_fails_explicitly_and_leaves_no_partial_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / "custom-payload.zip"
            write_archive(
                firmware,
                [("payload.bin", b"payload"), ("boot.img", b"incidental boot")],
            )
            output = root / "processed"
            service, repository = self.make_service(output)

            result = service.process(firmware)

            self.assertEqual(
                FirmwareProcessingCode.CUSTOM_PAYLOAD_UNSUPPORTED,
                result.code,
            )
            self.assertEqual(FirmwareProcessingStatus.FAILED, result.status)
            self.assertFalse(result.registered)
            self.assertEqual((), result.artifacts)
            self.assertEqual((), repository.resolve(AppSnapshot(firmware=result.firmware)))
            self.assertTrue(output.exists())
            self.assertEqual([], list(output.iterdir()))

    def test_cancellation_and_missing_files_return_explicit_results(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / "custom.zip"
            write_archive(firmware, [("boot.img", b"boot")])
            service, _repository = self.make_service(root / "processed")
            token = CancellationToken()
            token.cancel()

            cancelled = service.process(firmware, cancellation=token)
            missing = service.process(root / "missing.zip")

            self.assertEqual(FirmwareProcessingStatus.CANCELLED, cancelled.status)
            self.assertEqual(FirmwareProcessingCode.CANCELLED, cancelled.code)
            self.assertEqual(FirmwareProcessingStatus.FAILED, missing.status)
            self.assertEqual(FirmwareProcessingCode.FILE_NOT_FOUND, missing.code)
            self.assertIsInstance(cancelled.to_dict(), dict)
            self.assertIsInstance(missing.to_dict(), dict)

    def test_ota_without_payload_or_legacy_updater_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / "fake-ota.zip"
            write_archive(
                firmware,
                [
                    (
                        "META-INF/com/android/metadata",
                        b"ota-type=AB\npre-device=husky\npost-build-incremental=1\n",
                    )
                ],
            )
            service, _repository = self.make_service(root / "processed")

            result = service.process(firmware)

            self.assertEqual(FirmwareProcessingCode.OTA_LAYOUT_INVALID, result.code)
            self.assertFalse(result.firmware.processed)


if __name__ == "__main__":
    unittest.main()
