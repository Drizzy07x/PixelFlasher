from __future__ import annotations

import hashlib
import io
import json
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    ApplicationRuntime,
    BootInfo,
    DeviceInfo,
    FileArtifact,
    FirmwareArtifactService,
    FirmwareInfo,
    FirmwareInspection,
    FirmwareKind,
    FirmwareProcessingCode,
    FirmwareProcessingResult,
    FirmwareProcessingStatus,
    OperationPlan,
    OperationPlanner,
    OperationResult,
    OperationStatus,
    PixelFlasherEngine,
    ProcessRequest,
    SafetyPolicy,
)


def archive_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return stream.getvalue()


def write_factory(path: Path) -> None:
    inner = archive_bytes(
        [
            ("boot.img", b"stock boot"),
            ("init_boot.img", b"preferred stock init boot"),
            ("vbmeta.img", b"stock vbmeta"),
        ]
    )
    path.write_bytes(
        archive_bytes(
            [
                ("flash-all.sh", b"never execute"),
                ("image-husky-AP4A.260705.001.zip", inner),
            ]
        )
    )


def write_ota(path: Path) -> None:
    path.write_bytes(
        archive_bytes(
            [
                (
                    "META-INF/com/android/metadata",
                    b"ota-type=AB\npre-device=husky\npost-build-incremental=12345\n",
                ),
                ("payload.bin", b"opaque OTA payload"),
            ]
        )
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def selected_snapshot(firmware: FirmwareInfo = FirmwareInfo(), boot: BootInfo = BootInfo()):
    return AppSnapshot(
        devices=(
            DeviceInfo(
                "SERIAL",
                codename="husky",
                mode="fastboot",
                bootloader="unlocked",
            ),
        ),
        selected_serial="SERIAL",
        firmware=firmware,
        boot=boot,
    )


class BlockingFirmwareArtifactService(FirmwareArtifactService):
    def __init__(self, repository, output_root):
        super().__init__(repository, output_root)
        self.started = threading.Event()

    def process(self, path, *, expected_devices=(), cancellation=None):
        self.started.set()
        assert cancellation is not None
        cancellation.wait(2)
        inspection = FirmwareInspection(
            str(path),
            FirmwareKind.CORRUPT,
            code="firmware_cancelled",
            message="cancelled by test",
        )
        return FirmwareProcessingResult(
            status=FirmwareProcessingStatus.CANCELLED,
            code=FirmwareProcessingCode.CANCELLED,
            message="cancelled by test",
            inspection=inspection,
            firmware=inspection.to_firmware_info(processed=False),
        )


class SuccessfulBlockingFirmwareArtifactService(FirmwareArtifactService):
    def __init__(self, repository, output_root):
        super().__init__(repository, output_root)
        self.processed = threading.Event()
        self.release = threading.Event()

    def process(self, path, *, expected_devices=(), cancellation=None):
        result = super().process(
            path,
            expected_devices=expected_devices,
            cancellation=cancellation,
        )
        self.processed.set()
        self.release.wait(2)
        return result


class FirmwareEngineIntegrationTests(unittest.TestCase):
    def make_engine(self, cache: Path, snapshot: AppSnapshot | None = None):
        planner = OperationPlanner()
        service = FirmwareArtifactService(planner.artifact_repository, cache)
        engine = PixelFlasherEngine(
            store=AppStateStore(snapshot or selected_snapshot()),
            operation_planner=planner,
            firmware_artifact_service=service,
        )
        return engine, planner, service

    def test_factory_processing_promotes_verified_firmware_and_preferred_stock_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            factory = root / "factory.zip"
            write_factory(factory)
            engine, planner, service = self.make_engine(root / "cache")

            selected = engine.execute(
                AppCommand(
                    "firmware.select",
                    expected_revision=0,
                    payload={"path": str(factory)},
                )
            )
            processed = engine.execute(
                AppCommand("firmware.process", expected_revision=1)
            )

            snapshot = engine.store.snapshot()
            self.assertEqual(OperationStatus.SUCCESS, selected.status)
            self.assertEqual(OperationStatus.SUCCESS, processed.status)
            self.assertEqual("firmware_processed", processed.code)
            self.assertEqual(3, snapshot.revision)
            self.assertTrue(snapshot.firmware.verified)
            self.assertTrue(snapshot.firmware.processed)
            self.assertEqual("factory", snapshot.firmware.type)
            self.assertEqual("init_boot", snapshot.boot.flavor)
            self.assertFalse(snapshot.boot.patched)
            self.assertTrue(snapshot.boot.id.startswith("stock:init_boot:"))
            self.assertEqual(
                hashlib.sha256(Path(snapshot.boot.path).read_bytes()).hexdigest(),
                snapshot.boot.hash,
            )
            self.assertIs(
                service.repository,
                planner.artifact_repository,
            )
            registered = planner.artifact_repository.resolve(snapshot)
            self.assertTrue(any(item.role == "partition:init_boot" for item in registered))
            self.assertEqual(snapshot.firmware.to_dict(), processed.value["firmware"])
            self.assertEqual(snapshot.boot.to_dict(), processed.value["boot"])
            self.assertIsNone(snapshot.active_operation)
            self.assertEqual(processed, snapshot.last_result)

    def test_ota_success_promotes_firmware_without_inventing_a_boot_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ota = root / "ota.zip"
            write_ota(ota)
            engine, _planner, _service = self.make_engine(root / "cache")

            selected = engine.execute(
                AppCommand(
                    "firmware.select",
                    expected_revision=0,
                    payload={"path": str(ota)},
                )
            )
            processed = engine.execute(
                AppCommand("firmware.process", expected_revision=1)
            )

            snapshot = engine.store.snapshot()
            self.assertTrue(selected.ok)
            self.assertTrue(processed.ok)
            self.assertEqual("ota", snapshot.firmware.type)
            self.assertTrue(snapshot.firmware.processed)
            self.assertEqual(BootInfo(), snapshot.boot)
            self.assertIsNone(processed.value["boot"])

    def test_custom_direct_image_package_requires_and_promotes_stock_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            custom = root / "custom.zip"
            custom.write_bytes(
                archive_bytes(
                    [
                        ("android-info.txt", b"require product=husky\n"),
                        ("images/boot.img", b"custom stock boot"),
                        ("images/vendor_boot.img", b"custom vendor boot"),
                    ]
                )
            )
            engine, _planner, _service = self.make_engine(root / "cache")

            selected = engine.execute(
                AppCommand(
                    "firmware.select",
                    expected_revision=0,
                    payload={"path": str(custom)},
                )
            )
            processed = engine.execute(
                AppCommand("firmware.process", expected_revision=1)
            )

            self.assertTrue(selected.ok)
            self.assertTrue(processed.ok)
            self.assertEqual("custom", engine.store.snapshot().firmware.type)
            self.assertEqual("boot", engine.store.snapshot().boot.flavor)
            self.assertFalse(engine.store.snapshot().boot.patched)

    def test_failed_and_cancelled_processing_never_mutate_firmware_or_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot_path = root / "existing-boot.img"
            boot_path.write_bytes(b"existing")
            previous_boot = BootInfo(
                "existing",
                str(boot_path),
                sha256(boot_path),
                "boot",
                False,
            )
            corrupt = root / "corrupt.zip"
            corrupt.write_bytes(b"not a zip")
            previous_firmware = FirmwareInfo(
                str(corrupt),
                "custom",
                "old",
                sha256(corrupt),
                True,
                False,
            )
            original = selected_snapshot(previous_firmware, previous_boot)
            failed_engine, _planner, _service = self.make_engine(
                root / "failure-cache",
                original,
            )

            failed = failed_engine.execute(
                AppCommand("firmware.process", expected_revision=0)
            )

            self.assertEqual(OperationStatus.FAILED, failed.status)
            self.assertEqual(previous_firmware, failed_engine.store.snapshot().firmware)
            self.assertEqual(previous_boot, failed_engine.store.snapshot().boot)
            self.assertIsNone(failed_engine.store.snapshot().active_operation)

            valid = root / "valid.zip"
            write_factory(valid)
            selected_firmware = FirmwareInfo(
                str(valid),
                "factory",
                "new",
                sha256(valid),
                True,
                False,
            )
            cancel_snapshot = selected_snapshot(selected_firmware, previous_boot)
            planner = OperationPlanner()
            blocking = BlockingFirmwareArtifactService(
                planner.artifact_repository,
                root / "cancel-cache",
            )
            cancel_engine = PixelFlasherEngine(
                store=AppStateStore(cancel_snapshot),
                operation_planner=planner,
                firmware_artifact_service=blocking,
            )
            results = []
            command = AppCommand(
                "firmware.process",
                expected_revision=0,
                operation_id="cancel-firmware",
            )
            worker = threading.Thread(
                target=lambda: results.append(cancel_engine.execute(command)),
                daemon=True,
            )
            worker.start()
            self.assertTrue(blocking.started.wait(1))
            self.assertTrue(cancel_engine.cancel("cancel-firmware"))
            worker.join(2)

            self.assertFalse(worker.is_alive())
            self.assertEqual(OperationStatus.CANCELLED, results[0].status)
            self.assertEqual(selected_firmware, cancel_engine.store.snapshot().firmware)
            self.assertEqual(previous_boot, cancel_engine.store.snapshot().boot)
            self.assertIsNone(cancel_engine.store.snapshot().active_operation)

    def test_revision_change_during_processing_blocks_atomic_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / "factory.zip"
            write_factory(firmware)
            selected = FirmwareInfo(
                str(firmware),
                "factory",
                "42",
                sha256(firmware),
                True,
                False,
            )
            original = selected_snapshot(selected)
            planner = OperationPlanner()
            service = SuccessfulBlockingFirmwareArtifactService(
                planner.artifact_repository,
                root / "cache",
            )
            store = AppStateStore(original)
            engine = PixelFlasherEngine(
                store=store,
                operation_planner=planner,
                firmware_artifact_service=service,
            )
            results = []
            worker = threading.Thread(
                target=lambda: results.append(
                    engine.execute(AppCommand("firmware.process", expected_revision=0))
                ),
                daemon=True,
            )
            worker.start()
            self.assertTrue(service.processed.wait(2))
            store.update(expected_revision=1, selected_serials=())
            service.release.set()
            worker.join(2)

            self.assertFalse(worker.is_alive())
            self.assertEqual(OperationStatus.FAILED, results[0].status)
            self.assertEqual("firmware_selection_changed", results[0].code)
            self.assertEqual(selected, store.snapshot().firmware)
            self.assertEqual(BootInfo(), store.snapshot().boot)
            self.assertIsNone(store.snapshot().active_operation)

    def test_non_ota_package_without_boot_artifact_is_not_promoted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            custom = root / "custom-without-boot.zip"
            custom.write_bytes(
                archive_bytes([("images/vendor_boot.img", b"vendor only")])
            )
            engine, planner, _service = self.make_engine(root / "cache")
            selected = engine.execute(
                AppCommand(
                    "firmware.select",
                    expected_revision=0,
                    payload={"path": str(custom)},
                )
            )
            before = engine.store.snapshot()

            processed = engine.execute(
                AppCommand("firmware.process", expected_revision=1)
            )

            self.assertTrue(selected.ok)
            self.assertEqual(OperationStatus.FAILED, processed.status)
            self.assertEqual("stock_boot_artifact_required", processed.code)
            self.assertEqual(before.firmware, engine.store.snapshot().firmware)
            self.assertEqual(before.boot, engine.store.snapshot().boot)
            self.assertEqual(
                (),
                planner.artifact_repository.resolve(engine.store.snapshot()),
            )

    def test_process_payload_paths_hashes_argv_and_staging_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / "factory.zip"
            write_factory(firmware)
            selected = FirmwareInfo(
                str(firmware),
                "factory",
                "42",
                sha256(firmware),
                True,
                False,
            )
            engine, _planner, _service = self.make_engine(
                root / "cache",
                selected_snapshot(selected),
            )
            payloads = (
                {"path": str(firmware)},
                {"sha256": sha256(firmware)},
                {"argv": ["fastboot", "flash"]},
                {"outputRoot": str(root / "browser-controlled")},
                {"stagingPath": str(root / "browser-controlled")},
            )

            for payload in payloads:
                with self.subTest(payload=payload):
                    result = engine.execute(
                        AppCommand(
                            "firmware.process",
                            expected_revision=0,
                            payload=payload,
                        )
                    )
                    self.assertEqual(OperationStatus.FAILED, result.status)
                    self.assertEqual("invalid_firmware_process_payload", result.code)
                    self.assertEqual(0, engine.store.snapshot().revision)
            targeted = engine.execute(
                AppCommand(
                    "firmware.process",
                    expected_revision=0,
                    target_serial="SERIAL",
                )
            )
            self.assertEqual("firmware_process_target_not_allowed", targeted.code)
            self.assertFalse((root / "browser-controlled").exists())

    def test_injected_service_must_share_the_planners_exact_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            planner = OperationPlanner()
            unrelated = OperationPlanner()
            service = FirmwareArtifactService(
                unrelated.artifact_repository,
                Path(directory) / "cache",
            )

            with self.assertRaisesRegex(ValueError, "share one repository"):
                PixelFlasherEngine(
                    operation_planner=planner,
                    firmware_artifact_service=service,
                )

    def test_runtime_cache_is_next_to_config_and_rehydrates_verified_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            factory = root / "factory.zip"
            write_factory(factory)
            runtime = ApplicationRuntime.open(config)
            expected_cache = root / ".PixelFlasher.json.cache" / "firmware-artifacts"

            selected = runtime.execute(
                AppCommand(
                    "firmware.select",
                    expected_revision=0,
                    payload={"path": str(factory)},
                )
            )
            processed = runtime.execute(
                AppCommand("firmware.process", expected_revision=1)
            )
            before = runtime.snapshot()
            runtime.shutdown()

            self.assertTrue(selected.ok)
            self.assertTrue(processed.ok)
            self.assertEqual(expected_cache.resolve(), runtime.firmware_artifact_cache_root)
            self.assertTrue(Path(before.boot.path).is_relative_to(expected_cache))
            saved = json.loads(config.read_text(encoding="utf-8"))
            core = saved["_pixelflasher_core_state"]
            self.assertEqual(before.boot.to_dict(), core["boot"])
            self.assertTrue(core["processed_artifacts"])

            reopened = ApplicationRuntime.open(config)
            restored = reopened.snapshot()
            registered = reopened.engine.operation_planner.artifact_repository.resolve(restored)
            self.assertEqual(before.firmware, restored.firmware)
            self.assertEqual(before.boot, restored.boot)
            self.assertTrue(any(item.role == "partition:init_boot" for item in registered))
            self.assertIs(
                reopened.engine.firmware_artifact_service.repository,
                reopened.engine.operation_planner.artifact_repository,
            )
            reopened.shutdown()

    def test_config_cannot_restore_partition_artifacts_outside_backend_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.json"
            firmware = root / "factory.zip"
            firmware.write_bytes(b"factory")
            outside = root / "outside.img"
            outside.write_bytes(b"outside")
            info = FirmwareInfo(
                str(firmware),
                "factory",
                "42",
                sha256(firmware),
                True,
                True,
            )
            config.write_text(
                json.dumps(
                    {
                        "_pixelflasher_core_state": {
                            "firmware": info.to_dict(),
                            "processed_artifacts": [
                                FileArtifact(
                                    str(outside),
                                    sha256(outside),
                                    "partition:boot",
                                ).to_dict()
                            ],
                        }
                    }
                ),
                encoding="utf-8",
            )

            runtime = ApplicationRuntime.open(config)
            restored = runtime.engine.operation_planner.artifact_repository.resolve(
                runtime.snapshot()
            )

            self.assertEqual((), restored)
            runtime.shutdown()

    def test_store_promotes_firmware_and_boot_together_only_on_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware_path = root / "factory.zip"
            boot_path = root / "boot.img"
            firmware_path.write_bytes(b"factory")
            boot_path.write_bytes(b"boot")
            firmware = FirmwareInfo(
                str(firmware_path),
                "factory",
                "42",
                sha256(firmware_path),
                True,
                True,
            )
            boot = BootInfo("stock", str(boot_path), sha256(boot_path), "boot", False)
            store = AppStateStore()
            store.begin_operation("success", expected_revision=0)
            result = OperationResult.success("success", code="firmware_processed")

            completed = store.complete_operation(result, firmware=firmware, boot=boot)

            self.assertEqual(firmware, completed.firmware)
            self.assertEqual(boot, completed.boot)
            self.assertEqual(2, completed.revision)

            store.begin_operation("failed", expected_revision=2)
            failed = OperationResult.failed("failed", code="failed")
            with self.assertRaisesRegex(ValueError, "only by a successful"):
                store.complete_operation(failed, firmware=FirmwareInfo(), boot=BootInfo())
            closed = store.complete_operation(failed)
            self.assertEqual(firmware, closed.firmware)
            self.assertEqual(boot, closed.boot)

    def test_safety_rejects_caller_plan_for_firmware_processing(self):
        plan = OperationPlan(
            requests=(ProcessRequest(("python", "untrusted.py")),),
            target_serial=None,
        )
        command = AppCommand(
            "firmware.process",
            expected_revision=0,
            operation_plan=plan,
        )

        decision = SafetyPolicy().evaluate(command, AppSnapshot())

        self.assertFalse(decision.allowed)
        self.assertEqual("untrusted_operation_plan", decision.code)


if __name__ == "__main__":
    unittest.main()
