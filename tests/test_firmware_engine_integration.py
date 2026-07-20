from __future__ import annotations

import hashlib
import io
import json
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from pixelflasher_core import (
    AppCommand,
    ApplicationRuntime,
    AppSnapshot,
    AppStateStore,
    ArtifactRepository,
    BootInfo,
    BootRepository,
    DeviceInfo,
    FileArtifact,
    FirmwareArtifactService,
    FirmwareInfo,
    FirmwareInspection,
    FirmwareKind,
    FirmwareProcessingCode,
    FirmwareProcessingResult,
    FirmwareProcessingStatus,
    FirmwareRepository,
    OperationPlan,
    OperationPlanner,
    OperationResult,
    OperationStatus,
    PersistentProcessedArtifactRepository,
    ProcessRequest,
    SafetyPolicy,
)
from pixelflasher_core.boot_inventory import BootInventoryService
from tests.command_engine_factory import make_test_command_engine as CommandEngine
from tests.test_payload_processing import minimal_payload, payload_properties


def archive_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return stream.getvalue()


def write_factory(path: Path) -> None:
    inner = archive_bytes(
        [
            ("boot.img", b"ANDROID!stock boot"),
            ("init_boot.img", b"ANDROID!preferred stock init boot"),
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
                (
                    "META-INF/com/google/android/update-binary",
                    b"never execute archive-provided code",
                ),
            ]
        )
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def selected_snapshot(
    firmware: FirmwareInfo | None = None,
    boot: BootInfo | None = None,
):
    firmware = firmware or FirmwareInfo()
    boot = boot or BootInfo()
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
        engine = CommandEngine(
            interaction_handler=lambda _request: True,
            store=AppStateStore(snapshot or selected_snapshot()),
            operation_planner=planner,
            firmware_artifact_service=service,
        )
        return engine, planner, service

    def test_expired_select_and_process_deadlines_are_failed_timeouts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            factory = root / "factory.zip"
            write_factory(factory)
            expired_at = time.monotonic() - 1

            select_engine, _planner, _service = self.make_engine(root / "select-cache")
            selected = select_engine.execute(
                AppCommand(
                    "firmware.select",
                    expected_revision=0,
                    payload={"path": str(factory)},
                    execution_timeout_seconds=0.01,
                    _accepted_monotonic=expired_at,
                )
            )
            self.assertEqual(OperationStatus.FAILED, selected.status)
            self.assertEqual("timed_out", selected.code)
            self.assertEqual(0, select_engine.store.snapshot().revision)

            firmware = FirmwareInfo(
                str(factory),
                "factory",
                "AP4A.260705.001",
                sha256(factory),
                True,
                False,
            )
            process_engine, _planner, _service = self.make_engine(
                root / "process-cache",
                selected_snapshot(firmware),
            )
            processed = process_engine.execute(
                AppCommand(
                    "firmware.process",
                    expected_revision=0,
                    execution_timeout_seconds=0.01,
                    _accepted_monotonic=expired_at,
                )
            )
            self.assertEqual(OperationStatus.FAILED, processed.status)
            self.assertEqual("timed_out", processed.code)
            self.assertEqual(firmware, process_engine.store.snapshot().firmware)

    def test_selection_cancellation_reaches_content_addressed_firmware_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            factory = root / "factory.zip"
            write_factory(factory)
            planner = OperationPlanner()
            repository = ArtifactRepository(root / "repository")
            firmware_repository = FirmwareRepository(repository)
            engine = CommandEngine(
                interaction_handler=lambda _request: True,
                store=AppStateStore(selected_snapshot()),
                operation_planner=planner,
                firmware_artifact_service=FirmwareArtifactService(
                    planner.artifact_repository,
                    root / "cache",
                ),
                firmware_repository=firmware_repository,
            )
            started = threading.Event()
            results: list[OperationResult] = []

            from pixelflasher_core import repositories as repository_module

            original_copy = repository_module._copy_to_stream

            def blocking_copy(source, output_stream, *, cancellation=None):
                started.set()
                self.assertIsNotNone(cancellation)
                assert cancellation is not None
                while not cancellation.cancelled:
                    time.sleep(0.005)
                return original_copy(
                    source,
                    output_stream,
                    cancellation=cancellation,
                )

            command = AppCommand(
                "firmware.select",
                expected_revision=0,
                payload={"path": str(factory)},
                operation_id="cancel-firmware-import",
            )
            with patch(
                "pixelflasher_core.repositories._copy_to_stream",
                side_effect=blocking_copy,
            ):
                worker = threading.Thread(
                    target=lambda: results.append(engine.execute(command)),
                    daemon=True,
                )
                worker.start()
                self.assertTrue(started.wait(2))
                self.assertTrue(engine.cancel(command.operation_id))
                worker.join(2)

            self.assertFalse(worker.is_alive())
            self.assertEqual(OperationStatus.CANCELLED, results[0].status)
            self.assertEqual("firmware_cancelled", results[0].code)
            self.assertEqual(0, engine.store.snapshot().revision)
            self.assertEqual(FirmwareInfo(), engine.store.snapshot().firmware)
            self.assertEqual((), firmware_repository.list())
            self.assertEqual(
                (),
                tuple(
                    path
                    for path in (root / "repository" / "objects").rglob("*")
                    if path.is_file()
                ),
            )
            repository.close()

    def test_revision_change_after_import_rolls_back_new_firmware_object(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            factory = root / "factory.zip"
            write_factory(factory)
            planner = OperationPlanner()
            repository = ArtifactRepository(root / "repository")
            firmware_repository = FirmwareRepository(repository)
            store = AppStateStore(selected_snapshot())
            engine = CommandEngine(
                interaction_handler=lambda _request: True,
                store=store,
                operation_planner=planner,
                firmware_artifact_service=FirmwareArtifactService(
                    planner.artifact_repository,
                    root / "cache",
                ),
                firmware_repository=firmware_repository,
            )
            original_import = firmware_repository.import_selection

            def import_then_change_revision(*args, **kwargs):
                record = original_import(*args, **kwargs)
                store.update(expected_revision=0, selected_serial="SERIAL")
                return record

            with patch.object(
                firmware_repository,
                "import_selection",
                side_effect=import_then_change_revision,
            ):
                result = engine.execute(
                    AppCommand(
                        "firmware.select",
                        expected_revision=0,
                        payload={"path": str(factory)},
                    )
                )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("stale_revision", result.code)
            self.assertEqual(FirmwareInfo(), store.snapshot().firmware)
            self.assertEqual((), firmware_repository.list())
            self.assertEqual(
                (),
                tuple(
                    path
                    for path in (root / "repository" / "objects").rglob("*")
                    if path.is_file()
                ),
            )
            repository.close()

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
                        ("images/boot.img", b"ANDROID!custom stock boot"),
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

    def test_runtime_processes_custom_payload_into_persistent_stock_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            custom = root / "custom-payload.zip"
            payload = minimal_payload(
                {"boot": b"ANDROID!verified custom payload boot"},
            )
            custom.write_bytes(
                archive_bytes(
                    [
                        ("android-info.txt", b"require product=husky\n"),
                        ("payload.bin", payload),
                        ("payload_properties.txt", payload_properties(payload)),
                    ]
                )
            )
            runtime = ApplicationRuntime.open(
                config,
                interaction_handler=lambda _request: True,
            )
            try:
                selected = runtime.execute(
                    AppCommand(
                        "firmware.select",
                        expected_revision=0,
                        payload={"path": str(custom)},
                    )
                )
                processed = runtime.execute(
                    AppCommand("firmware.process", expected_revision=1)
                )
                snapshot = runtime.snapshot()
                boot_records = runtime.boot_repository.list()

                self.assertTrue(selected.ok)
                self.assertTrue(processed.ok)
                self.assertEqual("custom", snapshot.firmware.type)
                self.assertTrue(snapshot.firmware.processed)
                self.assertEqual("boot", snapshot.boot.flavor)
                self.assertEqual(1, len(boot_records))
                self.assertEqual(snapshot.boot.id, boot_records[0].artifact_id)
                self.assertEqual(snapshot.firmware.hash, boot_records[0].source_hash)
                self.assertEqual(("husky",), boot_records[0].device_codenames)
                self.assertEqual("processed", boot_records[0].provenance.value)
            finally:
                runtime.shutdown()

    def test_stock_and_custom_picker_intents_reject_the_wrong_package_kind(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            factory = root / "factory.zip"
            custom = root / "custom.zip"
            write_factory(factory)
            custom.write_bytes(
                archive_bytes(
                    [
                        ("android-info.txt", b"require product=husky\n"),
                        ("boot.img", b"ANDROID!custom boot"),
                    ]
                )
            )
            cases = (
                (factory, "custom"),
                (custom, "stock"),
            )
            for index, (path, expected_kind) in enumerate(cases):
                with self.subTest(expected_kind=expected_kind):
                    engine, _planner, _service = self.make_engine(
                        root / f"cache-{index}",
                    )
                    result = engine.execute(
                        AppCommand(
                            "firmware.select",
                            expected_revision=0,
                            payload={
                                "path": str(path),
                                "expectedKind": expected_kind,
                            },
                        )
                    )

                    self.assertEqual(OperationStatus.FAILED, result.status)
                    self.assertEqual("firmware_kind_mismatch", result.code)
                    self.assertEqual(0, engine.store.snapshot().revision)
                    self.assertEqual(FirmwareInfo(), engine.store.snapshot().firmware)

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
            cancel_engine = CommandEngine(
                interaction_handler=lambda _request: True,
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
            engine = CommandEngine(
                interaction_handler=lambda _request: True,
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
            self.assertEqual((), planner.artifact_repository.resolve(store.snapshot()))
            self.assertEqual(
                (),
                tuple(path for path in (root / "cache").rglob("*") if path.is_file()),
            )

    def test_revision_change_rolls_back_persistent_processed_artifacts(self):
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
            repository = ArtifactRepository(root / "repository")
            firmware_repository = FirmwareRepository(repository)
            selection_record = firmware_repository.import_selection(
                firmware,
                firmware_type="factory",
                build="42",
                expected_sha256=selected.hash,
                package_signature="user_confirmed",
            )
            processed_repository = PersistentProcessedArtifactRepository(
                firmware_repository,
            )
            planner = OperationPlanner(artifact_repository=processed_repository)
            service = SuccessfulBlockingFirmwareArtifactService(
                processed_repository,
                root / "cache",
            )
            store = AppStateStore(selected_snapshot(selected))
            engine = CommandEngine(
                interaction_handler=lambda _request: True,
                store=store,
                operation_planner=planner,
                firmware_artifact_service=service,
                firmware_repository=firmware_repository,
                boot_inventory_service=BootInventoryService(
                    BootRepository(repository),
                ),
            )
            results: list[OperationResult] = []
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
            self.assertEqual("firmware_selection_changed", results[0].code)
            self.assertEqual((selection_record,), firmware_repository.list())
            self.assertEqual((selection_record,), repository.list())
            self.assertEqual(
                (selection_record.path,),
                tuple(sorted(
                    path
                    for path in repository.objects_root.rglob("*")
                    if path.is_file()
                )),
            )
            self.assertEqual(
                (),
                tuple(path for path in (root / "cache").rglob("*") if path.is_file()),
            )
            repository.close()

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
                CommandEngine(
                    operation_planner=planner,
                    firmware_artifact_service=service,
                )

    def test_runtime_cache_is_next_to_config_and_rehydrates_verified_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            factory = root / "factory.zip"
            write_factory(factory)
            runtime = ApplicationRuntime.open(
                config,
                interaction_handler=lambda _request: True,
            )
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
            boot_records = runtime.boot_repository.list()
            runtime.shutdown()

            self.assertTrue(selected.ok)
            self.assertTrue(processed.ok)
            self.assertEqual(expected_cache.resolve(), runtime.firmware_artifact_cache_root)
            self.assertEqual(1, len(boot_records))
            self.assertEqual(before.boot.id, boot_records[0].artifact_id)
            self.assertEqual("processed", boot_records[0].provenance.value)
            self.assertEqual(before.firmware.hash, boot_records[0].source_hash)
            self.assertEqual(("husky",), boot_records[0].device_codenames)
            self.assertTrue(
                Path(before.boot.path).is_relative_to(runtime.artifact_repository.objects_root)
            )
            saved = json.loads(config.read_text(encoding="utf-8"))
            core = saved["_pixelflasher_core_state"]
            self.assertEqual(before.firmware.hash, core["firmware"]["hash"])
            self.assertEqual(before.boot.hash, core["boot"]["hash"])
            self.assertNotIn("path", core["firmware"])
            self.assertNotIn("path", core["boot"])
            self.assertNotIn("processed_artifacts", core)

            reopened = ApplicationRuntime.open(config)
            restored = reopened.snapshot()
            registered = reopened.command_engine.operation_planner.artifact_repository.resolve(
                restored
            )
            self.assertEqual(before.firmware.hash, restored.firmware.hash)
            self.assertEqual(before.firmware.type, restored.firmware.type)
            self.assertEqual(before.firmware.build, restored.firmware.build)
            self.assertTrue(restored.firmware.verified)
            self.assertTrue(restored.firmware.processed)
            self.assertEqual(before.boot.hash, restored.boot.hash)
            self.assertEqual(before.boot.flavor, restored.boot.flavor)
            self.assertTrue(
                Path(restored.firmware.path).is_relative_to(
                    reopened.artifact_repository.objects_root
                )
            )
            self.assertTrue(
                Path(restored.boot.path).is_relative_to(
                    reopened.artifact_repository.objects_root
                )
            )
            self.assertTrue(any(item.role == "partition:init_boot" for item in registered))
            self.assertIs(
                reopened.command_engine.firmware_artifact_service.repository,
                reopened.command_engine.operation_planner.artifact_repository,
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
            restored = runtime.command_engine.operation_planner.artifact_repository.resolve(
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
