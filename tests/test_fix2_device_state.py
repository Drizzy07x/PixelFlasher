from __future__ import annotations

import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from pixelflasher_core import (
    AppCommand,
    ApplicationRuntime,
    AppSnapshot,
    AppStateStore,
    BootInfo,
    CommandExecutor,
    DeviceInfo,
    DeviceScanResult,
    FakeProcessTransport,
    FirmwareInfo,
    OperationPlanner,
    OperationStatus,
    ToolchainInfo,
    TransportOutcome,
)
from tests.command_engine_factory import make_test_command_engine as CommandEngine
from tests.test_firmware_engine_integration import (
    SuccessfulBlockingFirmwareArtifactService,
    selected_snapshot,
    sha256,
    write_factory,
)

NO_PERMISSIONS_OUTPUT = (
    "List of devices attached\n"
    "0123456789ABCDEF\tno permissions (user in plugdev group); "
    "see [http://developer.android.com/tools/device.html]\n"
)


def ready_toolchain() -> ToolchainInfo:
    return ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True)


class DeviceScanDiagnosticTests(unittest.TestCase):
    """BLOCKING-01: a succeeded-but-degraded scan must say why it found nothing."""

    def test_successful_scan_reports_the_device_adb_refused(self):
        transport = FakeProcessTransport(
            [
                TransportOutcome(0, NO_PERMISSIONS_OUTPUT),
                TransportOutcome(0, ""),
            ]
        )
        engine = CommandEngine(
            store=AppStateStore(AppSnapshot(toolchain=ready_toolchain())),
            executor=CommandExecutor(transport),
        )

        result = engine.execute(AppCommand("device.scan", expected_revision=0))

        self.assertEqual(OperationStatus.SUCCESS, result.status)
        self.assertEqual("device_scan_succeeded", result.code)
        self.assertEqual((), engine.store.snapshot().devices)
        self.assertIn("found 0 device(s)", result.message)
        self.assertIn("adb:no_permissions:0123456789ABCDEF", result.message)
        self.assertIn(
            "adb:no_permissions:0123456789ABCDEF",
            result.value["warnings"],
        )

    def test_clean_scan_keeps_the_terse_summary(self):
        transport = FakeProcessTransport(
            [
                TransportOutcome(0, "List of devices attached\n"),
                TransportOutcome(0, ""),
            ]
        )
        engine = CommandEngine(
            store=AppStateStore(AppSnapshot(toolchain=ready_toolchain())),
            executor=CommandExecutor(transport),
        )

        result = engine.execute(AppCommand("device.scan", expected_revision=0))

        self.assertEqual("found 0 device(s)", result.message)
        self.assertEqual([], result.value["warnings"])


class CompletionGuardTests(unittest.TestCase):
    """BLOCKING-03: a concurrent preference write must not discard a finished run."""

    def _run_firmware_process(self, root: Path, mutate):
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
        planner = OperationPlanner()
        service = SuccessfulBlockingFirmwareArtifactService(
            planner.artifact_repository,
            root / "cache",
        )
        store = AppStateStore(selected_snapshot(selected))
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
        self.assertTrue(service.processed.wait(5))
        mutate(store)
        service.release.set()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        return results[0], store, planner

    def test_zoom_change_during_processing_keeps_the_promoted_result(self):
        with tempfile.TemporaryDirectory() as directory:
            result, store, planner = self._run_firmware_process(
                Path(directory),
                lambda store: store.update(
                    expected_revision=1,
                    preferences=replace(store.snapshot().preferences, zoom=110),
                ),
            )

            self.assertEqual(OperationStatus.SUCCESS, result.status)
            self.assertNotEqual("firmware_selection_changed", result.code)
            self.assertNotEqual("firmware_state_promotion_failed", result.code)
            self.assertEqual(110, store.snapshot().preferences.zoom)
            self.assertTrue(store.snapshot().firmware.processed)
            self.assertNotEqual(
                (),
                planner.artifact_repository.resolve(store.snapshot()),
            )
            self.assertIsNone(store.snapshot().active_operation)

    def test_selection_change_during_processing_still_aborts_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            result, store, planner = self._run_firmware_process(
                Path(directory),
                lambda store: store.update(
                    expected_revision=1,
                    selected_serials=(),
                    selected_serial=None,
                ),
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("firmware_selection_changed", result.code)
            self.assertEqual(BootInfo(), store.snapshot().boot)
            self.assertEqual((), planner.artifact_repository.resolve(store.snapshot()))
            self.assertIsNone(store.snapshot().active_operation)


class HotplugRootStateTests(unittest.TestCase):
    """IMPORTANT-01: the unenriched poller must not publish a probed root away."""

    def test_hotplug_republication_preserves_probed_root(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = ApplicationRuntime.open(Path(directory) / "PixelFlasher.json")
            try:
                runtime.store.update(
                    expected_revision=0,
                    devices=(
                        DeviceInfo("A", mode="adb", root=True),
                        DeviceInfo("B", mode="adb"),
                    ),
                    selected_serials=("A",),
                    selected_serial="A",
                )

                runtime._handle_device_scan(
                    DeviceScanResult(
                        (DeviceInfo("A", mode="adb"), DeviceInfo("C", mode="adb")),
                        successful_sources=("adb", "fastboot"),
                    )
                )

                devices = {
                    device.serial: device for device in runtime.snapshot().devices
                }
                self.assertEqual({"A", "C"}, set(devices))
                self.assertTrue(devices["A"].root)
                self.assertFalse(devices["C"].root)
            finally:
                runtime.shutdown()

    def test_mode_transition_forces_a_fresh_root_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = ApplicationRuntime.open(Path(directory) / "PixelFlasher.json")
            try:
                runtime.store.update(
                    expected_revision=0,
                    devices=(DeviceInfo("A", mode="adb", root=True),),
                    selected_serials=("A",),
                    selected_serial="A",
                )

                runtime._handle_device_scan(
                    DeviceScanResult(
                        (DeviceInfo("A", mode="fastboot"),),
                        successful_sources=("adb", "fastboot"),
                    )
                )

                device = runtime.snapshot().devices[0]
                self.assertEqual("fastboot", device.mode)
                self.assertFalse(device.root)
            finally:
                runtime.shutdown()


class LegacySelectionMirrorTests(unittest.TestCase):
    """IMPORTANT-07: a proven-empty selection must not resurrect a 9.x serial."""

    def test_shutdown_persists_a_modern_deselection(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "PixelFlasher.json"
            config.write_text(json.dumps({"device": "SERIAL-A"}), encoding="utf-8")

            runtime = ApplicationRuntime.open(config)
            self.assertEqual("SERIAL-A", runtime.snapshot().selected_serial)
            runtime.store.update(
                expected_revision=0,
                selected_serials=(),
                selected_serial=None,
            )
            runtime.shutdown()

            persisted = json.loads(config.read_text(encoding="utf-8"))
            self.assertIsNone(persisted["device"])

            reopened = ApplicationRuntime.open(config)
            try:
                self.assertIsNone(reopened.snapshot().selected_serial)
                self.assertEqual((), reopened.snapshot().selected_serials)
            finally:
                reopened.shutdown()

    def test_untouched_legacy_selection_still_survives(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "PixelFlasher.json"
            config.write_text(json.dumps({"device": "SERIAL-A"}), encoding="utf-8")

            runtime = ApplicationRuntime.open(config)
            runtime.shutdown()

            persisted = json.loads(config.read_text(encoding="utf-8"))
            self.assertEqual("SERIAL-A", persisted["device"])


class StartupWarningTests(unittest.TestCase):
    """IMPORTANT-08: a failed 9.x migration must not degrade silently."""

    def test_failed_legacy_migration_is_announced(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "PixelFlasher.json"
            stream = io.StringIO()
            with (
                patch.object(
                    ApplicationRuntime,
                    "_migrate_legacy_artifacts",
                    side_effect=OSError("the firmware volume is unavailable"),
                ),
                redirect_stdout(stream),
            ):
                runtime = ApplicationRuntime.open(config)
            try:
                self.assertEqual("failed", runtime.legacy_migration_report.status)
                self.assertIsNotNone(runtime.legacy_migration_error)
                self.assertTrue(
                    any(
                        "legacy 9.x migration failed" in warning
                        for warning in runtime.startup_warnings
                    ),
                    runtime.startup_warnings,
                )
                self.assertIn("legacy 9.x migration failed", stream.getvalue())
                self.assertIn("the firmware volume is unavailable", stream.getvalue())
            finally:
                runtime.shutdown()

    def test_clean_startup_stays_quiet(self):
        with tempfile.TemporaryDirectory() as directory:
            stream = io.StringIO()
            with redirect_stdout(stream):
                runtime = ApplicationRuntime.open(Path(directory) / "PixelFlasher.json")
            try:
                self.assertEqual((), runtime.startup_warnings)
                self.assertEqual("", stream.getvalue())
            finally:
                runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
