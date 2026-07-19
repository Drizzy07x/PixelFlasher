import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pixelflasher_core import ApplicationRuntime, ConfigError, DeviceInfo, DeviceScanResult
from pixelflasher_core.devices import DevicePoller


class RuntimeDeviceMonitorTests(unittest.TestCase):
    def test_production_monitor_lifecycle_is_owned_by_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "PixelFlasher.json"
            with (
                patch.object(DevicePoller, "start", return_value=True) as start,
                patch.object(DevicePoller, "stop", return_value=True) as stop,
            ):
                runtime = ApplicationRuntime.open(
                    config,
                    enable_device_monitor=True,
                )
                start.assert_called_once_with()

                runtime.shutdown()

            stop.assert_called_once_with()

    def test_hotplug_inventory_repairs_selection_without_auto_selecting_new_device(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = ApplicationRuntime.open(Path(directory) / "PixelFlasher.json")
            runtime.store.update(
                expected_revision=0,
                devices=(DeviceInfo("A", mode="adb"), DeviceInfo("B", mode="fastboot")),
                selected_serials=("A",),
                selected_serial="A",
            )

            runtime._handle_device_scan(
                DeviceScanResult(
                    (DeviceInfo("B", mode="fastbootd"), DeviceInfo("C", mode="adb")),
                    successful_sources=("adb", "fastboot"),
                )
            )

            snapshot = runtime.snapshot()
            self.assertEqual(("B", "C"), tuple(item.serial for item in snapshot.devices))
            self.assertEqual((), snapshot.selected_serials)
            self.assertIsNone(snapshot.selected_serial)
            persisted = json.loads(runtime.config_store.path.read_text(encoding="utf-8"))
            self.assertIsNone(persisted["device"])
            self.assertEqual(
                [],
                persisted["_pixelflasher_core_state"]["selected_serials"],
            )
            runtime.shutdown()

    def test_failed_hotplug_persistence_invalidates_the_suppression_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = ApplicationRuntime.open(Path(directory) / "PixelFlasher.json")
            result = DeviceScanResult(
                (DeviceInfo("SERIAL", mode="adb"),),
                successful_sources=("adb", "fastboot"),
            )
            before = runtime.snapshot()

            with (
                patch.object(
                    runtime.config_store,
                    "save",
                    side_effect=ConfigError("temporary write failure"),
                ),
                patch.object(
                    runtime.device_poller,
                    "invalidate_observation",
                ) as invalidate,
            ):
                runtime._handle_device_scan(result)

            invalidate.assert_called_once_with()
            self.assertIs(before, runtime.snapshot())
            runtime._handle_device_scan(result)
            self.assertEqual(
                ("SERIAL",),
                tuple(item.serial for item in runtime.snapshot().devices),
            )
            runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
