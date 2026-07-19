import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pixelflasher_core import ApplicationRuntime, DeviceInfo, DeviceScanResult
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
            runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
