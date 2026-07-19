from __future__ import annotations

import threading
import time
import unittest
from dataclasses import dataclass

from pixelflasher_core.contracts import AppSnapshot, DeviceInfo, ProcessRequest, ToolchainInfo
from pixelflasher_core.devices import (
    DevicePoller,
    DeviceScanResult,
    DeviceService,
    canonicalize_device_inventory,
    reconcile_device_selection,
)
from pixelflasher_core.executor import CancellationToken, TransportOutcome
from pixelflasher_core.store import AppStateStore

TOOLCHAIN = ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True)


class ModeAwareTransport:
    def __init__(self) -> None:
        self.calls: list[ProcessRequest] = []

    def run(
        self,
        request: ProcessRequest,
        _cancellation: CancellationToken,
    ) -> TransportOutcome:
        self.calls.append(request)
        argv = request.argv
        if argv == ("ADB", "devices", "-l"):
            return TransportOutcome(
                0,
                "List of devices attached\n"
                "NORMAL device model:Pixel_9 device:tokay usb:1-1\n"
                "REC device model:Pixel_8 device:shiba usb:1-2\n"
                "SIDE sideload usb:1-3\n",
            )
        if argv == ("FASTBOOT", "devices", "-l"):
            return TransportOutcome(
                0,
                "BOOT fastboot product:husky usb:2-1\n"
                "USER fastbootd product:akita usb:2-2\n",
            )
        if len(argv) == 5 and argv[:2] == ("FASTBOOT", "-s"):
            serial, variable = argv[2], argv[4]
            values = {
                ("BOOT", "current-slot"): "a",
                ("BOOT", "unlocked"): "yes",
                ("BOOT", "is-userspace"): "no",
                ("USER", "current-slot"): "b",
                ("USER", "unlocked"): "no",
                ("USER", "is-userspace"): "yes",
            }
            return TransportOutcome(0, stderr=f"(bootloader) {variable}: {values[serial, variable]}\n")
        if argv == ("ADB", "-s", "NORMAL", "shell", "getprop"):
            return TransportOutcome(
                0,
                "[ro.bootmode]: [normal]\n[ro.product.model]: [Pixel 9]\n",
            )
        if argv == ("ADB", "-s", "REC", "shell", "getprop"):
            return TransportOutcome(
                0,
                "[ro.bootmode]: [recovery]\n[ro.product.model]: [Pixel 8]\n",
            )
        raise AssertionError(f"unexpected process request: {request!r}")


@dataclass(frozen=True, slots=True)
class ScanState:
    adb: TransportOutcome
    fastboot: TransportOutcome


class StatefulHotplugTransport:
    def __init__(self, states: tuple[ScanState, ...]) -> None:
        self.states = states
        self.calls: list[ProcessRequest] = []
        self.scan_index = 0
        self._active_index = 0
        self._lock = threading.Lock()

    def run(
        self,
        request: ProcessRequest,
        _cancellation: CancellationToken,
    ) -> TransportOutcome:
        with self._lock:
            self.calls.append(request)
            argv = request.argv
            if argv == ("ADB", "devices", "-l"):
                self._active_index = min(self.scan_index, len(self.states) - 1)
                return self.states[self._active_index].adb
            if argv == ("FASTBOOT", "devices", "-l"):
                outcome = self.states[self._active_index].fastboot
                self.scan_index += 1
                return outcome
            if argv == ("FASTBOOT", "-s", "A", "getvar", "current-slot"):
                return TransportOutcome(0, stderr="current-slot: b\n")
            if argv == ("FASTBOOT", "-s", "A", "getvar", "unlocked"):
                return TransportOutcome(0, stderr="unlocked: yes\n")
            if argv == ("FASTBOOT", "-s", "A", "getvar", "is-userspace"):
                return TransportOutcome(0, stderr="is-userspace: no\n")
        raise AssertionError(f"unexpected process request: {request!r}")


class DeviceModeScanTests(unittest.TestCase):
    def test_scan_distinguishes_all_supported_modes_with_exact_serial_argv(self) -> None:
        transport = ModeAwareTransport()

        result = DeviceService(transport).scan(TOOLCHAIN, include_battery=False)

        self.assertTrue(result.ok)
        by_serial = {device.serial: device for device in result.devices}
        self.assertEqual(
            {
                "NORMAL": "adb",
                "REC": "recovery",
                "SIDE": "sideload",
                "BOOT": "fastboot",
                "USER": "fastbootd",
            },
            {serial: device.mode for serial, device in by_serial.items()},
        )
        self.assertTrue(all(device.online for device in by_serial.values()))
        self.assertEqual("a", by_serial["BOOT"].slot)
        self.assertEqual("b", by_serial["USER"].slot)
        self.assertNotIn(
            ("ADB", "-s", "SIDE", "shell", "getprop"),
            [request.argv for request in transport.calls],
        )
        self.assertEqual(
            [
                ("FASTBOOT", "-s", "BOOT", "getvar", "current-slot"),
                ("FASTBOOT", "-s", "BOOT", "getvar", "unlocked"),
                ("FASTBOOT", "-s", "BOOT", "getvar", "is-userspace"),
                ("FASTBOOT", "-s", "USER", "getvar", "current-slot"),
                ("FASTBOOT", "-s", "USER", "getvar", "unlocked"),
                ("FASTBOOT", "-s", "USER", "getvar", "is-userspace"),
            ],
            [request.argv for request in transport.calls[2:8]],
        )


class DevicePollerTests(unittest.TestCase):
    def test_hotplug_emits_only_real_changes_and_retains_identity_history(self) -> None:
        attached = TransportOutcome(
            0,
            "List of devices attached\nA device model:Pixel_9 device:tokay usb:1-1\n",
        )
        empty_adb = TransportOutcome(0, "List of devices attached\n")
        empty_fastboot = TransportOutcome(0, "")
        transport = StatefulHotplugTransport(
            (
                ScanState(attached, empty_fastboot),
                ScanState(attached, empty_fastboot),
                ScanState(TransportOutcome(1, stderr="temporary adb failure"), empty_fastboot),
                ScanState(empty_adb, empty_fastboot),
                ScanState(empty_adb, TransportOutcome(0, "A fastboot product:tokay\n")),
                ScanState(empty_adb, TransportOutcome(0, "A fastboot product:tokay\n")),
            )
        )
        observed: list[DeviceScanResult] = []
        completed = threading.Event()

        def listener(result: DeviceScanResult) -> None:
            observed.append(result)
            if len(observed) == 3:
                completed.set()

        poller = DevicePoller(
            DeviceService(transport),
            lambda: TOOLCHAIN,
            listener,
            interval_seconds=0.01,
            include_properties=False,
            history_limit=4,
        )

        self.assertTrue(poller.start())
        self.assertTrue(completed.wait(2))
        self.assertTrue(poller.close(1))
        self.assertFalse(poller.running)
        self.assertEqual([["A"], [], ["A"]], [[item.serial for item in scan.devices] for scan in observed])
        returned = observed[-1].devices[0]
        self.assertEqual("fastboot", returned.mode)
        self.assertEqual("Pixel 9", returned.model)
        self.assertEqual("Pixel 9", returned.name)
        self.assertGreaterEqual(transport.scan_index, 5)

    def test_stop_is_bounded_when_a_transport_ignores_cancellation(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        class BlockingTransport:
            def __init__(self) -> None:
                self.first = True

            def run(
                self,
                request: ProcessRequest,
                _cancellation: CancellationToken,
            ) -> TransportOutcome:
                if self.first:
                    self.first = False
                    entered.set()
                    release.wait(2)
                return TransportOutcome(0, "")

        poller = DevicePoller(
            DeviceService(BlockingTransport()),
            lambda: TOOLCHAIN,
            lambda _result: None,
            interval_seconds=0.01,
        )
        self.assertTrue(poller.start())
        self.assertTrue(entered.wait(1))
        started = time.monotonic()

        stopped = poller.stop(0.02)

        elapsed = time.monotonic() - started
        self.assertFalse(stopped)
        self.assertLess(elapsed, 0.25)
        release.set()
        self.assertTrue(poller.close(1))
        with self.assertRaises(ValueError):
            poller.stop(float("inf"))


class DeviceSelectionReconciliationTests(unittest.TestCase):
    def test_reconciliation_preserves_order_and_promotes_a_valid_primary(self) -> None:
        devices = (DeviceInfo("C"), DeviceInfo("B"))

        selected, primary = reconcile_device_selection(
            devices,
            ("C", "A", "B", "C"),
            "A",
        )

        self.assertEqual(("C", "B"), selected)
        self.assertEqual("C", primary)
        self.assertEqual(("B", "C"), tuple(item.serial for item in canonicalize_device_inventory(devices)))

    def test_store_reconciliation_is_atomic_idempotent_and_never_auto_selects(self) -> None:
        store = AppStateStore(
            AppSnapshot(
                devices=(DeviceInfo("A"), DeviceInfo("B"), DeviceInfo("C")),
                selected_serials=("C", "A", "B"),
                selected_serial="A",
            )
        )
        revisions: list[int] = []
        subscription = store.subscribe(lambda snapshot: revisions.append(snapshot.revision))

        first = store.reconcile_devices((DeviceInfo("C"), DeviceInfo("B")), expected_revision=0)
        unchanged = store.reconcile_devices((DeviceInfo("B"), DeviceInfo("C")), expected_revision=1)
        second = store.reconcile_devices((DeviceInfo("B"),), expected_revision=1)
        third = store.reconcile_devices((DeviceInfo("D"),), expected_revision=2)

        subscription.cancel()
        self.assertIs(first, unchanged)
        self.assertEqual(("C", "B"), first.selected_serials)
        self.assertEqual("C", first.selected_serial)
        self.assertEqual(("B",), second.selected_serials)
        self.assertEqual("B", second.selected_serial)
        self.assertEqual((), third.selected_serials)
        self.assertIsNone(third.selected_serial)
        self.assertEqual([1, 2, 3], revisions)

    def test_conflicting_duplicate_inventory_is_rejected_without_revision(self) -> None:
        store = AppStateStore()

        with self.assertRaisesRegex(ValueError, "duplicate device serial"):
            store.reconcile_devices((DeviceInfo("A", mode="adb"), DeviceInfo("A", mode="fastboot")))

        self.assertEqual(0, store.snapshot().revision)


if __name__ == "__main__":
    unittest.main()
