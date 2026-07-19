from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path

from pixelflasher_core.config_store import ConfigDocument
from pixelflasher_core.contracts import DeviceInfo, DeviceManagementState, ManagedDeviceInfo, ToolchainInfo
from pixelflasher_core.device_management import (
    DEVICE_MANAGEMENT_KEY,
    DeviceManagementError,
    backup_legacy_devices,
    device_management_from_document,
    device_management_from_mapping,
    document_with_device_management,
    import_legacy_devices,
    paused_device_management,
    reconcile_device_management,
    remove_managed_device,
    update_managed_device,
)
from pixelflasher_core.devices import DevicePoller, DeviceScanResult, DeviceService
from pixelflasher_core.executor import CancellationToken, TransportOutcome

TOOLCHAIN = ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True)


def managed_device(
    serial: str,
    *,
    label: str = "",
    enabled: bool = True,
    connected: bool = False,
    mode: str = "offline",
    first_seen: int = 0,
    last_seen: int = 0,
) -> ManagedDeviceInfo:
    return ManagedDeviceInfo(
        serial=serial,
        label=label,
        enabled=enabled,
        model=f"Model {serial}",
        codename=f"code-{serial.casefold()}",
        connected=connected,
        mode=mode,
        first_seen=first_seen,
        last_seen=last_seen,
    )


class DeviceManagementCodecTests(unittest.TestCase):
    def test_closed_mapping_round_trips_through_config_document(self) -> None:
        state = DeviceManagementState(
            scan_enabled=False,
            scan_scope="all",
            devices=(
                managed_device(
                    "SERIAL-B",
                    label="Daily driver",
                    enabled=False,
                    connected=True,
                    mode="fastbootd",
                    first_seen=10,
                    last_seen=20,
                ),
                managed_device("SERIAL-A"),
            ),
        )

        document = document_with_device_management(
            ConfigDocument(values={"unrelated": {"keep": True}}),
            state,
        )

        self.assertEqual(state, device_management_from_document(document))
        self.assertEqual(state, device_management_from_mapping(state.to_dict()))
        self.assertEqual({"keep": True}, document.values["unrelated"])
        self.assertEqual(
            ["SERIAL-A", "SERIAL-B"],
            [entry["serial"] for entry in document.to_dict()[DEVICE_MANAGEMENT_KEY]["devices"]],
        )

    def test_absent_mapping_uses_fail_safe_defaults(self) -> None:
        self.assertEqual(DeviceManagementState(), device_management_from_document(ConfigDocument()))
        self.assertEqual(DeviceManagementState(), device_management_from_mapping({}))

    def test_closed_mapping_rejects_unknown_missing_and_invalid_values(self) -> None:
        valid_device = managed_device("SERIAL").to_dict()
        cases = (
            ({"future": True}, "device_management_field_unknown"),
            ({"schemaVersion": 2}, "device_management_schema_unsupported"),
            ({"scanEnabled": 1}, "device_management_scan_enabled_invalid"),
            ({"scanScope": "disabled"}, "device_management_scope_invalid"),
            ({"devices": {}}, "device_management_devices_invalid"),
            ({"devices": [valid_device | {"future": True}]}, "managed_device_field_unknown"),
            ({"devices": [{key: value for key, value in valid_device.items() if key != "serial"}]}, "managed_device_field_missing"),
            (
                {"devices": [valid_device | {"lastSeen": 9_000_000_000_000_000}]},
                "managed_device_invalid",
            ),
            ({"devices": [valid_device, valid_device]}, "device_management_invalid"),
        )

        for raw, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(DeviceManagementError) as caught:
                    device_management_from_mapping(raw)
                self.assertEqual(code, caught.exception.code)

        with self.assertRaises(DeviceManagementError) as oversized:
            device_management_from_mapping(
                {
                    "devices": [
                        managed_device(f"SERIAL-{index:03d}").to_dict()
                        for index in range(257)
                    ]
                }
            )
        self.assertEqual("device_management_devices_oversized", oversized.exception.code)

    def test_existing_unreadable_state_is_never_overwritten(self) -> None:
        document = ConfigDocument(values={DEVICE_MANAGEMENT_KEY: {"schemaVersion": 99}})

        with self.assertRaises(DeviceManagementError) as caught:
            document_with_device_management(document, DeviceManagementState())
        self.assertEqual("device_management_schema_unsupported", caught.exception.code)
        self.assertEqual({"schemaVersion": 99}, document.values[DEVICE_MANAGEMENT_KEY])

    def test_runtime_state_and_reconciliation_never_exceed_the_record_limit(self) -> None:
        records = tuple(
            ManagedDeviceInfo(serial=f"SERIAL-{index:03d}") for index in range(256)
        )
        state = DeviceManagementState(devices=records)
        with self.assertRaisesRegex(ValueError, "exceeds its limit"):
            DeviceManagementState(
                devices=records + (ManagedDeviceInfo(serial="OVERFLOW"),)
            )
        with self.assertRaises(DeviceManagementError) as overflow:
            reconcile_device_management(
                state,
                (DeviceInfo("NEW-SERIAL", mode="adb"),),
            )
        self.assertEqual(
            "device_management_devices_oversized",
            overflow.exception.code,
        )


class LegacyDeviceMigrationTests(unittest.TestCase):
    def test_real_9x_document_migrates_identity_policy_and_iso_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "devices.json"
            path.write_text(
                json.dumps(
                    {
                        "devices": {
                            "SERIAL-B": {
                                "enabled": False,
                                "device_name": "tokay",
                                "hardware": "Pixel 9",
                                "custom_label": "Daily driver",
                                "first_detected": "2026-01-02T03:04:05.123456",
                                "last_seen": "2026-01-03T04:05:06.654321",
                                "connected": True,
                            },
                            "SERIAL-A": {
                                "first_detected": "2025-05-06 07:08:09",
                                "last_seen": "malformed-but-optional",
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )

            state = import_legacy_devices(path)

        self.assertTrue(state.scan_enabled)
        self.assertEqual("enabled", state.scan_scope)
        self.assertEqual(("SERIAL-A", "SERIAL-B"), tuple(item.serial for item in state.devices))
        first, second = state.devices
        self.assertEqual(int(datetime.fromisoformat("2025-05-06 07:08:09").timestamp()), first.first_seen)
        self.assertEqual(0, first.last_seen)
        self.assertEqual("Daily driver", second.label)
        self.assertFalse(second.enabled)
        self.assertEqual("Pixel 9", second.model)
        self.assertEqual("tokay", second.codename)
        self.assertFalse(second.connected)
        self.assertEqual("offline", second.mode)
        self.assertEqual(
            int(datetime.fromisoformat("2026-01-02T03:04:05.123456").timestamp()),
            second.first_seen,
        )
        self.assertEqual(
            int(datetime.fromisoformat("2026-01-03T04:05:06.654321").timestamp()),
            second.last_seen,
        )

    def test_missing_corrupt_duplicate_and_oversized_files_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(DeviceManagementState(), import_legacy_devices(root / "missing.json"))

            corrupt = root / "corrupt.json"
            corrupt.write_bytes(b"{\xff")
            with self.assertRaises(DeviceManagementError) as invalid:
                import_legacy_devices(corrupt)
            self.assertEqual("legacy_devices_invalid", invalid.exception.code)

            duplicate = root / "duplicate.json"
            duplicate.write_text('{"devices":{"SERIAL":{},"SERIAL":{}}}', encoding="utf-8")
            with self.assertRaises(DeviceManagementError) as repeated:
                import_legacy_devices(duplicate)
            self.assertEqual("legacy_devices_duplicate_key", repeated.exception.code)

            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (2 * 1024 * 1024 + 1))
            with self.assertRaises(DeviceManagementError) as too_large:
                import_legacy_devices(oversized)
            self.assertEqual("legacy_devices_oversized", too_large.exception.code)

    def test_out_of_range_legacy_timestamps_remain_optional(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "devices.json"
            path.write_text(
                json.dumps(
                    {
                        "devices": {
                            "SERIAL": {
                                "first_detected": "0001-01-01T00:00:00",
                                "last_seen": "9999-12-31T23:59:59-12:00",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            state = import_legacy_devices(path)

        self.assertEqual(0, state.devices[0].first_seen)
        self.assertEqual(0, state.devices[0].last_seen)

    def test_backup_is_atomic_idempotent_and_rejects_stale_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "devices.json"
            original = b'{"devices":{"SERIAL":{}}}'
            source.write_bytes(original)

            destination = backup_legacy_devices(source)

            self.assertIsNotNone(destination)
            assert destination is not None
            self.assertEqual(original, destination.read_bytes())
            self.assertEqual(destination, backup_legacy_devices(source))
            self.assertEqual([], list(source.parent.glob("*.backup.tmp")))

            source.write_bytes(b'{"devices":{"OTHER":{}}}')
            with self.assertRaises(DeviceManagementError) as mismatch:
                backup_legacy_devices(source)
            self.assertEqual("legacy_devices_backup_mismatch", mismatch.exception.code)
            self.assertEqual(original, destination.read_bytes())

    def test_invalid_legacy_root_and_record_types_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "devices.json"
            cases = (
                ([], "legacy_devices_invalid"),
                ({"devices": {}, "future": True}, "legacy_devices_invalid"),
                ({"devices": []}, "legacy_devices_invalid"),
                ({"devices": {"SERIAL": []}}, "legacy_device_invalid"),
                ({"devices": {"SERIAL": {"enabled": 1}}}, "legacy_device_invalid"),
                ({"devices": {"SERIAL": {"custom_label": 7}}}, "legacy_device_invalid"),
            )
            for payload, code in cases:
                with self.subTest(code=code, payload=payload):
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaises(DeviceManagementError) as caught:
                        import_legacy_devices(path)
                    self.assertEqual(code, caught.exception.code)


class DeviceManagementReconciliationTests(unittest.TestCase):
    def test_paused_policy_never_observes_or_repopulates_devices(self) -> None:
        paused = DeviceManagementState(
            scan_enabled=False,
            devices=(managed_device("SERIAL", connected=True, mode="adb"),),
        )

        updated, visible = reconcile_device_management(
            paused,
            (DeviceInfo("NEW", mode="adb"),),
        )

        self.assertEqual((), visible)
        self.assertEqual(("SERIAL",), tuple(item.serial for item in updated.devices))
        self.assertFalse(updated.devices[0].connected)
        self.assertEqual("offline", updated.devices[0].mode)

    def test_add_disconnect_repeated_scan_and_reconnect_have_no_timestamp_churn(self) -> None:
        empty = DeviceManagementState()
        adb = DeviceInfo("SERIAL", model="Pixel 9", codename="tokay", mode="adb", name="Pixel 9")

        connected, visible = reconcile_device_management(empty, (adb,), observed_at=100)
        repeated, repeated_visible = reconcile_device_management(connected, (adb,), observed_at=200)
        disconnected, none_visible = reconcile_device_management(repeated, (), observed_at=300)
        disconnected_again, _ = reconcile_device_management(disconnected, (), observed_at=400)
        fastboot = DeviceInfo("SERIAL", mode="fastboot", name="SERIAL")
        reconnected, fastboot_visible = reconcile_device_management(
            disconnected_again,
            (fastboot,),
            observed_at=500,
        )

        self.assertEqual((adb,), visible)
        self.assertEqual((adb,), repeated_visible)
        self.assertEqual(connected, repeated)
        self.assertEqual((), none_visible)
        self.assertEqual(disconnected, disconnected_again)
        first = connected.devices[0]
        self.assertEqual((100, 100), (first.first_seen, first.last_seen))
        offline = disconnected.devices[0]
        self.assertEqual((False, "offline", 100, 100), (offline.connected, offline.mode, offline.first_seen, offline.last_seen))
        restored = reconnected.devices[0]
        self.assertEqual((True, "fastboot", 100, 500), (restored.connected, restored.mode, restored.first_seen, restored.last_seen))
        self.assertEqual("Pixel 9", restored.model)
        self.assertEqual("tokay", restored.codename)
        self.assertEqual("fastboot", fastboot_visible[0].mode)

    def test_enabled_scope_filters_before_display_while_all_scope_preserves_aliases(self) -> None:
        disabled = managed_device("A", label="Personal", enabled=False)
        enabled = managed_device("B", label="Work", enabled=True)
        observed = (
            DeviceInfo("B", model="Pixel B", mode="adb", name="Pixel B"),
            DeviceInfo("A", model="Pixel A", mode="fastboot", name="Pixel A"),
        )

        enabled_state, visible = reconcile_device_management(
            DeviceManagementState(scan_scope="enabled", devices=(disabled, enabled)),
            observed,
            observed_at=10,
        )
        all_state, all_visible = reconcile_device_management(
            DeviceManagementState(scan_scope="all", devices=(disabled, enabled)),
            observed,
            observed_at=10,
        )

        self.assertEqual(("B",), tuple(item.serial for item in visible))
        self.assertEqual("Work", visible[0].name)
        self.assertTrue(next(item for item in enabled_state.devices if item.serial == "A").connected)
        self.assertEqual(("A", "B"), tuple(item.serial for item in all_visible))
        self.assertEqual(("Personal", "Work"), tuple(item.name for item in all_visible))
        self.assertEqual(all_state.devices, enabled_state.devices)

    def test_alias_enable_pause_and_remove_mutations_are_immutable_and_strict(self) -> None:
        initial = DeviceManagementState(
            devices=(managed_device("A", connected=True, mode="adb"), managed_device("B"))
        )

        updated = update_managed_device(initial, "A", label="Primary", enabled=False)
        paused = paused_device_management(updated)
        removed = remove_managed_device(paused, "B")

        self.assertEqual("", initial.devices[0].label)
        self.assertEqual(("Primary", False), (updated.devices[0].label, updated.devices[0].enabled))
        self.assertFalse(paused.devices[0].connected)
        self.assertEqual("offline", paused.devices[0].mode)
        self.assertEqual(("A",), tuple(item.serial for item in removed.devices))
        for operation in (
            lambda: update_managed_device(initial, "UNKNOWN", label="x"),
            lambda: remove_managed_device(initial, "UNKNOWN"),
        ):
            with self.assertRaises(DeviceManagementError) as caught:
                operation()
            self.assertEqual("managed_device_not_found", caught.exception.code)


class FilteringTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(self, request, _cancellation: CancellationToken) -> TransportOutcome:
        self.calls.append(request.argv)
        if request.argv == ("ADB", "devices", "-l"):
            return TransportOutcome(
                0,
                "List of devices attached\n"
                "BLOCKED device model:Pixel_8 device:shiba\n"
                "ALLOWED device model:Pixel_9 device:tokay\n",
            )
        if request.argv == ("FASTBOOT", "devices", "-l"):
            return TransportOutcome(0, "BLOCKED-FASTBOOT fastboot product:husky\n")
        if request.argv == ("ADB", "-s", "ALLOWED", "shell", "getprop"):
            return TransportOutcome(0, "[ro.product.model]: [Pixel 9 Pro]\n")
        raise AssertionError(f"excluded device was enriched: {request.argv!r}")


class DeviceServiceManagementTests(unittest.TestCase):
    def test_excluded_serials_are_filtered_before_any_property_enrichment(self) -> None:
        transport = FilteringTransport()

        scan = DeviceService(transport).scan(
            TOOLCHAIN,
            include_properties=True,
            include_battery=False,
            excluded_serials=frozenset({"BLOCKED", "BLOCKED-FASTBOOT"}),
        )

        self.assertTrue(scan.ok)
        self.assertEqual(("ALLOWED",), tuple(item.serial for item in scan.devices))
        self.assertEqual(
            ("ALLOWED", "BLOCKED", "BLOCKED-FASTBOOT"),
            tuple(item.serial for item in scan.discovered_devices),
        )
        self.assertEqual(
            [
                ("ADB", "devices", "-l"),
                ("FASTBOOT", "devices", "-l"),
                ("ADB", "-s", "ALLOWED", "shell", "getprop"),
            ],
            transport.calls,
        )

    def test_duplicate_discovery_across_adb_and_fastboot_has_one_fastboot_identity(self) -> None:
        class DuplicateTransport:
            def run(self, request, _cancellation: CancellationToken) -> TransportOutcome:
                if request.argv == ("ADB", "devices", "-l"):
                    return TransportOutcome(0, "DUP device model:Pixel_9 device:tokay\nDUP device model:Pixel_9 device:tokay\n")
                if request.argv == ("FASTBOOT", "devices", "-l"):
                    return TransportOutcome(0, "DUP fastboot product:tokay\nDUP fastboot product:tokay\n")
                variable = request.argv[-1]
                values = {"current-slot": "a", "unlocked": "yes", "is-userspace": "no"}
                return TransportOutcome(0, stderr=f"{variable}: {values[variable]}\n")

        scan = DeviceService(DuplicateTransport()).scan(TOOLCHAIN, include_properties=False)

        self.assertEqual(1, len(scan.devices))
        self.assertEqual(1, len(scan.discovered_devices))
        device = scan.devices[0]
        self.assertEqual(("DUP", "fastboot", "tokay", "tokay", "a", "unlocked"), (
            device.serial,
            device.mode,
            device.model,
            device.codename,
            device.slot,
            device.bootloader,
        ))


class ScriptedScanService:
    def __init__(self) -> None:
        self.calls = 0
        self.called = threading.Event()

    def scan(self, *_args, **_kwargs) -> DeviceScanResult:
        self.calls += 1
        self.called.set()
        return DeviceScanResult(
            (DeviceInfo("SERIAL", mode="adb"),),
            successful_sources=("adb", "fastboot"),
        )


class DevicePollerLifecycleTests(unittest.TestCase):
    def test_pause_resume_and_shutdown_are_idempotent_and_do_not_scan_while_paused(self) -> None:
        service = ScriptedScanService()
        observed: list[DeviceScanResult] = []
        poller = DevicePoller(
            service,  # type: ignore[arg-type]
            lambda: TOOLCHAIN,
            observed.append,
            interval_seconds=0.5,
        )

        self.assertTrue(poller.pause())
        self.assertFalse(poller.pause())
        self.assertTrue(poller.start())
        self.assertFalse(poller.start())
        self.assertFalse(service.called.wait(0.05))
        self.assertTrue(poller.resume())
        self.assertFalse(poller.resume())
        self.assertTrue(service.called.wait(1))
        self.assertEqual(1, service.calls)
        self.assertEqual(1, len(observed))
        self.assertTrue(poller.pause())
        time.sleep(0.05)
        self.assertEqual(1, service.calls)
        service.called.clear()
        self.assertTrue(poller.resume())
        self.assertTrue(service.called.wait(1))
        deadline = time.monotonic() + 1
        while len(observed) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertGreaterEqual(service.calls, 2)
        self.assertEqual(2, len(observed))
        service.called.clear()
        poller.invalidate_observation()
        self.assertTrue(service.called.wait(1))
        deadline = time.monotonic() + 1
        while len(observed) < 3 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(3, len(observed))
        self.assertTrue(poller.close(1))
        self.assertTrue(poller.close(0))
        self.assertFalse(poller.running)


if __name__ == "__main__":
    unittest.main()
