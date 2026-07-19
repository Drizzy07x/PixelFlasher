from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pixelflasher_core.config_store import CURRENT_SCHEMA_VERSION, ConfigDocument, ConfigStore
from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    DeviceManagementState,
    ManagedDeviceInfo,
    OperationStatus,
    ProcessRequest,
    ToolchainInfo,
)
from pixelflasher_core.device_management import DEVICE_MANAGEMENT_KEY, DeviceManagementError
from pixelflasher_core.devices import DeviceScanResult
from pixelflasher_core.executor import CancellationToken, TransportOutcome
from pixelflasher_core.runtime import ApplicationRuntime


def managed(
    serial: str,
    *,
    label: str = "",
    enabled: bool = True,
    connected: bool = True,
    mode: str = "adb",
) -> ManagedDeviceInfo:
    return ManagedDeviceInfo(
        serial,
        label=label,
        enabled=enabled,
        model=f"Pixel {serial}",
        codename=f"code-{serial.casefold()}",
        connected=connected,
        mode=mode,
        first_seen=10,
        last_seen=20,
    )


def current_config(path: Path, **values: object) -> None:
    path.write_text(
        json.dumps(
            {
                **values,
                "modern": {},
                "_pixelflasher_core_schema": CURRENT_SCHEMA_VERSION,
            }
        ),
        encoding="utf-8",
    )


class RuntimeDeviceManagerMigrationTests(unittest.TestCase):
    def test_legacy_roster_is_backed_up_imported_once_and_reopen_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "PixelFlasher.json"
            legacy_path = root / "devices.json"
            original = {
                "devices": {
                    "SERIAL-A": {
                        "enabled": False,
                        "custom_label": "Imported",
                        "hardware": "Pixel 9",
                        "device_name": "tokay",
                        "first_detected": "2026-01-02T03:04:05.123456",
                        "last_seen": "2026-01-03T04:05:06.654321",
                    }
                }
            }
            legacy_bytes = json.dumps(original).encode()
            legacy_path.write_bytes(legacy_bytes)

            runtime = ApplicationRuntime.open(config_path, legacy_devices_path=legacy_path)
            imported = runtime.snapshot().device_management
            runtime.shutdown()

            backup = root / "devices.json.v9.bak"
            self.assertEqual(legacy_bytes, backup.read_bytes())
            self.assertEqual(("SERIAL-A",), tuple(item.serial for item in imported.devices))
            self.assertEqual("Imported", imported.devices[0].label)
            persisted = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertIn(DEVICE_MANAGEMENT_KEY, persisted)
            self.assertIn(DEVICE_MANAGEMENT_KEY, persisted["modern"])

            legacy_path.write_text(
                json.dumps({"devices": {"SERIAL-B": {"custom_label": "Must not replace"}}}),
                encoding="utf-8",
            )
            reopened = ApplicationRuntime.open(config_path, legacy_devices_path=legacy_path)
            self.assertEqual(
                ("SERIAL-A",),
                tuple(item.serial for item in reopened.snapshot().device_management.devices),
            )
            reopened.shutdown()
            self.assertEqual(legacy_bytes, backup.read_bytes())

    def test_corrupt_legacy_roster_aborts_startup_without_creating_canonical_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "PixelFlasher.json"
            legacy_path = root / "devices.json"
            legacy_path.write_text('{"devices":{"A":{},"A":{}}}', encoding="utf-8")

            with self.assertRaises(DeviceManagementError) as caught:
                ApplicationRuntime.open(config_path, legacy_devices_path=legacy_path)

            self.assertEqual("legacy_devices_duplicate_key", caught.exception.code)
            self.assertFalse(config_path.exists())
            self.assertFalse((root / "devices.json.v9.bak").exists())


class RuntimeDeviceManagerCommandTests(unittest.TestCase):
    def make_runtime(self, root: Path, *, store_type: type[ConfigStore] = ConfigStore) -> ApplicationRuntime:
        path = root / "PixelFlasher.json"
        current_config(path, unrelated={"keep": True})
        store = store_type(path)
        document = store.load()
        management = DeviceManagementState(devices=(managed("A"), managed("B")))
        snapshot = AppSnapshot(
            devices=(
                DeviceInfo("A", model="Pixel A", mode="adb", name="Pixel A"),
                DeviceInfo("B", model="Pixel B", mode="fastboot", name="Pixel B"),
            ),
            device_management=management,
            selected_serials=("A", "B"),
            selected_serial="A",
        )
        return ApplicationRuntime(store, document, snapshot)

    def test_policy_alias_disable_remove_and_pause_persist_with_selection_repair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = self.make_runtime(root)

            alias = runtime.execute(
                AppCommand(
                    "device.manager.update",
                    expected_revision=0,
                    payload={"serial": "A", "label": "Primary"},
                )
            )
            disabled = runtime.execute(
                AppCommand(
                    "device.manager.update",
                    expected_revision=1,
                    payload={"serial": "A", "enabled": False},
                )
            )
            removed = runtime.execute(
                AppCommand(
                    "device.manager.remove",
                    expected_revision=2,
                    payload={"serial": "A"},
                )
            )
            paused = runtime.execute(
                AppCommand(
                    "device.manager.policy",
                    expected_revision=3,
                    payload={"scanEnabled": False},
                )
            )

            self.assertEqual(
                [OperationStatus.SUCCESS] * 4,
                [alias.status, disabled.status, removed.status, paused.status],
            )
            self.assertEqual("Primary", alias.value["devices"][0]["name"])
            self.assertEqual(["B"], [item["serial"] for item in disabled.value["devices"]])
            self.assertEqual(["B"], [item["serial"] for item in removed.value["devices"]])
            self.assertEqual((), runtime.snapshot().devices)
            self.assertEqual((), runtime.snapshot().selected_serials)
            self.assertIsNone(runtime.snapshot().selected_serial)
            self.assertFalse(runtime.snapshot().device_management.scan_enabled)
            self.assertEqual(("B",), tuple(item.serial for item in runtime.snapshot().device_management.devices))
            self.assertFalse(runtime.snapshot().device_management.devices[0].connected)
            payload = json.loads((root / "PixelFlasher.json").read_text(encoding="utf-8"))
            persisted = payload[DEVICE_MANAGEMENT_KEY]
            self.assertFalse(persisted["scanEnabled"])
            self.assertEqual(["B"], [item["serial"] for item in persisted["devices"]])
            self.assertIsNone(payload["device"])
            self.assertEqual(
                [],
                payload["_pixelflasher_core_state"]["selected_serials"],
            )
            self.assertEqual({"keep": True}, payload["unrelated"])
            runtime.shutdown()

    def test_multiselection_is_bounded_deduplicated_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = self.make_runtime(root)
            path = root / "PixelFlasher.json"

            selected = runtime.execute(
                AppCommand(
                    "device.select",
                    expected_revision=0,
                    payload={"serials": ["B", "A", "B"]},
                )
            )

            self.assertEqual(OperationStatus.SUCCESS, selected.status)
            self.assertEqual(("B", "A"), runtime.snapshot().selected_serials)
            self.assertEqual("B", runtime.snapshot().selected_serial)
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("B", persisted["device"])
            self.assertEqual(
                ["B", "A"],
                persisted["_pixelflasher_core_state"]["selected_serials"],
            )

            before = path.read_bytes()
            snapshot = runtime.snapshot()
            for serials in (["B", "UNKNOWN"], ["A"] * 33, [" A"]):
                with self.subTest(serials=serials):
                    result = runtime.execute(
                        AppCommand(
                            "device.select",
                            expected_revision=1,
                            payload={"serials": serials},
                        )
                    )
                    self.assertEqual(OperationStatus.FAILED, result.status)
                    self.assertIs(snapshot, runtime.snapshot())
                    self.assertEqual(before, path.read_bytes())
            runtime.shutdown()

    def test_missing_stale_and_invalid_payloads_never_change_state_or_disk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = self.make_runtime(root)
            path = root / "PixelFlasher.json"
            before = path.read_bytes()
            snapshot = runtime.snapshot()
            cases = (
                (AppCommand("device.manager.policy", payload={"scanEnabled": False}), "revision_required"),
                (
                    AppCommand(
                        "device.manager.policy",
                        expected_revision=1,
                        payload={"scanEnabled": False},
                    ),
                    "stale_revision",
                ),
                (AppCommand("device.manager.policy", expected_revision=0), "device_manager_payload_invalid"),
                (
                    AppCommand(
                        "device.manager.policy",
                        expected_revision=0,
                        payload={"scanEnabled": 1},
                    ),
                    "device_manager_payload_invalid",
                ),
                (
                    AppCommand(
                        "device.manager.policy",
                        expected_revision=0,
                        payload={"scanScope": "disabled"},
                    ),
                    "device_manager_payload_invalid",
                ),
                (
                    AppCommand(
                        "device.manager.policy",
                        expected_revision=0,
                        payload={"scanScope": "all", "future": True},
                    ),
                    "device_manager_payload_invalid",
                ),
                (
                    AppCommand(
                        "device.manager.update",
                        expected_revision=0,
                        payload={"serial": "A"},
                    ),
                    "device_manager_payload_invalid",
                ),
                (
                    AppCommand(
                        "device.manager.update",
                        expected_revision=0,
                        payload={"serial": "A", "label": 7},
                    ),
                    "device_manager_payload_invalid",
                ),
                (
                    AppCommand(
                        "device.manager.update",
                        expected_revision=0,
                        payload={"serial": "UNKNOWN", "enabled": False},
                    ),
                    "managed_device_not_found",
                ),
                (
                    AppCommand(
                        "device.manager.remove",
                        expected_revision=0,
                        payload={"serial": " A"},
                    ),
                    "device_manager_payload_invalid",
                ),
                (
                    AppCommand(
                        "device.manager.remove",
                        expected_revision=0,
                        payload={"serial": "A", "enabled": False},
                    ),
                    "device_manager_payload_invalid",
                ),
            )

            for command, code in cases:
                with self.subTest(code=code, command=command.kind):
                    result = runtime.execute(command)
                    self.assertEqual(OperationStatus.FAILED, result.status)
                    self.assertEqual(code, result.code)
                    self.assertIs(snapshot, runtime.snapshot())
                    self.assertEqual(before, path.read_bytes())
            runtime.shutdown()

    def test_noop_is_explicit_and_does_not_consume_revision_or_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = self.make_runtime(root)
            path = root / "PixelFlasher.json"
            before = path.read_bytes()

            result = runtime.execute(
                AppCommand(
                    "device.manager.policy",
                    expected_revision=0,
                    payload={"scanEnabled": True, "scanScope": "enabled"},
                )
            )

            self.assertTrue(result.ok)
            self.assertEqual("device_manager_unchanged", result.code)
            self.assertEqual(0, runtime.snapshot().revision)
            self.assertEqual(before, path.read_bytes())
            runtime.shutdown()

    def test_persistence_failure_never_promotes_snapshot_or_document(self) -> None:
        class FailingStore(ConfigStore):
            def save(self, _document: ConfigDocument) -> None:
                raise OSError("disk unavailable")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = self.make_runtime(root, store_type=FailingStore)
            before_snapshot = runtime.snapshot()
            before_document = runtime.config_document
            before_disk = (root / "PixelFlasher.json").read_bytes()

            result = runtime.execute(
                AppCommand(
                    "device.manager.update",
                    expected_revision=0,
                    payload={"serial": "A", "enabled": False},
                )
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("device_manager_save_failed", result.code)
            self.assertIs(before_snapshot, runtime.snapshot())
            self.assertIs(before_document, runtime.config_document)
            self.assertEqual(before_disk, (root / "PixelFlasher.json").read_bytes())
            runtime.config_store = ConfigStore(root / "PixelFlasher.json")
            runtime.shutdown()


class ScanTransport:
    def __init__(self) -> None:
        self.calls: list[ProcessRequest] = []

    def run(self, request: ProcessRequest, _cancellation: CancellationToken) -> TransportOutcome:
        self.calls.append(request)
        if request.argv == ("ADB", "devices", "-l"):
            return TransportOutcome(
                0,
                "List of devices attached\n"
                "ADB-SERIAL device model:Pixel_9 device:tokay usb:1-1\n"
                "DISABLED device model:Pixel_8 device:shiba usb:1-2\n",
            )
        if request.argv == ("FASTBOOT", "devices", "-l"):
            return TransportOutcome(0, "FASTBOOT-SERIAL fastboot product:husky usb:2-1\n")
        if request.argv == ("ADB", "-s", "ADB-SERIAL", "shell", "getprop"):
            return TransportOutcome(0, "[ro.product.model]: [Pixel 9 Pro]\n[ro.product.device]: [tokay]\n")
        if request.argv == ("ADB", "-s", "ADB-SERIAL", "shell", "dumpsys", "battery"):
            return TransportOutcome(0, "level: 80\n")
        if request.argv[:3] == ("FASTBOOT", "-s", "FASTBOOT-SERIAL"):
            variable = request.argv[-1]
            values = {"current-slot": "b", "unlocked": "yes", "is-userspace": "no"}
            return TransportOutcome(0, stderr=f"{variable}: {values[variable]}\n")
        raise AssertionError(f"unexpected or policy-excluded request: {request.argv!r}")


class RuntimeManualScanTests(unittest.TestCase):
    def test_manual_scan_applies_policy_repairs_selection_and_persists_roster_and_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "PixelFlasher.json"
            current_config(path, unrelated="preserved")
            transport = ScanTransport()
            runtime = ApplicationRuntime.open(path, transport=transport)
            management = DeviceManagementState(
                devices=(managed("DISABLED", enabled=False, connected=False, mode="offline"),)
            )
            prepared = runtime.store.update(
                expected_revision=0,
                devices=(DeviceInfo("VANISHED", mode="adb"),),
                device_management=management,
                selected_serials=("VANISHED",),
                selected_serial="VANISHED",
                toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
            )

            result = runtime.execute(
                AppCommand(
                    "device.scan",
                    expected_revision=prepared.revision,
                    payload={"includeProperties": True, "includeBattery": True},
                )
            )

            self.assertTrue(result.ok)
            self.assertEqual("device_scan_succeeded", result.code)
            snapshot = runtime.snapshot()
            self.assertEqual(("ADB-SERIAL", "FASTBOOT-SERIAL"), tuple(item.serial for item in snapshot.devices))
            self.assertEqual((), snapshot.selected_serials)
            self.assertIsNone(snapshot.selected_serial)
            self.assertEqual(
                ("ADB-SERIAL", "DISABLED", "FASTBOOT-SERIAL"),
                tuple(item.serial for item in snapshot.device_management.devices),
            )
            self.assertNotIn(
                "DISABLED",
                {part for request in transport.calls[2:] for part in request.argv},
            )
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("preserved", persisted["unrelated"])
            self.assertEqual(
                ["ADB-SERIAL", "DISABLED", "FASTBOOT-SERIAL"],
                [item["serial"] for item in persisted[DEVICE_MANAGEMENT_KEY]["devices"]],
            )
            self.assertIsNone(persisted["device"])
            self.assertEqual(
                [],
                persisted["_pixelflasher_core_state"]["selected_serials"],
            )
            self.assertEqual("ADB", persisted["_pixelflasher_core_state"]["toolchain"]["adb"])
            runtime.shutdown()

            reopened = ApplicationRuntime.open(path, transport=transport)
            self.assertEqual(
                ("ADB-SERIAL", "DISABLED", "FASTBOOT-SERIAL"),
                tuple(item.serial for item in reopened.snapshot().device_management.devices),
            )
            self.assertTrue(all(not item.connected for item in reopened.snapshot().device_management.devices))
            reopened.shutdown()

    def test_paused_manual_scan_fails_without_touching_transport_or_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PixelFlasher.json"
            current_config(path)
            transport = ScanTransport()
            runtime = ApplicationRuntime.open(path, transport=transport)
            paused = DeviceManagementState(scan_enabled=False)
            runtime.store.update(
                expected_revision=0,
                device_management=paused,
                toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
            )

            result = runtime.execute(AppCommand("device.scan", expected_revision=1))

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("device_scanning_paused", result.code)
            self.assertEqual(1, runtime.snapshot().revision)
            self.assertEqual([], transport.calls)
            runtime.shutdown()

    def test_manual_scan_rejects_a_257th_identity_without_state_or_disk_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PixelFlasher.json"
            current_config(path)
            runtime = ApplicationRuntime.open(path, transport=ScanTransport())
            prepared = runtime.store.update(
                expected_revision=0,
                toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
            )
            devices = tuple(
                DeviceInfo(f"SERIAL-{index:03d}", mode="adb")
                for index in range(257)
            )
            scan = DeviceScanResult(
                devices,
                successful_sources=("adb", "fastboot"),
                discovered_devices=devices,
            )
            before_snapshot = runtime.snapshot()
            before_disk = path.read_bytes()

            with patch.object(runtime.device_service, "scan", return_value=scan):
                result = runtime.execute(
                    AppCommand(
                        "device.scan",
                        expected_revision=prepared.revision,
                        payload={"includeProperties": False, "includeBattery": False},
                    )
                )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("device_management_devices_oversized", result.code)
            self.assertIs(before_snapshot, runtime.snapshot())
            self.assertEqual(before_disk, path.read_bytes())
            runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
