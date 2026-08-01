"""Regression tests for the device inventory defects (BUG-02, BUG-45, BUG-46)."""

from __future__ import annotations

import unittest

from pixelflasher_core.contracts import DeviceInfo, ProcessRequest, ToolchainInfo
from pixelflasher_core.devices import (
    DeviceService,
    merge_device_history,
    merge_device_inventories,
    parse_adb_device_warnings,
    parse_adb_devices,
)
from pixelflasher_core.executor import CancellationToken, TransportOutcome

TOOLCHAIN = ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True)

ROOTED_GETPROP = (
    "[ro.product.model]: [Pixel 9 Pro]\n"
    "[ro.product.device]: [caiman]\n"
    "[ro.boot.slot_suffix]: [_a]\n"
    "[ro.build.id]: [BP2A.260101.001]\n"
)


class ScriptedTransport:
    """Answer exact argv tuples and record every request."""

    def __init__(self, responses: dict[tuple[str, ...], TransportOutcome]) -> None:
        self.responses = responses
        self.calls: list[ProcessRequest] = []

    def run(self, request: ProcessRequest, _cancellation: CancellationToken) -> TransportOutcome:
        self.calls.append(request)
        try:
            return self.responses[request.argv]
        except KeyError:  # pragma: no cover - guards test drift
            raise AssertionError(f"unexpected process request: {request.argv!r}") from None


def _base_responses(adb_output: str) -> dict[tuple[str, ...], TransportOutcome]:
    return {
        ("ADB", "devices", "-l"): TransportOutcome(0, adb_output),
        ("FASTBOOT", "devices", "-l"): TransportOutcome(0, ""),
    }


class RootDetectionTests(unittest.TestCase):
    """BUG-02: DeviceInfo.root was never populated by the device pipeline."""

    adb_output = "List of devices attached\nSERIAL-A device model:Pixel_9_Pro device:caiman usb:1-1\n"

    def _scan(self, root_outcome: TransportOutcome, **kwargs):
        responses = _base_responses(self.adb_output)
        responses[("ADB", "-s", "SERIAL-A", "shell", "getprop")] = TransportOutcome(
            0,
            ROOTED_GETPROP,
        )
        responses[("ADB", "-s", "SERIAL-A", "shell", "uname", "-r")] = TransportOutcome(
            0,
            "6.1.99-android14-11-gtest\n",
        )
        responses[("ADB", "-s", "SERIAL-A", "shell", "su", "-c", "id -u")] = root_outcome
        transport = ScriptedTransport(responses)
        return transport, DeviceService(transport).scan(
            TOOLCHAIN,
            include_battery=False,
            **kwargs,
        )

    def test_adb_scan_reports_a_rooted_device_as_rooted(self) -> None:
        transport, result = self._scan(TransportOutcome(0, "0\n"))

        self.assertTrue(result.ok)
        self.assertTrue(result.devices[0].root)
        self.assertTrue(result.devices[0].to_dict()["rooted"])
        self.assertIn(
            ProcessRequest(
                ("ADB", "-s", "SERIAL-A", "shell", "su", "-c", "id -u"),
                timeout_seconds=4.0,
            ),
            transport.calls,
        )

    def test_unrooted_device_stays_unrooted_without_a_scan_warning(self) -> None:
        _, result = self._scan(
            TransportOutcome(1, stderr="/system/bin/sh: su: inaccessible or not found\n"),
        )

        self.assertFalse(result.devices[0].root)
        self.assertEqual((), result.warnings)

    def test_root_probe_fails_closed_on_timeout_and_on_shell_noise(self) -> None:
        for outcome in (
            TransportOutcome(None, timed_out=True),
            TransportOutcome(0, "0\n", stderr="su: setexeccon failed\n"),
            TransportOutcome(0, "2000\n"),
        ):
            with self.subTest(outcome=outcome):
                _, result = self._scan(outcome)
                self.assertFalse(result.devices[0].root)

    def test_root_is_not_probed_for_recovery_or_fastboot_devices(self) -> None:
        responses = {
            ("ADB", "devices", "-l"): TransportOutcome(
                0,
                "List of devices attached\nSERIAL-R recovery model:Pixel_9\n",
            ),
            ("FASTBOOT", "devices", "-l"): TransportOutcome(0, "SERIAL-F fastboot product:caiman\n"),
            ("ADB", "-s", "SERIAL-R", "shell", "getprop"): TransportOutcome(0, ROOTED_GETPROP),
            ("ADB", "-s", "SERIAL-R", "shell", "uname", "-r"): TransportOutcome(0, "6.1.99\n"),
            ("FASTBOOT", "-s", "SERIAL-F", "getvar", "current-slot"): TransportOutcome(
                0,
                stderr="current-slot: a\n",
            ),
            ("FASTBOOT", "-s", "SERIAL-F", "getvar", "unlocked"): TransportOutcome(
                0,
                stderr="unlocked: yes\n",
            ),
            ("FASTBOOT", "-s", "SERIAL-F", "getvar", "is-userspace"): TransportOutcome(
                0,
                stderr="is-userspace: no\n",
            ),
        }
        transport = ScriptedTransport(responses)

        result = DeviceService(transport).scan(TOOLCHAIN, include_battery=False)

        self.assertTrue(result.ok)
        self.assertFalse(any(device.root for device in result.devices))
        self.assertNotIn(
            "su",
            [token for request in transport.calls for token in request.argv],
        )

    def test_root_is_never_inherited_from_history_or_from_the_other_transport(self) -> None:
        remembered = (DeviceInfo("SERIAL-A", model="Pixel 9 Pro", mode="adb", root=True),)

        merged = merge_device_history(
            (DeviceInfo("SERIAL-A", mode="fastboot", online=True),),
            remembered,
        )
        self.assertFalse(merged[0].root)
        self.assertEqual("Pixel 9 Pro", merged[0].model)

        inventories = merge_device_inventories(
            remembered,
            (DeviceInfo("SERIAL-A", mode="fastboot", online=True),),
        )
        self.assertFalse(inventories[0].root)

    def test_unenriched_scan_never_claims_root(self) -> None:
        transport = ScriptedTransport(_base_responses(self.adb_output))

        result = DeviceService(transport).scan(
            TOOLCHAIN,
            include_properties=False,
            previous_devices=(DeviceInfo("SERIAL-A", mode="adb", root=True),),
        )

        self.assertFalse(result.devices[0].root)


class UnusableAdbRowDiagnosticsTests(unittest.TestCase):
    """BUG-45: rows adb cannot map were dropped with no diagnostic at all."""

    def test_no_permissions_row_produces_a_scan_warning(self) -> None:
        output = (
            "List of devices attached\n"
            "9B021FFAZ00A9L         no permissions; see [http://developer.android.com/tools/device.html]\n"
            "SERIAL-A device model:Pixel_9 device:caiman usb:1-1\n"
        )

        self.assertEqual(
            ("adb:no_permissions:9B021FFAZ00A9L",),
            parse_adb_device_warnings(output),
        )
        self.assertEqual(("SERIAL-A",), tuple(item.serial for item in parse_adb_devices(output)))

    def test_unknown_state_is_named_and_transient_states_are_silent(self) -> None:
        self.assertEqual(
            ("adb:unknown_state:SERIAL-A:sideloading",),
            parse_adb_device_warnings(
                "SERIAL-A sideloading\nSERIAL-B authorizing\nSERIAL-C connecting\nSERIAL-D host\n"
            ),
        )

    def test_mapped_states_and_banner_noise_stay_warning_free(self) -> None:
        self.assertEqual(
            (),
            parse_adb_device_warnings(
                "* daemon started successfully\n"
                "List of devices attached\n"
                "SERIAL-A device product:shiba\n"
                "SERIAL-B recovery\n"
                "SERIAL-C sideload\n"
                "SERIAL-D unauthorized\n"
                "SERIAL-E offline\n"
                "malformed\n"
            ),
        )

    def test_scan_surfaces_the_diagnostic_in_its_warnings(self) -> None:
        transport = ScriptedTransport(
            _base_responses(
                "List of devices attached\n"
                "9B021FFAZ00A9L no permissions; see [http://developer.android.com/tools/device.html]\n"
            )
        )

        result = DeviceService(transport).scan(TOOLCHAIN)

        self.assertTrue(result.ok)
        self.assertEqual((), result.devices)
        self.assertIn("adb:no_permissions:9B021FFAZ00A9L", result.warnings)


class WirelessConnectionLabelTests(unittest.TestCase):
    """BUG-46: mDNS/TLS wireless serials were labelled as USB."""

    def test_mdns_wireless_serials_are_labelled_wi_fi(self) -> None:
        devices = parse_adb_devices(
            "adb-28221FDH2000GS-YoDXsC._adb-tls-connect._tcp device model:Pixel_6_Pro\n"
            "adb-28221FDH2000GS-YoDXsC._adb-tls-pairing._tcp device model:Pixel_6_Pro\n"
            "adb-28221FDH2000GS-YoDXsC._adb._tcp. device model:Pixel_6_Pro\n"
        )

        self.assertEqual(["Wi-Fi", "Wi-Fi", "Wi-Fi"], [device.connection for device in devices])

    def test_cable_and_legacy_wireless_labels_are_unchanged(self) -> None:
        devices = parse_adb_devices(
            "28221FDH2000GS device usb:1-2 model:Pixel_6_Pro\n"
            "192.168.1.44:5555 device model:Pixel_8\n"
            "emulator-5554 device model:sdk_gphone\n"
            "adb-28221FDH2000GS-YoDXsC._adb-tls-connect._tcp device usb:1-2 model:Pixel_6_Pro\n"
        )

        self.assertEqual(
            {
                "28221FDH2000GS": "USB",
                "192.168.1.44:5555": "Wi-Fi",
                "emulator-5554": "USB",
                "adb-28221FDH2000GS-YoDXsC._adb-tls-connect._tcp": "USB",
            },
            {device.serial: device.connection for device in devices},
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
