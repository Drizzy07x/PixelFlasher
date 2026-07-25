import hashlib
import json
import os
import stat
import threading
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from pixelflasher_core import (
    AppCommand,
    ApplicationRuntime,
    AppSnapshot,
    AppStateStore,
    CancellationToken,
    CommandExecutor,
    DeviceInfo,
    DevicePoller,
    DeviceService,
    FakeProcessTransport,
    FirmwareInspector,
    FirmwareKind,
    OperationStatus,
    ProcessRequest,
    ToolchainInfo,
    ToolchainService,
    TransportOutcome,
    derive_android_kmi,
    merge_device_history,
    merge_device_inventories,
    normalize_device_architecture,
    parse_adb_devices,
    parse_battery_level,
    parse_fastboot_devices,
    parse_fastboot_getvar,
    parse_getprop,
    parse_platform_tools_version,
)
from pixelflasher_core.platform_tools_setup import PlatformToolsSetupService
from tests.command_engine_factory import make_test_command_engine as CommandEngine

ADB_VERSION = "Android Debug Bridge version 1.0.41\nVersion 36.0.0-13206524\n"
FASTBOOT_VERSION = "fastboot version 36.0.0-13206524\n"


def make_toolchain_files(directory: Path):
    content = bytearray(128)
    content[:2] = b"MZ"
    content[60:64] = (64).to_bytes(4, "little")
    content[64:68] = b"PE\x00\x00"
    content[68:70] = (0x8664).to_bytes(2, "little")
    adb = directory / "adb.exe"
    fastboot = directory / "fastboot.exe"
    adb.write_bytes(content)
    fastboot.write_bytes(content)
    adb.chmod(adb.stat().st_mode | stat.S_IXUSR)
    fastboot.chmod(fastboot.stat().st_mode | stat.S_IXUSR)
    return adb.resolve(), fastboot.resolve()


def write_zip(path: Path, entries):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in entries.items():
            archive.writestr(name, value)


class PureParserTests(unittest.TestCase):
    def test_adb_parser_covers_all_states_and_ignores_noise(self):
        output = """* daemon started successfully
List of devices attached
SERIAL-A device product:shiba model:Pixel_8 device:shiba transport_id:1
SERIAL-B recovery product:husky model:Pixel_8_Pro device:husky
SERIAL-C sideload usb:2-1
SERIAL-D unauthorized usb:2-2
SERIAL-E offline
malformed
"""

        devices = parse_adb_devices(output)

        self.assertEqual(
            ["adb", "recovery", "sideload", "unauthorized", "offline"],
            [device.mode for device in devices],
        )
        self.assertEqual([True, True, True, False, False], [device.online for device in devices])
        self.assertEqual("Pixel 8", devices[0].model)
        self.assertEqual("shiba", devices[0].codename)
        wireless = parse_adb_devices("192.0.2.10:5555 device model:Pixel_9 device:tokay\n")
        self.assertEqual("Wi-Fi", wireless[0].connection)

    def test_fastboot_and_getprop_parsers_are_strict_but_tolerant(self):
        fastboot = parse_fastboot_devices(
            "SERIAL-F\tfastboot usb:1-2 product:akita\n"
            "SERIAL-G offline\n"
            "garbage line here\n"
        )
        properties = parse_getprop(
            "[ro.product.model]: [Pixel 9]\n"
            "bad line\n"
            "[ro.product.device]: [tokay]\n"
            "[ro.boot.slot_suffix]: [_b]\n"
        )

        self.assertEqual(["fastboot", "offline"], [device.mode for device in fastboot])
        self.assertEqual("akita", fastboot[0].codename)
        self.assertEqual("Pixel 9", properties["ro.product.model"])
        self.assertEqual("_b", properties["ro.boot.slot_suffix"])
        self.assertEqual(
            "yes",
            parse_fastboot_getvar(
                "Finished. Total time: 0.001s\n(bootloader) unlocked: yes\n",
                "unlocked",
            ),
        )
        self.assertEqual(
            "a",
            parse_fastboot_getvar("current-slot: a\nOKAY [  0.001s]\n", "current-slot"),
        )
        self.assertIsNone(parse_fastboot_getvar("unlocked: yes\n", "is-userspace"))
        self.assertEqual(87, parse_battery_level("status: 2\n  level: 87\n"))
        self.assertIsNone(parse_battery_level("level: 101\n"))
        self.assertEqual("arm64", normalize_device_architecture("arm64-v8a"))
        self.assertEqual("x86_64", normalize_device_architecture("x86_64,x86"))
        self.assertEqual("", normalize_device_architecture("mips"))
        self.assertEqual(
            "android14-5.15",
            derive_android_kmi("5.15.148-android14-11-gabcdef"),
        )
        self.assertEqual("", derive_android_kmi("5.15.148-custom-kernel"))

    def test_device_serialization_exposes_react_and_snake_case_aliases(self):
        device = DeviceInfo(
            "192.0.2.1:5555",
            model="Pixel 9",
            codename="tokay",
            mode="adb",
            android_version="16",
            build="BP2A",
            security_patch="2026-07-05",
            bootloader="locked",
            battery=64,
            connection="Wi-Fi",
            root=True,
        )

        serialized = device.to_dict()

        self.assertEqual("Pixel 9", serialized["name"])
        self.assertEqual(serialized["androidVersion"], serialized["android_version"])
        self.assertEqual(serialized["securityPatch"], serialized["security_patch"])
        self.assertEqual(serialized["root"], serialized["rooted"])
        self.assertEqual("unknown", serialized["slot"])

    def test_inventory_merge_keeps_one_stable_record_per_serial(self):
        adb = (
            DeviceInfo(
                "A",
                model="Pixel",
                codename="akita",
                mode="offline",
                root=True,
                online=False,
            ),
        )
        fastboot = (DeviceInfo("A", mode="fastboot", online=True), DeviceInfo("B", mode="fastboot"))

        merged = merge_device_inventories(adb, fastboot)

        self.assertEqual(["A", "B"], [device.serial for device in merged])
        self.assertEqual("fastboot", merged[0].mode)
        self.assertEqual("Pixel", merged[0].model)
        self.assertFalse(merged[0].root)

    def test_history_merge_preserves_identity_but_not_operational_state(self):
        previous = (
            DeviceInfo(
                "A",
                model="Pixel 9",
                codename="tokay",
                mode="adb",
                slot="a",
                root=True,
                name="My Pixel",
                android_version="16",
                build="BP2A",
                security_patch="2026-07-05",
                bootloader="unlocked",
                battery=78,
                connection="USB",
            ),
        )
        current = (DeviceInfo("A", codename="tokay", mode="fastboot", online=True),)

        merged = merge_device_history(current, previous)

        self.assertEqual("Pixel 9", merged[0].model)
        self.assertEqual("My Pixel", merged[0].name)
        self.assertEqual("BP2A", merged[0].build)
        self.assertEqual("", merged[0].slot)
        self.assertEqual("unknown", merged[0].bootloader)
        self.assertFalse(merged[0].root)

    def test_platform_version_parser_ignores_adb_protocol_version(self):
        self.assertEqual((36, 0, 0), parse_platform_tools_version(ADB_VERSION))
        self.assertIsNone(parse_platform_tools_version("unexpected output"))


class ToolchainServiceTests(unittest.TestCase):
    def test_configured_directory_is_validated_with_exact_commands(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            adb, fastboot = make_toolchain_files(root)
            transport = FakeProcessTransport(
                [TransportOutcome(0, ADB_VERSION), TransportOutcome(0, FASTBOOT_VERSION)]
            )

            check = ToolchainService(transport).discover(root)

            self.assertTrue(check.ok)
            self.assertEqual("36.0.0", check.info.version)
            self.assertEqual(
                [
                    ProcessRequest((str(adb), "version"), timeout_seconds=5.0),
                    ProcessRequest((str(fastboot), "--version"), timeout_seconds=5.0),
                ],
                transport.calls,
            )

    def test_path_discovery_uses_path_when_no_config_is_set(self):
        with TemporaryDirectory() as directory:
            adb, fastboot = make_toolchain_files(Path(directory))
            transport = FakeProcessTransport(
                [TransportOutcome(0, ADB_VERSION), TransportOutcome(0, FASTBOOT_VERSION)]
            )

            with patch(
                "pixelflasher_core.toolchain.shutil.which",
                side_effect=lambda name: str(adb if name == "adb" else fastboot),
            ):
                check = ToolchainService(transport).discover()

            self.assertTrue(check.ok)
            self.assertEqual(str(adb), check.info.adb)

    def test_timeout_malformed_and_mixed_versions_fail_closed(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            make_toolchain_files(root)
            cases = (
                ([TransportOutcome(None, timed_out=True)], "tool_timeout", 1),
                ([TransportOutcome(0, "garbage")], "tool_version_malformed", 1),
                (
                    [
                        TransportOutcome(0, ADB_VERSION),
                        TransportOutcome(0, "fastboot version 35.0.2"),
                    ],
                    "tool_version_mismatch",
                    2,
                ),
            )
            for outcomes, expected_code, expected_calls in cases:
                with self.subTest(expected_code=expected_code):
                    transport = FakeProcessTransport(outcomes)
                    check = ToolchainService(transport).discover(root)
                    self.assertFalse(check.ok)
                    self.assertEqual(expected_code, check.code)
                    self.assertEqual(expected_calls, len(transport.calls))

    def test_invalid_configured_path_never_falls_back_or_executes(self):
        transport = FakeProcessTransport([])
        check = ToolchainService(transport).discover("Z:/definitely/missing/platform-tools")
        self.assertEqual("toolchain_path_invalid", check.code)
        self.assertEqual([], transport.calls)

    def test_validation_failures_are_reported_without_using_an_unverified_pair(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            make_toolchain_files(root)
            cancelled = CancellationToken()
            cancelled.cancel()
            cases = (
                (FakeProcessTransport([]), cancelled, "cancelled"),
                (
                    Mock(run=Mock(side_effect=OSError("execution blocked"))),
                    CancellationToken(),
                    "tool_execution_failed",
                ),
                (
                    FakeProcessTransport([TransportOutcome(None, cancelled=True)]),
                    CancellationToken(),
                    "cancelled",
                ),
                (
                    FakeProcessTransport([TransportOutcome(7, stderr="failed")]),
                    CancellationToken(),
                    "tool_version_failed",
                ),
                (
                    FakeProcessTransport(
                        [TransportOutcome(0, ADB_VERSION), TransportOutcome(None, timed_out=True)]
                    ),
                    CancellationToken(),
                    "tool_timeout",
                ),
                (
                    FakeProcessTransport(
                        [
                            TransportOutcome(0, ADB_VERSION.replace("36.0.0", "32.0.0")),
                            TransportOutcome(0, FASTBOOT_VERSION.replace("36.0.0", "32.0.0")),
                        ]
                    ),
                    CancellationToken(),
                    "tool_version_unsupported",
                ),
            )
            for transport, cancellation, expected_code in cases:
                with self.subTest(expected_code=expected_code):
                    check = ToolchainService(transport).discover(
                        root,
                        cancellation=cancellation,
                    )
                    self.assertFalse(check.ok)
                    self.assertEqual(expected_code, check.code)

    def test_incomplete_or_non_executable_pair_is_rejected_before_version_checks(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            adb, fastboot = make_toolchain_files(root)
            fastboot.unlink()
            missing = ToolchainService(FakeProcessTransport([])).discover(root)
            self.assertEqual("tool_missing", missing.code)

            fastboot.write_bytes(adb.read_bytes())
            with patch("pixelflasher_core.toolchain.os") as platform_os:
                platform_os.name = "posix"
                platform_os.X_OK = os.X_OK
                platform_os.access.return_value = False
                non_executable = ToolchainService(FakeProcessTransport([])).discover(root)
            self.assertEqual("tool_not_executable", non_executable.code)


class DeviceServiceTests(unittest.TestCase):
    def setUp(self):
        self.toolchain = ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True)

    def test_scan_merges_modes_enriches_safe_devices_and_uses_exact_argv(self):
        adb_output = (
            "List of devices attached\n"
            "A device model:Old_Model device:old\n"
            "B unauthorized usb:2-1\n"
            "R recovery model:Recovery device:recovery\n"
        )
        fastboot_output = "F\tfastboot usb:3-1 product:akita\n"
        transport = FakeProcessTransport(
            [
                TransportOutcome(0, adb_output),
                TransportOutcome(0, fastboot_output),
                TransportOutcome(0, stderr="(bootloader) current-slot: b\n"),
                TransportOutcome(0, stderr="(bootloader) unlocked: yes\n"),
                TransportOutcome(0, stderr="(bootloader) is-userspace: no\n"),
                TransportOutcome(
                    0,
                    "[ro.product.model]: [Pixel 8]\n"
                    "[ro.product.device]: [shiba]\n"
                    "[ro.boot.slot_suffix]: [_a]\n"
                    "[ro.build.version.release]: [16]\n"
                    "[ro.build.id]: [BP2A.260101.001]\n"
                    "[ro.build.version.security_patch]: [2026-01-05]\n"
                    "[ro.product.cpu.abi]: [arm64-v8a]\n"
                    "[ro.boot.flash.locked]: [0]\n",
                ),
                TransportOutcome(0, "5.15.148-android14-11-gabcdef\n"),
                TransportOutcome(0, "AC powered: false\n  level: 87\n"),
                TransportOutcome(0, "[ro.product.device]: [recovery]\n"),
                TransportOutcome(0, "5.10.218-android13-4-gabcdef\n"),
            ]
        )

        result = DeviceService(transport).scan(self.toolchain)

        self.assertTrue(result.ok)
        self.assertEqual(["A", "B", "F", "R"], [device.serial for device in result.devices])
        selected = {device.serial: device for device in result.devices}
        self.assertEqual(("Pixel 8", "shiba", "a"), (selected["A"].model, selected["A"].codename, selected["A"].slot))
        self.assertEqual(
            ("Pixel 8", "16", "BP2A.260101.001", "2026-01-05", "unlocked", 87, "USB"),
            (
                selected["A"].name,
                selected["A"].android_version,
                selected["A"].build,
                selected["A"].security_patch,
                selected["A"].bootloader,
                selected["A"].battery,
                selected["A"].connection,
            ),
        )
        self.assertFalse(selected["B"].online)
        self.assertEqual("fastboot", selected["F"].mode)
        self.assertEqual("b", selected["F"].slot)
        self.assertEqual("unlocked", selected["F"].bootloader)
        self.assertEqual(
            ("arm64", "5.15.148-android14-11-gabcdef", "android14-5.15"),
            (selected["A"].architecture, selected["A"].kernel_release, selected["A"].kmi),
        )
        self.assertEqual(
            [
                ProcessRequest(("ADB", "devices", "-l"), timeout_seconds=8.0),
                ProcessRequest(("FASTBOOT", "devices", "-l"), timeout_seconds=8.0),
                ProcessRequest(
                    ("FASTBOOT", "-s", "F", "getvar", "current-slot"),
                    timeout_seconds=4.0,
                ),
                ProcessRequest(
                    ("FASTBOOT", "-s", "F", "getvar", "unlocked"),
                    timeout_seconds=4.0,
                ),
                ProcessRequest(
                    ("FASTBOOT", "-s", "F", "getvar", "is-userspace"),
                    timeout_seconds=4.0,
                ),
                ProcessRequest(("ADB", "-s", "A", "shell", "getprop"), timeout_seconds=4.0),
                ProcessRequest(
                    ("ADB", "-s", "A", "shell", "uname", "-r"),
                    timeout_seconds=4.0,
                ),
                ProcessRequest(
                    ("ADB", "-s", "A", "shell", "dumpsys", "battery"),
                    timeout_seconds=3.0,
                ),
                ProcessRequest(("ADB", "-s", "R", "shell", "getprop"), timeout_seconds=4.0),
                ProcessRequest(
                    ("ADB", "-s", "R", "shell", "uname", "-r"),
                    timeout_seconds=4.0,
                ),
            ],
            transport.calls,
        )

    def test_fastboot_getvars_detect_userspace_and_keep_previous_identity(self):
        previous = (
            DeviceInfo(
                "F",
                model="Google Pixel 9",
                codename="tokay",
                mode="adb",
                slot="a",
                root=True,
                name="Daily driver",
                build="BP2A",
                bootloader="unlocked",
            ),
        )
        transport = FakeProcessTransport(
            [
                TransportOutcome(0, "List of devices attached\n"),
                TransportOutcome(0, "F fastboot product:tokay\n"),
                TransportOutcome(0, stdout="current-slot: b\n"),
                TransportOutcome(0, stderr="(bootloader) unlocked: no\n"),
                TransportOutcome(0, stderr="is-userspace: yes\n"),
            ]
        )

        result = DeviceService(transport).scan(
            self.toolchain,
            include_properties=False,
            previous_devices=previous,
        )

        self.assertTrue(result.ok)
        device = result.devices[0]
        self.assertEqual("fastbootd", device.mode)
        self.assertEqual("b", device.slot)
        self.assertEqual("locked", device.bootloader)
        self.assertEqual("Google Pixel 9", device.model)
        self.assertEqual("Daily driver", device.name)
        self.assertEqual("BP2A", device.build)
        self.assertFalse(device.root)
        self.assertEqual(
            [
                ("FASTBOOT", "-s", "F", "getvar", "current-slot"),
                ("FASTBOOT", "-s", "F", "getvar", "unlocked"),
                ("FASTBOOT", "-s", "F", "getvar", "is-userspace"),
            ],
            [request.argv for request in transport.calls[2:]],
        )

    def test_fastboot_enrichment_stops_between_getvars_when_cancelled(self):
        token = CancellationToken()

        class CancellingTransport:
            def __init__(self):
                self.calls = []

            def run(self, request, cancellation):
                self.calls.append(request)
                if request.argv == ("ADB", "devices", "-l"):
                    return TransportOutcome(0, "")
                if request.argv == ("FASTBOOT", "devices", "-l"):
                    return TransportOutcome(0, "F fastboot product:tokay\n")
                cancellation.cancel()
                return TransportOutcome(0, stderr="current-slot: a\n")

        transport = CancellingTransport()
        result = DeviceService(transport).scan(self.toolchain, cancellation=token)

        self.assertTrue(result.cancelled)
        self.assertEqual(
            [("FASTBOOT", "-s", "F", "getvar", "current-slot")],
            [request.argv for request in transport.calls[2:]],
        )

    def test_timeout_disconnect_and_malformed_output_do_not_create_phantom_devices(self):
        transport = FakeProcessTransport(
            [
                TransportOutcome(None, timed_out=True),
                TransportOutcome(0, "malformed\nSERIAL no-recognized-state extra\n"),
            ]
        )
        result = DeviceService(transport).scan(self.toolchain)

        self.assertTrue(result.ok)
        self.assertEqual((), result.devices)
        self.assertIn("adb:timeout", result.warnings)

        disconnected = FakeProcessTransport(
            [
                TransportOutcome(0, "List of devices attached\nA device model:Pixel device:akita\n"),
                TransportOutcome(0, ""),
                TransportOutcome(1, stderr="device disconnected"),
            ]
        )
        result = DeviceService(disconnected).scan(self.toolchain)
        self.assertEqual(["A"], [device.serial for device in result.devices])
        self.assertIn("properties:A:exit:1", result.warnings)

    def test_both_scan_failures_are_explicit(self):
        transport = FakeProcessTransport([TransportOutcome(1), TransportOutcome(1)])
        result = DeviceService(transport).scan(self.toolchain)
        self.assertFalse(result.ok)
        self.assertEqual(("adb:exit:1", "fastboot:exit:1"), result.warnings)

    def test_hotplug_poller_stops_without_wx_or_a_leaked_thread(self):
        observed = threading.Event()
        transport = FakeProcessTransport([TransportOutcome(0, ""), TransportOutcome(0, "")])
        poller = DevicePoller(
            DeviceService(transport),
            lambda: self.toolchain,
            lambda _result: observed.set(),
            interval_seconds=1,
        )

        self.assertTrue(poller.start())
        self.assertTrue(observed.wait(1))
        self.assertTrue(poller.stop())
        self.assertEqual(2, len(transport.calls))


class FirmwareInspectorTests(unittest.TestCase):
    def test_factory_ota_custom_and_corrupt_detection_with_streaming_hash(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            factory = root / "factory.zip"
            ota = root / "ota.zip"
            custom = root / "custom.zip"
            corrupt = root / "broken.zip"
            write_zip(factory, {"flash-all.sh": "", "image-husky-AP4A.250.zip": b"image"})
            write_zip(
                ota,
                {
                    "META-INF/com/android/metadata": (
                        "ota-type=AB\npre-device=husky\npost-build-incremental=123456\n"
                    ),
                    "payload.bin": b"payload",
                },
            )
            write_zip(custom, {"boot.img": b"boot", "system.new.dat": b"system"})
            corrupt.write_bytes(b"not a zip")
            inspector = FirmwareInspector(hash_chunk_size=3)

            factory_result = inspector.inspect(factory, expected_devices=("husky",))
            ota_result = inspector.inspect(ota, expected_devices=("husky",))
            custom_result = inspector.inspect(custom)
            corrupt_result = inspector.inspect(corrupt)

            self.assertEqual(FirmwareKind.FACTORY, factory_result.kind)
            self.assertEqual("husky", factory_result.device)
            self.assertEqual("AP4A.250", factory_result.build)
            self.assertEqual(hashlib.sha256(factory.read_bytes()).hexdigest(), factory_result.sha256)
            self.assertEqual(FirmwareKind.OTA, ota_result.kind)
            self.assertEqual("123456", ota_result.build)
            self.assertEqual(FirmwareKind.CUSTOM, custom_result.kind)
            self.assertEqual("corrupt_firmware", corrupt_result.code)

    def test_path_traversal_is_rejected_without_extracting_anything(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "hostile.zip"
            write_zip(archive, {"../escaped.txt": "owned", "payload.bin": "payload"})

            result = FirmwareInspector().inspect(archive)

            self.assertEqual("unsafe_archive", result.code)
            self.assertFalse((root.parent / "escaped.txt").exists())

    def test_known_device_mismatch_and_cancellation_fail_closed(self):
        with TemporaryDirectory() as directory:
            ota = Path(directory) / "ota.zip"
            write_zip(
                ota,
                {"META-INF/com/android/metadata": "ota-type=AB\npre-device=husky\n"},
            )
            mismatch = FirmwareInspector().inspect(ota, expected_devices=("shiba",))
            token = CancellationToken()
            token.cancel()
            cancelled = FirmwareInspector().inspect(ota, cancellation=token)

            self.assertEqual("device_mismatch", mismatch.code)
            self.assertEqual("firmware_cancelled", cancelled.code)


class EngineServiceIntegrationTests(unittest.TestCase):
    def test_platform_setup_validates_path_without_network(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            adb, fastboot = make_toolchain_files(root)
            transport = FakeProcessTransport(
                [TransportOutcome(0, ADB_VERSION), TransportOutcome(0, FASTBOOT_VERSION)]
            )
            toolchain_service = ToolchainService(transport)
            setup_service = PlatformToolsSetupService(
                toolchain_service,
                cache_directory=root / "cache",
                install_directory=root / "install",
                platform="windows",
                architecture="x86_64",
            )
            engine = CommandEngine(
                executor=CommandExecutor(transport),
                toolchain_service=toolchain_service,
                platform_tools_setup_service=setup_service,
            )

            result = engine.execute(
                AppCommand(
                    "platformTools.setup",
                    expected_revision=0,
                    payload={"source": "directory", "path": str(root)},
                )
            )

            self.assertEqual(OperationStatus.SUCCESS, result.status)
            self.assertEqual("toolchain_ready", result.code)
            self.assertTrue(engine.store.snapshot().toolchain.ready)
            self.assertEqual((str(adb), "version"), transport.calls[0].argv)
            blocked = engine.execute(
                AppCommand(
                    "platformTools.setup",
                    expected_revision=1,
                    payload={"source": "official"},
                )
            )
            self.assertEqual("platform_tools_catalog_unavailable", blocked.code)

    def test_real_device_scan_updates_snapshot_and_preserves_stable_selection(self):
        transport = FakeProcessTransport(
            [
                TransportOutcome(0, "List of devices attached\nA device model:Pixel device:akita\n"),
                TransportOutcome(0, "F fastboot product:husky\n"),
                TransportOutcome(0, "[ro.product.device]: [akita]\n"),
            ]
        )
        initial = AppSnapshot(
            selected_serial="A",
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )
        engine = CommandEngine(
            store=AppStateStore(initial),
            executor=CommandExecutor(transport),
        )

        result = engine.execute(AppCommand("device.scan", expected_revision=0))

        snapshot = engine.store.snapshot()
        self.assertEqual(OperationStatus.SUCCESS, result.status)
        self.assertEqual("device_scan_succeeded", result.code)
        self.assertEqual(["A", "F"], [device.serial for device in snapshot.devices])
        self.assertEqual("A", snapshot.selected_serial)
        self.assertEqual(1, snapshot.revision)

    def test_device_scan_cancellation_remains_active_until_state_promotion(self):
        transport = FakeProcessTransport(
            [
                TransportOutcome(0, "List of devices attached\nA device model:Pixel device:akita\n"),
                TransportOutcome(0, ""),
            ]
        )
        engine = CommandEngine(
            store=AppStateStore(
                AppSnapshot(toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True))
            ),
            executor=CommandExecutor(transport),
        )
        intent = AppCommand(
            "device.scan",
            expected_revision=0,
            operation_id="scan-cancel-before-promotion",
            payload={"includeProperties": False, "includeBattery": False},
        )
        entered_promotion = threading.Event()
        release_promotion = threading.Event()
        original = engine._promote_device_scan

        def blocked_promotion(*args):
            entered_promotion.set()
            self.assertTrue(release_promotion.wait(2))
            return original(*args)

        results = []
        with patch.object(engine, "_promote_device_scan", side_effect=blocked_promotion):
            worker = threading.Thread(
                target=lambda: results.append(engine.execute(intent)),
                daemon=True,
            )
            worker.start()
            self.assertTrue(entered_promotion.wait(2))
            self.assertTrue(engine.cancel(intent.operation_id))
            release_promotion.set()
            worker.join(2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(1, len(results))
        self.assertEqual(OperationStatus.CANCELLED, results[0].status)
        self.assertEqual(0, engine.store.snapshot().revision)
        self.assertEqual((), engine.store.snapshot().devices)
        self.assertFalse(engine.cancel(intent.operation_id))

    def test_partial_scan_timeout_preserves_inventory_from_failed_source(self):
        transport = FakeProcessTransport(
            [TransportOutcome(0, "List of devices attached\n"), TransportOutcome(None, timed_out=True)]
        )
        initial = AppSnapshot(
            devices=(DeviceInfo("F", mode="fastboot", online=True),),
            selected_serial="F",
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )
        engine = CommandEngine(
            store=AppStateStore(initial),
            executor=CommandExecutor(transport),
        )

        result = engine.execute(
            AppCommand("device.scan", expected_revision=0, payload={"includeProperties": False})
        )

        self.assertEqual(OperationStatus.SUCCESS, result.status)
        self.assertEqual(["F"], [device.serial for device in engine.store.snapshot().devices])
        self.assertEqual("F", engine.store.snapshot().selected_serial)

    def test_device_select_rejects_a_serial_not_in_latest_inventory(self):
        engine = CommandEngine(
            store=AppStateStore(AppSnapshot(devices=(DeviceInfo("A"),)))
        )
        result = engine.execute(
            AppCommand("device.select", expected_revision=0, payload={"serial": "MISSING"})
        )
        self.assertEqual("device_not_found", result.code)

    def test_firmware_select_process_mismatch_and_plan_preview(self):
        with TemporaryDirectory() as directory:
            ota = Path(directory) / "ota.zip"
            write_zip(
                ota,
                {
                    "META-INF/com/android/metadata": (
                        "ota-type=AB\npre-device=husky\npost-build-incremental=42\n"
                    ),
                    "META-INF/com/google/android/update-binary": (
                        b"never execute archive-provided code"
                    ),
                },
            )
            initial = AppSnapshot(
                devices=(DeviceInfo("A", codename="husky", mode="sideload"),),
                selected_serial="A",
                toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
            )
            engine = CommandEngine(
                store=AppStateStore(initial),
                interaction_handler=lambda _request: True,
            )

            selected = engine.execute(
                AppCommand("firmware.select", expected_revision=0, payload={"path": str(ota)})
            )
            processed = engine.execute(
                AppCommand("firmware.process", expected_revision=1)
            )
            updated = engine.execute(
                AppCommand(
                    "flash.plan.update",
                    expected_revision=3,
                    payload={
                        "mode": "OTA",
                        "options": {"verify": True, "noReboot": True, "dryRun": True},
                    },
                )
            )
            preview = engine.execute(AppCommand("flash.plan.preview", expected_revision=4))

            self.assertEqual("firmware_selected", selected.code)
            self.assertEqual("ota", engine.store.snapshot().firmware.type)
            self.assertEqual("firmware_processed", processed.code)
            self.assertTrue(engine.store.snapshot().firmware.processed)
            self.assertEqual("state_updated", updated.code)
            self.assertEqual("flash_plan_preview", preview.code)
            self.assertEqual(engine.store.snapshot().plan.fingerprint, preview.value["plan"]["fingerprint"])

            mismatch_engine = CommandEngine(
                store=AppStateStore(
                    AppSnapshot(
                        devices=(DeviceInfo("B", codename="shiba"),),
                        selected_serial="B",
                    )
                )
            )
            mismatch = mismatch_engine.execute(
                AppCommand("firmware.select", expected_revision=0, payload={"path": str(ota)})
            )
            self.assertEqual("device_mismatch", mismatch.code)
            self.assertEqual(0, mismatch_engine.store.snapshot().revision)

    def test_runtime_uses_configured_toolchain_before_real_scan(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "platform-tools"
            tools.mkdir()
            adb, fastboot = make_toolchain_files(tools)
            config = root / "config.json"
            config.write_text(
                json.dumps({"platform_tools_path": str(tools)}),
                encoding="utf-8",
            )
            transport = FakeProcessTransport(
                [
                    TransportOutcome(0, ADB_VERSION),
                    TransportOutcome(0, FASTBOOT_VERSION),
                    TransportOutcome(0, "List of devices attached\n"),
                    TransportOutcome(0, ""),
                ]
            )
            runtime = ApplicationRuntime.open(config, transport=transport)

            result = runtime.execute(
                AppCommand("device.scan", expected_revision=0, payload={"includeProperties": False})
            )
            runtime.shutdown()

            self.assertEqual(OperationStatus.SUCCESS, result.status)
            self.assertTrue(runtime.snapshot().toolchain.ready)
            self.assertEqual(
                [
                    (str(adb), "version"),
                    (str(fastboot), "--version"),
                    (str(adb), "devices", "-l"),
                    (str(fastboot), "devices", "-l"),
                ],
                [request.argv for request in transport.calls],
            )


if __name__ == "__main__":
    unittest.main()
