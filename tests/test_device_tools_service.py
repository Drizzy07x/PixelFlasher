import hashlib
import pickle
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    ProcessRequest,
    ToolchainInfo,
)
from pixelflasher_core.device_tools import (
    DeviceToolPlanningError,
    DeviceToolsService,
    LaunchOutcome,
    ManagedProcessLauncher,
    SubprocessSecretRunner,
)
from pixelflasher_core.executor import CancellationToken


class RecordingLauncher:
    def __init__(self, *, pid=4242, error=None):
        self.pid = pid
        self.error = error
        self.calls = []
        self.shutdown_called = False

    def launch(self, request):
        self.calls.append(request)
        if self.error is not None:
            raise self.error
        return LaunchOutcome(self.pid)

    def shutdown(self):
        self.shutdown_called = True


class RecordingSecretRunner:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def run(self, request, secret, cancellation):
        self.calls.append((request, secret, cancellation))
        return self.outcome


def write_scrcpy_executable(path: Path) -> bytes:
    contents = b"MZ\x00\x00fake scrcpy" if sys.platform.startswith("win") else b"#!/bin/sh\nexit 0\n"
    path.write_bytes(contents)
    if not sys.platform.startswith("win"):
        path.chmod(path.stat().st_mode | 0o111)
    return contents


class DeviceToolsServiceTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = AppSnapshot(
            revision=7,
            devices=(DeviceInfo("SERIAL", mode="adb", online=True),),
            selected_serial="SERIAL",
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )
        self.service = DeviceToolsService(hash_chunk_size=2)

    def compile(self, kind, payload):
        return self.service.compile(
            AppCommand(
                kind,
                expected_revision=self.snapshot.revision,
                target_serial="SERIAL",
                payload=payload,
            ),
            self.snapshot,
        )

    def test_logcat_compiles_exact_serial_bound_bounded_argv(self):
        compilation = self.compile(
            "tools.logcat",
            {
                "buffers": ["main", "system"],
                "format": "threadtime",
                "filters": {
                    "System.err": "error",
                    "ActivityManager": "info",
                },
                "maxLines": 250,
                "timeoutSeconds": 12,
            },
        )

        self.assertEqual(
            (
                "ADB",
                "-s",
                "SERIAL",
                "logcat",
                "-d",
                "-b",
                "main",
                "-b",
                "system",
                "-v",
                "threadtime",
                "-t",
                "250",
                "ActivityManager:I",
                "System.err:E",
                "*:S",
            ),
            compilation.plan.request.argv,
        )
        self.assertEqual(12.0, compilation.plan.request.timeout_seconds)
        self.assertEqual("SERIAL", compilation.plan.target_serial)
        self.assertEqual("adb", compilation.plan.expected_device_state)
        self.assertFalse(compilation.device_write)
        self.assertFalse(compilation.requires_confirmation)

    def test_logcat_defaults_are_bounded_and_shell_free(self):
        compilation = self.compile("tools.logcat", {})

        self.assertEqual(
            (
                "ADB",
                "-s",
                "SERIAL",
                "logcat",
                "-d",
                "-b",
                "main",
                "-v",
                "threadtime",
                "-t",
                "1000",
            ),
            compilation.plan.request.argv,
        )
        self.assertEqual(30.0, compilation.plan.request.timeout_seconds)

    def test_logcat_rejects_filter_format_buffer_and_limit_injection(self):
        cases = (
            ({"filters": {"Good;rm": "info"}}, "logcat_filter_invalid"),
            ({"filters": {"Good": "I;rm"}}, "logcat_filter_invalid"),
            ({"format": "threadtime;rm"}, "logcat_format_invalid"),
            ({"buffers": ["main", "all"]}, "logcat_buffer_ambiguous"),
            ({"maxLines": 10_001}, "logcat_limit_invalid"),
            ({"timeoutSeconds": 0}, "logcat_timeout_invalid"),
        )
        for payload, code in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(DeviceToolPlanningError) as raised:
                    self.compile("tools.logcat", payload)
                self.assertEqual(code, raised.exception.code)

    def test_push_files_hashes_canonical_sources_and_fixed_destinations(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "alpha.bin"
            second = Path(directory) / "beta.zip"
            first.write_bytes(b"alpha contents")
            second.write_bytes(b"beta contents")

            compilation = self.compile(
                "tools.pushFiles",
                {
                    "paths": [str(first), str(second)],
                    "destination": "/sdcard/Download/",
                },
            )

            self.assertEqual(
                [
                    (
                        "ADB",
                        "-s",
                        "SERIAL",
                        "push",
                        str(first.resolve()),
                        "/sdcard/Download/alpha.bin",
                    ),
                    (
                        "ADB",
                        "-s",
                        "SERIAL",
                        "push",
                        str(second.resolve()),
                        "/sdcard/Download/beta.zip",
                    ),
                ],
                [request.argv for request in compilation.plan.requests],
            )
            self.assertEqual(
                [
                    hashlib.sha256(b"alpha contents").hexdigest(),
                    hashlib.sha256(b"beta contents").hexdigest(),
                ],
                [artifact.sha256 for artifact in compilation.plan.artifacts],
            )
            self.assertEqual(
                [str(first.resolve()), str(second.resolve())],
                [artifact.path for artifact in compilation.plan.artifacts],
            )
            self.assertTrue(compilation.device_write)
            self.assertTrue(compilation.requires_confirmation)
            self.assertFalse(compilation.destructive)

    def test_push_rejects_arbitrary_destination_name_and_ui_execution_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            safe = Path(directory) / "safe.bin"
            safe.write_bytes(b"safe")
            unsafe_name = Path(directory) / "unsafe name.bin"
            unsafe_name.write_bytes(b"unsafe")

            cases = (
                (
                    {"paths": [str(safe)], "destination": "/data/data/"},
                    "push_destination_invalid",
                ),
                (
                    {
                        "paths": [str(unsafe_name)],
                        "destination": "/data/local/tmp/",
                    },
                    "push_name_invalid",
                ),
                (
                    {
                        "paths": [str(safe)],
                        "destination": "/data/local/tmp/",
                        "argv": ["shell", "rm"],
                    },
                    "invalid_device_tool_payload",
                ),
                (
                    {
                        "paths": [str(safe)],
                        "destination": "/data/local/tmp/",
                        "sha256": "0" * 64,
                    },
                    "invalid_device_tool_payload",
                ),
            )
            for payload, code in cases:
                with self.subTest(payload=payload):
                    with self.assertRaises(DeviceToolPlanningError) as raised:
                        self.compile("tools.pushFiles", payload)
                    self.assertEqual(code, raised.exception.code)

    def test_push_rejects_relative_duplicate_and_remote_name_ambiguity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "one" / "same.bin"
            second = root / "two" / "SAME.bin"
            first.parent.mkdir()
            second.parent.mkdir()
            first.write_bytes(b"one")
            second.write_bytes(b"two")

            cases = (
                ["relative.bin"],
                [str(first), str(first)],
                [str(first), str(second)],
            )
            for paths in cases:
                with self.subTest(paths=paths):
                    with self.assertRaises(DeviceToolPlanningError) as raised:
                        self.compile(
                            "tools.pushFiles",
                            {
                                "paths": paths,
                                "destination": "/data/local/tmp/",
                            },
                        )
                    self.assertEqual("push_path_ambiguous", raised.exception.code)

    def test_push_requires_between_one_and_thirty_two_existing_files(self):
        with self.assertRaises(DeviceToolPlanningError) as raised:
            self.compile(
                "tools.pushFiles",
                {"paths": [], "destination": "/data/local/tmp/"},
            )
        self.assertEqual("push_paths_invalid", raised.exception.code)

        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.bin"
            with self.assertRaises(DeviceToolPlanningError) as raised:
                self.compile(
                    "tools.pushFiles",
                    {
                        "paths": [str(missing)],
                        "destination": "/data/local/tmp/",
                    },
                )
            self.assertEqual("push_path_invalid", raised.exception.code)

    def test_unknown_fields_fail_closed_for_both_supported_commands(self):
        for kind in ("tools.logcat", "tools.pushFiles"):
            with self.subTest(kind=kind):
                with self.assertRaises(DeviceToolPlanningError) as raised:
                    self.compile(kind, {"command": "shell id"})
                self.assertEqual("invalid_device_tool_payload", raised.exception.code)

    def test_arbitrary_adb_shell_has_an_explicit_unsupported_contract(self):
        with self.assertRaises(DeviceToolPlanningError) as raised:
            self.compile("tools.adbShell", {"command": "getprop"})

        self.assertEqual("adb_shell_unsupported", raised.exception.code)

    def test_requires_selected_online_adb_device_and_validated_toolchain(self):
        cases = (
            (
                AppSnapshot(
                    devices=(DeviceInfo("SERIAL", mode="fastboot"),),
                    selected_serial="SERIAL",
                    toolchain=self.snapshot.toolchain,
                ),
                "adb_device_required",
            ),
            (
                AppSnapshot(
                    devices=(DeviceInfo("SERIAL", mode="adb"),),
                    selected_serial="SERIAL",
                    toolchain=ToolchainInfo(),
                ),
                "toolchain_not_ready",
            ),
        )
        for snapshot, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(DeviceToolPlanningError) as raised:
                    self.service.compile(
                        AppCommand(
                            "tools.logcat",
                            expected_revision=0,
                            target_serial="SERIAL",
                        ),
                        snapshot,
                    )
                self.assertEqual(code, raised.exception.code)

    def test_serial_identity_mismatch_fails_closed(self):
        with self.assertRaises(DeviceToolPlanningError) as raised:
            self.service.compile(
                AppCommand(
                    "tools.logcat",
                    target_serial="SERIAL",
                    payload={"serial": "OTHER"},
                ),
                self.snapshot,
            )

        self.assertEqual("ambiguous_target_serial", raised.exception.code)

    def test_scrcpy_uses_only_backend_executable_and_exact_selected_serial(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "scrcpy.exe" if sys.platform.startswith("win") else "scrcpy"
            executable = Path(directory) / name
            contents = write_scrcpy_executable(executable)
            launcher = RecordingLauncher()
            service = DeviceToolsService(
                scrcpy_executable=executable,
                process_launcher=launcher,
            )

            compilation = service.compile(
                AppCommand(
                    "tools.scrcpy",
                    expected_revision=7,
                    target_serial="SERIAL",
                ),
                self.snapshot,
            )

            self.assertEqual(
                (str(executable.resolve()), "--serial", "SERIAL"),
                compilation.plan.request.argv,
            )
            self.assertEqual(str(executable.resolve().parent), compilation.plan.request.cwd)
            self.assertEqual("managed-launch", compilation.execution)
            self.assertEqual("scrcpy-executable", compilation.plan.artifacts[0].role)
            self.assertEqual(
                hashlib.sha256(contents).hexdigest(),
                compilation.plan.artifacts[0].sha256,
            )
            self.assertEqual([], launcher.calls)

            with self.assertRaises(DeviceToolPlanningError) as raised:
                service.compile(
                    AppCommand(
                        "tools.scrcpy",
                        expected_revision=7,
                        target_serial="SERIAL",
                        payload={"path": str(executable)},
                    ),
                    self.snapshot,
                )
            self.assertEqual("invalid_device_tool_payload", raised.exception.code)

    def test_scrcpy_missing_and_non_executable_config_fail_closed(self):
        with self.assertRaises(DeviceToolPlanningError) as missing:
            self.compile("tools.scrcpy", {})
        self.assertEqual("scrcpy_not_configured", missing.exception.code)

        with tempfile.TemporaryDirectory() as directory:
            wrong = Path(directory) / ("other.exe" if sys.platform.startswith("win") else "other")
            write_scrcpy_executable(wrong)
            service = DeviceToolsService(scrcpy_executable=wrong)
            with self.assertRaises(DeviceToolPlanningError) as invalid:
                service.compile(
                    AppCommand("tools.scrcpy", target_serial="SERIAL"),
                    self.snapshot,
                )
            self.assertEqual("scrcpy_path_invalid", invalid.exception.code)

    def test_wifi_pair_plan_never_contains_or_serializes_pairing_code(self):
        command = AppCommand(
            "tools.wifi",
            expected_revision=7,
            target_serial="SERIAL",
            payload={
                "action": "pair",
                "host": "192.0.2.20",
                "port": 37123,
                "pairingCode": "123456",
            },
        )

        compilation = self.service.compile(command, self.snapshot)

        self.assertEqual(("ADB", "pair", "192.0.2.20:37123"), compilation.plan.request.argv)
        self.assertEqual("secret-stdin", compilation.execution)
        self.assertNotIn("123456", repr(command))
        self.assertNotIn("123456", repr(compilation))
        self.assertNotIn("123456", str(command.to_dict()))
        self.assertNotIn("123456", str(compilation.to_dict()))
        self.assertEqual("[REDACTED]", command.to_dict()["payload"]["pairingCode"])
        with self.assertRaisesRegex(TypeError, "cannot be pickled"):
            pickle.dumps(command.payload["pairingCode"])

    def test_wifi_actions_compile_strict_endpoints_and_status_binding(self):
        for action in ("connect", "disconnect"):
            with self.subTest(action=action):
                compilation = self.compile(
                    "tools.wifi",
                    {"action": action, "host": "2001:db8::1", "port": 5555},
                )
                self.assertEqual(
                    ("ADB", action, "[2001:db8::1]:5555"),
                    compilation.plan.request.argv,
                )
                self.assertEqual("SERIAL", compilation.plan.target_serial)

        status = self.compile("tools.wifi", {"action": "status"})
        self.assertEqual(("ADB", "-s", "SERIAL", "get-state"), status.plan.request.argv)
        self.assertEqual("wifi.status", status.action)

    def test_wifi_rejects_host_port_pairing_and_action_ambiguity(self):
        cases = (
            ({"action": "connect", "host": "example.com", "port": 5555}, "wifi_host_invalid"),
            ({"action": "connect", "host": "192.0.2.1;rm", "port": 5555}, "wifi_host_invalid"),
            ({"action": "connect", "host": "192.0.2.1", "port": "5555"}, "wifi_port_invalid"),
            ({"action": "connect", "host": "192.0.2.1", "port": 70000}, "wifi_port_invalid"),
            (
                {
                    "action": "connect",
                    "host": "192.0.2.1",
                    "port": 5555,
                    "pairingCode": "123456",
                },
                "wifi_pairing_code_unexpected",
            ),
            (
                {
                    "action": "pair",
                    "host": "192.0.2.1",
                    "port": 5555,
                    "pairingCode": "12 456",
                },
                "wifi_pairing_code_invalid",
            ),
            ({"action": "status", "host": "192.0.2.1"}, "wifi_status_payload_invalid"),
            ({"action": "shell"}, "wifi_action_invalid"),
        )
        for payload, code in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(DeviceToolPlanningError) as raised:
                    self.compile("tools.wifi", payload)
                self.assertEqual(code, raised.exception.code)

    def test_default_scrcpy_launcher_uses_argv_shell_false_and_tracks_child(self):
        process = MagicMock()
        process.pid = 4242
        process.poll.return_value = 0
        process.wait.side_effect = subprocess.TimeoutExpired("scrcpy.exe", 0.1)
        with patch(
            "pixelflasher_core.device_tools.subprocess.Popen",
            return_value=process,
        ) as popen:
            launcher = ManagedProcessLauncher()
            outcome = launcher.launch(
                ProcessRequest(("scrcpy.exe", "--serial", "SERIAL"), cwd="C:/scrcpy")
            )
            launcher.shutdown()

        self.assertEqual(4242, outcome.pid)
        self.assertEqual(
            ["scrcpy.exe", "--serial", "SERIAL"],
            popen.call_args.args[0],
        )
        self.assertIs(False, popen.call_args.kwargs["shell"])
        self.assertEqual("C:/scrcpy", popen.call_args.kwargs["cwd"])
        with self.assertRaisesRegex(RuntimeError, "shut down"):
            launcher.launch(ProcessRequest(("scrcpy.exe", "--serial", "SERIAL")))

    def test_default_scrcpy_launcher_rejects_immediate_process_exit(self):
        process = MagicMock()
        process.pid = 4242
        process.wait.return_value = 7
        with patch(
            "pixelflasher_core.device_tools.subprocess.Popen",
            return_value=process,
        ):
            launcher = ManagedProcessLauncher()
            with self.assertRaisesRegex(RuntimeError, "status 7"):
                launcher.launch(
                    ProcessRequest(("scrcpy.exe", "--serial", "SERIAL"))
                )

    def test_default_pair_runner_writes_secret_to_stdin_never_argv(self):
        process = MagicMock()
        input_stream = MagicMock()
        process.stdin = input_stream
        process.returncode = 0
        process.communicate.return_value = ("Successfully paired", "")
        with patch(
            "pixelflasher_core.device_tools.subprocess.Popen",
            return_value=process,
        ) as popen:
            outcome = SubprocessSecretRunner().run(
                ProcessRequest(("ADB", "pair", "192.0.2.20:37123"), timeout_seconds=1),
                "123456",
                CancellationToken(),
            )

        self.assertEqual(0, outcome.returncode)
        self.assertNotIn("123456", popen.call_args.args[0])
        self.assertIs(False, popen.call_args.kwargs["shell"])
        input_stream.write.assert_called_once_with("123456\n")
        input_stream.flush.assert_called_once_with()
        input_stream.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
