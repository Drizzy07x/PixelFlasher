import hashlib
import pickle
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    OperationResult,
    OperationRisk,
    OperationStatus,
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
from pixelflasher_core.executor import CancellationToken, TransportOutcome
from pixelflasher_core.grants import PathGrantStore


class RecordingLauncher:
    def __init__(self, *, pid=4242, error=None, terminate_result=True):
        self.pid = pid
        self.error = error
        self.terminate_result = terminate_result
        self.calls = []
        self.terminated = []
        self.shutdown_called = False

    def launch(self, request):
        self.calls.append(request)
        if self.error is not None:
            raise self.error
        return LaunchOutcome(self.pid)

    def terminate(self, pid):
        self.terminated.append(pid)
        return self.terminate_result

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
            devices=(
                DeviceInfo("SERIAL", codename="akita", mode="adb", online=True),
            ),
            selected_serial="SERIAL",
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )
        self.service = DeviceToolsService(hash_chunk_size=2)

    def compile(self, kind, payload):
        return self.service.compile(
            AppCommand(
                kind,
                expected_revision=self.snapshot.revision,
                target_serial=None if kind == "tools.wifi" else "SERIAL",
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
        self.assertEqual(7, compilation.plan.snapshot_revision)
        self.assertEqual("akita", compilation.plan.expected_codename)
        self.assertEqual("adb", compilation.plan.expected_device_state)
        self.assertIs(OperationRisk.READ_ONLY, compilation.plan.risk)
        self.assertEqual((), compilation.plan.postconditions)
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
            self.assertIs(OperationRisk.MUTATING, compilation.plan.risk)
            self.assertEqual("user_file_write", compilation.plan.data_behavior)
            self.assertEqual(
                ("remote_files_written",),
                tuple(item.kind for item in compilation.plan.postconditions),
            )
            self.assertTrue(
                all(request.output_limit_bytes == 64 * 1024 for request in compilation.plan.requests)
            )
            self.assertEqual(
                [
                    {
                        "displayName": "alpha.bin",
                        "destination": "/sdcard/Download/alpha.bin",
                        "sha256": hashlib.sha256(b"alpha contents").hexdigest(),
                        "sizeBytes": len(b"alpha contents"),
                        "verified": True,
                    },
                    {
                        "displayName": "beta.zip",
                        "destination": "/sdcard/Download/beta.zip",
                        "sha256": hashlib.sha256(b"beta contents").hexdigest(),
                        "sizeBytes": len(b"beta contents"),
                        "verified": True,
                    },
                ],
                [receipt.to_dict() for receipt in compilation.push_files],
            )
            expected_hashes = compilation.plan.postconditions[0].expected["hashes"]
            self.assertEqual(
                {
                    "/sdcard/Download/alpha.bin": hashlib.sha256(
                        b"alpha contents"
                    ).hexdigest(),
                    "/sdcard/Download/beta.zip": hashlib.sha256(
                        b"beta contents"
                    ).hexdigest(),
                },
                expected_hashes,
            )

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

        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index in range(33):
                path = Path(directory) / f"file-{index:02d}.bin"
                path.write_bytes(bytes([index]))
                paths.append(str(path))
            compilation = self.compile(
                "tools.pushFiles",
                {"paths": paths[:32], "destination": "/data/local/tmp/"},
            )
            self.assertEqual(32, len(compilation.plan.requests))
            self.assertEqual(32, len(compilation.push_files))
            with self.assertRaises(DeviceToolPlanningError) as raised:
                self.compile(
                    "tools.pushFiles",
                    {"paths": paths, "destination": "/data/local/tmp/"},
                )
            self.assertEqual("push_paths_invalid", raised.exception.code)

    def test_push_hashing_honors_the_single_operation_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "payload.bin"
            source.write_bytes(b"payload")
            token = CancellationToken()
            token.set_deadline(0.001)
            self.assertTrue(token.wait(0.1))
            with self.assertRaises(DeviceToolPlanningError) as raised:
                self.service.compile(
                    AppCommand(
                        "tools.pushFiles",
                        expected_revision=self.snapshot.revision,
                        target_serial="SERIAL",
                        payload={
                            "paths": [str(source)],
                            "destination": "/data/local/tmp/",
                        },
                    ),
                    self.snapshot,
                    cancellation=token,
                )
            self.assertEqual("push_timed_out", raised.exception.code)

    def test_push_hashing_rejects_a_native_file_replaced_after_grant_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "payload.bin"
            source.write_bytes(b"approved")
            grants = PathGrantStore()
            issued = grants.issue_file(
                source,
                purpose="tools.pushFiles.sources",
            )
            bound = grants.resolve_bound_file(
                issued.token,
                purpose="tools.pushFiles.sources",
            )
            replacement = root / "replacement.bin"
            replacement.write_bytes(b"unapproved")
            replacement.replace(source)

            with self.assertRaises(DeviceToolPlanningError) as raised:
                self.compile(
                    "tools.pushFiles",
                    {
                        "paths": [bound],
                        "destination": "/data/local/tmp/",
                    },
                )

            self.assertEqual("grant_resource_changed", raised.exception.code)

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
                    expected_revision=7,
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
            self.assertFalse(compilation.device_write)
            self.assertIs(OperationRisk.READ_ONLY, compilation.plan.risk)
            self.assertEqual("preserve", compilation.plan.data_behavior)
            self.assertEqual((), compilation.plan.postconditions)
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
                    AppCommand(
                        "tools.scrcpy",
                        expected_revision=7,
                        target_serial="SERIAL",
                    ),
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
        self.assertEqual(64 * 1_024, compilation.plan.request.output_limit_bytes)
        self.assertEqual("secret-stdin", compilation.execution)
        self.assertTrue(compilation.device_write)
        self.assertIs(OperationRisk.MUTATING, compilation.plan.risk)
        self.assertEqual(
            "adb_wifi_pairing_recorded",
            compilation.plan.postconditions[0].kind,
        )
        self.assertEqual(
            "192.0.2.20:37123",
            compilation.plan.postconditions[0].expected["endpoint"],
        )
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
                self.assertIsNone(compilation.plan.target_serial)
                self.assertIs(OperationRisk.MUTATING, compilation.plan.risk)
                self.assertEqual(
                    "adb_wifi_endpoint_state",
                    compilation.plan.postconditions[0].kind,
                )
                self.assertIs(
                    action == "connect",
                    compilation.plan.postconditions[0].expected["connected"],
                )

        status = self.compile("tools.wifi.status", {})
        self.assertEqual(("ADB", "-s", "SERIAL", "get-state"), status.plan.request.argv)
        self.assertEqual(1_024, status.plan.request.output_limit_bytes)
        self.assertEqual("wifi.status", status.action)
        self.assertIs(OperationRisk.READ_ONLY, status.plan.risk)
        self.assertEqual((), status.plan.postconditions)

    def test_revision_is_required_and_stale_state_fails_before_planning(self):
        for revision, code in ((None, "revision_required"), (6, "stale_revision")):
            with self.subTest(revision=revision):
                with self.assertRaises(DeviceToolPlanningError) as raised:
                    self.service.compile(
                        AppCommand(
                            "tools.logcat",
                            expected_revision=revision,
                            target_serial="SERIAL",
                        ),
                        self.snapshot,
                    )
                self.assertEqual(code, raised.exception.code)

    def test_special_execution_results_are_always_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "scrcpy.exe" if sys.platform.startswith("win") else "scrcpy"
            executable = Path(directory) / name
            write_scrcpy_executable(executable)
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

            cancelled_token = CancellationToken()
            cancelled_token.cancel()
            cancelled = service.execute_special(
                compilation,
                "scrcpy-cancelled",
                cancelled_token,
            )
            succeeded = service.execute_special(
                compilation,
                "scrcpy-success",
                CancellationToken(),
            )

            self.assertIs(OperationStatus.CANCELLED, cancelled.status)
            self.assertIs(OperationStatus.SUCCESS, succeeded.status)
            self.assertEqual("scrcpy_launched", succeeded.code)

        pair_runner = RecordingSecretRunner(
            TransportOutcome(
                0,
                stdout="Successfully paired to 192.0.2.20:37123\n",
            )
        )
        pair_service = DeviceToolsService(secret_runner=pair_runner)
        pair = pair_service.compile(
            AppCommand(
                "tools.wifi",
                expected_revision=7,
                target_serial="SERIAL",
                payload={
                    "action": "pair",
                    "host": "192.0.2.20",
                    "port": 37123,
                    "pairingCode": "123456",
                },
            ),
            self.snapshot,
        )
        result = pair_service.execute_special(
            pair,
            "pair-success",
            CancellationToken(),
        )
        self.assertIs(OperationStatus.SUCCESS, result.status)
        self.assertEqual("wifi_pair_succeeded", result.code)

        limited = DeviceToolsService(
            secret_runner=RecordingSecretRunner(
                TransportOutcome(1, "x" * 1_024, output_limited=True)
            )
        ).execute_special(
            pair,
            "pair-output-limited",
            CancellationToken(),
        )
        self.assertIs(OperationStatus.FAILED, limited.status)
        self.assertEqual("output_limit_exceeded", limited.code)
        self.assertEqual("", limited.stdout)
        self.assertEqual("", limited.stderr)

        safety_failure = OperationResult.failed(
            "pair-guarded",
            code="postcondition_unverified",
            message="pairing evidence is unavailable",
        )
        self.assertEqual(
            safety_failure,
            pair_service.finalize_result(pair, safety_failure),
        )
        safety_cancelled = OperationResult.cancelled("pair-cancelled")
        self.assertEqual(
            safety_cancelled,
            pair_service.finalize_result(pair, safety_cancelled),
        )

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
            ({"action": "status", "host": "192.0.2.1"}, "wifi_action_invalid"),
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

    def test_default_scrcpy_launcher_terminates_one_tracked_process_tree(self):
        launcher = ManagedProcessLauncher()
        outcome = launcher.launch(
            ProcessRequest(
                (sys.executable, "-c", "import time; time.sleep(30)"),
            )
        )
        try:
            self.assertTrue(launcher.terminate(outcome.pid))
            self.assertFalse(launcher.terminate(outcome.pid))
        finally:
            launcher.shutdown()

    def test_default_pair_runner_writes_secret_to_stdin_never_argv(self):
        real_popen = subprocess.Popen
        with patch(
            "pixelflasher_core.device_tools.subprocess.Popen",
            wraps=real_popen,
        ) as popen:
            outcome = SubprocessSecretRunner().run(
                ProcessRequest(
                    (
                        sys.executable,
                        "-c",
                        "import sys; value=sys.stdin.readline(); print('Successfully paired')",
                    ),
                    timeout_seconds=5,
                    output_limit_bytes=1_024,
                ),
                "123456",
                CancellationToken(),
            )

        self.assertEqual(0, outcome.returncode)
        self.assertNotIn("123456", popen.call_args.args[0])
        self.assertIs(False, popen.call_args.kwargs["shell"])
        self.assertEqual("Successfully paired", outcome.stdout.strip())
        self.assertFalse(outcome.output_limited)

    def test_default_pair_runner_terminates_at_aggregate_output_limit(self):
        started = time.monotonic()
        outcome = SubprocessSecretRunner().run(
            ProcessRequest(
                (
                    sys.executable,
                    "-c",
                    (
                        "import sys,time; sys.stdin.readline(); "
                        "sys.stdout.buffer.write(b'x' * 2048); "
                        "sys.stdout.buffer.flush(); time.sleep(5)"
                    ),
                ),
                timeout_seconds=10,
                output_limit_bytes=1_024,
            ),
            "123456",
            CancellationToken(),
        )

        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(outcome.output_limited)
        self.assertFalse(outcome.timed_out)
        self.assertLessEqual(
            len(outcome.stdout.encode("utf-8"))
            + len(outcome.stderr.encode("utf-8")),
            1_024,
        )

    def test_default_pair_runner_maps_token_deadline_and_stops_process_tree(self):
        token = CancellationToken()
        token.set_deadline(0.03)
        started = time.monotonic()

        outcome = SubprocessSecretRunner().run(
            ProcessRequest(
                (
                    sys.executable,
                    "-c",
                    "import sys,time; sys.stdin.readline(); time.sleep(5)",
                ),
                timeout_seconds=10,
                output_limit_bytes=1_024,
            ),
            "123456",
            token,
        )

        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(outcome.timed_out)
        self.assertFalse(outcome.cancelled)


if __name__ == "__main__":
    unittest.main()
