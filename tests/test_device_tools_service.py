import hashlib
import pickle
import subprocess
import sys
import tempfile
import threading
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
    LogcatStreamOutcome,
    ManagedProcessLauncher,
    ManagedProcessTerminationError,
    SubprocessLogcatStreamRunner,
    SubprocessSecretRunner,
)
from pixelflasher_core.executor import CancellationToken, TransportOutcome
from pixelflasher_core.grants import AtomicWriteOutcomeUnknownError, GrantAccess, PathGrantStore


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


class RecordingLogcatRunner:
    def __init__(self, lines, *, outcome=None):
        self.lines = tuple(lines)
        self.outcome = outcome
        self.calls = []
        self.shutdown_called = False

    def run(self, request, cancellation, *, max_lines, line_handler):
        self.calls.append((request, cancellation, max_lines))
        safe = tuple(line_handler(line) for line in self.lines[:max_lines])
        if self.outcome is not None:
            return self.outcome
        return LogcatStreamOutcome(
            -15,
            safe,
            duration_completed=True,
            line_limit_reached=len(self.lines) >= max_lines,
        )

    def shutdown(self):
        self.shutdown_called = True


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
                "formatVerb": "threadtime",
                "filters": [
                    {"tag": "System.err", "priority": "E"},
                    {"tag": "ActivityManager", "priority": "I"},
                ],
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
        self.assertEqual(16 * 1024 * 1024, compilation.plan.request.output_limit_bytes)
        self.assertEqual("snapshot", compilation.logcat_mode)
        self.assertEqual("strict", compilation.logcat_redaction)

    def test_logcat_compiles_canonical_legacy_formats_regex_and_uid_filters(self):
        compilation = self.compile(
            "tools.logcat",
            {
                "formatVerb": "long",
                "formatModifiers": ["usec", "color", "descriptive", "uid"],
                "filters": [{"tag": "ActivityManager", "priority": "V"}],
                "regex": r"ActionProcessor.*ErrorCode::kSuccess",
                "uids": [10_001, 1_000],
                "maxLines": 400,
                "timeoutSeconds": 30,
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
                "-v",
                "long,color,descriptive,uid,usec",
                "-t",
                "400",
                "ActivityManager:V",
                "*:S",
                "-e",
                r"ActionProcessor.*ErrorCode::kSuccess",
                "--uid",
                "1000,10001",
            ),
            compilation.plan.request.argv,
        )

    def test_logcat_can_omit_device_formatting_without_an_alias(self):
        compilation = self.compile(
            "tools.logcat",
            {"formatEnabled": False, "maxLines": 10},
        )

        self.assertNotIn("-v", compilation.plan.request.argv)
        with self.assertRaises(DeviceToolPlanningError) as raised:
            self.compile(
                "tools.logcat",
                {"formatEnabled": False, "formatVerb": "long"},
            )
        self.assertEqual("logcat_format_ambiguous", raised.exception.code)

    def test_logcat_clear_compiles_a_destructive_confirmed_segmented_probe(self):
        tokens = tuple(f"{index:032x}" for index in range(1, 7))
        with patch(
            "pixelflasher_core.device_tools.secrets.token_hex",
            side_effect=tokens,
        ):
            compilation = self.compile("tools.logcat.clear", {})

        argv = tuple(request.argv for request in compilation.plan.requests)
        self.assertEqual(9, len(argv))
        self.assertEqual(
            ("ADB", "-s", "SERIAL", "logcat", "-b", "all", "-c"),
            argv[4],
        )
        for query in (argv[2], argv[7]):
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
                    "raw",
                    "PixelFlasherClear:I",
                    "*:S",
                ),
                query,
            )
            self.assertNotIn("-t", query)
            self.assertNotIn("-T", query)
        self.assertIs(OperationRisk.DESTRUCTIVE, compilation.plan.risk)
        self.assertTrue(compilation.device_write)
        self.assertTrue(compilation.destructive)
        self.assertTrue(compilation.requires_confirmation)
        self.assertEqual(
            ("logcat_buffers_cleared",),
            tuple(item.kind for item in compilation.plan.postconditions),
        )

    def test_logcat_clear_rejects_colliding_or_malformed_marker_entropy(self):
        for values in (
            ("a" * 32,) * 6,
            ("not-hex", "b" * 32, "c" * 32, "d" * 32, "e" * 32, "f" * 32),
        ):
            with self.subTest(values=values):
                with patch(
                    "pixelflasher_core.device_tools.secrets.token_hex",
                    side_effect=values,
                ):
                    with self.assertRaises(DeviceToolPlanningError) as raised:
                        self.compile("tools.logcat.clear", {})
                self.assertEqual("logcat_clear_marker_unavailable", raised.exception.code)

    def test_logcat_stream_is_incremental_shell_free_and_uses_canonical_filter_array(self):
        compilation = self.compile(
            "tools.logcat",
            {
                "mode": "stream",
                "filters": [
                    {"tag": "ActivityManager", "priority": "I"},
                    {"tag": "*", "priority": "W"},
                ],
                "maxLines": 40,
                "timeoutSeconds": 7,
                "redaction": "standard",
            },
        )

        self.assertEqual(
            (
                "ADB",
                "-s",
                "SERIAL",
                "logcat",
                "-b",
                "main",
                "-v",
                "threadtime",
                "ActivityManager:I",
                "*:W",
            ),
            compilation.plan.request.argv,
        )
        self.assertNotIn("-d", compilation.plan.request.argv)
        self.assertNotIn("-t", compilation.plan.request.argv)
        self.assertNotIn("shell", compilation.plan.request.argv)
        self.assertEqual("logcat-stream", compilation.execution)
        self.assertEqual("standard", compilation.logcat_redaction)

    def test_logcat_rejects_unknown_mode_redaction_and_arbitrary_export_path(self):
        cases = (
            ({"mode": "follow-forever"}, "logcat_mode_invalid"),
            ({"redaction": "custom-regex"}, "logcat_redaction_invalid"),
            ({"exportDestination": "C:/tmp/log.txt"}, "logcat_export_grant_required"),
        )
        for payload, code in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(DeviceToolPlanningError) as raised:
                    self.compile("tools.logcat", payload)
                self.assertEqual(code, raised.exception.code)

    def test_logcat_snapshot_redacts_bounds_and_discards_raw_process_output(self):
        compilation = self.compile(
            "tools.logcat",
            {"redaction": "strict", "maxLines": 2},
        )
        raw = (
            "I/Auth: SERIAL token=hunter2 user@example.com 192.168.1.4\n"
            "I/File: /data/user/0/example secret=value\x00\n"
            "I/Extra: ignored\n"
        )

        result = self.service.finalize_logcat(
            compilation,
            OperationResult.success("logcat-snapshot", stdout=raw),
            CancellationToken(),
        )

        self.assertTrue(result.ok)
        self.assertEqual("logcat_collected", result.code)
        self.assertEqual(2, result.value["lineCount"])
        self.assertEqual(result.value["text"], "\n".join(result.value["lines"]))
        self.assertEqual(2, result.value["redactedCount"])
        self.assertTrue(result.value["truncated"])
        rendered = result.value["text"]
        for secret in ("SERIAL", "hunter2", "user@example.com", "192.168.1.4", "/data/user"):
            self.assertNotIn(secret, rendered)
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)

    def test_logcat_snapshot_never_turns_stderr_into_success(self):
        compilation = self.compile("tools.logcat", {"maxLines": 2})

        result = self.service.finalize_logcat(
            compilation,
            OperationResult.success(
                "logcat-stderr",
                stdout="I/Ready: ok\n",
                stderr="transport warning",
            ),
            CancellationToken(),
        )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("logcat_stderr_unexpected", result.code)
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)

    def test_logcat_formatting_controls_are_sanitized_without_false_redaction(self):
        compilation = self.compile("tools.logcat", {"maxLines": 2})

        result = self.service.finalize_logcat(
            compilation,
            OperationResult.success(
                "logcat-color",
                stdout="\x1b[32mI/Ready: ok\x1b[0m\n",
            ),
            CancellationToken(),
        )

        self.assertTrue(result.ok)
        self.assertEqual(["I/Ready: ok"], result.value["lines"])
        self.assertEqual(0, result.value["redactedCount"])

    def test_logcat_none_still_removes_host_paths_required_by_public_boundary(self):
        compilation = self.compile(
            "tools.logcat",
            {"redaction": "none", "maxLines": 5},
        )
        result = self.service.finalize_logcat(
            compilation,
            OperationResult.success(
                "logcat-none",
                stdout=(
                    "I/Test: C:\\Users\\Alice Smith\\secret.txt; "
                    "/home/Alice Smith/token; WindowsPath('relative') "
                    "/data/local/tmp/device.txt\n"
                ),
            ),
            CancellationToken(),
        )

        self.assertTrue(result.ok)
        self.assertNotIn("C:\\Users", result.value["text"])
        self.assertNotIn("Alice Smith", result.value["text"])
        self.assertNotIn("/home/Alice", result.value["text"])
        self.assertNotIn("WindowsPath(", result.value["text"])
        self.assertIn("/data/local/tmp/device.txt", result.value["text"])
        self.assertEqual(1, result.value["redactedCount"])

    def test_logcat_strict_redacts_quoted_json_secrets_with_spaces(self):
        compilation = self.compile(
            "tools.logcat",
            {"redaction": "strict", "maxLines": 5},
        )
        result = self.service.finalize_logcat(
            compilation,
            OperationResult.success(
                "logcat-json-secrets",
                stdout=(
                    'I/Auth: {"access_token":"opaque-secret-123",'
                    '"password":"hello world","status":"ok"}\n'
                ),
            ),
            CancellationToken(),
        )

        self.assertTrue(result.ok)
        self.assertNotIn("opaque-secret-123", result.value["text"])
        self.assertNotIn("hello world", result.value["text"])
        self.assertIn('"access_token":"<redacted>"', result.value["text"])
        self.assertIn('"password":"<redacted>"', result.value["text"])
        self.assertIn('"status":"ok"', result.value["text"])
        self.assertEqual(1, result.value["redactedCount"])

    def test_logcat_export_writes_only_safe_text_atomically_with_hash_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "logcat.txt"
            grants = PathGrantStore()
            issued = grants.issue_file(
                destination,
                purpose="tools.logcat.export",
                access=GrantAccess.WRITE,
            )
            bound = grants.resolve_bound_write_file(
                issued.token,
                purpose="tools.logcat.export",
            )
            compilation = self.compile(
                "tools.logcat",
                {
                    "maxLines": 5,
                    "redaction": "strict",
                    "exportDestination": bound,
                },
            )

            result = self.service.finalize_logcat(
                compilation,
                OperationResult.success(
                    "logcat-export",
                    stdout="I/Auth: SERIAL password=hunter2\nI/Ready: ok\n",
                ),
                CancellationToken(),
            )

            self.assertTrue(result.ok)
            payload = result.value["text"].encode("utf-8")
            self.assertEqual(payload, destination.read_bytes())
            self.assertNotIn(b"hunter2", payload)
            self.assertEqual(destination.name, result.value["export"]["fileName"])
            self.assertEqual(len(payload), result.value["export"]["size"])
            self.assertEqual(
                hashlib.sha256(payload).hexdigest(),
                result.value["export"]["sha256"],
            )
            self.assertEqual([], list(Path(directory).glob(".pixelflasher-*")))

    def test_logcat_export_cancellation_preserves_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "logcat.txt"
            destination.write_text("original", encoding="utf-8")
            grants = PathGrantStore()
            issued = grants.issue_file(
                destination,
                purpose="tools.logcat.export",
                access=GrantAccess.WRITE,
            )
            compilation = self.compile(
                "tools.logcat",
                {
                    "exportDestination": grants.resolve_bound_write_file(
                        issued.token,
                        purpose="tools.logcat.export",
                    )
                },
            )
            token = CancellationToken()
            real_fsync = __import__("os").fsync

            def cancel_after_flush(descriptor):
                real_fsync(descriptor)
                token.cancel()

            with patch(
                "pixelflasher_core.device_tools.os.fsync",
                side_effect=cancel_after_flush,
            ):
                result = self.service.finalize_logcat(
                    compilation,
                    OperationResult.success("cancel-export", stdout="new contents\n"),
                    token,
                )

            self.assertEqual(OperationStatus.CANCELLED, result.status)
            self.assertEqual("original", destination.read_text(encoding="utf-8"))
            self.assertEqual([], list(Path(directory).glob(".pixelflasher-*")))

    def test_logcat_export_preserves_typed_outcome_unknown_from_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "logcat.txt"
            grants = PathGrantStore()
            issued = grants.issue_file(
                destination,
                purpose="tools.logcat.export",
                access=GrantAccess.WRITE,
            )
            bound = grants.resolve_bound_write_file(
                issued.token,
                purpose="tools.logcat.export",
            )
            compilation = self.compile(
                "tools.logcat",
                {"exportDestination": bound},
            )

            with patch.object(
                type(bound),
                "begin_atomic_replace",
                side_effect=AtomicWriteOutcomeUnknownError("directory durability is unknown"),
            ):
                result = self.service.finalize_logcat(
                    compilation,
                    OperationResult.success("unknown-export", stdout="I/Ready: complete\n"),
                    CancellationToken(),
                )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("outcome_unknown", result.code)
            self.assertNotIn(str(destination), result.message)

    def test_logcat_export_cancelled_during_post_commit_verification_is_outcome_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "logcat.txt"
            grants = PathGrantStore()
            issued = grants.issue_file(
                destination,
                purpose="tools.logcat.export",
                access=GrantAccess.WRITE,
            )
            compilation = self.compile(
                "tools.logcat",
                {
                    "exportDestination": grants.resolve_bound_write_file(
                        issued.token,
                        purpose="tools.logcat.export",
                    )
                },
            )
            token = CancellationToken()

            from pixelflasher_core.grants import BoundWriteTransaction

            real_open_committed = BoundWriteTransaction.open_committed

            def cancel_after_commit(transaction):
                token.cancel()
                return real_open_committed(transaction)

            with patch.object(
                BoundWriteTransaction,
                "open_committed",
                autospec=True,
                side_effect=cancel_after_commit,
            ):
                result = self.service.finalize_logcat(
                    compilation,
                    OperationResult.success("cancel-after-commit", stdout="I/Ready: complete\n"),
                    token,
                )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("outcome_unknown", result.code)
            self.assertEqual("I/Ready: complete", destination.read_text(encoding="utf-8"))
            self.assertEqual([], list(Path(directory).glob(".pixelflasher-*")))

    def test_logcat_stream_progress_contains_only_redacted_bounded_lines(self):
        raw_line = "I/Auth: SERIAL password=hunter2 " + ("x" * 5000)
        runner = RecordingLogcatRunner((raw_line, "I/Ready: ok"))
        service = DeviceToolsService(logcat_stream_runner=runner)
        compilation = service.compile(
            AppCommand(
                "tools.logcat",
                expected_revision=self.snapshot.revision,
                target_serial="SERIAL",
                payload={"mode": "stream", "maxLines": 2},
            ),
            self.snapshot,
        )
        progress = []

        result = service.execute_special(
            compilation,
            "stream-op",
            CancellationToken(),
            progress=lambda *values: progress.append(values),
        )

        self.assertTrue(result.ok)
        self.assertEqual("logcat_stream_completed", result.code)
        self.assertEqual(2, result.value["lineCount"])
        self.assertTrue(result.value["truncated"])
        self.assertEqual(2, len(progress))
        self.assertEqual((1, 2, None), progress[0][3:])
        self.assertNotIn("hunter2", progress[0][1])
        self.assertNotIn("SERIAL", progress[0][1])
        self.assertLessEqual(len(progress[0][1].encode("utf-8")), 4096)

    def test_logcat_stream_never_turns_stderr_into_success(self):
        runner = RecordingLogcatRunner(
            ("I/Ready: ok",),
            outcome=LogcatStreamOutcome(
                0,
                ("I/Ready: ok",),
                duration_completed=True,
                stderr_bytes=1,
            ),
        )
        service = DeviceToolsService(logcat_stream_runner=runner)
        compilation = service.compile(
            AppCommand(
                "tools.logcat",
                expected_revision=self.snapshot.revision,
                target_serial="SERIAL",
                payload={"mode": "stream", "maxLines": 2},
            ),
            self.snapshot,
        )

        result = service.execute_special(
            compilation,
            "stream-stderr",
            CancellationToken(),
        )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("logcat_stream_stderr_unexpected", result.code)

    def test_logcat_stream_rejects_an_injected_runner_that_bypasses_sanitizer(self):
        class UnsafeRunner:
            def run(self, request, cancellation, *, max_lines, line_handler):
                del request, cancellation, max_lines, line_handler
                return LogcatStreamOutcome(
                    0,
                    ("I/Auth: SERIAL password=hunter2\x00",),
                    duration_completed=True,
                )

            def shutdown(self):
                pass

        service = DeviceToolsService(logcat_stream_runner=UnsafeRunner())
        compilation = service.compile(
            AppCommand(
                "tools.logcat",
                expected_revision=self.snapshot.revision,
                target_serial="SERIAL",
                payload={"mode": "stream", "maxLines": 10},
            ),
            self.snapshot,
        )

        result = service.execute_special(
            compilation,
            "unsafe-stream",
            CancellationToken(),
        )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("logcat_stream_result_invalid", result.code)
        self.assertNotIn("hunter2", repr(result))

    def test_real_logcat_stream_runner_emits_before_cancellable_process_finishes(self):
        runner = SubprocessLogcatStreamRunner()
        token = CancellationToken()
        first_line = threading.Event()
        seen = []
        outcome = []

        def run_stream():
            outcome.append(
                runner.run(
                    ProcessRequest(
                        (
                            sys.executable,
                            "-u",
                            "-c",
                            "import time; print('first', flush=True); time.sleep(30)",
                        ),
                        timeout_seconds=20,
                        output_limit_bytes=1024 * 1024,
                    ),
                    token,
                    max_lines=10,
                    line_handler=lambda line: seen.append(line) or first_line.set() or line,
                )
            )

        worker = threading.Thread(target=run_stream)
        worker.start()
        self.assertTrue(first_line.wait(3), "first line was not streamed incrementally")
        self.assertTrue(worker.is_alive(), "stream waited for process completion")
        token.cancel()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(["first"], seen)
        self.assertTrue(outcome[0].cancelled)

    def test_real_logcat_stream_distinguishes_duration_from_global_deadline(self):
        request = ProcessRequest(
            (
                sys.executable,
                "-u",
                "-c",
                "import time; print('first', flush=True); time.sleep(30)",
            ),
            timeout_seconds=0.15,
            output_limit_bytes=1024 * 1024,
        )
        duration = SubprocessLogcatStreamRunner().run(
            request,
            CancellationToken(),
            max_lines=10,
            line_handler=lambda line: line,
        )
        deadline_token = CancellationToken()
        deadline_token.set_deadline(0.05)
        deadline = SubprocessLogcatStreamRunner().run(
            ProcessRequest(
                request.argv,
                timeout_seconds=5,
                output_limit_bytes=1024 * 1024,
            ),
            deadline_token,
            max_lines=10,
            line_handler=lambda line: line,
        )

        self.assertTrue(duration.duration_completed)
        self.assertFalse(duration.timed_out)
        self.assertFalse(duration.cancelled)
        self.assertTrue(deadline.timed_out)
        self.assertFalse(deadline.duration_completed)
        self.assertFalse(deadline.cancelled)

    def test_logcat_stop_failure_keeps_child_tracked_for_shutdown_retry(self):
        runner = SubprocessLogcatStreamRunner()
        token = CancellationToken()
        token.set_deadline(0.05)
        request = ProcessRequest(
            (
                sys.executable,
                "-u",
                "-c",
                "import time; time.sleep(30)",
            ),
            timeout_seconds=5,
            output_limit_bytes=1024 * 1024,
        )

        with patch.object(ManagedProcessLauncher, "_stop_child", return_value=False):
            with self.assertRaises(ManagedProcessTerminationError):
                runner.run(
                    request,
                    token,
                    max_lines=10,
                    line_handler=lambda line: line,
                )
            self.assertEqual(1, len(runner._children))
        runner.shutdown()
        self.assertEqual({}, runner._children)

    def test_logcat_rejects_filter_format_buffer_and_limit_injection(self):
        cases = (
            ({"filters": [{"tag": "Good;rm", "priority": "I"}]}, "logcat_filter_invalid"),
            ({"filters": [{"tag": "Good", "priority": "I;rm"}]}, "logcat_filter_invalid"),
            ({"formatVerb": "threadtime;rm"}, "logcat_format_invalid"),
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

    def test_scrcpy_typed_options_compile_to_exact_bounded_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "scrcpy.exe" if sys.platform.startswith("win") else "scrcpy"
            executable = Path(directory) / name
            write_scrcpy_executable(executable)
            service = DeviceToolsService(scrcpy_executable=executable)

            compilation = service.compile(
                AppCommand(
                    "tools.scrcpy",
                    expected_revision=7,
                    target_serial="SERIAL",
                    payload={
                        "serial": "SERIAL",
                        "maxSize": 1920,
                        "maxFps": 60,
                        "videoBitRateMbps": 12,
                        "fullscreen": True,
                        "alwaysOnTop": False,
                        "stayAwake": True,
                        "turnScreenOff": True,
                        "showTouches": False,
                        "noAudio": True,
                    },
                ),
                self.snapshot,
            )

            self.assertEqual(
                (
                    str(executable.resolve()),
                    "--serial",
                    "SERIAL",
                    "--max-size",
                    "1920",
                    "--max-fps",
                    "60",
                    "--video-bit-rate",
                    "12M",
                    "--fullscreen",
                    "--stay-awake",
                    "--turn-screen-off",
                    "--no-audio",
                ),
                compilation.plan.request.argv,
            )

    def test_scrcpy_options_reject_wrong_types_and_out_of_range_values(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "scrcpy.exe" if sys.platform.startswith("win") else "scrcpy"
            executable = Path(directory) / name
            write_scrcpy_executable(executable)
            service = DeviceToolsService(scrcpy_executable=executable)

            invalid_values = (
                ("maxSize", -1),
                ("maxSize", 8193),
                ("maxFps", 0),
                ("maxFps", 241),
                ("videoBitRateMbps", 0),
                ("videoBitRateMbps", 201),
                ("maxFps", True),
                ("fullscreen", 1),
                ("noAudio", "true"),
            )
            for field, value in invalid_values:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(DeviceToolPlanningError) as raised:
                        service.compile(
                            AppCommand(
                                "tools.scrcpy",
                                expected_revision=7,
                                target_serial="SERIAL",
                                payload={field: value},
                            ),
                            self.snapshot,
                        )
                    self.assertEqual("scrcpy_option_invalid", raised.exception.code)

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

        class UnstoppableSecretRunner(RecordingSecretRunner):
            def run(self, request, secret, cancellation):
                raise ManagedProcessTerminationError("still running")

        cleanup_failed = DeviceToolsService(
            secret_runner=UnstoppableSecretRunner(TransportOutcome(0))
        ).execute_special(
            pair,
            "pair-cleanup-failed",
            CancellationToken(),
        )
        self.assertIs(OperationStatus.FAILED, cleanup_failed.status)
        self.assertEqual("managed_process_termination_failed", cleanup_failed.code)

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

    def test_failed_scrcpy_termination_stays_tracked_for_shutdown_retry(self):
        process = MagicMock()
        process.pid = 4242
        process.poll.return_value = None
        process.wait.side_effect = subprocess.TimeoutExpired("scrcpy.exe", 0.1)
        with (
            patch(
                "pixelflasher_core.device_tools.subprocess.Popen",
                return_value=process,
            ),
            patch.object(
                ManagedProcessLauncher,
                "_stop_child",
                side_effect=(False, True),
            ) as stop_child,
        ):
            launcher = ManagedProcessLauncher()
            outcome = launcher.launch(
                ProcessRequest(("scrcpy.exe", "--serial", "SERIAL"))
            )

            self.assertFalse(launcher.terminate(outcome.pid))
            self.assertIn(outcome.pid, launcher._children)
            launcher.shutdown()

        self.assertEqual(2, stop_child.call_count)
        self.assertNotIn(outcome.pid, launcher._children)

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

    def test_pair_runner_tracks_child_when_forced_termination_fails(self):
        runner = SubprocessSecretRunner()
        token = CancellationToken()
        token.cancel()
        original_stop = ManagedProcessLauncher._stop_child
        attempts = 0

        def fail_once_then_stop(process):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return False
            return original_stop(process)

        with patch.object(
            ManagedProcessLauncher,
            "_stop_child",
            side_effect=fail_once_then_stop,
        ):
            with self.assertRaises(ManagedProcessTerminationError):
                runner.run(
                    ProcessRequest(
                        (
                            sys.executable,
                            "-c",
                            "import sys,time; sys.stdin.readline(); time.sleep(30)",
                        ),
                        timeout_seconds=10,
                        output_limit_bytes=1_024,
                    ),
                    "123456",
                    token,
                )
            self.assertEqual(1, len(runner._children))
            runner.shutdown()

        self.assertGreaterEqual(attempts, 2)
        self.assertEqual({}, runner._children)


if __name__ == "__main__":
    unittest.main()
