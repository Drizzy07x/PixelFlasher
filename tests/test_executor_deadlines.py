from __future__ import annotations

import math
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import psutil

from pixelflasher_core.contracts import (
    AppCommand,
    OperationPlan,
    OperationStatus,
    ProcessRequest,
    SensitiveText,
)
from pixelflasher_core.executor import (
    CancellationReason,
    CancellationToken,
    CommandExecutor,
    SubprocessTransport,
)


def sleeping_request(*, bounded: bool, timeout_seconds: float | None = 5.0) -> ProcessRequest:
    return ProcessRequest(
        (sys.executable, "-c", "import time; time.sleep(5)"),
        timeout_seconds=timeout_seconds,
        output_limit_bytes=1_024 if bounded else None,
    )


class CancellationTokenDeadlineTests(unittest.TestCase):
    def test_deadline_is_monotonic_may_shorten_and_never_extends(self) -> None:
        token = CancellationToken()
        self.assertIsNone(token.remaining_seconds)
        self.assertIsNone(token.reason)
        self.assertFalse(token.deadline_expired)

        token.set_deadline(0.25)
        first = token.remaining_seconds
        self.assertIsNotNone(first)
        assert first is not None
        self.assertGreater(first, 0)
        self.assertLessEqual(first, 0.25)

        token.set_deadline(1.0)
        unextended = token.remaining_seconds
        self.assertIsNotNone(unextended)
        assert unextended is not None
        self.assertLessEqual(unextended, first)

        token.set_deadline(0.03)
        shortened = token.remaining_seconds
        self.assertIsNotNone(shortened)
        assert shortened is not None
        self.assertLessEqual(shortened, 0.031)
        self.assertTrue(token.wait(0.5))
        self.assertTrue(token.cancelled)
        self.assertTrue(token.deadline_expired)
        self.assertEqual(0.0, token.remaining_seconds)
        self.assertIs(CancellationReason.DEADLINE, token.reason)

    def test_manual_cancellation_remains_the_first_reason_after_deadline(self) -> None:
        token = CancellationToken()
        token.set_deadline(0.04)
        token.cancel()

        self.assertTrue(token.cancelled)
        self.assertIs(CancellationReason.USER, token.reason)
        self.assertTrue(token.wait(0))
        time.sleep(0.06)
        self.assertTrue(token.deadline_expired)
        self.assertIs(CancellationReason.USER, token.reason)

    def test_expired_deadline_cannot_be_overwritten_by_late_cancel(self) -> None:
        token = CancellationToken()
        token.set_deadline(0.02)

        self.assertTrue(token.wait(0.5))
        token.cancel()

        self.assertIs(CancellationReason.DEADLINE, token.reason)
        self.assertTrue(token.deadline_expired)

    def test_waiter_recomputes_when_another_thread_sets_a_deadline(self) -> None:
        token = CancellationToken()
        started = threading.Event()
        observed: list[bool] = []

        def wait_without_caller_timeout() -> None:
            started.set()
            observed.append(token.wait())

        waiter = threading.Thread(target=wait_without_caller_timeout)
        waiter.start()
        self.assertTrue(started.wait(1))
        token.set_deadline(0.03)
        waiter.join(timeout=1)

        self.assertFalse(waiter.is_alive())
        self.assertEqual([True], observed)
        self.assertIs(CancellationReason.DEADLINE, token.reason)

    def test_wait_timeout_does_not_cancel_the_token(self) -> None:
        token = CancellationToken()

        self.assertFalse(token.wait(0.01))
        self.assertFalse(token.cancelled)
        self.assertIsNone(token.reason)

    def test_invalid_deadline_and_wait_values_fail_closed(self) -> None:
        token = CancellationToken()
        invalid_deadlines: tuple[object, ...] = (
            True,
            0,
            -1,
            math.nan,
            math.inf,
            threading.TIMEOUT_MAX * 2,
            "1",
        )
        for value in invalid_deadlines:
            with self.subTest(deadline=value), self.assertRaises(ValueError):
                token.set_deadline(value)  # type: ignore[arg-type]

        invalid_waits: tuple[object, ...] = (
            True,
            -1,
            math.nan,
            math.inf,
            threading.TIMEOUT_MAX * 2,
            "1",
        )
        for value in invalid_waits:
            with self.subTest(wait=value), self.assertRaises(ValueError):
                token.wait(value)  # type: ignore[arg-type]

    def test_absolute_deadline_may_already_be_expired(self) -> None:
        token = CancellationToken()
        token.set_deadline_at(time.monotonic() - 0.001)

        self.assertTrue(token.cancelled)
        self.assertIs(CancellationReason.DEADLINE, token.reason)
        self.assertEqual(0.0, token.remaining_seconds)


class SubprocessDeadlineTests(unittest.TestCase):
    def test_timeout_terminates_the_isolated_descendant_tree(self) -> None:
        for bounded in (False, True):
            with self.subTest(bounded=bounded), tempfile.TemporaryDirectory() as directory:
                pid_path = os.path.join(directory, "child.pid")
                child_code = "import time; time.sleep(30)"
                parent_code = (
                    "import pathlib,subprocess,sys,time; "
                    f"child=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
                    f"pathlib.Path({pid_path!r}).write_text(str(child.pid), encoding='ascii'); "
                    "time.sleep(0.05)"
                )
                request = ProcessRequest(
                    (sys.executable, "-c", parent_code),
                    timeout_seconds=0.2,
                    output_limit_bytes=1_024 if bounded else None,
                )

                started = time.monotonic()
                outcome = SubprocessTransport().run(request, CancellationToken())
                elapsed = time.monotonic() - started

                self.assertTrue(os.path.isfile(pid_path))
                child_pid = int(open(pid_path, encoding="ascii").read())
                deadline = time.monotonic() + 2
                while psutil.pid_exists(child_pid) and time.monotonic() < deadline:
                    time.sleep(0.02)

                self.assertTrue(outcome.timed_out)
                self.assertLess(elapsed, 3)
                self.assertFalse(psutil.pid_exists(child_pid))

    def test_preexpired_deadline_never_starts_bounded_or_unbounded_process(self) -> None:
        token = CancellationToken()
        token.set_deadline(0.01)
        self.assertTrue(token.wait(0.5))

        with patch("pixelflasher_core.executor.subprocess.Popen") as popen:
            for bounded in (False, True):
                with self.subTest(bounded=bounded):
                    outcome = SubprocessTransport().run(
                        sleeping_request(bounded=bounded),
                        token,
                    )
                    self.assertTrue(outcome.timed_out)
                    self.assertFalse(outcome.cancelled)
            popen.assert_not_called()

    def test_deadline_terminates_bounded_and_unbounded_processes_as_timeout(self) -> None:
        for bounded in (False, True):
            with self.subTest(bounded=bounded):
                token = CancellationToken()
                token.set_deadline(0.05)
                started = time.monotonic()

                outcome = SubprocessTransport().run(
                    sleeping_request(bounded=bounded),
                    token,
                )

                self.assertLess(time.monotonic() - started, 3)
                self.assertTrue(outcome.timed_out)
                self.assertFalse(outcome.cancelled)
                self.assertIs(CancellationReason.DEADLINE, token.reason)

    def test_manual_cancel_terminates_bounded_and_unbounded_processes_as_cancelled(self) -> None:
        for bounded in (False, True):
            with self.subTest(bounded=bounded):
                token = CancellationToken()
                token.set_deadline(2)
                timer = threading.Timer(0.05, token.cancel)
                timer.start()
                try:
                    outcome = SubprocessTransport().run(
                        sleeping_request(bounded=bounded),
                        token,
                    )
                finally:
                    timer.cancel()
                    timer.join(timeout=1)

                self.assertTrue(outcome.cancelled)
                self.assertFalse(outcome.timed_out)
                self.assertFalse(token.deadline_expired)
                self.assertIs(CancellationReason.USER, token.reason)

    def test_request_timeout_remains_distinct_from_token_deadline(self) -> None:
        for bounded in (False, True):
            with self.subTest(bounded=bounded):
                token = CancellationToken()
                token.set_deadline(1)

                outcome = SubprocessTransport().run(
                    sleeping_request(bounded=bounded, timeout_seconds=0.04),
                    token,
                )

                self.assertTrue(outcome.timed_out)
                self.assertFalse(outcome.cancelled)
                self.assertFalse(token.cancelled)
                self.assertIsNone(token.reason)
                remaining = token.remaining_seconds
                self.assertIsNotNone(remaining)
                assert remaining is not None
                self.assertGreater(remaining, 0)

    def test_output_limit_stops_a_still_running_child_immediately(self) -> None:
        request = ProcessRequest(
            (
                sys.executable,
                "-c",
                (
                    "import sys,time; "
                    "sys.stdout.buffer.write(b'x' * 2048); "
                    "sys.stdout.buffer.flush(); time.sleep(5)"
                ),
            ),
            timeout_seconds=10,
            output_limit_bytes=1_024,
        )
        started = time.monotonic()

        outcome = SubprocessTransport().run(request, CancellationToken())

        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(outcome.output_limited)
        self.assertFalse(outcome.timed_out)
        self.assertLessEqual(
            len(outcome.stdout.encode("utf-8")) + len(outcome.stderr.encode("utf-8")),
            1_024,
        )

    def test_preexpired_secret_deadline_does_not_reveal_or_start_process(self) -> None:
        request = ProcessRequest(
            ("secret-tool",),
            stdin_secret_field="superKey",
        )
        token = CancellationToken()
        token.set_deadline(0.01)
        self.assertTrue(token.wait(0.5))

        with patch("pixelflasher_core.executor.subprocess.Popen") as popen:
            outcome = SubprocessTransport().run_secret(
                request,
                SensitiveText("correct-horse"),
                token,
            )

        self.assertTrue(outcome.timed_out)
        self.assertFalse(outcome.cancelled)
        self.assertEqual("", outcome.stdout)
        self.assertEqual("", outcome.stderr)
        popen.assert_not_called()

    def test_command_executor_reports_deadline_and_manual_cancel_differently(self) -> None:
        plan = OperationPlan(requests=(ProcessRequest(("unused",)),))
        command = AppCommand("deadline.test", operation_id="deadline-operation")
        deadline = CancellationToken()
        deadline.set_deadline(0.01)
        self.assertTrue(deadline.wait(0.5))
        manual = CancellationToken()
        manual.cancel()

        timed_out = CommandExecutor(SubprocessTransport()).execute(
            command,
            plan,
            deadline,
        )
        cancelled = CommandExecutor(SubprocessTransport()).execute(
            command,
            plan,
            manual,
        )

        self.assertIs(OperationStatus.FAILED, timed_out.status)
        self.assertEqual("timed_out", timed_out.code)
        self.assertIs(OperationStatus.CANCELLED, cancelled.status)


if __name__ == "__main__":
    unittest.main()
