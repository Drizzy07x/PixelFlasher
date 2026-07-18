"""Typed, shell-free process execution with a deterministic fake transport."""

from __future__ import annotations

import os
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Protocol

from .contracts import (
    AppCommand,
    OperationPlan,
    OperationResult,
    ProgressEvent,
    ProgressPhase,
    ProcessRequest,
)


class CancellationToken:
    """Thread-safe cooperative cancellation token."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)


@dataclass(frozen=True, slots=True)
class TransportOutcome:
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    cancelled: bool = False
    timed_out: bool = False


class ProcessTransport(Protocol):
    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
    ) -> TransportOutcome: ...


class SubprocessTransport:
    """Execute an argv tuple directly; a command string is never interpreted."""

    poll_interval_seconds = 0.05

    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
    ) -> TransportOutcome:
        environment = None
        if request.env:
            environment = os.environ.copy()
            environment.update(dict(request.env))

        process = subprocess.Popen(  # noqa: S603 - argv is an explicit typed contract
            list(request.argv),
            cwd=request.cwd,
            env=environment,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding=request.encoding,
            errors="replace",
        )
        deadline = (
            time.monotonic() + request.timeout_seconds
            if request.timeout_seconds is not None
            else None
        )
        while True:
            if cancellation.cancelled:
                stdout, stderr = self._terminate(process)
                return TransportOutcome(
                    process.returncode,
                    stdout,
                    stderr,
                    cancelled=True,
                )
            if deadline is not None and time.monotonic() >= deadline:
                stdout, stderr = self._terminate(process)
                return TransportOutcome(
                    process.returncode,
                    stdout,
                    stderr,
                    timed_out=True,
                )
            try:
                stdout, stderr = process.communicate(timeout=self.poll_interval_seconds)
            except subprocess.TimeoutExpired:
                continue
            return TransportOutcome(process.returncode, stdout, stderr)

    @staticmethod
    def _terminate(process: subprocess.Popen[str]) -> tuple[str, str]:
        process.terminate()
        try:
            return process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            return process.communicate()


@dataclass(slots=True)
class FakeTransportStep:
    outcome: TransportOutcome
    started_event: threading.Event | None = None
    release_event: threading.Event | None = None


class FakeProcessTransport:
    """Scriptable transport that records exact requests and concurrency."""

    def __init__(self, steps: list[FakeTransportStep | TransportOutcome] | None = None) -> None:
        normalized = [
            step if isinstance(step, FakeTransportStep) else FakeTransportStep(step)
            for step in (steps or [])
        ]
        self._steps: deque[FakeTransportStep] = deque(normalized)
        self._lock = threading.Lock()
        self.calls: list[ProcessRequest] = []
        self.active_count = 0
        self.max_active_count = 0

    def enqueue(self, step: FakeTransportStep | TransportOutcome) -> None:
        normalized = step if isinstance(step, FakeTransportStep) else FakeTransportStep(step)
        with self._lock:
            self._steps.append(normalized)

    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
    ) -> TransportOutcome:
        with self._lock:
            if not self._steps:
                raise RuntimeError("fake transport has no queued outcome")
            step = self._steps.popleft()
            self.calls.append(request)
            self.active_count += 1
            self.max_active_count = max(self.max_active_count, self.active_count)
        try:
            if step.started_event is not None:
                step.started_event.set()
            if step.release_event is not None:
                while not step.release_event.wait(0.01):
                    if cancellation.cancelled:
                        return TransportOutcome(None, cancelled=True)
            if cancellation.cancelled:
                return TransportOutcome(None, cancelled=True)
            return step.outcome
        finally:
            with self._lock:
                self.active_count -= 1


ProgressListener = Callable[[ProgressEvent], None]


class CommandExecutor:
    def __init__(
        self,
        transport: ProcessTransport | None = None,
        progress_listener: ProgressListener | None = None,
    ) -> None:
        self.transport = transport or SubprocessTransport()
        self.progress_listener = progress_listener

    def execute(
        self,
        command: AppCommand,
        plan: OperationPlan,
        cancellation: CancellationToken | None = None,
    ) -> OperationResult:
        token = cancellation or CancellationToken()
        self._progress(command, ProgressPhase.STARTED, "operation started", 0)
        if token.cancelled:
            self._progress(command, ProgressPhase.CANCELLED, "operation cancelled")
            return OperationResult.cancelled(
                command.operation_id,
                message="cancelled before execution",
            )
        if plan.dry_run:
            self._progress(command, ProgressPhase.COMPLETED, "dry run completed", 100)
            return OperationResult.success(
                command.operation_id,
                code="dry_run_succeeded",
                message=f"planned {len(plan.requests)} command(s) without execution",
                value={
                    "dry_run": True,
                    "planned_requests": [request.to_dict() for request in plan.requests],
                },
            )
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        total = len(plan.requests)
        for index, request in enumerate(plan.requests, start=1):
            if token.cancelled:
                self._progress(command, ProgressPhase.CANCELLED, "operation cancelled")
                return OperationResult.cancelled(
                    command.operation_id,
                    message="operation cancelled",
                    stdout="".join(stdout_parts),
                    stderr="".join(stderr_parts),
                )
            self._progress(
                command,
                ProgressPhase.RUNNING,
                f"running command {index} of {total}",
                int(((index - 1) / total) * 100),
            )
            try:
                outcome = self.transport.run(request, token)
            except Exception as error:  # transport is an injectable system boundary
                self._progress(command, ProgressPhase.FAILED, str(error))
                return OperationResult.failed(
                    command.operation_id,
                    code="executor_error",
                    message=str(error),
                    stdout="".join(stdout_parts),
                    stderr="".join(stderr_parts),
                )
            stdout_parts.append(outcome.stdout)
            stderr_parts.append(outcome.stderr)
            stdout = "".join(stdout_parts)
            stderr = "".join(stderr_parts)

            if outcome.cancelled or token.cancelled:
                self._progress(command, ProgressPhase.CANCELLED, "operation cancelled")
                return OperationResult.cancelled(
                    command.operation_id,
                    message="operation cancelled",
                    stdout=stdout,
                    stderr=stderr,
                )
            if outcome.timed_out:
                self._progress(command, ProgressPhase.FAILED, "operation timed out")
                return OperationResult.failed(
                    command.operation_id,
                    code="timed_out",
                    message=f"command {index} of {total} timed out",
                    exit_code=outcome.returncode,
                    stdout=stdout,
                    stderr=stderr,
                )
            if outcome.returncode != 0:
                self._progress(command, ProgressPhase.FAILED, "process failed")
                return OperationResult.failed(
                    command.operation_id,
                    code="process_failed",
                    message=(
                        f"command {index} of {total} exited with status "
                        f"{outcome.returncode}"
                    ),
                    exit_code=outcome.returncode,
                    stdout=stdout,
                    stderr=stderr,
                )

        self._progress(command, ProgressPhase.COMPLETED, "operation completed", 100)
        return OperationResult.success(
            command.operation_id,
            code="process_succeeded",
            message=f"completed {total} command(s) successfully",
            exit_code=0,
            stdout="".join(stdout_parts),
            stderr="".join(stderr_parts),
        )

    def _progress(
        self,
        command: AppCommand,
        phase: ProgressPhase,
        message: str,
        percent: int | None = None,
    ) -> None:
        if self.progress_listener is None:
            return
        event = ProgressEvent(command.operation_id, phase, message, percent)
        try:
            self.progress_listener(event)
        except Exception:
            # Observers must not change execution semantics.
            pass
