"""Typed, shell-free process execution with a deterministic fake transport."""

from __future__ import annotations

import os
import subprocess
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .contracts import (
    AppCommand,
    OperationPlan,
    OperationResult,
    ProcessRequest,
    ProgressEvent,
    ProgressPhase,
    SensitiveText,
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


@runtime_checkable
class SecretProcessTransport(Protocol):
    """A process boundary capable of delivering an opaque secret over stdin."""

    def run_secret(
        self,
        request: ProcessRequest,
        secret: SensitiveText,
        cancellation: CancellationToken,
    ) -> TransportOutcome: ...


class SecretTransportError(RuntimeError):
    """A fixed-message failure that cannot include secret material."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_SECRET_TRANSPORT_ERROR_CODES = frozenset(
    {
        "secret_field_unsupported",
        "secret_marker_required",
        "secret_material_invalid",
        "secret_process_error",
        "secret_transport_required",
        "secret_verification_failed",
    }
)


def _validate_secret_input(request: ProcessRequest, secret: SensitiveText) -> None:
    """Validate secret content only after it reaches a secret-aware transport."""

    if request.stdin_secret_field != "superKey":
        raise SecretTransportError(
            "secret_field_unsupported",
            "the process transport does not support this secret input field",
        )
    if not secret.meets_policy(8, 128, nul_free=True):
        raise SecretTransportError(
            "secret_material_invalid",
            "the APatch superkey must contain 8 to 128 NUL-free characters",
        )


def _redact_secret_outcome(
    outcome: TransportOutcome,
    secret: SensitiveText,
) -> TransportOutcome:
    """Prevent a child process from reflecting secret stdin into public output."""

    return TransportOutcome(
        outcome.returncode,
        secret.redact(outcome.stdout),
        secret.redact(outcome.stderr),
        outcome.cancelled,
        outcome.timed_out,
    )


class SubprocessTransport:
    """Execute an argv tuple directly; a command string is never interpreted."""

    poll_interval_seconds = 0.05

    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
    ) -> TransportOutcome:
        if request.stdin_secret_field is not None:
            raise SecretTransportError(
                "secret_transport_required",
                "secret-bearing requests require the dedicated stdin transport",
            )
        return self._run_process(request, cancellation)

    def run_secret(
        self,
        request: ProcessRequest,
        secret: SensitiveText,
        cancellation: CancellationToken,
    ) -> TransportOutcome:
        if request.stdin_secret_field is None:
            raise SecretTransportError(
                "secret_marker_required",
                "the request is not marked for secret stdin",
            )
        if cancellation.cancelled:
            return TransportOutcome(None, cancelled=True)

        _validate_secret_input(request, secret)
        # This is the only production boundary where SensitiveText is
        # revealed. It is sent through stdin, never argv, env, cwd, or logs.
        secret_value = secret.reveal()
        try:
            outcome = self._run_process(
                request,
                cancellation,
                stdin_text=secret_value,
            )
            return _redact_secret_outcome(outcome, secret)
        except SecretTransportError:
            raise
        except Exception as error:
            message = secret.redact(str(error))
            raise SecretTransportError("secret_process_error", message) from None
        finally:
            # Python strings cannot be zeroized, but dropping the last local
            # reference keeps the plaintext lifetime at this boundary short.
            secret_value = ""

    def _run_process(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
        *,
        stdin_text: str | None = None,
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
            stdin=subprocess.PIPE if stdin_text is not None else None,
            text=True,
            encoding=request.encoding,
            errors="replace",
        )
        deadline = (
            time.monotonic() + request.timeout_seconds
            if request.timeout_seconds is not None
            else None
        )
        pending_input = stdin_text
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
                stdout, stderr = process.communicate(
                    input=pending_input,
                    timeout=self.poll_interval_seconds,
                )
                pending_input = None
            except subprocess.TimeoutExpired:
                # communicate() retains the partially written input. Supplying
                # it again would duplicate secret bytes on the pipe.
                pending_input = None
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
    expected_secret: SensitiveText | None = None

    def __post_init__(self) -> None:
        if self.expected_secret is not None and not isinstance(
            self.expected_secret, SensitiveText
        ):
            raise TypeError("expected_secret must be SensitiveText or null")


class FakeProcessTransport:
    """Scriptable transport that records exact requests and concurrency."""

    def __init__(
        self,
        steps: Sequence[FakeTransportStep | TransportOutcome] | None = None,
    ) -> None:
        normalized = [
            step if isinstance(step, FakeTransportStep) else FakeTransportStep(step)
            for step in (steps or [])
        ]
        self._steps: deque[FakeTransportStep] = deque(normalized)
        self._lock = threading.Lock()
        self.calls: list[ProcessRequest] = []
        # Secret calls retain only the redacted ProcessRequest marker. The
        # plaintext and its digest are never added to call history.
        self.secret_calls: list[ProcessRequest] = []
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
        if request.stdin_secret_field is not None:
            raise SecretTransportError(
                "secret_transport_required",
                "secret-bearing requests require the dedicated stdin transport",
            )
        step = self._take_step(request)
        return self._complete_step(step, cancellation)

    def run_secret(
        self,
        request: ProcessRequest,
        secret: SensitiveText,
        cancellation: CancellationToken,
    ) -> TransportOutcome:
        if request.stdin_secret_field is None:
            raise SecretTransportError(
                "secret_marker_required",
                "the request is not marked for secret stdin",
            )
        _validate_secret_input(request, secret)
        step = self._take_step(request, secret_call=True)
        if step.expected_secret is not None and not secret.same_value(
            step.expected_secret
        ):
            with self._lock:
                self.active_count -= 1
            raise SecretTransportError(
                "secret_verification_failed",
                "fake transport received unexpected secret input",
            )
        outcome = self._complete_step(step, cancellation)
        return _redact_secret_outcome(outcome, secret)

    def _take_step(
        self,
        request: ProcessRequest,
        *,
        secret_call: bool = False,
    ) -> FakeTransportStep:
        with self._lock:
            if not self._steps:
                raise RuntimeError("fake transport has no queued outcome")
            step = self._steps.popleft()
            self.calls.append(request)
            if secret_call:
                self.secret_calls.append(request)
            self.active_count += 1
            self.max_active_count = max(self.max_active_count, self.active_count)
        return step

    def _complete_step(
        self,
        step: FakeTransportStep,
        cancellation: CancellationToken,
    ) -> TransportOutcome:
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
                if request.stdin_secret_field is None:
                    outcome = self.transport.run(request, token)
                else:
                    secret = command.payload.get(request.stdin_secret_field)
                    if not isinstance(secret, SensitiveText):
                        self._progress(
                            command,
                            ProgressPhase.FAILED,
                            "required secret material is unavailable",
                        )
                        return OperationResult.failed(
                            command.operation_id,
                            code="secret_material_missing",
                            message="required secret material is unavailable",
                            stdout="".join(stdout_parts),
                            stderr="".join(stderr_parts),
                        )
                    if not isinstance(self.transport, SecretProcessTransport):
                        self._progress(
                            command,
                            ProgressPhase.FAILED,
                            "process transport does not support secret stdin",
                        )
                        return OperationResult.failed(
                            command.operation_id,
                            code="secret_transport_unsupported",
                            message="process transport does not support secret stdin",
                            stdout="".join(stdout_parts),
                            stderr="".join(stderr_parts),
                        )
                    outcome = self.transport.run_secret(request, secret, token)
                    # Enforce redaction even for third-party typed transports.
                    outcome = _redact_secret_outcome(outcome, secret)
            except SecretTransportError as error:
                message = str(error)
                raw_secret = command.payload.get(request.stdin_secret_field or "")
                if isinstance(raw_secret, SensitiveText):
                    message = raw_secret.redact(message)
                code = (
                    error.code
                    if error.code in _SECRET_TRANSPORT_ERROR_CODES
                    else "secret_transport_error"
                )
                self._progress(command, ProgressPhase.FAILED, message)
                return OperationResult.failed(
                    command.operation_id,
                    code=code,
                    message=message,
                    stdout="".join(stdout_parts),
                    stderr="".join(stderr_parts),
                )
            except Exception as error:  # transport is an injectable system boundary
                # A secret-aware transport is responsible for sanitizing its
                # diagnostics. For defence in depth, never forward an unknown
                # exception from that path.
                message = (
                    "secret process transport failed"
                    if request.stdin_secret_field is not None
                    else str(error)
                )
                self._progress(command, ProgressPhase.FAILED, message)
                return OperationResult.failed(
                    command.operation_id,
                    code="executor_error",
                    message=message,
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
