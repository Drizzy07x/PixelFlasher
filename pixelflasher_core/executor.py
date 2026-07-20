"""Typed, shell-free process execution with a deterministic fake transport."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from typing import Any, BinaryIO, Protocol, cast, runtime_checkable

from .cancellation import CancellationReason, CancellationToken
from .contracts import (
    AppCommand,
    OperationPlan,
    OperationResult,
    ProcessRequest,
    ProgressEvent,
    ProgressPhase,
    SensitiveText,
)


@dataclass(frozen=True, slots=True)
class TransportOutcome:
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    cancelled: bool = False
    timed_out: bool = False
    output_limited: bool = False


class ProcessTransport(Protocol):
    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
    ) -> TransportOutcome: ...


OutputListener = Callable[[str, str], None]


@runtime_checkable
class StreamingProcessTransport(Protocol):
    """A process boundary that reports bounded output chunks while running."""

    def run_streaming(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
        output_listener: OutputListener,
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
        outcome.output_limited,
    )


class SubprocessTransport:
    """Execute an argv tuple directly; a command string is never interpreted."""

    poll_interval_seconds = 0.05
    streaming_output_limit_bytes = 4 * 1_024 * 1_024

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
        if cancellation.cancelled:
            return self._cancellation_outcome(cancellation)
        return self._run_process(request, cancellation)

    def run_streaming(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
        output_listener: OutputListener,
    ) -> TransportOutcome:
        if request.stdin_secret_field is not None:
            raise SecretTransportError(
                "secret_transport_required",
                "secret-bearing requests require the dedicated stdin transport",
            )
        if cancellation.cancelled:
            return self._cancellation_outcome(cancellation)
        environment = None
        if request.env:
            environment = os.environ.copy()
            environment.update(dict(request.env))
        bounded_request = request
        if bounded_request.output_limit_bytes is None:
            bounded_request = replace(
                bounded_request,
                output_limit_bytes=self.streaming_output_limit_bytes,
            )
        return self._run_bounded_process(
            bounded_request,
            cancellation,
            environment=environment,
            stdin_text=None,
            output_listener=output_listener,
        )

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
            return self._cancellation_outcome(cancellation)

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
        if cancellation.cancelled:
            return self._cancellation_outcome(cancellation)
        environment = None
        if request.env:
            environment = os.environ.copy()
            environment.update(dict(request.env))

        if request.output_limit_bytes is not None:
            return self._run_bounded_process(
                request,
                cancellation,
                environment=environment,
                stdin_text=stdin_text,
            )

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
            start_new_session=os.name != "nt",
            creationflags=self._creation_flags(),
        )
        self._attach_windows_job(process)
        try:
            return self._communicate_process(
                process,
                request,
                cancellation,
                stdin_text,
            )
        finally:
            self._release_windows_job(process)

    def _communicate_process(
        self,
        process: subprocess.Popen[str],
        request: ProcessRequest,
        cancellation: CancellationToken,
        stdin_text: str | None,
    ) -> TransportOutcome:
        deadline = (
            time.monotonic() + request.timeout_seconds
            if request.timeout_seconds is not None
            else None
        )
        pending_input = stdin_text
        while True:
            if cancellation.cancelled:
                stdout, stderr = self._terminate(process, request.encoding)
                return self._cancellation_outcome(
                    cancellation,
                    process.returncode,
                    stdout,
                    stderr,
                )
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                stdout, stderr = self._terminate(process, request.encoding)
                return TransportOutcome(
                    process.returncode,
                    stdout,
                    stderr,
                    timed_out=True,
                )
            wait_seconds = self._next_poll_timeout(cancellation, deadline, now)
            if wait_seconds <= 0:
                continue
            try:
                stdout, stderr = process.communicate(
                    input=pending_input,
                    timeout=wait_seconds,
                )
                pending_input = None
            except subprocess.TimeoutExpired:
                # communicate() retains the partially written input. Supplying
                # it again would duplicate secret bytes on the pipe.
                pending_input = None
                continue
            if cancellation.cancelled:
                return self._cancellation_outcome(
                    cancellation,
                    process.returncode,
                    stdout,
                    stderr,
                )
            return TransportOutcome(process.returncode, stdout, stderr)

    def _run_bounded_process(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
        *,
        environment: dict[str, str] | None,
        stdin_text: str | None,
        output_listener: OutputListener | None = None,
    ) -> TransportOutcome:
        """Drain both pipes concurrently and terminate at the aggregate byte cap."""

        limit = request.output_limit_bytes
        assert limit is not None
        if cancellation.cancelled:
            return self._cancellation_outcome(cancellation)
        process: subprocess.Popen[bytes] = subprocess.Popen(  # noqa: S603
            list(request.argv),
            cwd=request.cwd,
            env=environment,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if stdin_text is not None else None,
            text=False,
            start_new_session=os.name != "nt",
            creationflags=self._creation_flags(),
        )
        self._attach_windows_job(process)
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        capture_lock = threading.Lock()
        output_limited = threading.Event()
        captured_bytes = 0

        def collect(stream_name: str, stream: BinaryIO, target: bytearray) -> None:
            nonlocal captured_bytes
            while True:
                with capture_lock:
                    # Read one sentinel byte past the shared remainder so the
                    # process is stopped as soon as either pipe crosses the cap.
                    chunk_size = min(64 * 1_024, max(1, limit - captured_bytes + 1))
                chunk = os.read(stream.fileno(), chunk_size)
                if not chunk:
                    return
                with capture_lock:
                    remaining = max(0, limit - captured_bytes)
                    accepted = min(len(chunk), remaining)
                    if accepted:
                        target.extend(chunk[:accepted])
                        captured_bytes += accepted
                    if accepted != len(chunk):
                        output_limited.set()
                if accepted and output_listener is not None:
                    try:
                        output_listener(
                            stream_name,
                            chunk[:accepted].decode(request.encoding, errors="replace"),
                        )
                    except Exception:
                        # Output observers must not change process semantics.
                        pass
                if accepted != len(chunk):
                    return

        readers = (
            threading.Thread(
                target=collect,
                args=("stdout", process.stdout, stdout_buffer),
                name="pixelflasher-stdout-capture",
                daemon=True,
            ),
            threading.Thread(
                target=collect,
                args=("stderr", process.stderr, stderr_buffer),
                name="pixelflasher-stderr-capture",
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()

        if stdin_text is not None and process.stdin is not None:
            try:
                process.stdin.write(
                    stdin_text.encode(request.encoding, errors="replace")
                )
                process.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                process.stdin.close()

        deadline = (
            time.monotonic() + request.timeout_seconds
            if request.timeout_seconds is not None
            else None
        )
        cancelled = False
        timed_out = False
        while process.poll() is None or any(reader.is_alive() for reader in readers):
            if output_limited.is_set():
                self._stop_process(process)
                break
            if cancellation.cancelled:
                reason = cancellation.reason
                cancelled = reason is CancellationReason.USER
                timed_out = reason is CancellationReason.DEADLINE
                self._stop_process(process)
                break
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                timed_out = True
                self._stop_process(process)
                break
            wait_seconds = self._next_poll_timeout(cancellation, deadline, now)
            if wait_seconds > 0:
                cancellation.wait(wait_seconds)

        if not cancelled and not timed_out and not output_limited.is_set() and cancellation.cancelled:
            reason = cancellation.reason
            cancelled = reason is CancellationReason.USER
            timed_out = reason is CancellationReason.DEADLINE

        for reader in readers:
            reader.join(timeout=1)
        for stream, reader in zip((process.stdout, process.stderr), readers, strict=True):
            if reader.is_alive():
                stream.close()
                reader.join(timeout=1)

        try:
            return TransportOutcome(
                process.returncode,
                stdout_buffer.decode(request.encoding, errors="replace"),
                stderr_buffer.decode(request.encoding, errors="replace"),
                cancelled=cancelled,
                timed_out=timed_out,
                output_limited=output_limited.is_set(),
            )
        finally:
            self._release_windows_job(process)

    def _next_poll_timeout(
        self,
        cancellation: CancellationToken,
        request_deadline: float | None,
        now: float,
    ) -> float:
        wait_seconds = self.poll_interval_seconds
        if request_deadline is not None:
            wait_seconds = min(wait_seconds, max(0.0, request_deadline - now))
        remaining = cancellation.remaining_seconds
        if remaining is not None:
            wait_seconds = min(wait_seconds, remaining)
        return max(0.0, wait_seconds)

    @staticmethod
    def _cancellation_outcome(
        cancellation: CancellationToken,
        returncode: int | None = None,
        stdout: str = "",
        stderr: str = "",
    ) -> TransportOutcome:
        if cancellation.reason is CancellationReason.DEADLINE:
            return TransportOutcome(
                returncode,
                stdout,
                stderr,
                timed_out=True,
            )
        return TransportOutcome(
            returncode,
            stdout,
            stderr,
            cancelled=True,
        )

    @staticmethod
    def _creation_flags() -> int:
        if os.name != "nt":
            return 0
        return int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))

    @classmethod
    def _stop_process(cls, process: subprocess.Popen[bytes]) -> None:
        cls._signal_process_tree(process, force=False)
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            cls._signal_process_tree(process, force=True)
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                # A failed OS termination boundary must not turn a bounded
                # timeout/cancellation into another unbounded wait.
                return

    @classmethod
    def _terminate(
        cls,
        process: subprocess.Popen[str],
        encoding: str,
    ) -> tuple[str, str]:
        cls._signal_process_tree(process, force=False)
        try:
            return process.communicate(timeout=1)
        except subprocess.TimeoutExpired as first_timeout:
            cls._signal_process_tree(process, force=True)
            try:
                return process.communicate(timeout=1)
            except subprocess.TimeoutExpired as final_timeout:
                cls._close_process_pipes(process)
                return (
                    cls._partial_text(
                        final_timeout.output
                        if final_timeout.output is not None
                        else first_timeout.output,
                        encoding,
                    ),
                    cls._partial_text(
                        final_timeout.stderr
                        if final_timeout.stderr is not None
                        else first_timeout.stderr,
                        encoding,
                    ),
                )

    @staticmethod
    def _signal_process_tree(
        process: subprocess.Popen[Any],
        *,
        force: bool,
    ) -> None:
        if os.name == "nt":
            if SubprocessTransport._terminate_windows_job(process):
                return
            # CREATE_NEW_PROCESS_GROUP isolates the launched command. taskkill
            # is invoked directly with an integer PID and shell=False semantics
            # so descendants cannot retain inherited output pipes.
            flags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
            try:
                subprocess.run(  # noqa: S603 - fixed system argv and owned PID
                    (
                        "taskkill.exe",
                        "/PID",
                        str(process.pid),
                        "/T",
                        "/F",
                    ),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=2,
                    shell=False,
                    creationflags=flags,
                )
            except (OSError, subprocess.SubprocessError):
                try:
                    process.kill()
                except OSError:
                    pass
            return

        tree_signal = signal.SIGKILL if force else signal.SIGTERM
        try:
            os.killpg(process.pid, tree_signal)
        except ProcessLookupError:
            return
        except OSError:
            try:
                process.kill() if force else process.terminate()
            except OSError:
                pass

    @staticmethod
    def _attach_windows_job(process: subprocess.Popen[Any]) -> None:
        """Assign a new Windows process to an owned descendant-tracking job."""

        if os.name != "nt":
            return
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.AssignProcessToJobObject.argtypes = (
                wintypes.HANDLE,
                wintypes.HANDLE,
            )
            kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.CloseHandle.restype = wintypes.BOOL
            job_handle = kernel32.CreateJobObjectW(None, None)
            if not job_handle:
                return
            raw_process_handle: object = vars(process).get("_handle")
            try:
                process_handle = int(cast(Any, raw_process_handle))
            except (TypeError, ValueError):
                kernel32.CloseHandle(job_handle)
                return
            if not kernel32.AssignProcessToJobObject(job_handle, process_handle):
                kernel32.CloseHandle(job_handle)
                return
            vars(process)["_pixelflasher_job_handle"] = int(job_handle)
        except (AttributeError, OSError, TypeError, ValueError):
            return

    @staticmethod
    def _terminate_windows_job(process: subprocess.Popen[Any]) -> bool:
        if os.name != "nt":
            return False
        raw_job_handle: object = vars(process).get("_pixelflasher_job_handle")
        if not isinstance(raw_job_handle, int) or raw_job_handle <= 0:
            return False
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
            kernel32.TerminateJobObject.restype = wintypes.BOOL
            return bool(kernel32.TerminateJobObject(raw_job_handle, 1))
        except (AttributeError, OSError, TypeError, ValueError):
            return False

    @staticmethod
    def _release_windows_job(process: subprocess.Popen[Any]) -> None:
        if os.name != "nt":
            return
        raw_job_handle: object = vars(process).get("_pixelflasher_job_handle")
        if not isinstance(raw_job_handle, int) or raw_job_handle <= 0:
            return
        vars(process)["_pixelflasher_job_handle"] = None
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.CloseHandle.restype = wintypes.BOOL
            kernel32.CloseHandle(raw_job_handle)
        except (AttributeError, OSError, TypeError, ValueError):
            return

    @staticmethod
    def _close_process_pipes(process: subprocess.Popen[Any]) -> None:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is None:
                continue
            try:
                stream.close()
            except OSError:
                continue

    @staticmethod
    def _partial_text(value: bytes | str | None, encoding: str) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        return value.decode(encoding, errors="replace")


@dataclass(slots=True)
class FakeTransportStep:
    outcome: TransportOutcome
    started_event: threading.Event | None = None
    release_event: threading.Event | None = None
    expected_secret: SensitiveText | None = None
    output_chunks: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if self.expected_secret is not None and not isinstance(
            self.expected_secret, SensitiveText
        ):
            raise TypeError("expected_secret must be SensitiveText or null")
        normalized_chunks: list[tuple[str, str]] = []
        for chunk in self.output_chunks:
            if len(chunk) == 2 and all(isinstance(value, str) for value in chunk):
                normalized_chunks.append((chunk[0], chunk[1]))
            else:
                normalized_chunks.append(("", ""))
        self.output_chunks = tuple(normalized_chunks)
        if any(
            len(chunk) != 2
            or chunk[0] not in {"stdout", "stderr"}
            or not isinstance(chunk[1], str)
            for chunk in self.output_chunks
        ):
            raise ValueError("output chunks must contain a stdout/stderr name and text")


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

    def run_streaming(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
        output_listener: OutputListener,
    ) -> TransportOutcome:
        if request.stdin_secret_field is not None:
            raise SecretTransportError(
                "secret_transport_required",
                "secret-bearing requests require the dedicated stdin transport",
            )
        step = self._take_step(request)
        chunks = step.output_chunks
        if not chunks:
            chunks = tuple(
                (stream, value)
                for stream, value in (
                    ("stdout", step.outcome.stdout),
                    ("stderr", step.outcome.stderr),
                )
                if value
            )
        for stream_name, value in chunks:
            if cancellation.cancelled:
                break
            try:
                output_listener(stream_name, value)
            except Exception:
                pass
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

_ADB_EXECUTABLES = frozenset({"adb", "adb.exe"})
_PERCENT_PATTERN = re.compile(
    r"(?:^|[\r\n])serving:\s*'[^'\r\n]{0,180}'\s*"
    r"\(\s*~\s*(100|[0-9]{1,2})\s*%\s*\)"
)


def _is_ota_sideload_request(request: ProcessRequest) -> bool:
    return (
        len(request.argv) >= 3
        and os.path.basename(request.argv[0]).casefold() in _ADB_EXECUTABLES
        and request.argv[-2].casefold() == "sideload"
    )


class _OtaSideloadProgress:
    """Parse adb sideload percentages without exposing process output."""

    def __init__(self, listener: Callable[[int], None]) -> None:
        self._listener = listener
        self._buffers = {"stdout": "", "stderr": ""}
        self._last_percent = -1

    def feed(self, stream_name: str, value: str) -> None:
        if stream_name not in self._buffers or not isinstance(value, str):
            return
        combined = (self._buffers[stream_name] + value)[-256:]
        self._buffers[stream_name] = combined
        for match in _PERCENT_PATTERN.finditer(combined):
            percent = int(match.group(1))
            if percent <= self._last_percent:
                continue
            self._last_percent = percent
            self._listener(percent)


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
        self._progress(
            command,
            ProgressPhase.STARTED,
            "operation started",
            10 if command.kind == "tools.pushFiles" else 0,
        )
        if token.cancelled:
            if token.reason is CancellationReason.DEADLINE:
                self._progress(command, ProgressPhase.FAILED, "operation timed out")
                return OperationResult.failed(
                    command.operation_id,
                    code="timed_out",
                    message="operation deadline expired before execution",
                )
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
        ota_sideload_index = next(
            (
                index
                for index, candidate in enumerate(plan.requests, start=1)
                if _is_ota_sideload_request(candidate)
            ),
            None,
        )
        for index, request in enumerate(plan.requests, start=1):
            if token.cancelled:
                if token.reason is CancellationReason.DEADLINE:
                    self._progress(command, ProgressPhase.FAILED, "operation timed out")
                    return OperationResult.failed(
                        command.operation_id,
                        code="timed_out",
                        message=f"operation deadline expired before command {index} of {total}",
                        stdout="".join(stdout_parts),
                        stderr="".join(stderr_parts),
                    )
                self._progress(command, ProgressPhase.CANCELLED, "operation cancelled")
                return OperationResult.cancelled(
                    command.operation_id,
                    message="operation cancelled",
                    stdout="".join(stdout_parts),
                    stderr="".join(stderr_parts),
                )
            progress_percent = self._request_progress_percent(
                index,
                total,
                ota_sideload_index,
            )
            progress_current: int | None = None
            progress_total: int | None = None
            progress_item: str | None = None
            if command.kind == "tools.pushFiles":
                progress_percent = 10 + int(((index - 1) / total) * 75)
                progress_current = index
                progress_total = total
                candidate = request.argv[-1].rsplit("/", 1)[-1]
                if (
                    candidate
                    and len(candidate) <= 128
                    and candidate[0].isalnum()
                    and all(character.isalnum() or character in "._-" for character in candidate)
                ):
                    progress_item = candidate
            self._progress(
                command,
                ProgressPhase.RUNNING,
                f"running command {index} of {total}",
                progress_percent,
                current=progress_current,
                total=progress_total,
                item=progress_item,
            )
            ota_progress = (
                _OtaSideloadProgress(
                    lambda raw_percent: self._progress(
                        command,
                        ProgressPhase.RUNNING,
                        f"OTA sideload transfer: {raw_percent}%",
                        10 + int(raw_percent * 80 / 100),
                    )
                )
                if index == ota_sideload_index
                else None
            )
            try:
                if request.stdin_secret_field is None:
                    if ota_progress is not None and isinstance(
                        self.transport,
                        StreamingProcessTransport,
                    ):
                        outcome = self.transport.run_streaming(
                            request,
                            token,
                            ota_progress.feed,
                        )
                    else:
                        outcome = self.transport.run(request, token)
                        if ota_progress is not None:
                            ota_progress.feed("stdout", outcome.stdout)
                            ota_progress.feed("stderr", outcome.stderr)
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
            captured_bytes = len(outcome.stdout.encode(request.encoding, errors="replace"))
            captured_bytes += len(
                outcome.stderr.encode(request.encoding, errors="replace")
            )
            if outcome.output_limited or (
                request.output_limit_bytes is not None
                and captured_bytes > request.output_limit_bytes
            ):
                self._progress(
                    command,
                    ProgressPhase.FAILED,
                    "process output exceeded its safety limit",
                )
                return OperationResult.failed(
                    command.operation_id,
                    code="output_limit_exceeded",
                    message=f"command {index} of {total} exceeded its output limit",
                    exit_code=outcome.returncode,
                    stdout="".join(stdout_parts),
                    stderr="".join(stderr_parts),
                )
            stdout_parts.append(outcome.stdout)
            stderr_parts.append(outcome.stderr)
            stdout = "".join(stdout_parts)
            stderr = "".join(stderr_parts)

            if outcome.timed_out or (
                token.cancelled and token.reason is CancellationReason.DEADLINE
            ):
                self._progress(command, ProgressPhase.FAILED, "operation timed out")
                return OperationResult.failed(
                    command.operation_id,
                    code="timed_out",
                    message=f"command {index} of {total} timed out",
                    exit_code=outcome.returncode,
                    stdout=stdout,
                    stderr=stderr,
                )
            if outcome.cancelled or token.cancelled:
                self._progress(command, ProgressPhase.CANCELLED, "operation cancelled")
                return OperationResult.cancelled(
                    command.operation_id,
                    message="operation cancelled",
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

        push_files = command.kind == "tools.pushFiles"
        self._progress(
            command,
            ProgressPhase.RUNNING if push_files else ProgressPhase.COMPLETED,
            "file transfer completed; verifying" if push_files else "operation completed",
            90 if push_files else 100,
            current=None,
            total=None,
            item=None,
        )
        return OperationResult.success(
            command.operation_id,
            code="process_succeeded",
            message=f"completed {total} command(s) successfully",
            exit_code=0,
            stdout="".join(stdout_parts),
            stderr="".join(stderr_parts),
        )

    @staticmethod
    def _request_progress_percent(
        index: int,
        total: int,
        ota_sideload_index: int | None,
    ) -> int:
        if ota_sideload_index is None:
            return int(((index - 1) / total) * 100)
        if index < ota_sideload_index:
            transition_count = max(1, ota_sideload_index - 1)
            return int(((index - 1) / transition_count) * 10)
        if index == ota_sideload_index:
            return 10
        remaining_count = max(1, total - ota_sideload_index)
        return 90 + int(((index - ota_sideload_index - 1) / remaining_count) * 9)

    def _progress(
        self,
        command: AppCommand,
        phase: ProgressPhase,
        message: str,
        percent: int | None = None,
        *,
        current: int | None = None,
        total: int | None = None,
        item: str | None = None,
    ) -> None:
        if self.progress_listener is None:
            return
        event = ProgressEvent(
            command.operation_id,
            phase,
            message,
            percent,
            kind=str(command.kind),
            current=current,
            total=total,
            item=item,
            target_serial=command.target_serial,
        )
        try:
            self.progress_listener(event)
        except Exception:
            # Observers must not change execution semantics.
            pass
