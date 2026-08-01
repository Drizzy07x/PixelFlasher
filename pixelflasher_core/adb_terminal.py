"""Revision-bound interactive ADB terminal sessions.

The browser never chooses a host command.  This service launches only the
canonical ``adb -s SERIAL shell`` argv through a platform PTY adapter and
closes the session whenever canonical device state changes.
"""

from __future__ import annotations

import base64
import errno
import importlib
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, cast
from uuid import uuid4

from .contracts import AppCommand, AppSnapshot, is_valid_target_serial
from .safety import SafetyPolicy

TERMINAL_MINIMUM_COLUMNS = 2
TERMINAL_MAXIMUM_COLUMNS = 500
TERMINAL_MINIMUM_ROWS = 1
TERMINAL_MAXIMUM_ROWS = 200
TERMINAL_MAXIMUM_INPUT_BYTES = 64 * 1024
TERMINAL_MAXIMUM_OUTPUT_CHUNK_BYTES = 64 * 1024

# Operation kinds that run entirely on the host and never claim the device
# transport.  Every other kind owns the device, so a live shell must give way.
_LOCAL_OPERATION_KINDS = frozenset(
    {
        "firmware.process",
        "support.create",
        "tools.avb",
        "tools.keybox",
        "tools.xml",
    }
)


@dataclass(frozen=True, slots=True)
class TerminalCommandResult:
    accepted: bool
    code: str
    message: str
    session_id: str | None = None

    def __post_init__(self) -> None:
        if not self.code or not self.message:
            raise ValueError("terminal command results require a code and message")
        if self.accepted != (self.session_id is not None):
            raise ValueError("accepted terminal results require one session id")

    def to_public_dict(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "code": self.code,
            "message": self.message,
            "sessionId": self.session_id,
        }


@dataclass(frozen=True, slots=True)
class TerminalOutputEvent:
    session_id: str
    sequence: int
    data: bytes

    def __post_init__(self) -> None:
        if not self.session_id or self.sequence < 1:
            raise ValueError("terminal output identity is invalid")
        if not self.data or len(self.data) > TERMINAL_MAXIMUM_OUTPUT_CHUNK_BYTES:
            raise ValueError("terminal output chunk is outside its bounds")

    def to_public_dict(self) -> dict[str, object]:
        return {
            "type": "output",
            "sessionId": self.session_id,
            "sequence": self.sequence,
            "encoding": "base64",
            "data": base64.b64encode(self.data).decode("ascii"),
        }


@dataclass(frozen=True, slots=True)
class TerminalClosedEvent:
    session_id: str
    sequence: int
    code: str
    message: str
    exit_code: int | None = None

    def __post_init__(self) -> None:
        if not self.session_id or self.sequence < 1 or not self.code or not self.message:
            raise ValueError("terminal close event is invalid")

    def to_public_dict(self) -> dict[str, object]:
        return {
            "type": "closed",
            "sessionId": self.session_id,
            "sequence": self.sequence,
            "code": self.code,
            "message": self.message,
            "exitCode": self.exit_code,
        }


TerminalEvent = TerminalOutputEvent | TerminalClosedEvent
TerminalListener = Callable[[TerminalEvent], None]


class TerminalProcess(Protocol):
    def write(self, data: bytes) -> None: ...

    def resize(self, *, columns: int, rows: int) -> None: ...

    def terminate(self) -> None: ...


class TerminalBackend(Protocol):
    def start(
        self,
        argv: tuple[str, ...],
        *,
        columns: int,
        rows: int,
        on_output: Callable[[bytes], None],
        on_exit: Callable[[int | None], None],
    ) -> TerminalProcess: ...


class _WinPtyBackendEnum(Protocol):
    ConPTY: int


class _WinPtyProcess(Protocol):
    exitstatus: int | None
    fileobj: _SocketLike
    _server: _SocketLike

    def write(self, data: str) -> object: ...

    def setwinsize(self, rows: int, columns: int) -> None: ...

    def close(self, force: bool = False) -> None: ...

    def isalive(self) -> bool: ...

    def read(self, size: int = 1024) -> str: ...

    def wait(self) -> int: ...


class _SocketLike(Protocol):
    def settimeout(self, timeout: float | None) -> None: ...

    def shutdown(self, how: int) -> None: ...

    def close(self) -> None: ...


class _WinPtyFactory(Protocol):
    def spawn(
        self,
        argv: list[str],
        *,
        dimensions: tuple[int, int],
        backend: int,
    ) -> _WinPtyProcess: ...


@dataclass(slots=True)
class _ActiveTerminal:
    session_id: str
    serial: str
    revision: int
    adb: str
    process: TerminalProcess | None = None
    sequence: int = 0


class AdbTerminalService:
    """Own at most one bounded interactive device shell session."""

    def __init__(
        self,
        snapshot_provider: Callable[[], AppSnapshot],
        backend: TerminalBackend,
        *,
        safety_policy: SafetyPolicy | None = None,
    ) -> None:
        self._snapshot_provider = snapshot_provider
        self._backend = backend
        self._safety_policy = safety_policy or SafetyPolicy()
        self._lock = threading.RLock()
        self._active: _ActiveTerminal | None = None
        self._listeners: dict[str, TerminalListener] = {}
        self._shutdown = False

    def subscribe(self, listener: TerminalListener) -> Callable[[], None]:
        listener_id = uuid4().hex
        with self._lock:
            if self._shutdown:
                raise RuntimeError("terminal service has shut down")
            self._listeners[listener_id] = listener

        def unsubscribe() -> None:
            with self._lock:
                self._listeners.pop(listener_id, None)

        return unsubscribe

    def open(
        self,
        *,
        serial: str,
        expected_revision: int,
        columns: int,
        rows: int,
    ) -> TerminalCommandResult:
        invalid = self._validate_open_request(
            serial=serial,
            expected_revision=expected_revision,
            columns=columns,
            rows=rows,
        )
        if invalid is not None:
            return invalid
        snapshot = self._snapshot_provider()
        device = next((item for item in snapshot.devices if item.serial == serial), None)
        if snapshot.revision != expected_revision:
            return self._rejected("revision_conflict", "Application state changed before opening ADB Shell.")
        safety = self._safety_policy.evaluate(
            AppCommand(
                kind="tools.adbShell",
                expected_revision=expected_revision,
                target_serial=serial,
                payload={"serial": serial, "columns": columns, "rows": rows},
            ),
            snapshot,
        )
        if not safety.allowed:
            return self._rejected(safety.code, safety.message)
        if not snapshot.preferences.expert_mode:
            return self._rejected("expert_mode_required", "ADB Shell is available only in Expert Mode.")
        if snapshot.selected_serial != serial or serial not in snapshot.selected_serials:
            return self._rejected("target_serial_changed", "The selected device changed before opening ADB Shell.")
        if device is None or not device.online:
            return self._rejected("device_disconnected", "The selected device is no longer online.")
        if device.mode != "adb":
            return self._rejected("adb_device_required", "ADB Shell requires an online ADB device.")
        if not snapshot.toolchain.ready or not snapshot.toolchain.adb:
            return self._rejected("toolchain_not_ready", "Android Platform Tools are not ready.")
        if _operation_owns_device(snapshot):
            return self._rejected("operation_active", "ADB Shell is unavailable while an operation is running.")

        if self._release_orphan_session():
            return self._rejected(
                "terminal_session_active",
                "The previous ADB Shell was released; open it again.",
            )

        with self._lock:
            if self._shutdown:
                return self._rejected("terminal_shutdown", "ADB Shell is shutting down.")
            if self._active is not None:
                return self._rejected("terminal_session_active", "Close the current ADB Shell first.")
            session = _ActiveTerminal(
                session_id=uuid4().hex,
                serial=serial,
                revision=expected_revision,
                adb=snapshot.toolchain.adb,
            )
            self._active = session

        argv = (snapshot.toolchain.adb, "-s", serial, "shell")
        try:
            process = self._backend.start(
                argv,
                columns=columns,
                rows=rows,
                on_output=lambda data: self._on_output(session.session_id, data),
                on_exit=lambda exit_code: self._on_exit(session.session_id, exit_code),
            )
        except Exception:
            self._close_session(
                session.session_id,
                code="terminal_start_failed",
                message="ADB Shell could not be started.",
                terminate=False,
            )
            return self._rejected("terminal_start_failed", "ADB Shell could not be started.")

        terminate_process = False
        with self._lock:
            if self._active is session:
                session.process = process
            else:
                terminate_process = True
        if terminate_process:
            process.terminate()
            return self._rejected("terminal_exited_during_start", "ADB Shell exited while starting.")

        current = self._snapshot_provider()
        close_code = self._session_mismatch(session, current)
        if close_code is not None:
            self._close_session(
                session.session_id,
                code=close_code,
                message="ADB Shell closed because application or device state changed.",
            )
            return self._rejected(close_code, "Application or device state changed while opening ADB Shell.")
        self._rebind_session(session, current)
        return TerminalCommandResult(
            True,
            "terminal_opened",
            "ADB Shell opened.",
            session.session_id,
        )

    def write(
        self,
        session_id: str,
        data: bytes,
        *,
        expected_revision: int,
    ) -> TerminalCommandResult:
        if (
            not isinstance(data, bytes)
            or not data
            or len(data) > TERMINAL_MAXIMUM_INPUT_BYTES
        ):
            return self._rejected("terminal_input_invalid", "Terminal input is empty or too large.")
        session, rejected = self._current_session(session_id, expected_revision)
        if rejected is not None:
            return rejected
        assert session is not None and session.process is not None
        try:
            session.process.write(data)
        except Exception:
            self._close_session(
                session.session_id,
                code="terminal_write_failed",
                message="ADB Shell closed after an input failure.",
            )
            return self._rejected("terminal_write_failed", "Terminal input could not be written.")
        return TerminalCommandResult(True, "terminal_input_written", "Terminal input written.", session.session_id)

    def resize(
        self,
        session_id: str,
        *,
        expected_revision: int,
        columns: int,
        rows: int,
    ) -> TerminalCommandResult:
        if not _valid_size(columns=columns, rows=rows):
            return self._rejected("terminal_size_invalid", "Terminal dimensions are outside their safe bounds.")
        session, rejected = self._current_session(session_id, expected_revision)
        if rejected is not None:
            return rejected
        assert session is not None and session.process is not None
        try:
            session.process.resize(columns=columns, rows=rows)
        except Exception:
            self._close_session(
                session.session_id,
                code="terminal_resize_failed",
                message="ADB Shell closed after a resize failure.",
            )
            return self._rejected("terminal_resize_failed", "Terminal dimensions could not be changed.")
        return TerminalCommandResult(True, "terminal_resized", "Terminal resized.", session.session_id)

    def close(
        self,
        session_id: str,
        *,
        expected_revision: int,
    ) -> TerminalCommandResult:
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 0
        ):
            return self._rejected("revision_invalid", "Expected revision is invalid.")
        with self._lock:
            session = self._active
        if session is None or session.session_id != session_id:
            return self._rejected("terminal_session_missing", "ADB Shell is no longer active.")
        self._close_session(
            session.session_id,
            code="terminal_closed",
            message="ADB Shell closed.",
        )
        return TerminalCommandResult(True, "terminal_closed", "ADB Shell closed.", session.session_id)

    def observe_snapshot(self, snapshot: AppSnapshot) -> None:
        with self._lock:
            session = self._active
        if session is None:
            return
        code = self._session_mismatch(session, snapshot)
        if code is not None:
            self._close_session(
                session.session_id,
                code=code,
                message="ADB Shell closed because application or device state changed.",
            )
            return
        self._rebind_session(session, snapshot)

    def shutdown(self) -> None:
        with self._lock:
            if self._shutdown:
                return
            self._shutdown = True
            session = self._active
        if session is not None:
            self._close_session(
                session.session_id,
                code="terminal_shutdown",
                message="ADB Shell closed during application shutdown.",
            )
        with self._lock:
            self._listeners.clear()

    def _current_session(
        self,
        session_id: str,
        expected_revision: int,
    ) -> tuple[_ActiveTerminal | None, TerminalCommandResult | None]:
        if not isinstance(session_id, str) or not session_id:
            return None, self._rejected("terminal_session_invalid", "Terminal session ID is invalid.")
        with self._lock:
            session = self._active
        if session is None or session.session_id != session_id or session.process is None:
            return None, self._rejected("terminal_session_missing", "ADB Shell is no longer active.")
        snapshot = self._snapshot_provider()
        mismatch = self._session_mismatch(session, snapshot)
        if expected_revision != snapshot.revision or mismatch is not None:
            self._close_session(
                session.session_id,
                code=mismatch or "revision_conflict",
                message="ADB Shell closed because application or device state changed.",
            )
            return None, self._rejected(
                mismatch or "revision_conflict",
                "ADB Shell is no longer bound to the current application state.",
            )
        self._rebind_session(session, snapshot)
        return session, None

    @staticmethod
    def _validate_open_request(
        *,
        serial: object,
        expected_revision: object,
        columns: object,
        rows: object,
    ) -> TerminalCommandResult | None:
        if not isinstance(serial, str) or not is_valid_target_serial(serial):
            return AdbTerminalService._rejected("target_serial_invalid", "Target serial is invalid.")
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 0
        ):
            return AdbTerminalService._rejected("revision_invalid", "Expected revision is invalid.")
        if not _valid_size(columns=columns, rows=rows):
            return AdbTerminalService._rejected(
                "terminal_size_invalid",
                "Terminal dimensions are outside their safe bounds.",
            )
        return None

    def _session_mismatch(self, session: _ActiveTerminal, snapshot: AppSnapshot) -> str | None:
        """Re-validate every condition that authorised the session, not its revision.

        A bare revision bump is not a mismatch: the shell stays valid as long as
        Expert Mode, the safety policy, the target device and the toolchain that
        opened it are still the canonical ones and no operation owns the device.
        """

        if not snapshot.preferences.expert_mode:
            return "expert_mode_required"
        if snapshot.selected_serial != session.serial or session.serial not in snapshot.selected_serials:
            return "target_serial_changed"
        if snapshot.toolchain.adb != session.adb or not snapshot.toolchain.ready:
            return "toolchain_changed"
        device = next((item for item in snapshot.devices if item.serial == session.serial), None)
        if device is None or not device.online:
            return "device_disconnected"
        if device.mode != "adb":
            return "device_state_changed"
        if _operation_owns_device(snapshot):
            return "operation_active"
        safety = self._safety_policy.evaluate(
            AppCommand(
                kind="tools.adbShell",
                expected_revision=snapshot.revision,
                target_serial=session.serial,
                payload={"serial": session.serial},
            ),
            snapshot,
        )
        if not safety.allowed:
            return safety.code
        return None

    def _release_orphan_session(self) -> bool:
        """Free a session whose client is gone before refusing a fresh request.

        A reloaded or crashed web view never sends ``tools.adbShell.close``, so
        without this the PTY would keep running ownerless and every later open
        would dead-end.  The request that finds it is still refused, so a client
        that does own the session is never replaced behind its back; the caller
        retries and binds a new shell.  Called only once every other precondition
        for the new session has been validated.
        """

        with self._lock:
            session = None if self._shutdown else self._active
        if session is None:
            return False
        self._close_session(
            session.session_id,
            code="terminal_superseded",
            message="ADB Shell released for a new session.",
        )
        return True

    def _rebind_session(self, session: _ActiveTerminal, snapshot: AppSnapshot) -> None:
        with self._lock:
            if self._active is session:
                session.revision = snapshot.revision

    def _on_output(self, session_id: str, data: bytes) -> None:
        if not isinstance(data, bytes) or not data:
            return
        for start in range(0, len(data), TERMINAL_MAXIMUM_OUTPUT_CHUNK_BYTES):
            chunk = data[start : start + TERMINAL_MAXIMUM_OUTPUT_CHUNK_BYTES]
            with self._lock:
                session = self._active
                if session is None or session.session_id != session_id:
                    return
                session.sequence += 1
                event = TerminalOutputEvent(session_id, session.sequence, chunk)
                listeners = tuple(self._listeners.values())
            for listener in listeners:
                listener(event)

    def _on_exit(self, session_id: str, exit_code: int | None) -> None:
        self._close_session(
            session_id,
            code="terminal_process_exited",
            message="ADB Shell process exited.",
            exit_code=exit_code,
            terminate=False,
        )

    def _close_session(
        self,
        session_id: str,
        *,
        code: str,
        message: str,
        exit_code: int | None = None,
        terminate: bool = True,
    ) -> None:
        with self._lock:
            session = self._active
            if session is None or session.session_id != session_id:
                return
            self._active = None
            session.sequence += 1
            event = TerminalClosedEvent(
                session.session_id,
                session.sequence,
                code,
                message,
                exit_code,
            )
            listeners = tuple(self._listeners.values())
            process = session.process
        if terminate and process is not None:
            try:
                process.terminate()
            except Exception:
                pass
        for listener in listeners:
            listener(event)

    @staticmethod
    def _rejected(code: str, message: str) -> TerminalCommandResult:
        return TerminalCommandResult(False, code, message)


def _operation_owns_device(snapshot: AppSnapshot) -> bool:
    operation = snapshot.active_operation
    return operation is not None and operation.kind not in _LOCAL_OPERATION_KINDS


def _valid_size(*, columns: object, rows: object) -> bool:
    return bool(
        isinstance(columns, int)
        and not isinstance(columns, bool)
        and TERMINAL_MINIMUM_COLUMNS <= columns <= TERMINAL_MAXIMUM_COLUMNS
        and isinstance(rows, int)
        and not isinstance(rows, bool)
        and TERMINAL_MINIMUM_ROWS <= rows <= TERMINAL_MAXIMUM_ROWS
    )


class _PosixTerminalProcess:
    def __init__(self, process: subprocess.Popen[bytes], master_fd: int) -> None:
        self._process = process
        self._master_fd = master_fd
        self._lock = threading.RLock()
        self._closed = False

    def write(self, data: bytes) -> None:
        with self._lock:
            if self._closed:
                raise OSError("terminal process is closed")
            descriptor = self._master_fd
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]

    def resize(self, *, columns: int, rows: int) -> None:
        import fcntl
        import struct
        import termios

        with self._lock:
            if self._closed:
                raise OSError("terminal process is closed")
            ioctl = cast(Callable[[int, int, bytes], int], vars(fcntl)["ioctl"])
            tiocswinsz = cast(int, vars(termios)["TIOCSWINSZ"])
            ioctl(self._master_fd, tiocswinsz, struct.pack("HHHH", rows, columns, 0, 0))

    def terminate(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            descriptor = self._master_fd
        kill_process_group = cast(Callable[[int, int], None], vars(os)["killpg"])
        sigkill = cast(int, vars(signal)["SIGKILL"])
        try:
            kill_process_group(self._process.pid, signal.SIGTERM)
            self._process.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired):
            try:
                kill_process_group(self._process.pid, sigkill)
            except OSError:
                pass
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def mark_exited(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            descriptor = self._master_fd
        try:
            os.close(descriptor)
        except OSError:
            pass


class PosixTerminalBackend:
    def start(
        self,
        argv: tuple[str, ...],
        *,
        columns: int,
        rows: int,
        on_output: Callable[[bytes], None],
        on_exit: Callable[[int | None], None],
    ) -> TerminalProcess:
        if os.name != "posix":
            raise OSError("POSIX PTY backend is unavailable")
        import fcntl
        import pty
        import struct
        import termios

        master_fd, slave_fd = pty.openpty()
        try:
            ioctl = cast(Callable[[int, int, bytes], int], vars(fcntl)["ioctl"])
            tiocswinsz = cast(int, vars(termios)["TIOCSWINSZ"])
            ioctl(slave_fd, tiocswinsz, struct.pack("HHHH", rows, columns, 0, 0))
            process = subprocess.Popen(  # noqa: S603 - fixed typed argv from backend service
                argv,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                shell=False,
                close_fds=True,
                start_new_session=True,
            )
        except Exception:
            os.close(master_fd)
            raise
        finally:
            os.close(slave_fd)
        terminal = _PosixTerminalProcess(process, master_fd)

        def read_output() -> None:
            try:
                while True:
                    try:
                        chunk = os.read(master_fd, 4096)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise
                    if not chunk:
                        break
                    on_output(chunk)
            finally:
                exit_code = process.wait()
                terminal.mark_exited()
                on_exit(exit_code)

        threading.Thread(target=read_output, name="PixelFlasherAdbPty", daemon=True).start()
        return terminal


class _WindowsTerminalProcess:
    def __init__(self, process: _WinPtyProcess) -> None:
        self._process = process
        self._lock = threading.RLock()
        self._closed = False

    def write(self, data: bytes) -> None:
        text = data.decode("utf-8", errors="surrogateescape")
        with self._lock:
            if self._closed:
                raise OSError("terminal process is closed")
            self._process.write(text)

    def resize(self, *, columns: int, rows: int) -> None:
        with self._lock:
            if self._closed:
                raise OSError("terminal process is closed")
            self._process.setwinsize(rows, columns)

    def terminate(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            process = self._process
        process.close(force=True)

    def mark_exited(self) -> None:
        """Close reader sockets after a natural exit without killing anything."""

        with self._lock:
            if self._closed:
                return
            self._closed = True
            process = self._process
        for stream in (process.fileobj, process._server):
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                stream.close()
            except OSError:
                pass


class WindowsConPtyBackend:
    def start(
        self,
        argv: tuple[str, ...],
        *,
        columns: int,
        rows: int,
        on_output: Callable[[bytes], None],
        on_exit: Callable[[int | None], None],
    ) -> TerminalProcess:
        if not sys.platform.startswith("win"):
            raise OSError("Windows ConPTY backend is unavailable")
        try:
            winpty = importlib.import_module("winpty")
            winpty_enums = importlib.import_module("winpty.enums")
        except ImportError as error:
            raise OSError("pywinpty is required for Windows ConPTY") from error
        factory = cast(_WinPtyFactory, winpty.PtyProcess)
        backend = cast(_WinPtyBackendEnum, winpty_enums.Backend)
        process = factory.spawn(
            list(argv),
            dimensions=(rows, columns),
            backend=backend.ConPTY,
        )
        process.fileobj.settimeout(0.2)
        terminal = _WindowsTerminalProcess(process)

        output_drained = threading.Event()

        def read_output() -> None:
            try:
                while True:
                    try:
                        text = process.read(4096)
                    except EOFError:
                        break
                    except TimeoutError:
                        if process.isalive():
                            continue
                        break
                    except OSError:
                        break
                    if text:
                        on_output(text.encode("utf-8", errors="surrogateescape"))
                    elif not process.isalive():
                        break
            finally:
                output_drained.set()

        def observe_exit() -> None:
            while process.isalive():
                time.sleep(0.05)
            output_drained.wait(0.5)
            exit_code = process.exitstatus
            terminal.mark_exited()
            on_exit(exit_code)

        threading.Thread(target=read_output, name="PixelFlasherAdbConPty", daemon=True).start()
        threading.Thread(target=observe_exit, name="PixelFlasherAdbConPtyExit", daemon=True).start()
        return terminal


def native_terminal_backend() -> TerminalBackend:
    if sys.platform.startswith("win"):
        return WindowsConPtyBackend()
    return PosixTerminalBackend()


__all__ = [
    "AdbTerminalService",
    "PosixTerminalBackend",
    "TerminalBackend",
    "TerminalClosedEvent",
    "TerminalCommandResult",
    "TerminalEvent",
    "TerminalListener",
    "TerminalOutputEvent",
    "TerminalProcess",
    "WindowsConPtyBackend",
    "native_terminal_backend",
]
