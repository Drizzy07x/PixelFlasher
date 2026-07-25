from __future__ import annotations

import errno
import socket
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

import pytest

import pixelflasher_core.adb_terminal as terminal_module
from pixelflasher_core.adb_terminal import (
    AdbTerminalService,
    PosixTerminalBackend,
    TerminalClosedEvent,
    TerminalCommandResult,
    TerminalOutputEvent,
    WindowsConPtyBackend,
    _PosixTerminalProcess,
    _WindowsTerminalProcess,
)
from pixelflasher_core.contracts import (
    AppSnapshot,
    DeviceInfo,
    ModernPreferences,
    ToolchainInfo,
)


class FakePopen:
    def __init__(self, *, pid: int = 42, wait_results: list[object] | None = None) -> None:
        self.pid = pid
        self._wait_results = list(wait_results or [0])
        self.wait_calls: list[float | None] = []

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls.append(timeout)
        result = self._wait_results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return int(result)


class CapturedThread:
    created: list[CapturedThread] = []

    def __init__(self, *, target, name: str, daemon: bool) -> None:
        self.target = target
        self.name = name
        self.daemon = daemon
        self.started = False
        self.created.append(self)

    def start(self) -> None:
        self.started = True


class FakeSocket:
    def __init__(self, *, fail_shutdown: bool = False, fail_close: bool = False) -> None:
        self.fail_shutdown = fail_shutdown
        self.fail_close = fail_close
        self.timeouts: list[float | None] = []
        self.shutdowns: list[int] = []
        self.close_calls = 0

    def settimeout(self, timeout: float | None) -> None:
        self.timeouts.append(timeout)

    def shutdown(self, how: int) -> None:
        self.shutdowns.append(how)
        if self.fail_shutdown:
            raise OSError("shutdown failed")

    def close(self) -> None:
        self.close_calls += 1
        if self.fail_close:
            raise OSError("close failed")


class FakeWinPty:
    def __init__(
        self,
        *,
        reads: list[object] | None = None,
        alive: list[bool] | None = None,
        exitstatus: int | None = 0,
    ) -> None:
        self.exitstatus = exitstatus
        self.fileobj = FakeSocket()
        self._server = FakeSocket(fail_shutdown=True, fail_close=True)
        self._reads = list(reads or [])
        self._alive = list(alive or [False])
        self.writes: list[str] = []
        self.sizes: list[tuple[int, int]] = []
        self.closes: list[bool] = []

    def write(self, data: str) -> object:
        self.writes.append(data)
        return len(data)

    def setwinsize(self, rows: int, columns: int) -> None:
        self.sizes.append((rows, columns))

    def close(self, force: bool = False) -> None:
        self.closes.append(force)

    def isalive(self) -> bool:
        if len(self._alive) > 1:
            return self._alive.pop(0)
        return self._alive[0]

    def read(self, size: int = 1024) -> str:
        del size
        result = self._reads.pop(0)
        if isinstance(result, BaseException):
            raise result
        return str(result)

    def wait(self) -> int:
        return int(self.exitstatus or 0)


class FakeServiceProcess:
    def __init__(self) -> None:
        self.fail_write = False
        self.fail_resize = False
        self.fail_terminate = False
        self.terminated = 0

    def write(self, _data: bytes) -> None:
        if self.fail_write:
            raise OSError("write failed")

    def resize(self, *, columns: int, rows: int) -> None:
        del columns, rows
        if self.fail_resize:
            raise OSError("resize failed")

    def terminate(self) -> None:
        self.terminated += 1
        if self.fail_terminate:
            raise OSError("terminate failed")


class FakeServiceBackend:
    def __init__(self, *, exit_during_start: bool = False) -> None:
        self.process = FakeServiceProcess()
        self.exit_during_start = exit_during_start
        self.output = lambda _data: None
        self.exit = lambda _code: None

    def start(self, _argv, *, columns, rows, on_output, on_exit):
        del columns, rows
        self.output = on_output
        self.exit = on_exit
        if self.exit_during_start:
            on_exit(0)
        return self.process


def service_snapshot(
    *,
    revision: int = 1,
    devices: tuple[DeviceInfo, ...] | None = None,
    selected_serial: str | None = "SERIAL",
    ready: bool = True,
) -> AppSnapshot:
    return AppSnapshot(
        revision=revision,
        preferences=ModernPreferences(expert_mode=True),
        devices=devices
        if devices is not None
        else (DeviceInfo("SERIAL", mode="adb", online=True),),
        selected_serials=("SERIAL",) if selected_serial else (),
        selected_serial=selected_serial,
        toolchain=ToolchainInfo("ADB", "FASTBOOT", "36", ready),
    )


class TestAdbTerminalServiceBoundaries:
    def test_public_result_and_events_validate_their_invariants(self) -> None:
        with pytest.raises(ValueError, match="code and message"):
            TerminalCommandResult(False, "", "message")
        with pytest.raises(ValueError, match="session id"):
            TerminalCommandResult(True, "ok", "message")
        with pytest.raises(ValueError, match="identity"):
            TerminalOutputEvent("", 1, b"x")
        with pytest.raises(ValueError, match="bounds"):
            TerminalOutputEvent("session", 1, b"")
        with pytest.raises(ValueError, match="invalid"):
            TerminalClosedEvent("session", 0, "closed", "message")

        result = TerminalCommandResult(True, "opened", "message", "session")
        output = TerminalOutputEvent("session", 1, b"x")
        closed = TerminalClosedEvent("session", 2, "closed", "message", 7)
        assert result.to_public_dict()["sessionId"] == "session"
        assert output.to_public_dict()["encoding"] == "base64"
        assert closed.to_public_dict()["exitCode"] == 7

    @pytest.mark.parametrize(
        ("serial", "revision", "columns", "expected"),
        [
            ("", 1, 80, "target_serial_invalid"),
            ("SERIAL", True, 80, "revision_invalid"),
            ("SERIAL", 1, 1, "terminal_size_invalid"),
        ],
    )
    def test_open_rejects_invalid_request_fields_before_reading_state(
        self,
        serial: str,
        revision: int,
        columns: int,
        expected: str,
    ) -> None:
        provider = Mock(side_effect=AssertionError("state must not be read"))
        result = AdbTerminalService(provider, FakeServiceBackend()).open(
            serial=serial,
            expected_revision=revision,
            columns=columns,
            rows=24,
        )
        assert result.code == expected
        provider.assert_not_called()

    def test_open_rechecks_revision_and_device_state_after_process_start(self) -> None:
        backend = FakeServiceBackend()
        snapshots = iter(
            [
                service_snapshot(),
                service_snapshot(revision=2),
            ]
        )
        service = AdbTerminalService(lambda: next(snapshots), backend)

        result = service.open(
            serial="SERIAL",
            expected_revision=1,
            columns=80,
            rows=24,
        )

        assert result.code == "revision_conflict"
        assert backend.process.terminated == 1

    def test_open_fails_closed_for_missing_device_shutdown_and_exit_during_start(self) -> None:
        missing = AdbTerminalService(
            lambda: service_snapshot(devices=()),
            FakeServiceBackend(),
        ).open(serial="SERIAL", expected_revision=1, columns=80, rows=24)
        assert missing.code == "device_disconnected"

        shutdown_service = AdbTerminalService(
            service_snapshot,
            FakeServiceBackend(),
        )
        shutdown_service.shutdown()
        shutdown = shutdown_service.open(
            serial="SERIAL",
            expected_revision=1,
            columns=80,
            rows=24,
        )
        assert shutdown.code == "terminal_shutdown"
        with pytest.raises(RuntimeError, match="shut down"):
            shutdown_service.subscribe(lambda _event: None)
        shutdown_service.shutdown()

        raced = AdbTerminalService(
            service_snapshot,
            FakeServiceBackend(exit_during_start=True),
        ).open(serial="SERIAL", expected_revision=1, columns=80, rows=24)
        assert raced.code == "terminal_exited_during_start"

    def test_process_io_failures_close_the_session_once(self) -> None:
        backend = FakeServiceBackend()
        service = AdbTerminalService(service_snapshot, backend)
        events: list[TerminalClosedEvent | TerminalOutputEvent] = []
        unsubscribe = service.subscribe(events.append)
        opened = service.open(
            serial="SERIAL",
            expected_revision=1,
            columns=80,
            rows=24,
        )
        assert opened.session_id is not None
        backend.process.fail_write = True

        failed = service.write(
            opened.session_id,
            b"input",
            expected_revision=1,
        )
        backend.output(b"stale")
        backend.exit(1)
        unsubscribe()

        assert failed.code == "terminal_write_failed"
        assert backend.process.terminated == 1
        assert len(events) == 1
        assert isinstance(events[0], TerminalClosedEvent)

        resize_backend = FakeServiceBackend()
        resize_service = AdbTerminalService(service_snapshot, resize_backend)
        resized = resize_service.open(
            serial="SERIAL",
            expected_revision=1,
            columns=80,
            rows=24,
        )
        assert resized.session_id is not None
        resize_backend.process.fail_resize = True
        resize_failure = resize_service.resize(
            resized.session_id,
            expected_revision=1,
            columns=100,
            rows=30,
        )
        assert resize_failure.code == "terminal_resize_failed"

    def test_invalid_or_missing_sessions_and_close_revisions_are_explicit(self) -> None:
        service = AdbTerminalService(service_snapshot, FakeServiceBackend())
        invalid = service.write("", b"x", expected_revision=1)
        missing = service.write("missing", b"x", expected_revision=1)
        missing_resize = service.resize(
            "missing",
            expected_revision=1,
            columns=80,
            rows=24,
        )
        bad_close = service.close("missing", expected_revision=True)
        absent_close = service.close("missing", expected_revision=1)
        service.observe_snapshot(service_snapshot())
        service.shutdown()

        assert invalid.code == "terminal_session_invalid"
        assert missing.code == "terminal_session_missing"
        assert missing_resize.code == "terminal_session_missing"
        assert bad_close.code == "revision_invalid"
        assert absent_close.code == "terminal_session_missing"

    def test_shutdown_closes_an_active_session_and_ignores_invalid_output(self) -> None:
        backend = FakeServiceBackend()
        service = AdbTerminalService(service_snapshot, backend)
        opened = service.open(
            serial="SERIAL",
            expected_revision=1,
            columns=80,
            rows=24,
        )
        assert opened.session_id is not None
        backend.output(b"")
        backend.output("not-bytes")  # type: ignore[arg-type]

        service.shutdown()

        assert backend.process.terminated == 1

    def test_terminate_and_listener_failures_do_not_block_other_listeners(self) -> None:
        backend = FakeServiceBackend()
        service = AdbTerminalService(service_snapshot, backend)
        delivered: list[object] = []

        def broken_listener(_event: object) -> None:
            raise RuntimeError("listener failed")

        service.subscribe(broken_listener)
        service.subscribe(delivered.append)
        opened = service.open(
            serial="SERIAL",
            expected_revision=1,
            columns=80,
            rows=24,
        )
        assert opened.session_id is not None
        backend.process.fail_terminate = True

        with pytest.raises(RuntimeError, match="listener failed"):
            service.close(opened.session_id, expected_revision=1)

        assert backend.process.terminated == 1
        assert delivered == []


class TestPosixTerminalProcess:
    def test_write_handles_partial_writes_and_rejects_use_after_exit(self) -> None:
        process = FakePopen()
        terminal = _PosixTerminalProcess(process, 15)  # type: ignore[arg-type]

        with patch.object(terminal_module.os, "write", side_effect=[2, 3]) as write:
            terminal.write(b"hello")

        assert [bytes(call.args[1]) for call in write.call_args_list] == [b"hello", b"llo"]
        with patch.object(terminal_module.os, "close") as close:
            terminal.mark_exited()
            terminal.mark_exited()
        close.assert_called_once_with(15)
        with pytest.raises(OSError, match="closed"):
            terminal.write(b"x")

    def test_resize_uses_packed_rows_and_columns(self) -> None:
        process = FakePopen()
        terminal = _PosixTerminalProcess(process, 16)  # type: ignore[arg-type]
        ioctl = Mock(return_value=0)
        fake_fcntl = ModuleType("fcntl")
        fake_fcntl.ioctl = ioctl
        fake_termios = ModuleType("termios")
        fake_termios.TIOCSWINSZ = 0x5414

        with patch.dict(sys.modules, {"fcntl": fake_fcntl, "termios": fake_termios}):
            terminal.resize(columns=120, rows=35)
            descriptor, operation, packed = ioctl.call_args.args
            assert descriptor == 16
            assert operation == 0x5414
            assert len(packed) == 8
            terminal.mark_exited()
            with pytest.raises(OSError, match="closed"):
                terminal.resize(columns=80, rows=24)

    def test_terminate_escalates_after_timeout_and_always_closes_descriptor(self) -> None:
        process = FakePopen(
            wait_results=[terminal_module.subprocess.TimeoutExpired("adb", 1)]
        )
        terminal = _PosixTerminalProcess(process, 17)  # type: ignore[arg-type]
        killpg = Mock()

        with (
            patch.object(terminal_module.os, "killpg", killpg, create=True),
            patch.object(terminal_module.signal, "SIGKILL", 9, create=True),
            patch.object(terminal_module.os, "close") as close,
        ):
            terminal.terminate()
            terminal.terminate()

        assert killpg.call_count == 2
        assert killpg.call_args_list[0].args == (42, terminal_module.signal.SIGTERM)
        assert killpg.call_args_list[1].args == (42, 9)
        close.assert_called_once_with(17)

    def test_terminate_tolerates_missing_process_group_and_close_failures(self) -> None:
        process = FakePopen(wait_results=[OSError("gone")])
        terminal = _PosixTerminalProcess(process, 18)  # type: ignore[arg-type]
        killpg = Mock(side_effect=[OSError("gone"), OSError("gone")])

        with (
            patch.object(terminal_module.os, "killpg", killpg, create=True),
            patch.object(terminal_module.signal, "SIGKILL", 9, create=True),
            patch.object(terminal_module.os, "close", side_effect=OSError("closed")),
        ):
            terminal.terminate()

        assert killpg.call_count == 2


class TestPosixTerminalBackend:
    @staticmethod
    def _platform_modules(ioctl: Mock) -> dict[str, ModuleType]:
        fake_pty = ModuleType("pty")
        fake_pty.openpty = Mock(return_value=(20, 21))
        fake_fcntl = ModuleType("fcntl")
        fake_fcntl.ioctl = ioctl
        fake_termios = ModuleType("termios")
        fake_termios.TIOCSWINSZ = 0x5414
        return {"pty": fake_pty, "fcntl": fake_fcntl, "termios": fake_termios}

    def test_start_configures_pty_drains_output_and_reports_exit(self) -> None:
        CapturedThread.created.clear()
        ioctl = Mock(return_value=0)
        process = FakePopen(wait_results=[23])
        outputs: list[bytes] = []
        exits: list[int | None] = []

        with (
            patch.object(terminal_module.os, "name", "posix"),
            patch.dict(sys.modules, self._platform_modules(ioctl)),
            patch.object(terminal_module.subprocess, "Popen", return_value=process) as popen,
            patch.object(terminal_module.os, "close") as close,
            patch.object(
                terminal_module.os,
                "read",
                side_effect=[b"first", b"second", OSError(errno.EIO, "finished")],
            ),
            patch.object(terminal_module.threading, "Thread", CapturedThread),
        ):
            terminal = PosixTerminalBackend().start(
                ("adb", "-s", "SERIAL", "shell"),
                columns=100,
                rows=30,
                on_output=outputs.append,
                on_exit=exits.append,
            )
            assert isinstance(terminal, _PosixTerminalProcess)
            assert len(CapturedThread.created) == 1
            CapturedThread.created[0].target()

        assert CapturedThread.created[0].started is True
        assert outputs == [b"first", b"second"]
        assert exits == [23]
        assert close.call_args_list[0].args == (21,)
        assert close.call_args_list[-1].args == (20,)
        assert popen.call_args.kwargs["shell"] is False
        assert popen.call_args.kwargs["start_new_session"] is True

    def test_start_closes_both_descriptors_when_spawn_fails(self) -> None:
        ioctl = Mock(return_value=0)
        with (
            patch.object(terminal_module.os, "name", "posix"),
            patch.dict(sys.modules, self._platform_modules(ioctl)),
            patch.object(terminal_module.subprocess, "Popen", side_effect=OSError("spawn failed")),
            patch.object(terminal_module.os, "close") as close,
        ):
            with pytest.raises(OSError, match="spawn failed"):
                PosixTerminalBackend().start(
                    ("adb", "shell"),
                    columns=80,
                    rows=24,
                    on_output=lambda _data: None,
                    on_exit=lambda _code: None,
                )

        assert [call.args[0] for call in close.call_args_list] == [20, 21]

    @pytest.mark.parametrize(
        "read_result",
        [b"", OSError(errno.EPERM, "read failed")],
    )
    def test_reader_handles_eof_and_propagates_non_pty_errors(
        self,
        read_result: bytes | OSError,
    ) -> None:
        CapturedThread.created.clear()
        ioctl = Mock(return_value=0)
        process = FakePopen(wait_results=[0])
        exits: list[int | None] = []
        with (
            patch.object(terminal_module.os, "name", "posix"),
            patch.dict(sys.modules, self._platform_modules(ioctl)),
            patch.object(terminal_module.subprocess, "Popen", return_value=process),
            patch.object(terminal_module.os, "close"),
            patch.object(terminal_module.os, "read", side_effect=[read_result]),
            patch.object(terminal_module.threading, "Thread", CapturedThread),
        ):
            PosixTerminalBackend().start(
                ("adb", "shell"),
                columns=80,
                rows=24,
                on_output=lambda _data: pytest.fail("unexpected output"),
                on_exit=exits.append,
            )
            if isinstance(read_result, OSError):
                with pytest.raises(OSError, match="read failed"):
                    CapturedThread.created[0].target()
            else:
                CapturedThread.created[0].target()
        assert exits == [0]

    def test_start_rejects_non_posix_hosts(self) -> None:
        with patch.object(terminal_module.os, "name", "nt"):
            with pytest.raises(OSError, match="unavailable"):
                PosixTerminalBackend().start(
                    ("adb", "shell"),
                    columns=80,
                    rows=24,
                    on_output=lambda _data: None,
                    on_exit=lambda _code: None,
                )


class TestWindowsTerminalProcess:
    def test_write_resize_terminate_and_closed_state(self) -> None:
        process = FakeWinPty()
        terminal = _WindowsTerminalProcess(process)
        terminal.write(b"hello")
        terminal.resize(columns=100, rows=30)
        terminal.terminate()
        terminal.terminate()

        assert process.writes == ["hello"]
        assert process.sizes == [(30, 100)]
        assert process.closes == [True]
        with pytest.raises(OSError, match="closed"):
            terminal.write(b"x")
        with pytest.raises(OSError, match="closed"):
            terminal.resize(columns=80, rows=24)

    def test_mark_exited_drains_both_socket_ends_without_masking_errors(self) -> None:
        process = FakeWinPty()
        terminal = _WindowsTerminalProcess(process)

        terminal.mark_exited()
        terminal.mark_exited()

        assert process.fileobj.shutdowns == [socket.SHUT_RDWR]
        assert process.fileobj.close_calls == 1
        assert process._server.shutdowns == [socket.SHUT_RDWR]
        assert process._server.close_calls == 1
        assert process.closes == []


class TestWindowsConPtyBackend:
    @staticmethod
    def _winpty_modules(factory: object) -> dict[str, ModuleType]:
        winpty = ModuleType("winpty")
        winpty.PtyProcess = factory
        enums = ModuleType("winpty.enums")
        enums.Backend = SimpleNamespace(ConPTY=99)
        return {"winpty": winpty, "winpty.enums": enums}

    def test_start_drains_output_then_observes_exit(self) -> None:
        CapturedThread.created.clear()
        process = FakeWinPty(
            reads=[TimeoutError(), "hello", EOFError()],
            alive=[True, False],
            exitstatus=31,
        )

        class Factory:
            calls: list[tuple[list[str], tuple[int, int], int]] = []

            @classmethod
            def spawn(cls, argv, *, dimensions, backend):
                cls.calls.append((argv, dimensions, backend))
                return process

        outputs: list[bytes] = []
        exits: list[int | None] = []
        with (
            patch.object(terminal_module.sys, "platform", "win32"),
            patch.dict(sys.modules, self._winpty_modules(Factory)),
            patch.object(terminal_module.threading, "Thread", CapturedThread),
        ):
            terminal = WindowsConPtyBackend().start(
                ("adb", "-s", "SERIAL", "shell"),
                columns=120,
                rows=40,
                on_output=outputs.append,
                on_exit=exits.append,
            )
            assert isinstance(terminal, _WindowsTerminalProcess)
            assert len(CapturedThread.created) == 2
            CapturedThread.created[0].target()
            CapturedThread.created[1].target()

        assert Factory.calls == [
            (["adb", "-s", "SERIAL", "shell"], (40, 120), 99)
        ]
        assert process.fileobj.timeouts == [0.2]
        assert outputs == [b"hello"]
        assert exits == [31]
        assert all(thread.started for thread in CapturedThread.created)

    @pytest.mark.parametrize("read_error", [OSError("closed"), EOFError()])
    def test_reader_treats_terminal_close_as_end_of_stream(
        self,
        read_error: BaseException,
    ) -> None:
        CapturedThread.created.clear()
        process = FakeWinPty(reads=[read_error], alive=[False])

        class Factory:
            @staticmethod
            def spawn(*_args, **_kwargs):
                return process

        with (
            patch.object(terminal_module.sys, "platform", "win32"),
            patch.dict(sys.modules, self._winpty_modules(Factory)),
            patch.object(terminal_module.threading, "Thread", CapturedThread),
        ):
            WindowsConPtyBackend().start(
                ("adb", "shell"),
                columns=80,
                rows=24,
                on_output=lambda _data: pytest.fail("unexpected output"),
                on_exit=lambda _code: None,
            )
            CapturedThread.created[0].target()

    @pytest.mark.parametrize("reads", [[TimeoutError()], [""]])
    def test_reader_stops_when_process_is_dead_without_output(
        self,
        reads: list[object],
    ) -> None:
        CapturedThread.created.clear()
        process = FakeWinPty(reads=reads, alive=[False])

        class Factory:
            @staticmethod
            def spawn(*_args, **_kwargs):
                return process

        with (
            patch.object(terminal_module.sys, "platform", "win32"),
            patch.dict(sys.modules, self._winpty_modules(Factory)),
            patch.object(terminal_module.threading, "Thread", CapturedThread),
        ):
            WindowsConPtyBackend().start(
                ("adb", "shell"),
                columns=80,
                rows=24,
                on_output=lambda _data: pytest.fail("unexpected output"),
                on_exit=lambda _code: None,
            )
            CapturedThread.created[0].target()

    def test_exit_observer_waits_while_process_is_alive(self) -> None:
        CapturedThread.created.clear()
        process = FakeWinPty(reads=[EOFError()], alive=[True, False])

        class Factory:
            @staticmethod
            def spawn(*_args, **_kwargs):
                return process

        exits: list[int | None] = []
        with (
            patch.object(terminal_module.sys, "platform", "win32"),
            patch.dict(sys.modules, self._winpty_modules(Factory)),
            patch.object(terminal_module.threading, "Thread", CapturedThread),
            patch.object(terminal_module.time, "sleep") as sleep,
        ):
            WindowsConPtyBackend().start(
                ("adb", "shell"),
                columns=80,
                rows=24,
                on_output=lambda _data: None,
                on_exit=exits.append,
            )
            CapturedThread.created[0].target()
            CapturedThread.created[1].target()
        sleep.assert_called_once_with(0.05)
        assert exits == [0]

    def test_start_rejects_non_windows_hosts(self) -> None:
        with patch.object(terminal_module.sys, "platform", "linux"):
            with pytest.raises(OSError, match="unavailable"):
                WindowsConPtyBackend().start(
                    ("adb", "shell"),
                    columns=80,
                    rows=24,
                    on_output=lambda _data: None,
                    on_exit=lambda _code: None,
                )

    def test_start_reports_missing_pywinpty_as_backend_error(self) -> None:
        with (
            patch.object(terminal_module.sys, "platform", "win32"),
            patch.dict(sys.modules, {"winpty": None}),
        ):
            with pytest.raises(OSError, match="pywinpty"):
                WindowsConPtyBackend().start(
                    ("adb", "shell"),
                    columns=80,
                    rows=24,
                    on_output=lambda _data: None,
                    on_exit=lambda _code: None,
                )


def test_native_backend_matches_the_host_platform() -> None:
    with patch.object(terminal_module.sys, "platform", "win32"):
        assert isinstance(terminal_module.native_terminal_backend(), WindowsConPtyBackend)
    with patch.object(terminal_module.sys, "platform", "linux"):
        assert isinstance(terminal_module.native_terminal_backend(), PosixTerminalBackend)
