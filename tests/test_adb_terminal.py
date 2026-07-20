import base64
import unittest
from dataclasses import replace
from pathlib import Path

from pixelflasher_core.adb_terminal import (
    TERMINAL_MAXIMUM_INPUT_BYTES,
    TERMINAL_MAXIMUM_OUTPUT_CHUNK_BYTES,
    AdbTerminalService,
    TerminalClosedEvent,
    TerminalOutputEvent,
)
from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    ModernPreferences,
    ToolchainInfo,
)
from pixelflasher_core.safety import SafetyPolicy


class FakeTerminalProcess:
    def __init__(self) -> None:
        self.writes: list[bytes] = []
        self.sizes: list[tuple[int, int]] = []
        self.terminated = False

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    def resize(self, *, columns: int, rows: int) -> None:
        self.sizes.append((columns, rows))

    def terminate(self) -> None:
        self.terminated = True


class FakeTerminalBackend:
    def __init__(self, *, fail_start: bool = False) -> None:
        self.fail_start = fail_start
        self.calls: list[tuple[tuple[str, ...], int, int]] = []
        self.process = FakeTerminalProcess()
        self.on_output = lambda _data: None
        self.on_exit = lambda _exit_code: None

    def start(self, argv, *, columns, rows, on_output, on_exit):
        self.calls.append((argv, columns, rows))
        if self.fail_start:
            raise OSError("start failed")
        self.on_output = on_output
        self.on_exit = on_exit
        return self.process


def snapshot(
    *,
    revision: int = 7,
    serial: str = "SERIAL",
    mode: str = "adb",
    expert: bool = True,
    ready: bool = True,
) -> AppSnapshot:
    return AppSnapshot(
        revision=revision,
        preferences=ModernPreferences(expert_mode=expert),
        devices=(DeviceInfo(serial, mode=mode, online=mode not in {"offline", "unauthorized"}),),
        selected_serials=(serial,),
        selected_serial=serial,
        toolchain=ToolchainInfo("C:/platform-tools/adb.exe", "FASTBOOT", "36.0.0", ready),
    )


class AdbTerminalServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.current = snapshot()
        self.backend = FakeTerminalBackend()
        self.service = AdbTerminalService(lambda: self.current, self.backend)
        self.events = []
        self.service.subscribe(self.events.append)

    def open(self):
        return self.service.open(
            serial="SERIAL",
            expected_revision=7,
            columns=120,
            rows=36,
        )

    def test_open_uses_only_fixed_serial_bound_adb_argv(self):
        result = self.open()

        self.assertTrue(result.accepted)
        self.assertEqual("terminal_opened", result.code)
        self.assertEqual(
            [(('C:/platform-tools/adb.exe', '-s', 'SERIAL', 'shell'), 120, 36)],
            self.backend.calls,
        )

    def test_open_contract_is_revisioned_by_the_canonical_safety_policy(self):
        policy = SafetyPolicy()

        self.assertIn("tools.adbShell", policy.revisioned_kinds)
        decision = policy.evaluate(
            AppCommand(
                "tools.adbShell",
                target_serial="SERIAL",
                payload={"serial": "SERIAL", "columns": 80, "rows": 24},
            ),
            self.current,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual("revision_required", decision.code)

    def test_open_requires_expert_current_revision_selected_adb_and_toolchain(self):
        cases = (
            (replace(self.current, revision=8), "revision_conflict"),
            (replace(self.current, preferences=ModernPreferences(expert_mode=False)), "expert_mode_required"),
            (replace(self.current, selected_serial="OTHER"), "target_serial_changed"),
            (snapshot(mode="fastboot"), "adb_device_required"),
            (snapshot(ready=False), "toolchain_not_ready"),
        )
        for current, code in cases:
            with self.subTest(code=code):
                backend = FakeTerminalBackend()
                service = AdbTerminalService(lambda current=current: current, backend)
                result = service.open(
                    serial="SERIAL",
                    expected_revision=7,
                    columns=80,
                    rows=24,
                )
                self.assertFalse(result.accepted)
                self.assertEqual(code, result.code)
                self.assertEqual([], backend.calls)

    def test_write_resize_and_close_are_bound_to_the_same_session(self):
        opened = self.open()
        assert opened.session_id is not None

        written = self.service.write(opened.session_id, b"id\r", expected_revision=7)
        resized = self.service.resize(
            opened.session_id,
            expected_revision=7,
            columns=90,
            rows=30,
        )
        closed = self.service.close(opened.session_id, expected_revision=7)

        self.assertTrue(written.accepted)
        self.assertTrue(resized.accepted)
        self.assertTrue(closed.accepted)
        self.assertEqual([b"id\r"], self.backend.process.writes)
        self.assertEqual([(90, 30)], self.backend.process.sizes)
        self.assertTrue(self.backend.process.terminated)
        self.assertIsInstance(self.events[-1], TerminalClosedEvent)
        self.assertEqual("terminal_closed", self.events[-1].code)

    def test_binary_output_is_chunked_and_base64_projected_without_loss(self):
        opened = self.open()
        assert opened.session_id is not None
        payload = bytes(range(256)) * 300

        self.backend.on_output(payload)

        outputs = [event for event in self.events if isinstance(event, TerminalOutputEvent)]
        self.assertEqual(2, len(outputs))
        self.assertLessEqual(len(outputs[0].data), TERMINAL_MAXIMUM_OUTPUT_CHUNK_BYTES)
        self.assertEqual(payload, b"".join(event.data for event in outputs))
        self.assertEqual(
            outputs[0].data,
            base64.b64decode(str(outputs[0].to_public_dict()["data"]), validate=True),
        )
        self.assertEqual([1, 2], [event.sequence for event in outputs])

    def test_stale_revision_and_device_change_fail_closed_and_terminate(self):
        opened = self.open()
        assert opened.session_id is not None
        self.current = replace(self.current, revision=8)

        rejected = self.service.write(opened.session_id, b"pwd\r", expected_revision=7)

        self.assertFalse(rejected.accepted)
        self.assertEqual("revision_conflict", rejected.code)
        self.assertTrue(self.backend.process.terminated)
        self.assertEqual([], self.backend.process.writes)
        self.assertEqual("revision_conflict", self.events[-1].code)

    def test_explicit_close_remains_available_after_revision_changes(self):
        opened = self.open()
        assert opened.session_id is not None
        self.current = replace(self.current, revision=8)

        closed = self.service.close(opened.session_id, expected_revision=7)

        self.assertTrue(closed.accepted)
        self.assertTrue(self.backend.process.terminated)
        self.assertEqual("terminal_closed", self.events[-1].code)

    def test_snapshot_observer_closes_on_selection_mode_disconnect_or_toolchain_change(self):
        changes = (
            (replace(self.current, selected_serial="OTHER"), "target_serial_changed"),
            (snapshot(mode="fastboot"), "device_state_changed"),
            (snapshot(mode="offline"), "device_disconnected"),
            (
                replace(
                    self.current,
                    toolchain=ToolchainInfo("OTHER_ADB", "FASTBOOT", "36.0.0", True),
                ),
                "toolchain_changed",
            ),
        )
        for changed, code in changes:
            with self.subTest(code=code):
                backend = FakeTerminalBackend()
                service = AdbTerminalService(lambda: self.current, backend)
                events = []
                service.subscribe(events.append)
                opened = service.open(
                    serial="SERIAL",
                    expected_revision=7,
                    columns=80,
                    rows=24,
                )
                self.assertTrue(opened.accepted)
                service.observe_snapshot(changed)
                self.assertTrue(backend.process.terminated)
                self.assertEqual(code, events[-1].code)

    def test_input_size_dimensions_duplicate_session_and_start_failure_are_explicit(self):
        opened = self.open()
        assert opened.session_id is not None
        duplicate = self.open()
        oversized = self.service.write(
            opened.session_id,
            b"x" * (TERMINAL_MAXIMUM_INPUT_BYTES + 1),
            expected_revision=7,
        )
        bad_size = self.service.resize(
            opened.session_id,
            expected_revision=7,
            columns=1,
            rows=24,
        )

        self.assertEqual("terminal_session_active", duplicate.code)
        self.assertEqual("terminal_input_invalid", oversized.code)
        self.assertEqual("terminal_size_invalid", bad_size.code)

        failed = AdbTerminalService(lambda: self.current, FakeTerminalBackend(fail_start=True)).open(
            serial="SERIAL",
            expected_revision=7,
            columns=80,
            rows=24,
        )
        self.assertEqual("terminal_start_failed", failed.code)

    def test_process_exit_and_shutdown_are_terminal_once(self):
        opened = self.open()
        assert opened.session_id is not None
        self.backend.on_exit(17)
        self.service.shutdown()

        closed = [event for event in self.events if isinstance(event, TerminalClosedEvent)]
        self.assertEqual(1, len(closed))
        self.assertEqual("terminal_process_exited", closed[0].code)
        self.assertEqual(17, closed[0].exit_code)


class AdbTerminalDeliveryTests(unittest.TestCase):
    def test_windows_conpty_dependency_is_native_and_packaged_for_both_architectures(self):
        requirements = Path("requirements.txt").read_text(encoding="utf-8")
        self.assertIn('pywinpty==3.0.5; sys_platform == "win32"', requirements)
        backend = Path("pixelflasher_core/adb_terminal.py").read_text(encoding="utf-8")
        self.assertIn("backend=Backend.ConPTY", backend)
        for path in (Path("build-on-win.spec"), Path("build-on-win-arm64.spec")):
            with self.subTest(path=path):
                source = path.read_text(encoding="utf-8")
                self.assertIn("collect_dynamic_libs('winpty')", source)
                self.assertIn("collect_data_files('winpty', includes=['*.exe'])", source)
                self.assertIn("'winpty._winpty'", source)
                self.assertIn("console=True", source)
                self.assertIn("hide_console='hide-early'", source)


if __name__ == "__main__":
    unittest.main()
