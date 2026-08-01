import unittest
from dataclasses import replace

from pixelflasher_core.adb_terminal import AdbTerminalService, TerminalClosedEvent
from pixelflasher_core.contracts import (
    ActiveOperation,
    AppSnapshot,
    DeviceInfo,
    ModernPreferences,
    ToolchainInfo,
)


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
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], int, int]] = []
        self.process = FakeTerminalProcess()

    def start(self, argv, *, columns, rows, on_output, on_exit):
        self.calls.append((argv, columns, rows))
        return self.process


def snapshot(*, revision: int = 7, serial: str = "SERIAL", mode: str = "adb", expert: bool = True) -> AppSnapshot:
    return AppSnapshot(
        revision=revision,
        preferences=ModernPreferences(expert_mode=expert),
        devices=(DeviceInfo(serial, mode=mode, online=mode not in {"offline", "unauthorized"}),),
        selected_serials=(serial,),
        selected_serial=serial,
        toolchain=ToolchainInfo("C:/platform-tools/adb.exe", "FASTBOOT", "36.0.0", True),
    )


class AdbTerminalRevisionRebindTests(unittest.TestCase):
    """BUG-23 / BUG-24: a live shell must survive revision bumps that do not invalidate it."""

    def setUp(self) -> None:
        self.current = snapshot()
        self.backend = FakeTerminalBackend()
        self.service = AdbTerminalService(lambda: self.current, self.backend)
        self.events = []
        self.service.subscribe(self.events.append)
        self.opened = self.service.open(
            serial="SERIAL",
            expected_revision=7,
            columns=120,
            rows=36,
        )
        assert self.opened.session_id is not None

    def closed_events(self):
        return [event for event in self.events if isinstance(event, TerminalClosedEvent)]

    def test_unrelated_revision_bump_keeps_the_session_open_and_input_flowing(self):
        self.current = replace(self.current, revision=8)

        self.service.observe_snapshot(self.current)
        written = self.service.write(self.opened.session_id, b"id\r", expected_revision=8)
        resized = self.service.resize(self.opened.session_id, expected_revision=8, columns=90, rows=30)

        self.assertEqual([], self.closed_events())
        self.assertFalse(self.backend.process.terminated)
        self.assertTrue(written.accepted)
        self.assertTrue(resized.accepted)
        self.assertEqual([b"id\r"], self.backend.process.writes)

    def test_input_is_accepted_at_the_current_revision_without_an_observation(self):
        self.current = replace(self.current, revision=9)

        written = self.service.write(self.opened.session_id, b"pwd\r", expected_revision=9)

        self.assertTrue(written.accepted)
        self.assertEqual([b"pwd\r"], self.backend.process.writes)
        self.assertEqual([], self.closed_events())

    def test_repeated_revision_bumps_never_exhaust_the_session(self):
        for revision in range(8, 20):
            self.current = replace(self.current, revision=revision)
            self.service.observe_snapshot(self.current)
            written = self.service.write(self.opened.session_id, b"\r", expected_revision=revision)
            self.assertTrue(written.accepted, msg=f"rejected at revision {revision}: {written.code}")

        self.assertEqual([], self.closed_events())
        self.assertEqual(12, len(self.backend.process.writes))

    def test_stale_expected_revision_still_fails_closed(self):
        self.current = replace(self.current, revision=8)

        rejected = self.service.write(self.opened.session_id, b"pwd\r", expected_revision=7)

        self.assertFalse(rejected.accepted)
        self.assertEqual("revision_conflict", rejected.code)
        self.assertEqual([], self.backend.process.writes)
        self.assertTrue(self.backend.process.terminated)
        self.assertEqual("revision_conflict", self.events[-1].code)

    def test_observer_closes_the_session_when_expert_mode_is_revoked(self):
        revoked = replace(
            self.current,
            revision=8,
            preferences=ModernPreferences(expert_mode=False),
        )

        self.service.observe_snapshot(revoked)

        self.assertTrue(self.backend.process.terminated)
        self.assertEqual("expert_mode_required", self.events[-1].code)

    def test_observer_closes_the_session_when_an_operation_takes_the_device(self):
        busy = replace(
            self.current,
            revision=8,
            active_operation=ActiveOperation("op-1", "flash.execute", "Flashing", "SERIAL"),
        )

        self.service.observe_snapshot(busy)

        self.assertTrue(self.backend.process.terminated)
        self.assertEqual("operation_active", self.events[-1].code)

    def test_input_is_rejected_and_the_session_closed_while_an_operation_is_active(self):
        self.current = replace(
            self.current,
            revision=8,
            active_operation=ActiveOperation("op-1", "flash.execute", "Flashing", "SERIAL"),
        )

        rejected = self.service.write(self.opened.session_id, b"rm -rf /\r", expected_revision=8)

        self.assertFalse(rejected.accepted)
        self.assertEqual("operation_active", rejected.code)
        self.assertEqual([], self.backend.process.writes)
        self.assertTrue(self.backend.process.terminated)

    def test_opening_is_refused_while_an_operation_is_active(self):
        self.service.close(self.opened.session_id, expected_revision=7)
        busy = replace(
            self.current,
            active_operation=ActiveOperation("op-1", "flash.execute", "Flashing", "SERIAL"),
        )
        backend = FakeTerminalBackend()
        service = AdbTerminalService(lambda: busy, backend)

        result = service.open(serial="SERIAL", expected_revision=7, columns=80, rows=24)

        self.assertFalse(result.accepted)
        self.assertEqual("operation_active", result.code)
        self.assertEqual([], backend.calls)

    def test_open_survives_a_revision_bump_during_process_start(self):
        self.service.close(self.opened.session_id, expected_revision=7)
        snapshots = iter([snapshot(), snapshot(revision=8)])
        backend = FakeTerminalBackend()
        service = AdbTerminalService(lambda: next(snapshots), backend)

        result = service.open(serial="SERIAL", expected_revision=7, columns=80, rows=24)

        self.assertTrue(result.accepted)
        self.assertEqual("terminal_opened", result.code)
        self.assertFalse(backend.process.terminated)

    def test_identity_changes_still_close_the_session_after_a_revision_bump(self):
        changes = (
            (replace(snapshot(revision=8), selected_serial="OTHER"), "target_serial_changed"),
            (snapshot(revision=8, mode="fastboot"), "device_state_changed"),
            (snapshot(revision=8, mode="offline"), "device_disconnected"),
            (
                replace(
                    snapshot(revision=8),
                    toolchain=ToolchainInfo("OTHER_ADB", "FASTBOOT", "36.0.0", True),
                ),
                "toolchain_changed",
            ),
        )
        for changed, code in changes:
            with self.subTest(code=code):
                current = snapshot()
                backend = FakeTerminalBackend()
                service = AdbTerminalService(lambda current=current: current, backend)
                events = []
                service.subscribe(events.append)
                opened = service.open(serial="SERIAL", expected_revision=7, columns=80, rows=24)
                self.assertTrue(opened.accepted)

                service.observe_snapshot(changed)

                self.assertTrue(backend.process.terminated)
                self.assertEqual(code, events[-1].code)


if __name__ == "__main__":
    unittest.main()
