"""Round-2 regressions for the revision-bound ADB terminal service.

BLOCKING-05: a session whose client vanished must be releasable, otherwise the
PTY runs ownerless and every later open dead-ends on terminal_session_active.
IMPORTANT-15: host-only operations must not evict a live device shell.
"""

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
        self.terminated = False

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    def resize(self, *, columns: int, rows: int) -> None:
        return None

    def terminate(self) -> None:
        self.terminated = True


class FakeTerminalBackend:
    def __init__(self) -> None:
        self.processes: list[FakeTerminalProcess] = []

    def start(self, argv, *, columns, rows, on_output, on_exit):
        process = FakeTerminalProcess()
        self.processes.append(process)
        return process


def snapshot(*, revision: int = 7, serial: str = "SERIAL") -> AppSnapshot:
    return AppSnapshot(
        revision=revision,
        preferences=ModernPreferences(expert_mode=True),
        devices=(DeviceInfo(serial, mode="adb", online=True),),
        selected_serials=(serial,),
        selected_serial=serial,
        toolchain=ToolchainInfo("C:/platform-tools/adb.exe", "FASTBOOT", "36.0.0", True),
    )


class AdbTerminalPacketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.current = snapshot()
        self.backend = FakeTerminalBackend()
        self.service = AdbTerminalService(lambda: self.current, self.backend)
        self.events: list[object] = []
        self.service.subscribe(self.events.append)

    def open(self, *, revision: int = 7):
        return self.service.open(
            serial="SERIAL",
            expected_revision=revision,
            columns=80,
            rows=24,
        )

    def closed_events(self):
        return [event for event in self.events if isinstance(event, TerminalClosedEvent)]

    def test_an_orphaned_session_is_released_so_the_shell_can_be_opened_again(self):
        first = self.open()
        self.assertTrue(first.accepted)

        # The web view reloads: nobody ever sends tools.adbShell.close.
        refused = self.open()

        self.assertFalse(refused.accepted)
        self.assertEqual("terminal_session_active", refused.code)
        self.assertTrue(self.backend.processes[0].terminated)
        self.assertEqual("terminal_superseded", self.closed_events()[-1].code)

        recovered = self.open()

        self.assertTrue(recovered.accepted)
        self.assertNotEqual(first.session_id, recovered.session_id)
        self.assertEqual(2, len(self.backend.processes))
        self.assertFalse(self.backend.processes[1].terminated)

    def test_a_refused_open_never_releases_the_live_session(self):
        opened = self.open()
        assert opened.session_id is not None
        self.current = replace(self.current, revision=8)

        refused = self.service.open(
            serial="OTHER",
            expected_revision=8,
            columns=80,
            rows=24,
        )

        self.assertFalse(refused.accepted)
        self.assertEqual("target_serial_changed", refused.code)
        self.assertFalse(self.backend.processes[0].terminated)
        self.assertEqual([], self.closed_events())
        self.assertTrue(self.service.write(opened.session_id, b"id\r", expected_revision=8).accepted)

    def test_a_host_only_operation_keeps_the_shell_alive(self):
        opened = self.open()
        assert opened.session_id is not None
        for kind in ("tools.xml", "tools.avb", "tools.keybox", "firmware.process", "support.create"):
            with self.subTest(kind=kind):
                self.current = replace(
                    self.current,
                    revision=self.current.revision + 1,
                    active_operation=ActiveOperation("op-1", kind, "Working", None),
                )

                self.service.observe_snapshot(self.current)
                written = self.service.write(
                    opened.session_id,
                    b"id\r",
                    expected_revision=self.current.revision,
                )

                self.assertTrue(written.accepted, msg=written.code)
                self.assertEqual([], self.closed_events())
                self.assertFalse(self.backend.processes[0].terminated)

    def test_a_host_only_operation_does_not_refuse_a_new_shell(self):
        self.current = replace(
            self.current,
            active_operation=ActiveOperation("op-1", "tools.xml", "Decoding", None),
        )

        opened = self.open()

        self.assertTrue(opened.accepted, msg=opened.code)

    def test_a_device_operation_still_evicts_and_refuses_the_shell(self):
        opened = self.open()
        assert opened.session_id is not None
        self.current = replace(
            self.current,
            revision=8,
            active_operation=ActiveOperation("op-1", "flash.execute", "Flashing", "SERIAL"),
        )

        self.service.observe_snapshot(self.current)
        refused = self.service.open(serial="SERIAL", expected_revision=8, columns=80, rows=24)

        self.assertTrue(self.backend.processes[0].terminated)
        self.assertEqual("operation_active", self.closed_events()[-1].code)
        self.assertFalse(refused.accepted)
        self.assertEqual("operation_active", refused.code)


if __name__ == "__main__":
    unittest.main()
