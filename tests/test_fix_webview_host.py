import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pixelflasher_core import AppCommand, AppSnapshot, OperationResult
from ui.bridge_contract import BRIDGE_VERSION, BridgeRequest
from ui.core_command_factory import CommandFactoryError, create_command_factory
from ui.pages.modern_webview_host import (
    ModernWebViewFrame,
    ReplayAction,
    ReplayCapacity,
    _RequestReplayLedger,
    _SerialCommandWorker,
)


def raw_request(request_id="request-1", *, command="device.scan", payload=None, revision=3):
    return json.dumps(
        {
            "version": BRIDGE_VERSION,
            "requestId": request_id,
            "command": command,
            "payload": payload or {},
            "expectedRevision": revision,
        }
    )


def request(request_id="request-1", *, command="device.scan", payload=None, revision=3):
    return BridgeRequest.from_json(
        raw_request(request_id, command=command, payload=payload, revision=revision)
    )


def response(request_id, *, value=None):
    return {
        "version": BRIDGE_VERSION,
        "requestId": request_id,
        "ok": True,
        "result": {} if value is None else {"value": value},
    }


class ReplayLedgerLifecycleTests(unittest.TestCase):
    def test_a_session_is_not_hard_stopped_after_a_thousand_requests(self):
        ledger = _RequestReplayLedger()

        for index in range(2_048):
            keystroke = request(
                f"shell-write-{index}",
                command="tools.adbShell.write",
                payload={"sessionId": "session-1", "data": "a"},
            )
            self.assertIs(ReplayAction.EXECUTE, ledger.begin(keystroke).action)
            ledger.complete(keystroke, response(keystroke.request_id))

        self.assertIs(
            ReplayAction.EXECUTE,
            ledger.begin(request("after-the-old-wall")).action,
        )

    def test_old_response_bodies_are_released_but_their_ids_stay_consumed(self):
        ledger = _RequestReplayLedger(
            maximum_completed=64,
            retained_payload_bytes=4 * 1_024,
        )
        retired = request("retired-request")
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(retired).action)
        ledger.complete(retired, response(retired.request_id, value="x" * 512))

        for index in range(32):
            later = request(f"later-request-{index}")
            self.assertIs(ReplayAction.EXECUTE, ledger.begin(later).action)
            ledger.complete(later, response(later.request_id, value="y" * 512))

        self.assertLess(ledger.retained_bytes, 16 * 1_024)
        replay = ledger.begin(retired)
        self.assertIs(ReplayAction.REPLAY, replay.action)
        assert replay.message is not None
        self.assertFalse(replay.message["ok"])
        self.assertEqual("response_replay_expired", replay.message["error"]["code"])

    def test_the_newest_completion_keeps_its_verbatim_body(self):
        ledger = _RequestReplayLedger(
            maximum_completed=64,
            retained_payload_bytes=2 * 1_024,
        )
        newest = request("newest-request")
        message = response(newest.request_id, value="z" * 4_096)
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(newest).action)
        ledger.complete(newest, message)

        replay = ledger.begin(newest)

        self.assertIs(ReplayAction.REPLAY, replay.action)
        self.assertEqual(message, replay.message)

    def test_lifecycle_commands_survive_a_full_identifier_ledger(self):
        ledger = _RequestReplayLedger(maximum_completed=2)
        for index in range(2):
            filler = request(f"filler-{index}")
            self.assertIs(ReplayAction.EXECUTE, ledger.begin(filler).action)
            ledger.complete(filler, response(filler.request_id))

        blocked = ledger.begin(request("blocked-request"))
        self.assertIs(ReplayAction.CAPACITY, blocked.action)
        self.assertIs(ReplayCapacity.IDENTIFIERS, blocked.capacity)

        cancel = request(
            "cancel-request",
            command="operation.cancel",
            payload={"operationId": "running-flash"},
        )
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(cancel).action)
        ledger.complete(cancel, response(cancel.request_id))

        exit_request = request("exit-request", command="app.exit")
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(exit_request).action)

    def test_in_flight_reservations_no_longer_cap_the_bridge_at_sixteen(self):
        ledger = _RequestReplayLedger()

        for index in range(64):
            self.assertIs(
                ReplayAction.EXECUTE,
                ledger.begin(request(f"in-flight-{index}")).action,
            )

    def test_byte_capacity_reports_transient_back_pressure(self):
        ledger = _RequestReplayLedger(
            maximum_completed=8,
            maximum_bytes=8 * 1_024,
            default_reservation_bytes=4 * 1_024,
        )
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(request("reserve-1")).action)
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(request("reserve-2")).action)

        refused = ledger.begin(request("reserve-3"))

        self.assertIs(ReplayAction.CAPACITY, refused.action)
        self.assertIs(ReplayCapacity.MEMORY, refused.capacity)

    def test_capacity_reasons_map_to_distinct_bridge_errors(self):
        busy_ledger = _RequestReplayLedger(
            maximum_completed=8,
            maximum_bytes=8 * 1_024,
            default_reservation_bytes=4 * 1_024,
        )
        busy_ledger.begin(request("reserve-1"))
        busy_ledger.begin(request("reserve-2"))
        full_ledger = _RequestReplayLedger(maximum_completed=1)
        full_ledger.begin(request("only-slot"))
        emitted: list[dict] = []

        for ledger in (busy_ledger, full_ledger):
            host = SimpleNamespace(_replay_ledger=ledger, _emit=emitted.append)
            ModernWebViewFrame._on_script_message(
                host,
                SimpleNamespace(GetString=lambda: raw_request("refused-request")),
            )

        self.assertEqual(
            ["request_queue_busy", "request_ledger_full"],
            [message["error"]["code"] for message in emitted],
        )
        self.assertNotIn("restart PixelFlasher", emitted[0]["error"]["message"])


class HostConfigurationLaneTests(unittest.TestCase):
    def test_host_configuration_commands_use_their_own_lane(self):
        host = SimpleNamespace(_command_worker=object(), _config_worker=object())

        self.assertIs(host._config_worker, ModernWebViewFrame._worker_for(host, "settings.update"))
        self.assertIs(host._config_worker, ModernWebViewFrame._worker_for(host, "settings.get"))
        self.assertIs(host._command_worker, ModernWebViewFrame._worker_for(host, "flash.execute"))

    def test_settings_update_runs_while_the_device_lane_is_blocked(self):
        started = threading.Event()
        release = threading.Event()
        delivered: list[str] = []

        def execute(command: AppCommand) -> OperationResult:
            if command.kind == "device.scan":
                started.set()
                release.wait(2)
            return OperationResult.success(command.operation_id)

        with patch(
            "ui.pages.modern_webview_host.wx.CallAfter",
            side_effect=lambda callback, *args: callback(*args),
        ):
            engine = SimpleNamespace(execute=execute)
            device_worker = _SerialCommandWorker(
                engine,
                lambda bridge_request, _result: delivered.append(bridge_request.request_id),
            )
            config_worker = _SerialCommandWorker(
                engine,
                lambda bridge_request, _result: delivered.append(bridge_request.request_id),
                thread_name="pixelflasher-config-test",
            )
            host = SimpleNamespace(_command_worker=device_worker, _config_worker=config_worker)
            try:
                ModernWebViewFrame._worker_for(host, "device.scan").submit(
                    request("blocking-scan"),
                    AppCommand("device.scan", operation_id="blocking-scan"),
                )
                self.assertTrue(started.wait(1))
                ModernWebViewFrame._worker_for(host, "settings.update").submit(
                    request("theme-update", command="settings.update", payload={"theme": "dark"}),
                    AppCommand(
                        "settings.update",
                        operation_id="theme-update",
                        expected_revision=3,
                        payload={"theme": "dark"},
                    ),
                )
                for _attempt in range(200):
                    if delivered:
                        break
                    threading.Event().wait(0.01)

                self.assertEqual(["theme-update"], delivered)
            finally:
                release.set()
                device_worker.shutdown(timeout_seconds=2)
                config_worker.shutdown(timeout_seconds=2)


class NativePickerRevisionTests(unittest.TestCase):
    def test_a_background_revision_change_during_the_dialog_keeps_the_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "firmware.zip"
            selected.write_bytes(b"firmware")
            revision = {"value": 9}
            factory = create_command_factory(lambda: AppSnapshot(revision=revision["value"]))
            picker = request(
                "firmware-picker",
                command="native.pickFile",
                payload={"purpose": "firmware.select", "title": "Choose firmware"},
                revision=9,
            )

            factory.validate_native_request(picker)
            # The device poller observes an unplug while the modal is open.
            revision["value"] = 10
            public = factory.issue_native_grants(picker, (selected,))

            self.assertEqual("firmware.select", public["purpose"])
            self.assertEqual(selected.name, public["displayName"])

    def test_the_pre_dialog_check_still_rejects_a_stale_revision(self):
        factory = create_command_factory(lambda: AppSnapshot(revision=9))
        stale = request(
            "stale-picker",
            command="native.pickFile",
            payload={"purpose": "firmware.select"},
            revision=8,
        )

        with self.assertRaises(CommandFactoryError) as conflict:
            factory.validate_native_request(stale)

        self.assertEqual("revision_conflict", conflict.exception.code)

    def test_issuing_grants_still_enforces_the_picker_purpose_allow_list(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "firmware.zip"
            selected.write_bytes(b"firmware")
            factory = create_command_factory(lambda: AppSnapshot(revision=9))
            picker = request(
                "wrong-purpose-picker",
                command="native.pickFile",
                payload={"purpose": "platformTools.setup.directory"},
                revision=9,
            )

            with self.assertRaises(CommandFactoryError) as wrong:
                factory.issue_native_grants(picker, (selected,))

            self.assertEqual("native_purpose_not_allowed", wrong.exception.code)


if __name__ == "__main__":
    unittest.main()
