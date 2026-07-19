import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    CommandAck,
    InteractionKind,
    InteractionRequest,
    OperationFinished,
    OperationResult,
    ProgressEvent,
    ProgressPhase,
    SnapshotChanged,
)
from ui.bridge_contract import BRIDGE_VERSION, BridgeRequest
from ui.pages.modern_webview_host import (
    ModernWebViewFrame,
    ReplayAction,
    _is_allowed_local_url,
    _jsonable,
    _limit_bridge_payload,
    _RequestReplayLedger,
    _safe_wildcard,
    _SerialCommandWorker,
)
from ui.public_bridge import PublicProjectionError


def request(request_id="request-1", *, command="device.scan", payload=None):
    return BridgeRequest.from_json(
        json.dumps(
            {
                "version": BRIDGE_VERSION,
                "requestId": request_id,
                "command": command,
                "payload": payload or {},
                "expectedRevision": 3,
            }
        )
    )


class ModernWebViewHostContractTests(unittest.TestCase):
    def test_cancel_notifies_worker_and_engine_for_pending_interactions(self):
        calls: list[tuple[str, str]] = []
        responses: list[dict] = []
        host = SimpleNamespace(
            _command_worker=SimpleNamespace(
                cancel=lambda operation_id: calls.append(("worker", operation_id)) or True
            ),
            _engine=SimpleNamespace(
                cancel=lambda operation_id: calls.append(("engine", operation_id))
                or CommandAck(True, "cancellation_requested"),
                snapshot=lambda: AppSnapshot(revision=3),
            ),
            _complete_request=lambda _request, message: responses.append(message),
        )

        ModernWebViewFrame._handle_operation_cancel(
            host,
            request(
                "cancel-request",
                command="operation.cancel",
                payload={"operationId": "pending-operation"},
            ),
        )

        self.assertEqual(
            [("worker", "pending-operation"), ("engine", "pending-operation")],
            calls,
        )
        self.assertTrue(responses[0]["ok"])
        self.assertEqual("cancellation_requested", responses[0]["result"]["code"])

    def test_engine_worker_cancels_an_accepted_command_before_fifo_execution(self):
        first_started = threading.Event()
        release_first = threading.Event()
        delivered: list[tuple[BridgeRequest, OperationResult | None]] = []
        executed: list[str] = []

        def execute(command: AppCommand) -> OperationResult:
            executed.append(command.operation_id)
            if command.operation_id == "first-operation":
                first_started.set()
                release_first.wait(2)
            return OperationResult.success(command.operation_id)

        with patch(
            "ui.pages.modern_webview_host.wx.CallAfter",
            side_effect=lambda callback, *args: callback(*args),
        ):
            worker = _SerialCommandWorker(
                SimpleNamespace(execute=execute),
                lambda bridge_request, result: delivered.append((bridge_request, result)),
            )
            try:
                worker.submit(
                    request("first-operation"),
                    AppCommand("device.scan", operation_id="first-operation"),
                )
                self.assertTrue(first_started.wait(1))
                worker.submit(
                    request("queued-operation"),
                    AppCommand("device.scan", operation_id="queued-operation"),
                )

                self.assertTrue(worker.cancel("queued-operation"))
                release_first.set()
                for _attempt in range(100):
                    if len(delivered) == 2:
                        break
                    threading.Event().wait(0.01)
            finally:
                release_first.set()
                worker.shutdown(timeout_seconds=2)

        queued_result = next(
            result
            for bridge_request, result in delivered
            if bridge_request.request_id == "queued-operation"
        )
        self.assertIsNotNone(queued_result)
        assert queued_result is not None
        self.assertEqual("cancelled", queued_result.status.value)
        self.assertEqual("cancelled", queued_result.code)
        self.assertNotIn("queued-operation", executed)

    def test_engine_worker_carries_cancellation_across_the_engine_handoff(self):
        handoff_started = threading.Event()
        release_handoff = threading.Event()
        delivered: list[tuple[BridgeRequest, OperationResult | None]] = []

        def execute(command: AppCommand) -> OperationResult:
            handoff_started.set()
            release_handoff.wait(2)
            if command.cancellation_reason is not None:
                return OperationResult.cancelled(command.operation_id, code="cancelled")
            return OperationResult.success(command.operation_id)

        with patch(
            "ui.pages.modern_webview_host.wx.CallAfter",
            side_effect=lambda callback, *args: callback(*args),
        ):
            worker = _SerialCommandWorker(
                SimpleNamespace(execute=execute),
                lambda bridge_request, result: delivered.append((bridge_request, result)),
            )
            try:
                worker.submit(
                    request("handoff-operation"),
                    AppCommand("device.scan", operation_id="handoff-operation"),
                )
                self.assertTrue(handoff_started.wait(1))
                self.assertTrue(worker.cancel("handoff-operation"))
                release_handoff.set()
                for _attempt in range(100):
                    if delivered:
                        break
                    threading.Event().wait(0.01)
            finally:
                release_handoff.set()
                worker.shutdown(timeout_seconds=2)

        self.assertEqual(1, len(delivered))
        result = delivered[0][1]
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual("cancelled", result.status.value)

    def test_engine_worker_preserves_deadline_as_the_first_queued_stop_cause(self):
        first_started = threading.Event()
        release_first = threading.Event()
        delivered: list[tuple[BridgeRequest, OperationResult | None]] = []

        def execute(command: AppCommand) -> OperationResult:
            if command.operation_id == "deadline-blocker":
                first_started.set()
                release_first.wait(2)
            return OperationResult.success(command.operation_id)

        with patch(
            "ui.pages.modern_webview_host.wx.CallAfter",
            side_effect=lambda callback, *args: callback(*args),
        ):
            worker = _SerialCommandWorker(
                SimpleNamespace(execute=execute),
                lambda bridge_request, result: delivered.append((bridge_request, result)),
            )
            try:
                worker.submit(
                    request("deadline-blocker"),
                    AppCommand("device.scan", operation_id="deadline-blocker"),
                )
                self.assertTrue(first_started.wait(1))
                expired = AppCommand(
                    "device.scan",
                    operation_id="expired-operation",
                    execution_timeout_seconds=0.01,
                    _accepted_monotonic=0,
                )
                worker.submit(request("expired-operation"), expired)
                self.assertTrue(worker.cancel("expired-operation"))
                release_first.set()
                for _attempt in range(100):
                    if len(delivered) == 2:
                        break
                    threading.Event().wait(0.01)
            finally:
                release_first.set()
                worker.shutdown(timeout_seconds=2)

        expired_result = next(
            result
            for bridge_request, result in delivered
            if bridge_request.request_id == "expired-operation"
        )
        self.assertIsNotNone(expired_result)
        assert expired_result is not None
        self.assertEqual("failed", expired_result.status.value)
        self.assertEqual("timed_out", expired_result.code)

    def test_closed_app_events_map_to_the_existing_four_v2_event_names(self):
        snapshot = AppSnapshot(revision=7)
        emitted = []
        host = SimpleNamespace(
            _closing=False,
            _engine=SimpleNamespace(snapshot=lambda: snapshot),
            _emit=emitted.append,
            _operation_commands={},
            _operation_commands_lock=threading.RLock(),
        )
        events = (
            SnapshotChanged(snapshot),
            ProgressEvent(
                "op",
                ProgressPhase.RUNNING,
                "Working",
                50,
                kind="tools.pushFiles",
                current=1,
                total=2,
                item="alpha.bin",
                target_serial="SERIAL",
            ),
            InteractionRequest(
                "op",
                InteractionKind.CONFIRM,
                "Confirm",
                "Continue?",
                7,
            ),
            OperationFinished(OperationResult.success("op", code="complete")),
        )

        for event in events:
            ModernWebViewFrame._on_engine_event(host, event)

        self.assertEqual(
            ["snapshot", "progress", "interaction", "runtime"],
            [message["event"] for message in emitted],
        )
        self.assertTrue(all(message["revision"] == 7 for message in emitted))
        self.assertEqual(7, emitted[0]["payload"]["revision"])
        self.assertEqual(
            {
                "event_type": "progress",
                "operation_id": "op",
                "phase": "running",
                "message": "Working",
                "percent": 50,
                "kind": "tools.pushFiles",
                "current": 1,
                "total": 2,
                "item": "alpha.bin",
                "target_serial": "SERIAL",
            },
            emitted[1]["payload"],
        )
        self.assertEqual("complete", emitted[-1]["payload"]["code"])

    def test_wifi_discovery_runtime_event_never_rebroadcasts_lan_endpoints(self):
        snapshot = AppSnapshot(revision=7)
        emitted = []
        host = SimpleNamespace(
            _closing=False,
            _engine=SimpleNamespace(snapshot=lambda: snapshot),
            _emit=emitted.append,
            _operation_commands={"wifi-op": "tools.wifi.discover"},
            _operation_commands_lock=threading.RLock(),
        )
        result = OperationResult.success(
            "wifi-op",
            code="wifi_mdns_discovery_succeeded",
            value={"services": [{"endpoint": "192.168.1.42:37123"}]},
        )

        ModernWebViewFrame._on_engine_event(host, OperationFinished(result))

        self.assertEqual("runtime", emitted[0]["event"])
        self.assertNotIn("value", emitted[0]["payload"])
        self.assertNotIn("192.168.1.42", repr(emitted[0]))

    def test_invalid_successful_public_result_is_a_typed_bridge_failure(self):
        completed = []
        host = SimpleNamespace(
            _closing=False,
            _engine=SimpleNamespace(snapshot=lambda: AppSnapshot(revision=7)),
            _operation_commands={"wifi-op": "tools.wifi.discover"},
            _operation_commands_lock=threading.RLock(),
            _complete_request=lambda _request, message: completed.append(message),
            _emit_snapshot=lambda: None,
        )

        ModernWebViewFrame._command_finished(
            host,
            request(command="tools.wifi.discover"),
            OperationResult.success("wifi-op"),
        )

        self.assertFalse(completed[0]["ok"])
        self.assertEqual("public_result_invalid", completed[0]["error"]["code"])

    def test_navigation_is_restricted_to_the_bundled_asset_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            asset = root / "assets" / "app.js"
            asset.parent.mkdir()
            asset.write_text("", encoding="utf-8")

            self.assertTrue(_is_allowed_local_url(asset.as_uri(), root))
            self.assertTrue(_is_allowed_local_url("about:blank", root))
            self.assertFalse(_is_allowed_local_url("https://example.com", root))
            self.assertFalse(_is_allowed_local_url((root.parent / "secret.txt").as_uri(), root))
            remote_authority = asset.as_uri().replace("file:///", "file://attacker/", 1)
            self.assertFalse(_is_allowed_local_url(remote_authority, root))

    def test_file_filter_builder_only_accepts_simple_extensions(self):
        wildcard = _safe_wildcard(
            [
                {"label": "Android packages", "extensions": ["zip", ".img", "*.apk"]},
                {"label": "Unsafe|label", "extensions": ["../exe", "tar.gz"]},
            ]
        )

        self.assertIn("*.zip;*.img;*.apk", wildcard)
        self.assertNotIn("../", wildcard)
        self.assertNotIn("tar.gz", wildcard)
        self.assertTrue(wildcard.endswith("All files (*.*)|*.*"))

    def test_json_conversion_never_emits_python_objects(self):
        with self.assertRaises(PublicProjectionError):
            _jsonable({"path": Path("firmware.zip"), "items": (1, 2)})

    def test_progress_projection_drops_untrusted_kind_and_host_item(self):
        projected = _jsonable(
            ProgressEvent(
                "op",
                ProgressPhase.RUNNING,
                "Working",
                25,
                kind=r"C:\\private\\command",
                current=1,
                total=1,
                item=r"C:\\private\\payload.zip",
            )
        )

        self.assertEqual("", projected["kind"])
        self.assertIsNone(projected["item"])
        self.assertNotIn("private", repr(projected))

    def test_outbound_logs_are_bounded_before_script_injection(self):
        bounded = _limit_bridge_payload({"stdout": "x" * 40_000, "message": "ok"})

        self.assertLess(len(bounded["stdout"]), 40_000)
        self.assertIn("truncated", bounded["stdout"])
        self.assertEqual("ok", bounded["message"])

    def test_request_ids_execute_once_and_inflight_replays_wait_for_the_same_result(self):
        ledger = _RequestReplayLedger(maximum_completed=4)
        first = request()

        self.assertIs(ReplayAction.EXECUTE, ledger.begin(first).action)
        self.assertIs(ReplayAction.WAIT, ledger.begin(first).action)
        responses = ledger.complete(
            first,
            {"version": 2, "requestId": "request-1", "ok": True, "result": {"value": 1}},
        )

        self.assertEqual(2, len(responses))
        self.assertEqual(responses[0], responses[1])
        replay = ledger.begin(first)
        self.assertIs(ReplayAction.REPLAY, replay.action)
        self.assertEqual(responses[0], replay.message)

    def test_request_id_reuse_with_a_different_fingerprint_is_rejected(self):
        ledger = _RequestReplayLedger()
        first = request(payload={"includeBattery": True})
        conflicting = request(payload={"includeBattery": False})

        self.assertIs(ReplayAction.EXECUTE, ledger.begin(first).action)
        self.assertIs(ReplayAction.CONFLICT, ledger.begin(conflicting).action)
        ledger.complete(
            first,
            {"version": 2, "requestId": "request-1", "ok": True, "result": {}},
        )
        self.assertIs(ReplayAction.CONFLICT, ledger.begin(conflicting).action)

    def test_completed_ids_are_never_evicted_and_capacity_fails_closed(self):
        ledger = _RequestReplayLedger(maximum_completed=2)
        mutation = request(
            "mutation-1",
            command="settings.update",
            payload={"theme": "dark"},
        )
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(mutation).action)
        original = {
            "version": 2,
            "requestId": "mutation-1",
            "ok": True,
            "result": {"revision": 4},
        }
        ledger.complete(mutation, original)

        read = request("read-1", command="snapshot.get")
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(read).action)
        ledger.complete(
            read,
            {
                "version": 2,
                "requestId": "read-1",
                "ok": True,
                "result": {},
            },
        )
        self.assertIs(
            ReplayAction.CAPACITY,
            ledger.begin(request("read-2", command="snapshot.get")).action,
        )

        replay = ledger.begin(mutation)
        self.assertIs(ReplayAction.REPLAY, replay.action)
        self.assertEqual(original, replay.message)

    def test_host_source_has_no_future_or_dynamic_engine_dispatch(self):
        source = Path("ui/pages/modern_webview_host.py").read_text(encoding="utf-8")
        self.assertNotIn("ThreadPoolExecutor", source)
        self.assertNotIn("add_done_callback", source)
        self.assertNotIn(".result()", source)
        self.assertNotIn("getattr(", source)


if __name__ == "__main__":
    unittest.main()
