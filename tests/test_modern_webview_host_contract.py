import json
import tempfile
import threading
import unittest
from collections.abc import Callable
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
    _LogcatProgressBatcher,
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
    @staticmethod
    def _progress_message(sequence: int, *, text: str = "line") -> dict:
        return {
            "version": 2,
            "event": "progress",
            "revision": 7,
            "payload": {
                "event_type": "progress",
                "operation_id": "logcat-operation",
                "phase": "running",
                "message": f"{sequence}:{text}",
                "current": sequence,
            },
        }

    def test_cancel_notifies_worker_and_engine_for_pending_interactions(self):
        calls: list[tuple[str, str]] = []
        responses: list[dict] = []
        host = SimpleNamespace(
            _command_worker=SimpleNamespace(cancel=lambda operation_id: calls.append(("worker", operation_id)) or True),
            _engine=SimpleNamespace(
                cancel=lambda operation_id: (
                    calls.append(("engine", operation_id)) or CommandAck(True, "cancellation_requested")
                ),
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
            result for bridge_request, result in delivered if bridge_request.request_id == "queued-operation"
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
            result for bridge_request, result in delivered if bridge_request.request_id == "expired-operation"
        )
        self.assertIsNotNone(expired_result)
        assert expired_result is not None
        self.assertEqual("failed", expired_result.status.value)
        self.assertEqual("timed_out", expired_result.code)

    def test_logcat_batcher_uses_one_callback_and_drains_every_fifo_chunk(self):
        scheduled: list[Callable[[], None]] = []
        batches: list[tuple[dict, ...]] = []
        batcher = _LogcatProgressBatcher(
            lambda batch: batches.append(tuple(batch)),
            scheduled.append,
            is_gui_thread=lambda: False,
            maximum_messages=16,
            maximum_bytes=64 * 1_024,
            batch_maximum_messages=3,
            batch_maximum_bytes=8 * 1_024,
        )

        for sequence in range(8):
            self.assertTrue(batcher.enqueue(self._progress_message(sequence)))

        self.assertEqual(1, len(scheduled))
        self.assertTrue(batcher.flush_scheduled)
        self.assertEqual(8, batcher.queued_messages)

        scheduled[0]()

        self.assertEqual([3, 3, 2], [len(batch) for batch in batches])
        self.assertEqual(
            list(range(8)),
            [message["payload"]["current"] for batch in batches for message in batch],
        )
        self.assertEqual(0, batcher.queued_messages)
        self.assertEqual(0, batcher.queued_bytes)
        self.assertFalse(batcher.flush_scheduled)
        # The callback drained all chunks synchronously; it did not enqueue a
        # second callback that a terminal runtime/response could overtake.
        self.assertEqual(1, len(scheduled))

    def test_logcat_batcher_gui_enqueue_flushes_once_without_scheduling(self):
        scheduled: list[Callable[[], None]] = []
        emitted: list[dict] = []
        batcher = _LogcatProgressBatcher(
            lambda batch: emitted.extend(batch),
            scheduled.append,
            is_gui_thread=lambda: True,
            maximum_messages=2,
            maximum_bytes=4 * 1_024,
            batch_maximum_messages=2,
            batch_maximum_bytes=4 * 1_024,
        )

        self.assertTrue(batcher.enqueue(self._progress_message(1)))

        self.assertEqual([1], [message["payload"]["current"] for message in emitted])
        self.assertEqual([], scheduled)
        self.assertEqual(0, batcher.queued_messages)
        self.assertEqual(0, batcher.queued_bytes)
        self.assertFalse(batcher.flush_scheduled)

    def test_logcat_batcher_splits_on_encoded_bytes_without_losing_order(self):
        scheduled: list[Callable[[], None]] = []
        batches: list[tuple[dict, ...]] = []
        byte_limit = 900
        batcher = _LogcatProgressBatcher(
            lambda batch: batches.append(tuple(batch)),
            scheduled.append,
            is_gui_thread=lambda: False,
            maximum_messages=16,
            maximum_bytes=16 * 1_024,
            batch_maximum_messages=16,
            batch_maximum_bytes=byte_limit,
        )

        for sequence in range(7):
            self.assertTrue(batcher.enqueue(self._progress_message(sequence, text='quoted \\" value ' + "x" * 180)))
        scheduled[0]()

        self.assertGreater(len(batches), 1)
        self.assertEqual(
            list(range(7)),
            [message["payload"]["current"] for batch in batches for message in batch],
        )
        for batch in batches:
            encoded = json.dumps(batch, ensure_ascii=True, separators=(",", ":")).encode("ascii")
            self.assertLessEqual(len(encoded), byte_limit)
            self.assertLessEqual(len(batch), 128)

    def test_logcat_batcher_applies_backpressure_instead_of_evicting_fifo_events(self):
        scheduled: list[Callable[[], None]] = []
        emitted: list[dict] = []
        producer_started = threading.Event()
        producer_finished = threading.Event()
        batcher = _LogcatProgressBatcher(
            lambda batch: emitted.extend(batch),
            scheduled.append,
            is_gui_thread=lambda: False,
            maximum_messages=2,
            maximum_bytes=8 * 1_024,
            batch_maximum_messages=2,
            batch_maximum_bytes=8 * 1_024,
        )
        self.assertTrue(batcher.enqueue(self._progress_message(1)))
        self.assertTrue(batcher.enqueue(self._progress_message(2)))

        def enqueue_third() -> None:
            producer_started.set()
            batcher.enqueue(self._progress_message(3))
            producer_finished.set()

        producer = threading.Thread(target=enqueue_third)
        producer.start()
        self.assertTrue(producer_started.wait(1))
        self.assertFalse(producer_finished.wait(0.05))
        self.assertEqual(2, batcher.queued_messages)

        scheduled[0]()
        self.assertTrue(producer_finished.wait(1))
        producer.join(1)
        for callback in scheduled[1:]:
            callback()

        self.assertFalse(producer.is_alive())
        self.assertEqual(
            [1, 2, 3],
            [message["payload"]["current"] for message in emitted],
        )
        self.assertEqual(0, batcher.queued_messages)
        self.assertEqual(0, batcher.queued_bytes)

    def test_emit_batch_uses_one_webview_script_for_every_message(self):
        scripts: list[str] = []
        host = SimpleNamespace(
            _closing=False,
            _loaded=True,
            _pending_messages=[],
            _view=SimpleNamespace(RunScriptAsync=scripts.append),
        )
        messages = tuple(self._progress_message(sequence) for sequence in range(4))

        ModernWebViewFrame._emit_batch(host, messages)

        self.assertEqual(1, len(scripts))
        prefix = "for(const detail of "
        suffix = "){window.dispatchEvent"
        self.assertTrue(scripts[0].startswith(prefix))
        payload = scripts[0][len(prefix) : scripts[0].index(suffix)]
        self.assertEqual(list(messages), json.loads(payload))

    def test_logcat_flush_is_ordered_before_terminal_runtime_and_response_callbacks(self):
        callbacks: list[tuple[Callable[..., None], tuple]] = []
        emitted: list[dict] = []
        batches: list[int] = []

        def emit_batch(batch):
            batches.append(len(batch))
            emitted.extend(batch)

        def call_after(callback, *args):
            callbacks.append((callback, args))

        batcher = _LogcatProgressBatcher(
            emit_batch,
            lambda callback: call_after(callback),
            is_gui_thread=lambda: False,
        )
        snapshot = AppSnapshot(revision=7)
        host = SimpleNamespace(
            _closing=False,
            _engine=SimpleNamespace(snapshot=lambda: snapshot),
            _emit=emitted.append,
            _logcat_progress_batcher=batcher,
            _operation_commands={"logcat-operation": "tools.logcat"},
            _operation_commands_lock=threading.RLock(),
        )

        def publish_operation_events():
            for sequence in range(300):
                ModernWebViewFrame._on_engine_event(
                    host,
                    ProgressEvent(
                        "logcat-operation",
                        ProgressPhase.RUNNING,
                        f"line {sequence}",
                        None,
                        kind="tools.logcat",
                        current=sequence + 1,
                        total=300,
                    ),
                )
            ModernWebViewFrame._on_engine_event(
                host,
                OperationFinished(OperationResult.success("logcat-operation", code="complete")),
            )
            call_after(
                emitted.append,
                {"version": 2, "requestId": "logcat-request", "ok": True},
            )

        with patch("ui.pages.modern_webview_host.wx.CallAfter", side_effect=call_after):
            producer = threading.Thread(target=publish_operation_events)
            producer.start()
            producer.join(2)

        self.assertFalse(producer.is_alive())
        self.assertEqual(3, len(callbacks))
        for callback, args in callbacks:
            callback(*args)

        self.assertEqual([128, 128, 44], batches)
        self.assertEqual(
            list(range(1, 301)),
            [message["payload"]["current"] for message in emitted[:300]],
        )
        self.assertEqual("runtime", emitted[300]["event"])
        self.assertEqual("logcat-request", emitted[301]["requestId"])

    def test_closing_logcat_batcher_clears_accounting_and_pending_callback(self):
        scheduled: list[Callable[[], None]] = []
        emitted: list[tuple[dict, ...]] = []
        batcher = _LogcatProgressBatcher(
            lambda batch: emitted.append(tuple(batch)),
            scheduled.append,
            is_gui_thread=lambda: False,
            maximum_messages=2,
            maximum_bytes=4 * 1_024,
            batch_maximum_messages=2,
            batch_maximum_bytes=4 * 1_024,
        )
        self.assertTrue(batcher.enqueue(self._progress_message(1)))
        self.assertGreater(batcher.queued_bytes, 0)

        batcher.close()
        scheduled[0]()

        self.assertEqual(0, batcher.queued_messages)
        self.assertEqual(0, batcher.queued_bytes)
        self.assertFalse(batcher.flush_scheduled)
        self.assertFalse(batcher.enqueue(self._progress_message(2)))
        self.assertEqual([], emitted)

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

    def test_logcat_runtime_event_never_rebroadcasts_the_correlated_log(self):
        snapshot = AppSnapshot(revision=7)
        emitted = []
        host = SimpleNamespace(
            _closing=False,
            _engine=SimpleNamespace(snapshot=lambda: snapshot),
            _emit=emitted.append,
            _operation_commands={"logcat-op": "tools.logcat"},
            _operation_commands_lock=threading.RLock(),
        )
        result = OperationResult.success(
            "logcat-op",
            code="logcat_collected",
            value={"lines": ["private device log"]},
        )

        ModernWebViewFrame._on_engine_event(host, OperationFinished(result))

        self.assertEqual("runtime", emitted[0]["event"])
        self.assertNotIn("value", emitted[0]["payload"])
        self.assertNotIn("private device log", repr(emitted[0]))

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

    def test_closed_logcat_results_keep_their_validated_line_and_text_contract(self):
        lines = [f"{index:04d} " + "x" * 72 for index in range(2_100)]
        text = "\n".join(lines)
        value = {
            "targetSerial": "SERIAL123456",
            "mode": "snapshot",
            "lineCount": len(lines),
            "lines": lines,
            "text": text,
            "redaction": "strict",
            "redactedCount": 0,
            "bounded": True,
            "truncated": False,
        }

        bounded = _limit_bridge_payload({"result": {"value": value}})

        self.assertEqual(value, bounded["result"]["value"])
        self.assertGreater(len(text), 131_072)

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

    def test_replay_byte_budget_reserves_logcat_before_dispatch_and_releases_slack(self):
        ledger = _RequestReplayLedger(
            maximum_completed=8,
            maximum_bytes=12 * 1_024,
            default_reservation_bytes=4 * 1_024,
            logcat_reservation_bytes=9 * 1_024,
        )
        logcat = request(
            "logcat-reservation",
            command="tools.logcat",
            payload={"serial": "SERIAL123456", "mode": "snapshot"},
        )
        ordinary = request("ordinary-reservation", command="snapshot.get")

        self.assertIs(ReplayAction.EXECUTE, ledger.begin(logcat).action)
        self.assertEqual(9 * 1_024, ledger.reserved_bytes)
        self.assertIs(ReplayAction.CAPACITY, ledger.begin(ordinary).action)

        ledger.complete(
            logcat,
            {
                "version": 2,
                "requestId": "logcat-reservation",
                "ok": True,
                "result": {"status": "SUCCESS"},
            },
        )

        self.assertEqual(0, ledger.reserved_bytes)
        self.assertGreater(ledger.retained_bytes, 0)
        self.assertLess(ledger.retained_bytes, 9 * 1_024)
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(ordinary).action)
        self.assertEqual(
            ledger.retained_bytes + ledger.reserved_bytes,
            ledger.accounted_bytes,
        )

    def test_inflight_duplicate_waiters_are_coalesced_at_a_hard_limit(self):
        ledger = _RequestReplayLedger(
            maximum_completed=4,
            maximum_waiters=2,
        )
        first = request("bounded-waiters")

        self.assertIs(ReplayAction.EXECUTE, ledger.begin(first).action)
        for _ in range(20):
            self.assertIs(ReplayAction.WAIT, ledger.begin(first).action)

        responses = ledger.complete(
            first,
            {
                "version": 2,
                "requestId": "bounded-waiters",
                "ok": True,
                "result": {"value": 1},
            },
        )

        self.assertEqual(3, len(responses))
        self.assertTrue(all(message == responses[0] for message in responses))
        self.assertIs(ReplayAction.REPLAY, ledger.begin(first).action)

    def test_oversized_completion_records_a_compact_non_reexecutable_tombstone(self):
        ledger = _RequestReplayLedger(
            maximum_completed=4,
            maximum_bytes=8 * 1_024,
            default_reservation_bytes=4 * 1_024,
            logcat_reservation_bytes=4 * 1_024,
        )
        oversized = request("oversized-response")
        reserved = request("other-inflight", command="snapshot.get")

        self.assertIs(ReplayAction.EXECUTE, ledger.begin(oversized).action)
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(reserved).action)
        responses = ledger.complete(
            oversized,
            {
                "version": 2,
                "requestId": "oversized-response",
                "ok": True,
                "result": {"value": "x" * 5_000},
            },
        )

        self.assertEqual(1, len(responses))
        self.assertFalse(responses[0]["ok"])
        self.assertEqual(
            "response_replay_budget_exceeded",
            responses[0]["error"]["code"],
        )
        replay = ledger.begin(oversized)
        self.assertIs(ReplayAction.REPLAY, replay.action)
        self.assertEqual(responses[0], replay.message)
        self.assertLessEqual(ledger.accounted_bytes, 8 * 1_024)

    def test_clear_releases_completed_and_inflight_byte_accounting(self):
        ledger = _RequestReplayLedger(
            maximum_completed=4,
            maximum_bytes=16 * 1_024,
            default_reservation_bytes=4 * 1_024,
            logcat_reservation_bytes=8 * 1_024,
        )
        completed = request("clear-completed")
        inflight = request(
            "clear-inflight",
            command="tools.logcat",
            payload={"serial": "SERIAL123456", "mode": "snapshot"},
        )
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(completed).action)
        ledger.complete(
            completed,
            {
                "version": 2,
                "requestId": "clear-completed",
                "ok": True,
                "result": {},
            },
        )
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(inflight).action)
        self.assertGreater(ledger.retained_bytes, 0)
        self.assertEqual(8 * 1_024, ledger.reserved_bytes)

        ledger.clear()

        self.assertEqual(0, ledger.retained_bytes)
        self.assertEqual(0, ledger.reserved_bytes)
        self.assertEqual(0, ledger.accounted_bytes)
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(completed).action)

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
