import json
import tempfile
import threading
import unittest
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from constants import VERSION
from pixelflasher_core import (
    ActiveOperation,
    AppCommand,
    AppSnapshot,
    CommandAck,
    GrantAccess,
    InteractionKind,
    InteractionRequest,
    OperationFinished,
    OperationResult,
    ProgressEvent,
    ProgressPhase,
    SnapshotChanged,
    TerminalCommandResult,
    TerminalOutputEvent,
)
from ui.bridge_contract import BRIDGE_VERSION, BridgeRequest
from ui.core_command_factory import create_command_factory
from ui.pages.modern_webview_host import (
    _UI_SMOKE_ROUTES,
    ModernWebViewFrame,
    ReplayAction,
    _extract_ui_smoke_script_output,
    _is_allowed_local_url,
    _jsonable,
    _limit_bridge_payload,
    _LogcatProgressBatcher,
    _RequestReplayLedger,
    _safe_wildcard,
    _SerialCommandWorker,
)
from ui.public_bridge import PublicProjectionError, project_operation_result


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

    def test_application_ready_returns_the_host_version_and_refreshes_snapshot(self):
        responses: list[dict] = []
        snapshots: list[bool] = []
        ready_revisions: list[int] = []
        host = SimpleNamespace(
            _engine=SimpleNamespace(snapshot=lambda: AppSnapshot(revision=3)),
            _complete_request=lambda _request, message: responses.append(message),
            _emit_snapshot=lambda: snapshots.append(True),
            _bridge_ready_callback=ready_revisions.append,
            _bridge_ready_signalled=False,
        )
        host._signal_bridge_ready = lambda revision: ModernWebViewFrame._signal_bridge_ready(  # type: ignore[attr-defined]
            host,
            revision,
        )

        ModernWebViewFrame._dispatch_request(
            host,
            request("application-ready", command="app.ready"),
        )

        self.assertTrue(responses[0]["ok"])
        self.assertEqual(VERSION, responses[0]["result"]["version"])
        self.assertEqual([True], snapshots)
        self.assertEqual([3], ready_revisions)
        self.assertTrue(host._bridge_ready_signalled)

        ModernWebViewFrame._dispatch_request(
            host,
            request("application-ready-second", command="app.ready"),
        )
        self.assertEqual([3], ready_revisions)

    def test_ui_smoke_script_results_ignore_unmarked_webview_traffic(self):
        self.assertIsNone(_extract_ui_smoke_script_output("true"))
        self.assertIsNone(_extract_ui_smoke_script_output(json.dumps({"ok": True})))
        marked = json.dumps(
            json.dumps(
                {
                    "smokeToken": "pixelflasher-packaged-ui-smoke-v2",
                    "ok": True,
                }
            )
        )
        self.assertEqual({"ok": True}, json.loads(_extract_ui_smoke_script_output(marked) or "{}"))

    def test_packaged_ui_smoke_visits_every_route_by_keyboard_and_proves_focus(self):
        script_results = [json.dumps({"ok": True})]
        for route in _UI_SMOKE_ROUTES:
            script_results.extend(
                (
                    json.dumps({"ok": True, "defaultPrevented": True}),
                    json.dumps(
                        {
                            "ok": True,
                            "route": f"#/{route}",
                            "activeRoute": True,
                            "headingFocused": True,
                            "persistentDocument": True,
                        }
                    ),
                )
            )
        scripts: list[str] = []
        scheduled: list[Callable[[], None]] = []
        results: list[tuple[dict | None, str | None]] = []

        def run_script(script: str, callback: Callable[[str], None]):
            scripts.append(script)
            callback(script_results.pop(0))

        def call_later(_delay: int, callback: Callable[[int], None], index: int):
            scheduled.append(lambda: callback(index))
            return SimpleNamespace(Stop=lambda: None)

        host = SimpleNamespace(
            _closing=False,
            _loaded=True,
            _bridge_ready_signalled=True,
            _ui_smoke_in_progress=False,
            _ui_smoke_timer=None,
            _ui_smoke_script_callback=None,
            _run_ui_smoke_script=run_script,
        )
        with patch("ui.pages.modern_webview_host.wx.CallLater", side_effect=call_later):
            ModernWebViewFrame.run_packaged_ui_smoke(host, lambda result, error: results.append((result, error)))
            while scheduled:
                scheduled.pop(0)()

        self.assertEqual(19, len(scripts))
        self.assertEqual([], script_results)
        self.assertEqual(1, len(results))
        journey, error = results[0]
        self.assertIsNone(error)
        assert journey is not None
        self.assertEqual(list(_UI_SMOKE_ROUTES), journey["taskRoutes"])
        self.assertTrue(journey["keyboardRouteNavigation"])
        self.assertTrue(journey["focusTransferredToHeading"])
        self.assertTrue(journey["persistentDocument"])

    def test_packaged_ui_smoke_fails_closed_when_route_focus_is_missing(self):
        outputs = [
            json.dumps({"ok": True}),
            json.dumps({"ok": True, "defaultPrevented": True}),
            json.dumps(
                {
                    "ok": True,
                    "route": "#/dashboard",
                    "activeRoute": True,
                    "headingFocused": False,
                    "persistentDocument": True,
                }
            ),
        ]
        scheduled: list[Callable[[], None]] = []
        results: list[tuple[dict | None, str | None]] = []
        host = SimpleNamespace(
            _closing=False,
            _loaded=True,
            _bridge_ready_signalled=True,
            _ui_smoke_in_progress=False,
            _ui_smoke_timer=None,
            _ui_smoke_script_callback=None,
            _run_ui_smoke_script=lambda _script, callback: callback(outputs.pop(0)),
        )

        def call_later(_delay: int, callback: Callable[[int], None], index: int):
            scheduled.append(lambda: callback(index))
            return SimpleNamespace(Stop=lambda: None)

        with patch("ui.pages.modern_webview_host.wx.CallLater", side_effect=call_later):
            ModernWebViewFrame.run_packaged_ui_smoke(host, lambda result, error: results.append((result, error)))
            scheduled.pop(0)()

        self.assertEqual([(None, "Packaged UI did not transfer focus on dashboard")], results)

    def test_linux_ui_smoke_uses_webkit_synchronous_result_contract(self):
        outputs: list[str] = []
        host = SimpleNamespace(
            _ui_smoke_script_callback=None,
            _view=SimpleNamespace(
                RunScript=lambda script: (True, f"result:{script}"),
                RunScriptAsync=lambda _script: self.fail("Linux must use WebKit RunScript"),
            ),
        )
        with patch("ui.pages.modern_webview_host.sys.platform", "linux"):
            ModernWebViewFrame._run_ui_smoke_script(host, "document.title", outputs.append)
        self.assertEqual(["result:document.title"], outputs)
        self.assertIsNone(host._ui_smoke_script_callback)

        host._view.RunScript = lambda _script: (False, "")
        with (
            patch("ui.pages.modern_webview_host.sys.platform", "linux"),
            self.assertRaisesRegex(RuntimeError, "WebKit could not execute"),
        ):
            ModernWebViewFrame._run_ui_smoke_script(host, "broken()", outputs.append)

    def test_non_linux_ui_smoke_keeps_the_async_result_contract(self):
        scripts: list[str] = []

        def callback(_output: str) -> None:
            return None

        host = SimpleNamespace(
            _ui_smoke_script_callback=None,
            _view=SimpleNamespace(RunScriptAsync=scripts.append),
        )
        with patch("ui.pages.modern_webview_host.sys.platform", "win32"):
            ModernWebViewFrame._run_ui_smoke_script(host, "document.title", callback)
        self.assertEqual(["document.title"], scripts)
        self.assertIs(callback, host._ui_smoke_script_callback)

    def test_adb_terminal_requests_are_exactly_projected_to_the_native_service(self):
        calls: list[tuple] = []
        responses: list[dict] = []
        service = SimpleNamespace(
            open=lambda **values: calls.append(("open", values))
            or TerminalCommandResult(True, "terminal_opened", "opened", "session-1"),
            write=lambda session_id, data, **values: calls.append(("write", session_id, data, values))
            or TerminalCommandResult(True, "terminal_input_written", "written", session_id),
            resize=lambda session_id, **values: calls.append(("resize", session_id, values))
            or TerminalCommandResult(True, "terminal_resized", "resized", session_id),
            close=lambda session_id, **values: calls.append(("close", session_id, values))
            or TerminalCommandResult(True, "terminal_closed", "closed", session_id),
        )
        host = SimpleNamespace(
            _adb_terminal_service=service,
            _engine=SimpleNamespace(snapshot=lambda: AppSnapshot(revision=3)),
            _complete_request=lambda _request, message: responses.append(message),
        )

        requests = (
            request(
                "terminal-open",
                command="tools.adbShell",
                payload={"serial": "SERIAL", "columns": 100, "rows": 30},
            ),
            request(
                "terminal-write",
                command="tools.adbShell.write",
                payload={"sessionId": "session-1", "data": "id\r"},
            ),
            request(
                "terminal-resize",
                command="tools.adbShell.resize",
                payload={"sessionId": "session-1", "columns": 120, "rows": 40},
            ),
            request(
                "terminal-close",
                command="tools.adbShell.close",
                payload={"sessionId": "session-1"},
            ),
        )
        for terminal_request in requests:
            ModernWebViewFrame._handle_adb_terminal_request(host, terminal_request)

        self.assertEqual(
            [
                ("open", {"serial": "SERIAL", "expected_revision": 3, "columns": 100, "rows": 30}),
                ("write", "session-1", b"id\r", {"expected_revision": 3}),
                ("resize", "session-1", {"expected_revision": 3, "columns": 120, "rows": 40}),
                ("close", "session-1", {"expected_revision": 3}),
            ],
            calls,
        )
        self.assertTrue(all(response["ok"] for response in responses))
        self.assertEqual(
            ["terminal_opened", "terminal_input_written", "terminal_resized", "terminal_closed"],
            [response["result"]["code"] for response in responses],
        )

    def test_adb_terminal_event_uses_the_bounded_terminal_channel(self):
        messages: list[dict] = []
        host = SimpleNamespace(
            _engine=SimpleNamespace(snapshot=lambda: AppSnapshot(revision=9)),
            _terminal_event_batcher=SimpleNamespace(enqueue=messages.append),
        )

        ModernWebViewFrame._on_terminal_event(
            host,
            TerminalOutputEvent("session-1", 4, b"id=1000\r\n"),
        )

        self.assertEqual("terminal", messages[0]["event"])
        self.assertEqual(9, messages[0]["revision"])
        self.assertEqual("output", messages[0]["payload"]["type"])
        self.assertEqual("base64", messages[0]["payload"]["encoding"])
        self.assertNotIn("id=1000", json.dumps(messages[0]))

    def test_application_folders_are_backend_owned_and_never_disclose_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory) / "logs"
            logs.mkdir()
            responses: list[dict] = []
            host = SimpleNamespace(
                _engine=SimpleNamespace(snapshot=lambda: AppSnapshot(revision=3)),
                _application_directories={"logs": logs},
                _complete_request=lambda _request, message: responses.append(message),
            )
            with patch("ui.pages.modern_webview_host.open_path") as opened:
                ModernWebViewFrame._handle_application_request(
                    host,
                    request(
                        "open-logs",
                        command="app.openFolder",
                        payload={"target": "logs"},
                    ),
                )

            opened.assert_called_once_with(logs)
            self.assertTrue(responses[0]["ok"])
            self.assertEqual("application_directory_opened", responses[0]["result"]["code"])
            self.assertNotIn(str(logs), json.dumps(responses[0]))

        projected = project_operation_result(
            "app.openFolder",
            OperationResult.success("open-folder", value={"target": "logs"}),
        )
        self.assertEqual({"target": "logs"}, projected["value"])
        with self.assertRaises(PublicProjectionError):
            project_operation_result(
                "app.openFolder",
                OperationResult.success(
                    "open-folder-hostile",
                    value={"target": "logs", "path": "C:/secret"},
                ),
            )

    def test_application_links_are_fixed_https_targets_opened_outside_the_webview(self):
        responses: list[dict] = []
        host = SimpleNamespace(
            _engine=SimpleNamespace(snapshot=lambda: AppSnapshot(revision=3)),
            _complete_request=lambda _request, message: responses.append(message),
        )
        with patch("ui.pages.modern_webview_host.webbrowser.open", return_value=True) as opened:
            ModernWebViewFrame._handle_application_request(
                host,
                request(
                    "open-documentation",
                    command="app.openLink",
                    payload={"target": "documentation"},
                ),
            )

        opened.assert_called_once_with(
            "https://github.com/badabing2005/PixelFlasher#readme",
            new=2,
        )
        self.assertTrue(responses[0]["ok"])
        self.assertEqual("application_link_opened", responses[0]["result"]["code"])
        self.assertNotIn("https://", json.dumps(responses[0]))

        projected = project_operation_result(
            "app.openLink",
            OperationResult.success("open-link", value={"target": "releases"}),
        )
        self.assertEqual({"target": "releases"}, projected["value"])
        with self.assertRaises(PublicProjectionError):
            project_operation_result(
                "app.openLink",
                OperationResult.success(
                    "open-link-hostile",
                    value={"target": "releases", "url": "https://example.com"},
                ),
            )

    def test_application_link_fails_closed_when_native_browser_rejects_launch(self):
        responses: list[dict] = []
        host = SimpleNamespace(
            _engine=SimpleNamespace(snapshot=lambda: AppSnapshot(revision=3)),
            _complete_request=lambda _request, message: responses.append(message),
        )
        with patch("ui.pages.modern_webview_host.webbrowser.open", return_value=False):
            ModernWebViewFrame._handle_application_request(
                host,
                request(
                    "open-license",
                    command="app.openLink",
                    payload={"target": "license"},
                ),
            )
        self.assertFalse(responses[0]["ok"])
        self.assertEqual("application_link_open_failed", responses[0]["error"]["code"])

    def test_application_console_export_is_bounded_atomic_and_route_free(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "console.txt"
            factory = create_command_factory(lambda: AppSnapshot(revision=3))
            grant = factory.path_grants.issue_file(
                destination,
                purpose="app.console.export",
                access=GrantAccess.WRITE,
            )
            responses: list[dict] = []
            host = SimpleNamespace(
                _engine=SimpleNamespace(snapshot=lambda: AppSnapshot(revision=3)),
                _command_factory=factory,
                _complete_request=lambda _request, message: responses.append(message),
            )

            ModernWebViewFrame._handle_application_request(
                host,
                request(
                    "console-export",
                    command="app.console.export",
                    payload={
                        "grant": grant.token,
                        "lines": ["[PROGRESS 50%] Processing firmware."],
                    },
                ),
            )

            self.assertEqual(
                "[PROGRESS 50%] Processing firmware.\n",
                destination.read_text(encoding="utf-8"),
            )
            self.assertTrue(responses[0]["ok"])
            self.assertEqual("console_exported", responses[0]["result"]["code"])
            self.assertNotIn(str(destination), json.dumps(responses[0]))

    def test_application_console_export_rejects_a_host_route_before_consuming_grant(self):
        factory = create_command_factory(lambda: AppSnapshot(revision=3))
        responses: list[dict] = []
        host = SimpleNamespace(
            _engine=SimpleNamespace(snapshot=lambda: AppSnapshot(revision=3)),
            _command_factory=factory,
            _complete_request=lambda _request, message: responses.append(message),
        )

        ModernWebViewFrame._handle_application_request(
            host,
            request(
                "unsafe-console-export",
                command="app.console.export",
                payload={
                    "grant": "g" * 64,
                    "lines": ["Opened C:/Users/Alice/private.txt"],
                },
            ),
        )

        self.assertEqual("console_export_not_redacted", responses[0]["error"]["code"])

    def test_application_folder_and_exit_fail_closed_on_stale_or_active_state(self):
        responses: list[dict] = []
        snapshot = AppSnapshot(
            revision=4,
            active_operation=ActiveOperation("operation-1", "flash.execute"),
        )
        host = SimpleNamespace(
            _engine=SimpleNamespace(snapshot=lambda: snapshot),
            _application_directories={},
            _complete_request=lambda _request, message: responses.append(message),
            _has_active_work=lambda _snapshot: True,
        )
        ModernWebViewFrame._handle_application_request(
            host,
            request("stale-folder", command="app.openFolder", payload={"target": "logs"}),
        )
        ModernWebViewFrame._handle_application_request(
            host,
            request("active-exit", command="app.exit", payload={},),
        )

        self.assertEqual("revision_conflict", responses[0]["error"]["code"])
        self.assertEqual("revision_conflict", responses[1]["error"]["code"])

        responses.clear()
        snapshot = AppSnapshot(
            revision=3,
            active_operation=ActiveOperation("operation-1", "flash.execute"),
        )
        ModernWebViewFrame._handle_application_request(
            host,
            request("active-exit-current", command="app.exit", payload={}),
        )
        self.assertEqual("operation_active", responses[0]["error"]["code"])

    def test_application_folder_rejects_a_backend_target_that_became_a_symlink(self):
        responses: list[dict] = []
        host = SimpleNamespace(
            _engine=SimpleNamespace(snapshot=lambda: AppSnapshot(revision=3)),
            _application_directories={
                "logs": SimpleNamespace(
                    is_symlink=lambda: True,
                    is_dir=lambda: True,
                )
            },
            _complete_request=lambda _request, message: responses.append(message),
        )
        with patch("ui.pages.modern_webview_host.open_path") as opened:
            ModernWebViewFrame._handle_application_request(
                host,
                request(
                    "symlink-folder",
                    command="app.openFolder",
                    payload={"target": "logs"},
                ),
            )

        opened.assert_not_called()
        self.assertEqual(
            "application_directory_unavailable",
            responses[0]["error"]["code"],
        )

    def test_idle_exit_acks_before_requesting_the_native_close(self):
        responses: list[dict] = []
        closed: list[bool] = []
        host = SimpleNamespace(
            _engine=SimpleNamespace(snapshot=lambda: AppSnapshot(revision=3)),
            _application_directories={},
            _complete_request=lambda _request, message: responses.append(message),
            _has_active_work=lambda _snapshot: False,
            Close=lambda: closed.append(True),
        )
        with patch(
            "ui.pages.modern_webview_host.wx.CallAfter",
            side_effect=lambda callback, *args: callback(*args),
        ):
            ModernWebViewFrame._handle_application_request(
                host,
                request("idle-exit", command="app.exit", payload={}),
            )

        self.assertTrue(responses[0]["ok"])
        self.assertEqual("exit_requested", responses[0]["result"]["code"])
        self.assertEqual([True], closed)

    def test_native_window_close_is_vetoed_without_a_classic_dialog_during_work(self):
        emitted: list[dict] = []
        vetoed: list[bool] = []
        host = SimpleNamespace(
            _closing=False,
            _has_active_work=lambda: True,
            _engine=SimpleNamespace(snapshot=lambda: AppSnapshot(revision=3)),
            _emit=lambda message: emitted.append(message),
        )
        event = SimpleNamespace(
            CanVeto=lambda: True,
            Veto=lambda: vetoed.append(True),
            Skip=lambda: self.fail("active close must not skip"),
        )

        ModernWebViewFrame._on_close(host, event)

        self.assertEqual([True], vetoed)
        self.assertEqual("exitBlocked", emitted[0]["payload"]["status"])
        self.assertFalse(host._closing)

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

    def test_logcat_clear_uses_a_closed_response_and_never_exposes_its_transcript(self):
        receipt = {
            "targetSerial": "SERIAL",
            "buffers": ["all"],
            "clearCommandCompleted": True,
            "controlCommandVerified": True,
            "mainBufferSentinelVerified": True,
            "verificationEntryRetained": True,
        }
        completed = []
        snapshots = []
        host = SimpleNamespace(
            _closing=False,
            _engine=SimpleNamespace(snapshot=lambda: AppSnapshot(revision=7)),
            _operation_commands={"clear-op": "tools.logcat.clear"},
            _operation_commands_lock=threading.RLock(),
            _complete_request=lambda _request, message: completed.append(message),
            _emit_snapshot=lambda: snapshots.append(True),
        )
        bridge_request = request(
            "clear-op",
            command="tools.logcat.clear",
            payload={"serial": "SERIAL"},
        )

        ModernWebViewFrame._command_finished(
            host,
            bridge_request,
            OperationResult.success(
                "clear-op",
                code="logcat_buffers_cleared",
                stdout="PF10_PRE_private-verification-transcript",
                value=receipt,
            ),
        )

        self.assertTrue(completed[0]["ok"])
        self.assertEqual(receipt, completed[0]["result"]["value"])
        self.assertEqual(7, completed[0]["result"]["revision"])
        self.assertNotIn("stdout", completed[0]["result"])
        self.assertNotIn("PF10_PRE", repr(completed[0]))
        self.assertEqual([True], snapshots)

        expanded = dict(receipt, transcript="PF10_POST_private")
        ModernWebViewFrame._command_finished(
            host,
            bridge_request,
            OperationResult.success(
                "clear-op",
                code="logcat_buffers_cleared",
                value=expanded,
            ),
        )

        self.assertFalse(completed[1]["ok"])
        self.assertEqual("public_result_invalid", completed[1]["error"]["code"])
        self.assertNotIn("PF10_POST", repr(completed[1]))

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

    def test_logcat_clear_request_id_is_at_most_once_for_the_whole_session(self):
        ledger = _RequestReplayLedger(maximum_completed=4)
        clear = request(
            "clear-once",
            command="tools.logcat.clear",
            payload={"serial": "SERIAL"},
        )
        response = {
            "version": 2,
            "requestId": "clear-once",
            "ok": True,
            "result": {
                "status": "SUCCESS",
                "code": "logcat_buffers_cleared",
                "value": {
                    "targetSerial": "SERIAL",
                    "buffers": ["all"],
                    "clearCommandCompleted": True,
                    "controlCommandVerified": True,
                    "mainBufferSentinelVerified": True,
                    "verificationEntryRetained": True,
                },
            },
        }

        self.assertIs(ReplayAction.EXECUTE, ledger.begin(clear).action)
        for _duplicate in range(3):
            self.assertIs(ReplayAction.WAIT, ledger.begin(clear).action)
        waiting = ledger.complete(clear, response)

        self.assertEqual(4, len(waiting))
        self.assertTrue(all(message == response for message in waiting))
        for _duplicate in range(3):
            replay = ledger.begin(clear)
            self.assertIs(ReplayAction.REPLAY, replay.action)
            self.assertEqual(response, replay.message)

        changed_target = request(
            "clear-once",
            command="tools.logcat.clear",
            payload={"serial": "OTHER"},
        )
        self.assertIs(ReplayAction.CONFLICT, ledger.begin(changed_target).action)

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
