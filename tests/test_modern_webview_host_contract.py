import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from pixelflasher_core import (
    AppSnapshot,
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
            ProgressEvent("op", ProgressPhase.RUNNING, "Working", 50),
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
