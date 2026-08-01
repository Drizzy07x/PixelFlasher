import json
import unittest

from ui.bridge_contract import BRIDGE_VERSION, BridgeRequest
from ui.pages.modern_webview_host import ReplayAction, _RequestReplayLedger

RETAINED_BUDGET = 64 * 1_024


def request(request_id, *, command="device.scan", payload=None, revision=3):
    return BridgeRequest.from_json(
        json.dumps(
            {
                "version": BRIDGE_VERSION,
                "requestId": request_id,
                "command": command,
                "payload": payload or {},
                "expectedRevision": revision,
            }
        )
    )


def response(request_id, *, value=""):
    return {
        "version": BRIDGE_VERSION,
        "requestId": request_id,
        "ok": True,
        "result": {"value": value},
    }


def error_code(message):
    return None if message.get("ok") else message["error"]["code"]


class OversizedReplayPayloadTests(unittest.TestCase):
    def _ledger_with_small_completions(self, count):
        ledger = _RequestReplayLedger(
            maximum_completed=4_096,
            retained_payload_bytes=RETAINED_BUDGET,
        )
        sent = {}
        for index in range(count):
            small = request(f"small-{index}")
            self.assertIs(ReplayAction.EXECUTE, ledger.begin(small).action)
            message = response(small.request_id, value="s" * 64)
            sent[small.request_id] = message
            ledger.complete(small, message)
        self.assertLessEqual(ledger.retained_bytes, RETAINED_BUDGET)
        return ledger, sent

    def test_one_oversized_result_does_not_expire_every_other_retained_body(self):
        ledger, sent = self._ledger_with_small_completions(20)

        logcat = request("logcat-1", command="tools.logcat")
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(logcat).action)
        ledger.complete(logcat, response(logcat.request_id, value="L" * (256 * 1_024)))

        for request_id in ("small-0", "small-19"):
            replay = ledger.begin(request(request_id))
            self.assertIs(ReplayAction.REPLAY, replay.action)
            self.assertEqual(sent[request_id], replay.message)

    def test_an_oversized_result_is_demoted_instead_of_breaking_the_budget(self):
        ledger, _ = self._ledger_with_small_completions(20)

        logcat = request("logcat-1", command="tools.logcat")
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(logcat).action)
        ledger.complete(logcat, response(logcat.request_id, value="L" * (256 * 1_024)))

        self.assertLessEqual(ledger.retained_bytes, RETAINED_BUDGET)

        replay = ledger.begin(request("logcat-1", command="tools.logcat"))
        self.assertIs(ReplayAction.REPLAY, replay.action)
        assert replay.message is not None
        self.assertEqual("response_replay_expired", error_code(replay.message))

    def test_a_demoted_oversized_id_can_never_execute_again(self):
        ledger, _ = self._ledger_with_small_completions(4)

        logcat = request("logcat-1", command="tools.logcat")
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(logcat).action)
        ledger.complete(logcat, response(logcat.request_id, value="L" * (256 * 1_024)))

        for _ in range(3):
            replay = ledger.begin(request("logcat-1", command="tools.logcat"))
            self.assertIs(ReplayAction.REPLAY, replay.action)
            assert replay.message is not None
            self.assertEqual("response_replay_expired", error_code(replay.message))

    def test_completions_after_an_oversized_result_stay_replayable(self):
        ledger, sent = self._ledger_with_small_completions(4)

        logcat = request("logcat-1", command="tools.logcat")
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(logcat).action)
        ledger.complete(logcat, response(logcat.request_id, value="L" * (256 * 1_024)))

        later = request("after-the-logcat")
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(later).action)
        message = response(later.request_id, value="tail")
        ledger.complete(later, message)

        replay = ledger.begin(request("after-the-logcat"))
        self.assertIs(ReplayAction.REPLAY, replay.action)
        self.assertEqual(message, replay.message)
        self.assertLessEqual(ledger.retained_bytes, RETAINED_BUDGET)

        earlier = ledger.begin(request("small-0"))
        self.assertIs(ReplayAction.REPLAY, earlier.action)
        self.assertEqual(sent["small-0"], earlier.message)

    def test_a_lone_oversized_result_is_released_once_it_starts_costing_others(self):
        # The newest-entry exemption still applies while nothing else competes
        # for the budget: demotion only kicks in when a body would otherwise be
        # taken from an unrelated completion.
        ledger = _RequestReplayLedger(
            maximum_completed=4_096,
            retained_payload_bytes=RETAINED_BUDGET,
        )
        logcat = request("logcat-1", command="tools.logcat")
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(logcat).action)
        ledger.complete(logcat, response(logcat.request_id, value="L" * (256 * 1_024)))

        alone = ledger.begin(request("logcat-1", command="tools.logcat"))
        self.assertIs(ReplayAction.REPLAY, alone.action)
        assert alone.message is not None
        self.assertIsNone(error_code(alone.message))

        follow_up = request("small-0")
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(follow_up).action)
        message = response(follow_up.request_id, value="s" * 64)
        ledger.complete(follow_up, message)

        self.assertLessEqual(ledger.retained_bytes, RETAINED_BUDGET)
        replay = ledger.begin(request("small-0"))
        self.assertIs(ReplayAction.REPLAY, replay.action)
        self.assertEqual(message, replay.message)


if __name__ == "__main__":
    unittest.main()
