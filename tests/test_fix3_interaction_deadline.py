"""A deadline-bounded confirmation must always report the deadline.

The engine bounds a confirmation with `token.remaining_seconds`, so the wait can
return marginally before the deadline is technically reached. Probing the token
afterwards then reported whichever side of that boundary the scheduler landed
on, and one expiry surfaced as `timed_out` or `interaction_timed_out` at random
(measured: 1 in 20 runs). Callers branch on that code, so it must be settled.
"""

from __future__ import annotations

import time
import unittest

from pixelflasher_core.cancellation import CancellationReason, CancellationToken
from pixelflasher_core.contracts import InteractionKind, InteractionRequest
from pixelflasher_core.interaction import InteractionBroker, InteractionTimeoutError


def _request(operation_id: str, timeout_seconds: float | None) -> InteractionRequest:
    return InteractionRequest(
        operation_id=operation_id,
        kind=InteractionKind.CONFIRM,
        title="confirm",
        message="confirm",
        expected_revision=1,
        _timeout_seconds=timeout_seconds,
    )


class BrokerReportsWhichBudgetElapsedTests(unittest.TestCase):
    def test_the_request_budget_is_reported_when_it_is_the_shorter_one(self):
        broker = InteractionBroker(timeout_seconds=10)

        with self.assertRaises(InteractionTimeoutError) as raised:
            broker.request(_request("op-deadline", 0.01))

        self.assertTrue(raised.exception.bounded_by_request)

    def test_the_brokers_own_budget_is_reported_when_it_is_the_shorter_one(self):
        broker = InteractionBroker(timeout_seconds=0.01)

        with self.assertRaises(InteractionTimeoutError) as raised:
            broker.request(_request("op-broker", 30.0))

        self.assertFalse(raised.exception.bounded_by_request)

    def test_an_unbounded_request_reports_the_brokers_own_budget(self):
        broker = InteractionBroker(timeout_seconds=0.01)

        with self.assertRaises(InteractionTimeoutError) as raised:
            broker.request(_request("op-unbounded", None))

        self.assertFalse(raised.exception.bounded_by_request)


class SettledDeadlineIsDeterministicTests(unittest.TestCase):
    def _settle(self, token: CancellationToken, bounded: bool) -> None:
        from pixelflasher_core.engine import CommandEngine

        CommandEngine._settle_interaction_deadline(
            token,
            InteractionTimeoutError("timed out", bounded_by_request=bounded),
        )

    def test_an_early_wake_still_settles_as_a_deadline(self):
        token = CancellationToken()
        # A deadline far enough out that it cannot have elapsed on its own: this
        # is exactly the early-wake case the race produced.
        token.set_deadline(30.0)
        self.assertIsNone(token.reason)

        self._settle(token, True)

        self.assertIs(CancellationReason.DEADLINE, token.reason)

    def test_a_genuine_confirmation_timeout_never_invents_a_deadline(self):
        token = CancellationToken()
        token.set_deadline(30.0)

        self._settle(token, False)

        self.assertIsNone(token.reason)

    def test_a_user_cancellation_keeps_precedence(self):
        token = CancellationToken()
        token.set_deadline(30.0)
        token.cancel()

        self._settle(token, True)

        self.assertIs(CancellationReason.USER, token.reason)

    def test_settling_a_command_without_a_deadline_is_still_a_deadline_stop(self):
        token = CancellationToken()
        self.assertIsNone(token.remaining_seconds)

        self._settle(token, True)

        self.assertIs(CancellationReason.DEADLINE, token.reason)

    def test_the_settled_deadline_is_not_pushed_into_the_future(self):
        token = CancellationToken()
        token.set_deadline(30.0)

        self._settle(token, True)

        self.assertTrue(token.deadline_expired)
        self.assertEqual(0.0, token.remaining_seconds)
        self.assertLessEqual(token.remaining_seconds or 0.0, time.monotonic())


if __name__ == "__main__":
    unittest.main()
