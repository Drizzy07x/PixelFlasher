"""Cancellation primitives shared by accepted commands and process execution."""

from __future__ import annotations

import math
import threading
import time
from enum import StrEnum


class CancellationReason(StrEnum):
    USER = "user"
    DEADLINE = "deadline"


class CancellationToken:
    """Thread-safe cooperative cancellation with an optional monotonic deadline.

    The token is created with an ``AppCommand`` and therefore exists before the
    native host places that command on its FIFO.  Queue cancellation and engine
    execution consequently observe the same object, including during the
    otherwise racy handoff between those two owners.

    Deadlines may be shortened but never extended.  The first terminal cause is
    retained so a manual cancellation cannot later be misreported as a timeout,
    and a deadline which already elapsed cannot be overwritten by ``cancel()``.
    """

    def __init__(self) -> None:
        self._condition = threading.Condition(threading.RLock())
        self._deadline: float | None = None
        self._reason: CancellationReason | None = None

    def set_deadline(self, timeout_seconds: float) -> None:
        """Set or shorten the remaining monotonic time budget."""

        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > threading.TIMEOUT_MAX
        ):
            raise ValueError(
                "deadline timeout must be a finite positive number within the platform wait limit"
            )
        self.set_deadline_at(time.monotonic() + float(timeout_seconds))

    def set_deadline_at(self, deadline_monotonic: float) -> None:
        """Set or shorten an absolute monotonic deadline, including a past one."""

        now = time.monotonic()
        if (
            isinstance(deadline_monotonic, bool)
            or not isinstance(deadline_monotonic, (int, float))
            or not math.isfinite(deadline_monotonic)
            or deadline_monotonic < 0
            or deadline_monotonic - now > threading.TIMEOUT_MAX
        ):
            raise ValueError("absolute deadline must be finite and within the platform wait limit")
        candidate = float(deadline_monotonic)
        with self._condition:
            now = time.monotonic()
            self._refresh_deadline_locked(now)
            if self._reason is not None:
                return
            if self._deadline is None or candidate < self._deadline:
                self._deadline = candidate
                self._refresh_deadline_locked(now)
                self._condition.notify_all()

    def cancel(self) -> None:
        with self._condition:
            self._refresh_deadline_locked(time.monotonic())
            if self._reason is None:
                self._reason = CancellationReason.USER
                self._condition.notify_all()

    @property
    def cancelled(self) -> bool:
        with self._condition:
            self._refresh_deadline_locked(time.monotonic())
            return self._reason is not None

    @property
    def deadline_expired(self) -> bool:
        with self._condition:
            now = time.monotonic()
            self._refresh_deadline_locked(now)
            return self._deadline is not None and now >= self._deadline

    @property
    def remaining_seconds(self) -> float | None:
        with self._condition:
            now = time.monotonic()
            self._refresh_deadline_locked(now)
            if self._deadline is None:
                return None
            return max(0.0, self._deadline - now)

    @property
    def reason(self) -> CancellationReason | None:
        with self._condition:
            self._refresh_deadline_locked(time.monotonic())
            return self._reason

    def wait(self, timeout: float | None = None) -> bool:
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout < 0
            or timeout > threading.TIMEOUT_MAX
        ):
            raise ValueError(
                "wait timeout must be null or a finite non-negative number within the platform limit"
            )
        caller_deadline = None if timeout is None else time.monotonic() + float(timeout)
        with self._condition:
            while True:
                now = time.monotonic()
                self._refresh_deadline_locked(now)
                if self._reason is not None:
                    return True
                wake_at = self._earliest(self._deadline, caller_deadline)
                if wake_at is None:
                    self._condition.wait()
                    continue
                remaining = wake_at - now
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)

    def _refresh_deadline_locked(self, now: float) -> None:
        if self._reason is None and self._deadline is not None and now >= self._deadline:
            self._reason = CancellationReason.DEADLINE
            self._condition.notify_all()

    @staticmethod
    def _earliest(left: float | None, right: float | None) -> float | None:
        if left is None:
            return right
        if right is None:
            return left
        return min(left, right)
