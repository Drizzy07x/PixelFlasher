"""Thread-safe interaction rendezvous for headless hosts and UI bridges."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from .contracts import InteractionDecision, InteractionRequest


class InteractionTimeoutError(TimeoutError):
    """Raised when a confirmation receives no decision inside its wait budget."""


@dataclass(slots=True)
class _PendingInteraction:
    request: InteractionRequest
    event: threading.Event = field(default_factory=threading.Event)
    decision: InteractionDecision | None = None


class InteractionBroker:
    """Wait for UI responses without holding core state locks."""

    def __init__(
        self,
        timeout_seconds: float = 300.0,
        on_request: Callable[[InteractionRequest], None] | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.timeout_seconds = timeout_seconds
        self.on_request = on_request
        self._lock = threading.RLock()
        self._pending: dict[str, _PendingInteraction] = {}
        self._shutdown = False

    def request(self, request: InteractionRequest) -> InteractionDecision:
        started = time.monotonic()
        pending = _PendingInteraction(request)
        with self._lock:
            if self._shutdown or request.operation_id in self._pending:
                return InteractionDecision.CANCELLED
            self._pending[request.operation_id] = pending

        if self.on_request is not None:
            try:
                self.on_request(request)
            except Exception:
                pass

        wait_seconds = self.timeout_seconds
        if request.timeout_seconds is not None:
            elapsed = time.monotonic() - started
            wait_seconds = min(
                wait_seconds,
                max(0.0, request.timeout_seconds - elapsed),
            )
        signalled = pending.event.wait(wait_seconds)
        with self._lock:
            self._pending.pop(request.operation_id, None)
        if not signalled and pending.decision is None:
            raise InteractionTimeoutError("interaction response timed out")
        if pending.decision is None:
            return InteractionDecision.CANCELLED
        return pending.decision

    def respond(
        self,
        operation_id: str,
        decision: InteractionDecision,
        expected_revision: int,
    ) -> bool:
        if not isinstance(decision, InteractionDecision):
            return False
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool):
            return False
        with self._lock:
            pending = self._pending.get(operation_id)
            if pending is None:
                return False
            if pending.request.expected_revision != expected_revision:
                return False
            self._pending.pop(operation_id, None)
            pending.decision = decision
            pending.event.set()
            return True

    def cancel(self, operation_id: str) -> bool:
        with self._lock:
            pending = self._pending.pop(operation_id, None)
            if pending is None:
                return False
            pending.decision = InteractionDecision.CANCELLED
            pending.event.set()
            return True

    def shutdown(self) -> None:
        with self._lock:
            self._shutdown = True
            pending = tuple(self._pending.values())
            self._pending.clear()
        for item in pending:
            item.decision = InteractionDecision.CANCELLED
            item.event.set()

    def pending_requests(self) -> tuple[InteractionRequest, ...]:
        with self._lock:
            return tuple(item.request for item in self._pending.values())
