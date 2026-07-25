"""Native wx host for the local React application.

wx owns only the accessible system window, WebView, and native file/folder
pickers. Product state and operations belong to the injected headless engine.
"""

from __future__ import annotations

import json
import math
import os
import sys
import threading
import webbrowser
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Protocol, cast
from urllib.parse import unquote, urlparse

import wx

try:
    import wx.html2 as html2
except (ImportError, ModuleNotFoundError):
    html2 = None  # type: ignore[assignment]

from constants import APPNAME, VERSION
from pixelflasher_core import (
    AppCommand,
    AppEvent,
    AppSnapshot,
    CancellationReason,
    CommandAck,
    InteractionDecision,
    InteractionRequest,
    InteractionResponse,
    OperationFinished,
    OperationResult,
    ProgressEvent,
    SnapshotChanged,
    TerminalCommandResult,
    TerminalEvent,
)
from platform_utils import open_path
from ui.bridge_contract import (
    BRIDGE_CHANNEL,
    BridgeProtocolError,
    BridgeRequest,
    event_envelope,
    protocol_error_envelope,
    response_envelope,
)
from ui.core_command_factory import CommandFactoryError, CoreCommandFactory
from ui.public_bridge import (
    PublicProjectionError,
    ensure_public_json,
    project_operation_result,
    public_operation_summary,
    public_snapshot,
    safe_public_message,
)

_APPLICATION_LINKS = {
    "documentation": "https://github.com/badabing2005/PixelFlasher#readme",
    "license": "https://github.com/badabing2005/PixelFlasher/blob/main/LICENSE",
    "releases": "https://github.com/badabing2005/PixelFlasher/releases",
    "reportIssue": "https://github.com/badabing2005/PixelFlasher/issues/new/choose",
    "source": "https://github.com/badabing2005/PixelFlasher",
}


class EngineProtocol(Protocol):
    def snapshot(self) -> AppSnapshot: ...

    def subscribe(
        self,
        listener: Callable[[AppEvent], None],
        *,
        emit_current: bool = False,
    ) -> Callable[[], None]: ...

    def execute(self, command: AppCommand) -> OperationResult: ...

    def cancel(self, operation_id: str) -> CommandAck: ...

    def respond_interaction(
        self,
        request_id: str,
        response: InteractionResponse,
    ) -> CommandAck: ...

    def shutdown(self) -> None: ...


class SupportDestinationRegistrar(Protocol):
    """Native-only capability kept outside the public engine contract."""

    def __call__(
        self,
        destination: str | Path,
        *,
        allow_overwrite: bool = False,
    ) -> str: ...


class AdbTerminalProtocol(Protocol):
    def subscribe(self, listener: Callable[[TerminalEvent], None]) -> Callable[[], None]: ...

    def open(
        self,
        *,
        serial: str,
        expected_revision: int,
        columns: int,
        rows: int,
    ) -> TerminalCommandResult: ...

    def write(
        self,
        session_id: str,
        data: bytes,
        *,
        expected_revision: int,
    ) -> TerminalCommandResult: ...

    def resize(
        self,
        session_id: str,
        *,
        expected_revision: int,
        columns: int,
        rows: int,
    ) -> TerminalCommandResult: ...

    def close(
        self,
        session_id: str,
        *,
        expected_revision: int,
    ) -> TerminalCommandResult: ...


class ReplayAction(StrEnum):
    EXECUTE = "execute"
    WAIT = "wait"
    REPLAY = "replay"
    CONFLICT = "conflict"
    CAPACITY = "capacity"


_REPLAY_ENTRY_OVERHEAD_BYTES = 512
_REPLAY_MINIMUM_RESERVATION_BYTES = 2 * 1_024
_REPLAY_DEFAULT_MAXIMUM_BYTES = 128 * 1_024 * 1_024
_REPLAY_DEFAULT_RESERVATION_BYTES = 8 * 1_024 * 1_024
# A valid Logcat result can contain the same 16 MiB of bounded content in both
# ``lines`` and ``text``. JSON quoting can double ASCII-heavy input, so reserve
# four output windows plus envelope/array overhead before dispatching it.
_REPLAY_LOGCAT_RESERVATION_BYTES = 68 * 1_024 * 1_024
_REPLAY_DEFAULT_MAXIMUM_WAITERS = 4

_LOGCAT_PROGRESS_QUEUE_MAXIMUM_MESSAGES = 2_048
_LOGCAT_PROGRESS_QUEUE_MAXIMUM_BYTES = 32 * 1_024 * 1_024
_LOGCAT_PROGRESS_BATCH_MAXIMUM_MESSAGES = 128
# A projected ProgressEvent has one bounded public message.  Two MiB also
# covers the worst-case JSON escaping of that message while keeping each
# WebView script comfortably below the aggregate replay/result boundaries.
_LOGCAT_PROGRESS_BATCH_MAXIMUM_BYTES = 2 * 1_024 * 1_024


@dataclass(frozen=True, slots=True)
class _BatchedBridgeMessage:
    message: dict[str, Any] = field(repr=False)
    encoded_bytes: int


class _LogcatProgressBatcher:
    """Bounded FIFO that turns a logcat burst into one scheduled GUI flush."""

    def __init__(
        self,
        emit_batch: Callable[[Sequence[dict[str, Any]]], None],
        schedule_flush: Callable[[Callable[[], None]], None],
        *,
        is_gui_thread: Callable[[], bool] | None = None,
        maximum_messages: int = _LOGCAT_PROGRESS_QUEUE_MAXIMUM_MESSAGES,
        maximum_bytes: int = _LOGCAT_PROGRESS_QUEUE_MAXIMUM_BYTES,
        batch_maximum_messages: int = _LOGCAT_PROGRESS_BATCH_MAXIMUM_MESSAGES,
        batch_maximum_bytes: int = _LOGCAT_PROGRESS_BATCH_MAXIMUM_BYTES,
    ) -> None:
        if maximum_messages <= 0:
            raise ValueError("maximum_messages must be positive")
        if maximum_bytes <= 0:
            raise ValueError("maximum_bytes must be positive")
        if not 1 <= batch_maximum_messages <= maximum_messages:
            raise ValueError("batch_maximum_messages must fit within the queue")
        if not 1 <= batch_maximum_bytes <= maximum_bytes:
            raise ValueError("batch_maximum_bytes must fit within the queue")
        self._emit_batch = emit_batch
        self._schedule_flush = schedule_flush
        self._is_gui_thread = is_gui_thread or (lambda: threading.current_thread() is threading.main_thread())
        self._maximum_messages = maximum_messages
        self._maximum_bytes = maximum_bytes
        self._batch_maximum_messages = batch_maximum_messages
        self._batch_maximum_bytes = batch_maximum_bytes
        self._queue: deque[_BatchedBridgeMessage] = deque()
        self._queued_bytes = 0
        self._flush_scheduled = False
        self._closed = False
        self._condition = threading.Condition(threading.RLock())

    @property
    def queued_messages(self) -> int:
        with self._condition:
            return len(self._queue)

    @property
    def queued_bytes(self) -> int:
        with self._condition:
            return self._queued_bytes

    @property
    def flush_scheduled(self) -> bool:
        with self._condition:
            return self._flush_scheduled

    def enqueue(self, message: Mapping[str, Any]) -> bool:
        item = _prepare_batched_bridge_message(message)
        if item.encoded_bytes + 2 > self._batch_maximum_bytes:
            raise PublicProjectionError("logcat progress event exceeds the batch byte limit")
        gui_thread = self._is_gui_thread()
        while True:
            appended = False
            flush_inline = False
            schedule = False
            with self._condition:
                while not self._closed and not self._has_capacity(item):
                    if gui_thread:
                        flush_inline = True
                        break
                    # Backpressure is deliberate: the bounded producer may
                    # wait, but no device log event is evicted or coalesced.
                    self._condition.wait()
                if self._closed:
                    return False
                if not flush_inline:
                    self._queue.append(item)
                    self._queued_bytes += item.encoded_bytes
                    appended = True
                    if not self._flush_scheduled:
                        self._flush_scheduled = True
                        if gui_thread:
                            flush_inline = True
                        else:
                            schedule = True
            if flush_inline:
                self.flush()
                if schedule:
                    raise RuntimeError("logcat flush cannot be inline and scheduled")
                if appended:
                    return True
                # The queue was full before this item was appended.  The
                # synchronous GUI drain made room, so retry the insertion.
                continue
            if schedule:
                self._schedule_flush(self.flush)
            return True

    def flush(self) -> None:
        """Drain every queued item now, splitting only the WebView scripts."""

        while True:
            with self._condition:
                if self._closed:
                    self._flush_scheduled = False
                    return
                batch = self._take_batch_locked()
                if not batch:
                    # Empty and transition to unscheduled are atomic.  A
                    # producer arriving next will schedule exactly one new
                    # CallAfter, while a producer already present is consumed
                    # by this same callback before it returns.
                    self._flush_scheduled = False
                    self._condition.notify_all()
                    return
            self._emit_batch(tuple(item.message for item in batch))

    def close(self) -> None:
        with self._condition:
            self._closed = True
            self._queue.clear()
            self._queued_bytes = 0
            self._flush_scheduled = False
            self._condition.notify_all()

    def _has_capacity(self, item: _BatchedBridgeMessage) -> bool:
        return (
            len(self._queue) < self._maximum_messages and self._queued_bytes + item.encoded_bytes <= self._maximum_bytes
        )

    def _take_batch_locked(self) -> tuple[_BatchedBridgeMessage, ...]:
        batch: list[_BatchedBridgeMessage] = []
        batch_bytes = 2  # JSON array brackets.
        while self._queue and len(batch) < self._batch_maximum_messages:
            candidate = self._queue[0]
            separator_bytes = 1 if batch else 0
            if batch_bytes + separator_bytes + candidate.encoded_bytes > self._batch_maximum_bytes:
                break
            batch.append(self._queue.popleft())
            self._queued_bytes -= candidate.encoded_bytes
            batch_bytes += separator_bytes + candidate.encoded_bytes
        if self._queue and not batch:
            raise RuntimeError("queued logcat event cannot fit its configured batch")
        if batch:
            self._condition.notify_all()
        return tuple(batch)


def _prepare_batched_bridge_message(message: Mapping[str, Any]) -> _BatchedBridgeMessage:
    stable = _bounded_bridge_message(message)
    payload = _encode_bridge_message(stable)
    return _BatchedBridgeMessage(stable, len(payload.encode("ascii")))


def _bounded_bridge_message(message: Mapping[str, Any]) -> dict[str, Any]:
    bounded = _limit_bridge_payload(dict(message))
    if not isinstance(bounded, dict):
        raise PublicProjectionError("bridge message must remain an object")
    return cast("dict[str, Any]", bounded)


def _encode_bridge_message(message: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(message),
        ensure_ascii=True,
        separators=(",", ":"),
    )


def _schedule_wx_callback(callback: Callable[[], None]) -> None:
    call_after = cast("Callable[[Callable[[], None]], object]", vars(wx)["CallAfter"])
    call_after(callback)


@dataclass(frozen=True, slots=True)
class ReplayDecision:
    action: ReplayAction
    message: dict[str, Any] | None = field(default=None, repr=False)


@dataclass(slots=True)
class _InflightReplay:
    fingerprint: str
    reserved_bytes: int
    waiters: int = 0


@dataclass(frozen=True, slots=True)
class _CompletedReplay:
    fingerprint: str
    payload: bytes = field(repr=False)
    accounted_bytes: int


class _RequestReplayLedger:
    """Session-bounded requestId ledger for exact at-most-once dispatch."""

    def __init__(
        self,
        *,
        maximum_completed: int = 1_024,
        maximum_bytes: int = _REPLAY_DEFAULT_MAXIMUM_BYTES,
        default_reservation_bytes: int = _REPLAY_DEFAULT_RESERVATION_BYTES,
        logcat_reservation_bytes: int = _REPLAY_LOGCAT_RESERVATION_BYTES,
        maximum_waiters: int = _REPLAY_DEFAULT_MAXIMUM_WAITERS,
    ) -> None:
        if maximum_completed <= 0:
            raise ValueError("maximum_completed must be positive")
        if maximum_bytes <= 0:
            raise ValueError("maximum_bytes must be positive")
        if default_reservation_bytes < _REPLAY_MINIMUM_RESERVATION_BYTES:
            raise ValueError("default_reservation_bytes is below the safe minimum")
        if logcat_reservation_bytes < _REPLAY_MINIMUM_RESERVATION_BYTES:
            raise ValueError("logcat_reservation_bytes is below the safe minimum")
        if maximum_waiters < 0:
            raise ValueError("maximum_waiters must not be negative")
        self._maximum_completed = maximum_completed
        self._maximum_bytes = maximum_bytes
        self._default_reservation_bytes = default_reservation_bytes
        self._logcat_reservation_bytes = logcat_reservation_bytes
        self._maximum_waiters = maximum_waiters
        self._inflight: dict[str, _InflightReplay] = {}
        self._completed: OrderedDict[str, _CompletedReplay] = OrderedDict()
        self._reserved_bytes = 0
        self._completed_bytes = 0
        self._lock = threading.RLock()

    @property
    def reserved_bytes(self) -> int:
        with self._lock:
            return self._reserved_bytes

    @property
    def retained_bytes(self) -> int:
        with self._lock:
            return self._completed_bytes

    @property
    def accounted_bytes(self) -> int:
        with self._lock:
            return self._reserved_bytes + self._completed_bytes

    def begin(self, request: BridgeRequest) -> ReplayDecision:
        fingerprint = request.fingerprint()
        with self._lock:
            completed = self._completed.get(request.request_id)
            if completed is not None:
                if completed.fingerprint != fingerprint:
                    return ReplayDecision(ReplayAction.CONFLICT)
                self._completed.move_to_end(request.request_id)
                return ReplayDecision(
                    ReplayAction.REPLAY,
                    _decode_replay_payload(completed.payload),
                )

            inflight = self._inflight.get(request.request_id)
            if inflight is not None:
                if inflight.fingerprint != fingerprint:
                    return ReplayDecision(ReplayAction.CONFLICT)
                # Every duplicate has the same requestId on the same WebView
                # channel, so one terminal response is sufficient to resolve
                # callers beyond this bounded fan-out. Silently coalesce them
                # instead of emitting an early error that could reject the
                # original request while its operation is still running.
                if inflight.waiters < self._maximum_waiters:
                    inflight.waiters += 1
                return ReplayDecision(ReplayAction.WAIT)

            # Never evict an ID: eviction would make an old request executable
            # again. Once the bounded session ledger is full, fail closed and
            # require a new host session instead of weakening idempotency.
            if len(self._completed) + len(self._inflight) >= self._maximum_completed:
                return ReplayDecision(ReplayAction.CAPACITY)
            reservation = self._reservation_bytes(request)
            if self.accounted_bytes + reservation > self._maximum_bytes:
                return ReplayDecision(ReplayAction.CAPACITY)
            self._inflight[request.request_id] = _InflightReplay(
                fingerprint,
                reservation,
            )
            self._reserved_bytes += reservation
            return ReplayDecision(ReplayAction.EXECUTE)

    def complete(
        self,
        request: BridgeRequest,
        message: Mapping[str, Any],
    ) -> tuple[dict[str, Any], ...]:
        with self._lock:
            inflight = self._inflight.get(request.request_id)
            if inflight is None or inflight.fingerprint != request.fingerprint():
                raise RuntimeError("request replay ledger completion is inconsistent")
            bounded = _limit_bridge_payload(dict(message))
            if not isinstance(bounded, dict):
                raise TypeError("request replay payload must remain an object")
            stable_message = cast("dict[str, Any]", bounded)
            payload = _encode_replay_payload(stable_message)
            accounted_bytes = _accounted_replay_bytes(payload)
            base_bytes = self._completed_bytes + self._reserved_bytes - inflight.reserved_bytes
            if base_bytes + accounted_bytes > self._maximum_bytes:
                # The request has already crossed its at-most-once boundary.
                # Retain and replay a compact, explicit tombstone rather than
                # evicting the ID or allowing a later duplicate to execute it.
                stable_message = response_envelope(
                    request.request_id,
                    ok=False,
                    error={
                        "code": "response_replay_budget_exceeded",
                        "message": (
                            "The operation response exceeded the safe replay "
                            "budget. Its requestId remains consumed; do not retry it."
                        ),
                    },
                )
                payload = _encode_replay_payload(stable_message)
                accounted_bytes = _accounted_replay_bytes(payload)
                if accounted_bytes > inflight.reserved_bytes or base_bytes + accounted_bytes > self._maximum_bytes:
                    raise RuntimeError("reserved replay capacity cannot retain its failure tombstone")

            self._inflight.pop(request.request_id)
            self._reserved_bytes -= inflight.reserved_bytes
            completed = _CompletedReplay(
                inflight.fingerprint,
                payload,
                accounted_bytes,
            )
            self._completed[request.request_id] = completed
            self._completed.move_to_end(request.request_id)
            self._completed_bytes += accounted_bytes
            return tuple(dict(stable_message) for _ in range(inflight.waiters + 1))

    def clear(self) -> None:
        with self._lock:
            self._inflight.clear()
            self._completed.clear()
            self._reserved_bytes = 0
            self._completed_bytes = 0

    def _reservation_bytes(self, request: BridgeRequest) -> int:
        return self._logcat_reservation_bytes if request.command == "tools.logcat" else self._default_reservation_bytes


def _encode_replay_payload(message: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(message),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _decode_replay_payload(payload: bytes) -> dict[str, Any]:
    decoded: object = json.loads(payload)
    if not isinstance(decoded, dict):
        raise RuntimeError("stored request replay payload is not an object")
    decoded_mapping = cast("dict[object, object]", decoded)
    if any(not isinstance(key, str) for key in decoded_mapping):
        raise RuntimeError("stored request replay payload is not an object")
    return cast("dict[str, Any]", decoded_mapping)


def _accounted_replay_bytes(payload: bytes) -> int:
    return len(payload) + _REPLAY_ENTRY_OVERHEAD_BYTES


@dataclass(frozen=True, slots=True)
class _CommandWorkItem:
    request: BridgeRequest
    command: AppCommand = field(repr=False)


class _SerialCommandWorker:
    """One explicit FIFO worker; engine execution never blocks the wx loop."""

    def __init__(
        self,
        engine: EngineProtocol,
        deliver: Callable[[BridgeRequest, OperationResult | None], None],
    ) -> None:
        self._engine = engine
        self._deliver = deliver
        self._queue: Queue[_CommandWorkItem | None] = Queue()
        self._accepted_commands: dict[str, AppCommand] = {}
        self._closed = False
        self._lock = threading.RLock()
        self._thread = threading.Thread(
            target=self._run,
            name="pixelflasher-engine",
            # Engine shutdown cancels live work first. A wedged third-party
            # process boundary must never keep the native application alive
            # forever after its last window has closed.
            daemon=True,
        )
        self._thread.start()

    def submit(self, request: BridgeRequest, command: AppCommand) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("command worker has shut down")
            if command.operation_id in self._accepted_commands:
                raise RuntimeError("operation id is already accepted")
            self._accepted_commands[command.operation_id] = command
            self._queue.put(_CommandWorkItem(request, command))

    def cancel(self, operation_id: str) -> bool:
        """Cancel an accepted command before, during, or after engine handoff."""

        with self._lock:
            command = self._accepted_commands.get(operation_id)
            if command is None:
                return False
            # This is the same token CommandEngine registers. Cancellation
            # therefore cannot disappear in the queue-to-engine handoff.
            command.request_cancellation()
            return True

    @property
    def has_pending_commands(self) -> bool:
        with self._lock:
            return bool(self._accepted_commands)

    def shutdown(self, *, timeout_seconds: float = 10.0) -> bool:
        if timeout_seconds < 0:
            raise ValueError("timeout_seconds must not be negative")
        with self._lock:
            if self._closed:
                return not self._thread.is_alive()
            self._closed = True
            # Do not start queued commands while the application is closing.
            # The engine has already cancelled active work and rejects any
            # command that crosses its shutdown boundary.
            while True:
                try:
                    self._queue.get_nowait()
                except Empty:
                    break
            self._accepted_commands.clear()
            self._queue.put(None)
        self._thread.join(timeout_seconds)
        return not self._thread.is_alive()

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            outcome: OperationResult | None = None
            with self._lock:
                operation_id = item.command.operation_id
            try:
                cancellation_reason = item.command.cancellation_reason
                if cancellation_reason is CancellationReason.USER:
                    outcome = OperationResult.cancelled(
                        operation_id,
                        code="cancelled",
                        message="operation was cancelled while queued",
                    )
                elif cancellation_reason is CancellationReason.DEADLINE:
                    outcome = OperationResult.failed(
                        operation_id,
                        code="timed_out",
                        message="operation deadline expired while queued",
                    )
                else:
                    candidate = self._engine.execute(item.command)
                    if isinstance(candidate, OperationResult):
                        outcome = candidate
            except Exception:
                outcome = None
            finally:
                with self._lock:
                    self._accepted_commands.pop(operation_id, None)
            wx.CallAfter(self._deliver, item.request, outcome)


class FrontendAssetsNotFound(RuntimeError):
    pass


_UI_SMOKE_ROUTES = (
    "dashboard",
    "device",
    "flash",
    "firmware",
    "root",
    "apps",
    "backups",
    "tools",
    "settings",
)
_UI_SMOKE_SETTLE_MILLISECONDS = 75
_UI_SMOKE_SCRIPT_TOKEN = "pixelflasher-packaged-ui-smoke-v2"


def _decode_ui_smoke_script_result(output: str) -> dict[str, Any]:
    try:
        payload = json.loads(output)
        if isinstance(payload, str):
            payload = json.loads(payload)
    except (json.JSONDecodeError, TypeError) as exc:
        raise RuntimeError("WebView returned an invalid packaged UI smoke result") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(
            f"WebView returned a {type(payload).__name__} packaged UI smoke result"
        )
    unexpected_fields = set(payload) - {
        "ok",
        "code",
        "defaultPrevented",
        "route",
        "activeRoute",
        "headingFocused",
        "persistentDocument",
    }
    if unexpected_fields:
        raise RuntimeError(
            "WebView returned unexpected packaged UI smoke fields: "
            + ", ".join(sorted(str(field) for field in unexpected_fields))
        )
    if payload.get("ok") is not True:
        code = payload.get("code")
        raise RuntimeError(
            f"Packaged UI smoke failed: {code}"
            if isinstance(code, str) and code
            else "Packaged UI smoke failed"
        )
    return payload


def _extract_ui_smoke_script_output(output: str) -> str | None:
    try:
        payload = json.loads(output)
        if isinstance(payload, str):
            payload = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict) or payload.pop("smokeToken", None) != _UI_SMOKE_SCRIPT_TOKEN:
        return None
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _ui_smoke_initialization_script() -> str:
    return """(() => {
const shell = document.querySelector('.app-shell');
const routes = document.querySelectorAll('.task-nav button');
if (!shell || routes.length !== 9) {
return JSON.stringify({smokeToken:'pixelflasher-packaged-ui-smoke-v2',ok:false,code:'shell_contract_missing'});
}
window.__pixelflasherUiSmoke = {documentRef:document,shellRef:shell};
return JSON.stringify({smokeToken:'pixelflasher-packaged-ui-smoke-v2',ok:true});
})()"""


def _ui_smoke_navigation_script(index: int) -> str:
    key = index + 1
    return f"""(() => {{
const event = new KeyboardEvent('keydown', {{key:'{key}',altKey:true,bubbles:true,cancelable:true}});
window.dispatchEvent(event);
return JSON.stringify({{smokeToken:'pixelflasher-packaged-ui-smoke-v2',ok:true,defaultPrevented:event.defaultPrevented}});
}})()"""


def _ui_smoke_verification_script(route: str, index: int) -> str:
    encoded_route = json.dumps(route)
    return f"""(() => {{
const expectedRoute = {encoded_route};
const routes = Array.from(document.querySelectorAll('.task-nav button'));
const heading = document.querySelector('#main-content h1');
const marker = window.__pixelflasherUiSmoke;
return JSON.stringify({{
  smokeToken:'pixelflasher-packaged-ui-smoke-v2',
  ok:true,
  route:window.location.hash,
  activeRoute:routes[{index}]?.getAttribute('aria-current') === 'page',
  headingFocused:heading !== null && document.activeElement === heading,
  persistentDocument:Boolean(marker && marker.documentRef === document && marker.shellRef === document.querySelector('.app-shell')),
}});
}})()"""


def is_webview_available() -> bool:
    return _preferred_backend() is not None


def frontend_index_path() -> Path:
    """Resolve the bundled Vite entrypoint in source and frozen builds."""

    override = os.environ.get("PIXELFLASHER_WEB_DIST", "").strip()
    if override:
        candidate = Path(override).expanduser().resolve() / "index.html"
        if candidate.is_file():
            return candidate
        raise FrontendAssetsNotFound(f"Frontend index not found at {candidate}")

    roots: list[Path] = []
    frozen_root = vars(sys).get("_MEIPASS")
    if frozen_root:
        roots.append(Path(frozen_root))
    roots.append(Path(__file__).resolve().parents[2])

    for root in roots:
        candidate = root / "ui" / "web" / "dist" / "index.html"
        if candidate.is_file():
            return candidate

    checked = ", ".join(str(root / "ui" / "web" / "dist" / "index.html") for root in roots)
    raise FrontendAssetsNotFound("The React application has not been built. Expected index.html at: " + checked)


def create_modern_webview_frame(
    engine: EngineProtocol,
    *,
    adb_terminal_service: AdbTerminalProtocol,
    command_factory: CoreCommandFactory,
    support_destination_registrar: SupportDestinationRegistrar,
    application_directories: Mapping[str, str | Path] | None = None,
    bridge_ready_callback: Callable[[int], None] | None = None,
    parent: wx.Window | None = None,
    index_path: Path | None = None,
) -> ModernWebViewFrame:
    if not is_webview_available():
        raise RuntimeError("wx WebView is unavailable. Install the platform WebView runtime first.")
    return ModernWebViewFrame(
        engine=engine,
        adb_terminal_service=adb_terminal_service,
        command_factory=command_factory,
        support_destination_registrar=support_destination_registrar,
        application_directories=application_directories,
        bridge_ready_callback=bridge_ready_callback,
        parent=parent,
        index_path=index_path,
    )


class ModernWebViewFrame(wx.Frame):
    """One native window containing one persistent React document."""

    def __init__(
        self,
        *,
        engine: EngineProtocol,
        adb_terminal_service: AdbTerminalProtocol,
        command_factory: CoreCommandFactory,
        support_destination_registrar: SupportDestinationRegistrar,
        application_directories: Mapping[str, str | Path] | None = None,
        bridge_ready_callback: Callable[[int], None] | None = None,
        parent: wx.Window | None = None,
        index_path: Path | None = None,
    ) -> None:
        super().__init__(
            parent,
            title=f"{APPNAME} {VERSION}",
            size=(1536, 960),
            style=wx.DEFAULT_FRAME_STYLE | wx.CLIP_CHILDREN,
        )
        self.SetMinSize((960, 640))
        self.SetBackgroundColour(wx.Colour("#08111f"))
        _apply_frame_icon(self)

        self._engine = engine
        self._adb_terminal_service = adb_terminal_service
        self._command_factory = command_factory
        self._index_path = (index_path or frontend_index_path()).resolve()
        self._asset_root = self._index_path.parent
        self._application_directories = {
            target: Path(path).expanduser().absolute()
            for target, path in (application_directories or {}).items()
            if target in {"configuration", "logs", "cache"}
        }
        self._loaded = False
        self._closing = False
        self._bridge_ready_callback = bridge_ready_callback
        self._bridge_ready_signalled = False
        self._ui_smoke_in_progress = False
        self._ui_smoke_timer: object | None = None
        self._ui_smoke_script_callback: Callable[[str], None] | None = None
        self._pending_messages: list[dict[str, Any]] = []
        self._logcat_progress_batcher = _LogcatProgressBatcher(
            self._emit_batch,
            _schedule_wx_callback,
        )
        self._terminal_event_batcher = _LogcatProgressBatcher(
            self._emit_batch,
            _schedule_wx_callback,
        )
        self._replay_ledger = _RequestReplayLedger()
        self._operation_commands: dict[str, str] = {}
        self._operation_commands_lock = threading.RLock()
        self._subscription: Callable[[], None] | None = None
        self._terminal_subscription: Callable[[], None] | None = None
        self._command_factory.bind_support_destination_registrar(support_destination_registrar)
        self._command_worker = _SerialCommandWorker(self._engine, self._command_finished)

        backend = _preferred_backend()
        if backend is None:
            raise RuntimeError("wx WebView backend is unavailable")
        self._view = html2.WebView.New(self, backend=backend, style=wx.BORDER_NONE)  # type: ignore[union-attr]
        if not self._view.AddScriptMessageHandler(BRIDGE_CHANNEL):
            raise RuntimeError(f"Unable to register WebView message handler {BRIDGE_CHANNEL!r}")

        self._view.Bind(html2.EVT_WEBVIEW_SCRIPT_MESSAGE_RECEIVED, self._on_script_message)  # type: ignore[union-attr]
        self._view.Bind(html2.EVT_WEBVIEW_LOADED, self._on_loaded)  # type: ignore[union-attr]
        self._view.Bind(html2.EVT_WEBVIEW_NAVIGATING, self._on_navigating)  # type: ignore[union-attr]
        self._view.Bind(html2.EVT_WEBVIEW_ERROR, self._on_load_error)  # type: ignore[union-attr]
        self._view.Bind(html2.EVT_WEBVIEW_SCRIPT_RESULT, self._on_script_result)  # type: ignore[union-attr]
        self.Bind(wx.EVT_CLOSE, self._on_close)

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._view, 1, wx.EXPAND)
        self.SetSizer(sizer)
        self.Centre()

        self._subscription = self._engine.subscribe(self._on_engine_event)
        self._terminal_subscription = self._adb_terminal_service.subscribe(
            self._on_terminal_event
        )
        self._view.LoadURL(self._index_path.as_uri())

    def _on_loaded(self, event: object) -> None:
        if self._loaded:
            return
        self._loaded = True
        self._emit(
            event_envelope(
                "runtime",
                {"status": "ready", "version": VERSION},
                revision=_revision(self._engine.snapshot()),
            )
        )
        self._emit_snapshot()
        queued, self._pending_messages = self._pending_messages, []
        for message in queued:
            self._emit(message)

    def _on_load_error(self, event: object) -> None:
        message = "The local PixelFlasher interface could not be loaded."
        detail = str(event.GetString() or "").strip()  # type: ignore[attr-defined]
        if detail:
            message = f"{message} {detail}"
        wx.LogError(message)

    def _on_script_result(self, event: object) -> None:
        output = _extract_ui_smoke_script_output(str(event.GetString()))  # type: ignore[attr-defined]
        if output is None:
            event.Skip()  # type: ignore[attr-defined]
            return
        callback, self._ui_smoke_script_callback = self._ui_smoke_script_callback, None
        if callback is None:
            return
        callback(output)

    def _on_navigating(self, event: object) -> None:
        url = str(event.GetURL())  # type: ignore[attr-defined]
        if _is_allowed_local_url(url, self._asset_root):
            return
        event.Veto()  # type: ignore[attr-defined]
        self._emit(
            event_envelope(
                "runtime",
                {"status": "navigationBlocked", "message": "Navigation stayed inside PixelFlasher."},
                revision=_revision(self._engine.snapshot()),
            )
        )

    def _on_script_message(self, event: object) -> None:
        raw = str(event.GetString())  # type: ignore[attr-defined]
        try:
            request = BridgeRequest.from_json(raw)
        except BridgeProtocolError as exc:
            self._emit(protocol_error_envelope(exc))
            return

        replay = self._replay_ledger.begin(request)
        if replay.action is ReplayAction.REPLAY:
            if replay.message is not None:
                self._emit(replay.message)
            return
        if replay.action is ReplayAction.WAIT:
            return
        if replay.action is ReplayAction.CONFLICT:
            self._emit(
                response_envelope(
                    request.request_id,
                    ok=False,
                    error={
                        "code": "request_id_reused",
                        "message": "requestId was already used for a different request.",
                    },
                )
            )
            return
        if replay.action is ReplayAction.CAPACITY:
            self._emit(
                response_envelope(
                    request.request_id,
                    ok=False,
                    error={
                        "code": "request_ledger_full",
                        "message": (
                            "The request ledger reached its safe session ID or memory limit; "
                            "restart PixelFlasher before sending more commands."
                        ),
                    },
                )
            )
            return

        self._dispatch_request(request)

    def _dispatch_request(self, request: BridgeRequest) -> None:

        if request.command == "secret.issue":
            self._handle_secret_issue(request)
            return
        if request.command in {"app.console.export", "app.openFolder", "app.openLink", "app.exit"}:
            self._handle_application_request(request)
            return
        if request.command.startswith("native."):
            self._handle_native_request(request)
            return
        if request.command == "tools.adbShell" or request.command.startswith(
            "tools.adbShell."
        ):
            self._handle_adb_terminal_request(request)
            return
        if request.command == "app.ready":
            revision = _revision(self._engine.snapshot())
            self._complete_request(
                request,
                response_envelope(
                    request.request_id,
                    ok=True,
                    result={
                        "status": "SUCCESS",
                        "message": "Bridge ready.",
                        "version": VERSION,
                        "revision": revision,
                    },
                ),
            )
            self._emit_snapshot()
            self._signal_bridge_ready(revision)
            return
        if request.command == "snapshot.get":
            snapshot = self._engine.snapshot()
            self._complete_request(
                request,
                response_envelope(
                    request.request_id,
                    ok=True,
                    result=_mapping(snapshot),
                ),
            )
            return
        if request.command == "operation.cancel":
            self._handle_operation_cancel(request)
            return
        if request.command == "interaction.respond":
            self._handle_interaction_response(request)
            return

        try:
            command = self._command_factory(request)
        except (BridgeProtocolError, CommandFactoryError) as exc:
            code = exc.code
            self._complete_request(
                request,
                response_envelope(
                    request.request_id,
                    ok=False,
                    error={
                        "code": code,
                        "message": safe_public_message(
                            str(exc),
                            fallback="The command payload is invalid.",
                        ),
                    },
                ),
            )
            return
        except Exception:
            self._complete_request(
                request,
                response_envelope(
                    request.request_id,
                    ok=False,
                    error={"code": "invalid_command", "message": "The command payload is invalid."},
                ),
            )
            return

        with self._operation_commands_lock:
            self._operation_commands[command.operation_id] = request.command
        try:
            self._command_worker.submit(request, command)
        except RuntimeError:
            with self._operation_commands_lock:
                self._operation_commands.pop(command.operation_id, None)
            self._complete_request(
                request,
                response_envelope(
                    request.request_id,
                    ok=False,
                    error={"code": "engine_shutdown", "message": "The engine has shut down."},
                ),
            )

    def _handle_operation_cancel(self, request: BridgeRequest) -> None:
        operation_id = request.payload.get("operationId")
        if isinstance(operation_id, str):
            worker_cancelled = self._command_worker.cancel(operation_id)
            # Always notify the engine as well. ApplicationRuntime uses this
            # path to wake a pending InteractionBroker confirmation in addition
            # to cancelling the shared command token.
            engine_acknowledgement = self._engine.cancel(operation_id)
            acknowledgement = (
                CommandAck(True, "cancellation_requested", "Cancellation requested.")
                if worker_cancelled or engine_acknowledgement.accepted
                else engine_acknowledgement
            )
        else:
            acknowledgement = CommandAck(
                False,
                "invalid_operation_id",
                "Operation ID is required.",
            )
        accepted = acknowledgement.accepted
        acknowledgement_message = safe_public_message(
            acknowledgement.message,
            fallback="The cancellation request could not be completed.",
        )
        self._complete_request(
            request,
            response_envelope(
                request.request_id,
                ok=accepted,
                result={
                    "status": "SUCCESS" if accepted else "FAILED",
                    "code": acknowledgement.code,
                    "message": acknowledgement_message,
                    "revision": _revision(self._engine.snapshot()),
                },
                error={}
                if accepted
                else {
                    "code": acknowledgement.code,
                    "message": acknowledgement_message,
                },
            ),
        )

    def _handle_interaction_response(self, request: BridgeRequest) -> None:
        operation_id = request.payload.get("operationId")
        decision = request.payload.get("decision")
        acknowledgement = CommandAck(
            False,
            "invalid_interaction_response",
            "The interaction response is invalid.",
        )
        if (
            isinstance(operation_id, str)
            and decision in {"accepted", "cancelled"}
            and isinstance(request.expected_revision, int)
            and not isinstance(request.expected_revision, bool)
        ):
            acknowledgement = self._engine.respond_interaction(
                operation_id,
                InteractionResponse(
                    InteractionDecision(decision),
                    request.expected_revision,
                ),
            )
        accepted = acknowledgement.accepted
        acknowledgement_message = safe_public_message(
            acknowledgement.message,
            fallback="The interaction response could not be completed.",
        )
        self._complete_request(
            request,
            response_envelope(
                request.request_id,
                ok=accepted,
                result={
                    "status": "SUCCESS" if accepted else "FAILED",
                    "code": acknowledgement.code,
                    "message": acknowledgement_message,
                    "revision": _revision(self._engine.snapshot()),
                },
                error={}
                if accepted
                else {
                    "code": acknowledgement.code,
                    "message": acknowledgement_message,
                },
            ),
        )

    def _command_finished(
        self,
        request: BridgeRequest,
        result: OperationResult | None,
    ) -> None:
        if self._closing:
            return
        try:
            if not isinstance(result, OperationResult):
                raise TypeError("engine returned a non-OperationResult value")
            serialized = project_operation_result(request.command, result)
            status = str(serialized.get("status", "FAILED")).upper()
            ok = status == "SUCCESS"
            serialized["revision"] = _revision(self._engine.snapshot())
            error = {}
            if status == "FAILED":
                error = {
                    "code": str(serialized.get("code", "operation_failed")),
                    "message": str(serialized.get("message", "Operation failed.")),
                    "details": serialized,
                }
            elif status == "CANCELLED":
                error = {
                    "code": str(serialized.get("code", "operation_cancelled")),
                    "message": str(serialized.get("message", "Operation cancelled.")),
                    "details": serialized,
                }
            message = response_envelope(
                request.request_id,
                ok=ok,
                result=serialized,
                error=error,
            )
        except PublicProjectionError:
            message = response_envelope(
                request.request_id,
                ok=False,
                error={
                    "code": "public_result_invalid",
                    "message": "The operation returned an invalid public result.",
                },
            )
        except Exception:
            message = response_envelope(
                request.request_id,
                ok=False,
                error={"code": "engine_error", "message": "The operation could not be completed."},
            )
        with self._operation_commands_lock:
            if isinstance(result, OperationResult):
                self._operation_commands.pop(result.operation_id, None)
        self._complete_request(request, message)
        self._emit_snapshot()

    def _handle_native_request(self, request: BridgeRequest) -> None:
        try:
            self._command_factory.validate_native_request(request)
            selection = _run_native_picker(self, request.command, request.payload)
            if selection.cancelled:
                result = _cancelled_selection()
            else:
                data = self._command_factory.issue_native_grants(request, selection.paths)
                result = {
                    "status": "SUCCESS",
                    "message": "Native resource selected.",
                    "data": data,
                }
        except (BridgeProtocolError, CommandFactoryError) as exc:
            result = {
                "status": "FAILED",
                "code": exc.code,
                "message": safe_public_message(
                    str(exc),
                    fallback="The native resource selection is invalid.",
                ),
                "data": {},
            }
        except Exception:
            result = {
                "status": "FAILED",
                "code": "native_selection_invalid",
                "message": "The native resource selection is invalid.",
                "data": {},
            }
        status = str(result.get("status", "FAILED"))
        if status == "SUCCESS":
            result["revision"] = _revision(self._engine.snapshot())
        self._complete_request(
            request,
            response_envelope(
                request.request_id,
                ok=status == "SUCCESS",
                result=result,
                error={}
                if status == "SUCCESS"
                else {
                    "code": str(result.get("code", "operation_cancelled")),
                    "message": str(result.get("message", "Selection cancelled.")),
                    "details": result,
                },
            ),
        )

    def _handle_adb_terminal_request(self, request: BridgeRequest) -> None:
        result: TerminalCommandResult
        revision = request.expected_revision
        if not isinstance(revision, int) or isinstance(revision, bool):
            result = TerminalCommandResult(
                False,
                "revision_required",
                "Expected revision is required for ADB Shell.",
            )
        else:
            payload = request.payload
            try:
                if request.command == "tools.adbShell":
                    serial = payload["serial"]
                    columns = payload["columns"]
                    rows = payload["rows"]
                    if (
                        not isinstance(serial, str)
                        or not isinstance(columns, int)
                        or isinstance(columns, bool)
                        or not isinstance(rows, int)
                        or isinstance(rows, bool)
                    ):
                        raise TypeError
                    result = self._adb_terminal_service.open(
                        serial=serial,
                        expected_revision=revision,
                        columns=columns,
                        rows=rows,
                    )
                else:
                    session_id = payload["sessionId"]
                    if not isinstance(session_id, str):
                        raise TypeError
                    if request.command == "tools.adbShell.write":
                        data = payload["data"]
                        if not isinstance(data, str):
                            raise TypeError
                        result = self._adb_terminal_service.write(
                            session_id,
                            data.encode("utf-8", errors="strict"),
                            expected_revision=revision,
                        )
                    elif request.command == "tools.adbShell.resize":
                        columns = payload["columns"]
                        rows = payload["rows"]
                        if (
                            not isinstance(columns, int)
                            or isinstance(columns, bool)
                            or not isinstance(rows, int)
                            or isinstance(rows, bool)
                        ):
                            raise TypeError
                        result = self._adb_terminal_service.resize(
                            session_id,
                            expected_revision=revision,
                            columns=columns,
                            rows=rows,
                        )
                    elif request.command == "tools.adbShell.close":
                        result = self._adb_terminal_service.close(
                            session_id,
                            expected_revision=revision,
                        )
                    else:  # pragma: no cover - registry and dispatcher are closed
                        raise TypeError
            except (KeyError, TypeError, UnicodeError):
                result = TerminalCommandResult(
                    False,
                    "terminal_payload_invalid",
                    "ADB Shell request payload is invalid.",
                )
        public_result: dict[str, object] = result.to_public_dict()
        public_result["status"] = "SUCCESS" if result.accepted else "FAILED"
        public_result["revision"] = _revision(self._engine.snapshot())
        self._complete_request(
            request,
            response_envelope(
                request.request_id,
                ok=result.accepted,
                result=public_result,
                error={}
                if result.accepted
                else {
                    "code": result.code,
                    "message": result.message,
                    "details": public_result,
                },
            ),
        )

    def _handle_application_request(self, request: BridgeRequest) -> None:
        snapshot = self._engine.snapshot()
        if request.expected_revision != snapshot.revision:
            self._complete_request(
                request,
                response_envelope(
                    request.request_id,
                    ok=False,
                    error={
                        "code": "revision_conflict",
                        "message": "Application state changed before the shell action.",
                    },
                ),
            )
            return

        if request.command == "app.console.export":
            lines = request.payload.get("lines")
            if not isinstance(lines, list):
                self._complete_request(
                    request,
                    response_envelope(
                        request.request_id,
                        ok=False,
                        error={
                            "code": "console_export_invalid",
                            "message": "The console export is invalid.",
                        },
                    ),
                )
                return
            safe_lines = [
                safe_public_message(line, fallback="Operation update.")
                for line in lines
            ]
            if safe_lines != lines:
                self._complete_request(
                    request,
                    response_envelope(
                        request.request_id,
                        ok=False,
                        error={
                            "code": "console_export_not_redacted",
                            "message": "The console export contains unsafe content.",
                        },
                    ),
                )
                return
            try:
                destination = self._command_factory.resolve_application_console_export(
                    request.payload.get("grant")
                )
                if not destination.name.casefold().endswith(".txt"):
                    raise CommandFactoryError(
                        "console_export_extension_invalid",
                        "The console export must use the .txt extension.",
                    )
                payload = ("\n".join(safe_lines) + "\n").encode("utf-8")
                with destination.begin_atomic_replace() as transaction:
                    transaction.stream.write(payload)
                    transaction.stream.flush()
                    os.fsync(transaction.stream.fileno())
                    transaction.commit()
                    with transaction.open_committed() as committed:
                        if committed.read() != payload:
                            raise OSError("committed console export differs from payload")
            except CommandFactoryError as exc:
                code = exc.code
                message = safe_public_message(
                    str(exc),
                    fallback="The console export could not be written.",
                )
            except Exception:
                code = "console_export_failed"
                message = "The console export could not be written."
            else:
                self._complete_request(
                    request,
                    response_envelope(
                        request.request_id,
                        ok=True,
                        result={
                            "status": "SUCCESS",
                            "code": "console_exported",
                            "message": "Redacted console exported.",
                            "lineCount": len(safe_lines),
                            "byteCount": len(payload),
                            "revision": snapshot.revision,
                        },
                    ),
                )
                return
            self._complete_request(
                request,
                response_envelope(
                    request.request_id,
                    ok=False,
                    error={"code": code, "message": message},
                ),
            )
            return

        if request.command == "app.openFolder":
            target = request.payload.get("target")
            directory = self._application_directories.get(
                target if isinstance(target, str) else ""
            )
            if directory is None or directory.is_symlink() or not directory.is_dir():
                self._complete_request(
                    request,
                    response_envelope(
                        request.request_id,
                        ok=False,
                        error={
                            "code": "application_directory_unavailable",
                            "message": "The requested application folder is unavailable.",
                        },
                    ),
                )
                return
            try:
                open_path(directory)
            except Exception:
                self._complete_request(
                    request,
                    response_envelope(
                        request.request_id,
                        ok=False,
                        error={
                            "code": "application_directory_open_failed",
                            "message": "The application folder could not be opened.",
                        },
                    ),
                )
                return
            self._complete_request(
                request,
                response_envelope(
                    request.request_id,
                    ok=True,
                    result={
                        "status": "SUCCESS",
                        "code": "application_directory_opened",
                        "message": "Application folder opened.",
                        "target": target,
                        "revision": snapshot.revision,
                    },
                ),
            )
            return

        if request.command == "app.openLink":
            target = request.payload.get("target")
            url = _APPLICATION_LINKS.get(target if isinstance(target, str) else "")
            if url is None:
                self._complete_request(
                    request,
                    response_envelope(
                        request.request_id,
                        ok=False,
                        error={
                            "code": "application_link_unavailable",
                            "message": "The requested application link is unavailable.",
                        },
                    ),
                )
                return
            try:
                opened = webbrowser.open(url, new=2)
            except Exception:
                opened = False
            if not opened:
                self._complete_request(
                    request,
                    response_envelope(
                        request.request_id,
                        ok=False,
                        error={
                            "code": "application_link_open_failed",
                            "message": "The application link could not be opened.",
                        },
                    ),
                )
                return
            self._complete_request(
                request,
                response_envelope(
                    request.request_id,
                    ok=True,
                    result={
                        "status": "SUCCESS",
                        "code": "application_link_opened",
                        "message": "Application link opened.",
                        "target": target,
                        "revision": snapshot.revision,
                    },
                ),
            )
            return

        if self._has_active_work(snapshot):
            self._complete_request(
                request,
                response_envelope(
                    request.request_id,
                    ok=False,
                    error={
                        "code": "operation_active",
                        "message": "Cancel or finish the active operation before exiting PixelFlasher.",
                    },
                ),
            )
            return
        self._complete_request(
            request,
            response_envelope(
                request.request_id,
                ok=True,
                result={
                    "status": "SUCCESS",
                    "code": "exit_requested",
                    "message": "PixelFlasher is closing.",
                    "revision": snapshot.revision,
                },
            ),
        )
        wx.CallAfter(self.Close)

    def _has_active_work(self, snapshot: AppSnapshot | None = None) -> bool:
        current = snapshot or self._engine.snapshot()
        return current.active_operation is not None or self._command_worker.has_pending_commands

    def _handle_secret_issue(self, request: BridgeRequest) -> None:
        try:
            data = self._command_factory.issue_secret(request)
            result = {
                "status": "SUCCESS",
                "message": "Secret grant issued.",
                "data": data,
                "revision": _revision(self._engine.snapshot()),
            }
            message = response_envelope(request.request_id, ok=True, result=result)
        except (BridgeProtocolError, CommandFactoryError) as exc:
            message = response_envelope(
                request.request_id,
                ok=False,
                error={
                    "code": exc.code,
                    "message": safe_public_message(
                        str(exc),
                        fallback="The secret grant could not be issued.",
                    ),
                },
            )
        except Exception:
            message = response_envelope(
                request.request_id,
                ok=False,
                error={"code": "secret_issue_failed", "message": "The secret grant could not be issued."},
            )
        self._complete_request(request, message)

    def _on_engine_event(self, event: AppEvent) -> None:
        if self._closing:
            return
        revision = _revision(self._engine.snapshot())
        batch_logcat_progress = False
        if isinstance(event, SnapshotChanged):
            event_type = "snapshot"
            payload = _mapping(event.snapshot)
            revision = event.revision
        elif isinstance(event, ProgressEvent):
            event_type = "progress"
            payload = _mapping(event)
            with self._operation_commands_lock:
                batch_logcat_progress = self._operation_commands.get(event.operation_id) == "tools.logcat"
        elif isinstance(event, InteractionRequest):
            event_type = "interaction"
            payload = _mapping(event)
        elif isinstance(event, OperationFinished):
            event_type = "runtime"
            with self._operation_commands_lock:
                command = self._operation_commands.get(event.result.operation_id)
            if command in {
                "tools.logcat",
                "tools.logcat.clear",
                "tools.wifi.discover",
            }:
                # Discovery endpoints and high-volume device logs belong only
                # to their correlated request. The terminal runtime event
                # carries status and never rebroadcasts either payload.
                payload = public_operation_summary(event.result)
            else:
                payload = (
                    project_operation_result(command, event.result) if command is not None else _mapping(event.result)
                )
        else:
            return
        message = event_envelope(
            event_type,
            payload,
            revision=revision,
        )
        if batch_logcat_progress:
            self._logcat_progress_batcher.enqueue(message)
        elif threading.current_thread() is threading.main_thread():
            self._emit(message)
        else:
            wx.CallAfter(self._emit, message)

    def _on_terminal_event(self, event: TerminalEvent) -> None:
        message = event_envelope(
            "terminal",
            event.to_public_dict(),
            revision=_revision(self._engine.snapshot()),
        )
        self._terminal_event_batcher.enqueue(message)

    def _emit_snapshot(self) -> None:
        snapshot = self._engine.snapshot()
        self._emit(
            event_envelope(
                "snapshot",
                _mapping(snapshot),
                revision=_revision(snapshot),
            )
        )

    def _signal_bridge_ready(self, revision: int) -> None:
        callback = self._bridge_ready_callback
        if callback is None or self._bridge_ready_signalled:
            return
        self._bridge_ready_signalled = True
        callback(revision)

    def run_packaged_ui_smoke(
        self,
        callback: Callable[[dict[str, Any] | None, str | None], None],
    ) -> None:
        """Exercise the real React document through its public keyboard surface."""

        if self._closing:
            callback(None, "The native host began closing before the packaged UI journey")
            return
        if not self._bridge_ready_signalled:
            callback(None, "Bridge v2 was not ready for the packaged UI journey")
            return
        if self._ui_smoke_in_progress:
            callback(None, "A packaged UI journey is already running")
            return
        self._ui_smoke_in_progress = True
        visited: list[str] = []

        def finish(result: dict[str, Any] | None, error: str | None) -> None:
            if not self._ui_smoke_in_progress:
                return
            self._ui_smoke_in_progress = False
            self._ui_smoke_timer = None
            callback(result, error)

        def fail(exc: Exception) -> None:
            finish(None, str(exc))

        def verify_route(index: int) -> None:
            def verified(output: str) -> None:
                try:
                    route = _UI_SMOKE_ROUTES[index]
                    result = _decode_ui_smoke_script_result(output)
                    if result.get("route") != f"#/{route}":
                        raise RuntimeError(f"Packaged UI did not navigate to {route}")
                    if result.get("activeRoute") is not True:
                        raise RuntimeError(f"Packaged UI did not mark {route} active")
                    if result.get("headingFocused") is not True:
                        raise RuntimeError(f"Packaged UI did not transfer focus on {route}")
                    if result.get("persistentDocument") is not True:
                        raise RuntimeError("Packaged UI replaced its React document")
                    visited.append(route)
                    visit_route(index + 1)
                except Exception as exc:
                    fail(exc)

            try:
                route = _UI_SMOKE_ROUTES[index]
                self._run_ui_smoke_script(
                    _ui_smoke_verification_script(route, index),
                    verified,
                )
            except Exception as exc:
                fail(exc)

        def visit_route(index: int) -> None:
            if index >= len(_UI_SMOKE_ROUTES):
                finish(
                    {
                        "taskRoutes": list(visited),
                        "keyboardRouteNavigation": True,
                        "focusTransferredToHeading": True,
                        "persistentDocument": True,
                    },
                    None,
                )
                return
            try:
                def navigated(output: str) -> None:
                    try:
                        result = _decode_ui_smoke_script_result(output)
                        if result.get("defaultPrevented") is not True:
                            raise RuntimeError("Packaged UI keyboard shortcut was not handled")
                        self._ui_smoke_timer = wx.CallLater(
                            _UI_SMOKE_SETTLE_MILLISECONDS,
                            verify_route,
                            index,
                        )
                    except Exception as exc:
                        fail(exc)

                self._run_ui_smoke_script(_ui_smoke_navigation_script(index), navigated)
            except Exception as exc:
                fail(exc)

        try:
            def initialized(output: str) -> None:
                try:
                    _decode_ui_smoke_script_result(output)
                    visit_route(0)
                except Exception as exc:
                    fail(exc)

            self._run_ui_smoke_script(_ui_smoke_initialization_script(), initialized)
        except Exception as exc:
            fail(exc)

    def _run_ui_smoke_script(self, script: str, callback: Callable[[str], None]) -> None:
        if self._ui_smoke_script_callback is not None:
            raise RuntimeError("A packaged UI smoke script is already pending")
        if sys.platform.startswith("linux"):
            success, output = self._view.RunScript(script)
            if not success:
                raise RuntimeError("WebKit could not execute a packaged UI smoke script")
            callback(str(output))
            return
        self._ui_smoke_script_callback = callback
        self._view.RunScriptAsync(script)

    def _complete_request(
        self,
        request: BridgeRequest,
        message: Mapping[str, Any],
    ) -> None:
        public_message = ensure_public_json(message)
        if not isinstance(public_message, dict):
            raise PublicProjectionError("bridge response must be a public JSON object")
        for replay_message in self._replay_ledger.complete(request, public_message):
            self._emit(replay_message)

    def _emit(self, message: dict[str, Any]) -> None:
        if self._closing:
            return
        if not self._loaded:
            self._pending_messages.append(message)
            return
        payload = _encode_bridge_message(_bounded_bridge_message(message))
        script = f"window.dispatchEvent(new CustomEvent('pixelflasher:message',{{detail:{payload}}}));"
        self._view.RunScriptAsync(script)

    def _emit_batch(self, messages: Sequence[dict[str, Any]]) -> None:
        if self._closing or not messages:
            return
        if len(messages) > _LOGCAT_PROGRESS_BATCH_MAXIMUM_MESSAGES:
            raise ValueError("bridge event batch exceeds its message limit")
        bounded_messages: list[dict[str, Any]] = []
        payloads: list[str] = []
        for message in messages:
            stable = _bounded_bridge_message(message)
            bounded_messages.append(stable)
            payloads.append(_encode_bridge_message(stable))
        payload = f"[{','.join(payloads)}]"
        if len(payload.encode("ascii")) > _LOGCAT_PROGRESS_BATCH_MAXIMUM_BYTES:
            raise ValueError("bridge event batch exceeds its byte limit")
        if not self._loaded:
            self._pending_messages.extend(bounded_messages)
            return
        script = (
            f"for(const detail of {payload})"
            "{window.dispatchEvent(new CustomEvent('pixelflasher:message',{detail}));}"
        )
        self._view.RunScriptAsync(script)

    def _on_close(self, event: wx.CloseEvent) -> None:
        if self._closing:
            event.Skip()
            return
        if self._has_active_work() and event.CanVeto():
            event.Veto()
            self._emit(
                event_envelope(
                    "runtime",
                    {
                        "status": "exitBlocked",
                        "message": "Cancel or finish the active operation before exiting PixelFlasher.",
                    },
                    revision=_revision(self._engine.snapshot()),
                )
            )
            return
        self._closing = True
        self._ui_smoke_script_callback = None
        if self._ui_smoke_timer is not None:
            self._ui_smoke_timer.Stop()  # type: ignore[attr-defined]
            self._ui_smoke_timer = None
        # Wake a producer held by bounded logcat backpressure before engine
        # shutdown waits for the worker.  Pending UI-only events are discarded
        # at this explicit session boundary.
        self._logcat_progress_batcher.close()
        self._terminal_event_batcher.close()
        if self._subscription is not None:
            self._subscription()
        if self._terminal_subscription is not None:
            self._terminal_subscription()
        try:
            self._engine.shutdown()
        finally:
            stopped = self._command_worker.shutdown()
            if not stopped:
                wx.LogWarning("PixelFlasher's operation worker did not stop within the shutdown timeout.")
            self._command_factory.path_grants.clear()
            self._command_factory.secret_grants.clear()
            self._command_factory.clear_transient_resources()
            with self._operation_commands_lock:
                self._operation_commands.clear()
            self._replay_ledger.clear()
            event.Skip()


def _preferred_backend() -> str | None:
    if html2 is None:
        return None
    module_values = vars(html2)
    edge = module_values.get("WebViewBackendEdge", "")
    if edge:
        try:
            if html2.WebView.IsBackendAvailable(edge):
                return edge
        except Exception:
            pass
    default = module_values.get("WebViewBackendDefault", "")
    try:
        if html2.WebView.IsBackendAvailable(default):
            return default
    except Exception:
        return None
    return None


def _is_allowed_local_url(url: str, asset_root: Path) -> bool:
    if not url or url in {"about:blank", "about:srcdoc"}:
        return True
    parsed = urlparse(url)
    if parsed.scheme != "file" or parsed.netloc:
        return False
    try:
        path_text = unquote(parsed.path)
        if sys.platform == "win32" and path_text.startswith("/"):
            path_text = path_text[1:]
        candidate = Path(path_text).resolve()
        candidate.relative_to(asset_root.resolve())
        return True
    except (OSError, ValueError):
        return False


@dataclass(frozen=True, slots=True)
class _NativePickerSelection:
    paths: tuple[Path, ...] = field(default=(), repr=False)

    @property
    def cancelled(self) -> bool:
        return not self.paths


def _run_native_picker(
    parent: wx.Window,
    command: str,
    payload: Mapping[str, Any],
) -> _NativePickerSelection:
    title = str(payload.get("title") or "Choose a file")[:160]

    if command == "native.pickDirectory":
        dialog = wx.DirDialog(parent, title, style=wx.DD_DEFAULT_STYLE)
        try:
            if dialog.ShowModal() != wx.ID_OK:
                return _NativePickerSelection()
            return _NativePickerSelection((Path(dialog.GetPath()),))
        finally:
            dialog.Destroy()

    wildcard = _safe_wildcard(payload.get("filters"))
    style = wx.FD_OPEN | wx.FD_FILE_MUST_EXIST
    if command == "native.pickFiles":
        style |= wx.FD_MULTIPLE
    if command == "native.saveFile":
        style = wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT

    dialog = wx.FileDialog(
        parent,
        title,
        defaultFile=str(payload.get("defaultName") or ""),
        wildcard=wildcard,
        style=style,
    )
    try:
        if dialog.ShowModal() != wx.ID_OK:
            return _NativePickerSelection()
        if command == "native.pickFiles":
            return _NativePickerSelection(tuple(Path(path) for path in dialog.GetPaths()))
        return _NativePickerSelection((Path(dialog.GetPath()),))
    finally:
        dialog.Destroy()


def _safe_wildcard(raw_filters: object) -> str:
    if not isinstance(raw_filters, list):
        return "All files (*.*)|*.*"
    choices: list[str] = []
    for item in raw_filters[:12]:
        if not isinstance(item, dict):
            continue
        label = str(item.get("label") or "Files").replace("|", " ")[:60]
        extensions = item.get("extensions")
        if not isinstance(extensions, list):
            continue
        patterns = []
        for extension in extensions[:16]:
            normalized = str(extension).strip().lower().lstrip("*.")
            if normalized and normalized.replace("-", "").isalnum():
                patterns.append(f"*.{normalized}")
        if patterns:
            pattern = ";".join(patterns)
            choices.append(f"{label} ({pattern})|{pattern}")
    choices.append("All files (*.*)|*.*")
    return "|".join(choices)


def _cancelled_selection() -> dict[str, Any]:
    return {
        "status": "CANCELLED",
        "code": "user_cancelled",
        "message": "Selection cancelled.",
        "data": {},
    }


def _mapping(value: object) -> dict[str, Any]:
    mapped = _jsonable(value)
    if not isinstance(mapped, dict):
        raise PublicProjectionError("public bridge objects must serialize as objects")
    return mapped


def _jsonable(value: Any) -> Any:
    if isinstance(value, AppSnapshot):
        return public_snapshot(value)
    if isinstance(value, SnapshotChanged):
        return {
            "event_type": value.event_type,
            "snapshot": public_snapshot(value.snapshot),
        }
    if isinstance(value, ProgressEvent):
        return value.to_public_dict()
    if isinstance(value, InteractionRequest):
        return {
            "event_type": value.event_type,
            "operation_id": value.operation_id,
            "kind": value.kind.value,
            "title": safe_public_message(value.title, fallback="Confirm operation"),
            "message": safe_public_message(value.message, fallback="Continue?"),
            "expected_revision": value.expected_revision,
            "target_serial": value.target_serial,
            "destructive": value.destructive,
            "choices": list(value.choices),
            "reinforced": value.reinforced,
            "confirmation_nonce": value.confirmation_nonce,
        }
    if isinstance(value, OperationFinished):
        return {
            "event_type": value.event_type,
            "result": public_operation_summary(value.result),
        }
    if isinstance(value, OperationResult):
        return public_operation_summary(value)
    return ensure_public_json(value)


_LOGCAT_RESULT_FIELDS = frozenset(
    {
        "targetSerial",
        "mode",
        "lineCount",
        "lines",
        "text",
        "redaction",
        "redactedCount",
        "bounded",
        "truncated",
    }
)


def _limit_bridge_payload(
    value: Any,
    *,
    depth: int = 0,
    field: str = "",
    scope: str = "",
) -> Any:
    """Keep logs and malformed service data from overwhelming the WebView."""

    if depth > 20:
        return "[depth limit]"
    if isinstance(value, Mapping):
        keys = frozenset(key for key in value if isinstance(key, str))
        child_scope = (
            "logcat"
            if keys in {_LOGCAT_RESULT_FIELDS, _LOGCAT_RESULT_FIELDS | {"export"}}
            and value.get("bounded") is True
            and value.get("mode") in {"snapshot", "stream"}
            else scope
        )
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:2048]:
            if not isinstance(key, str):
                raise PublicProjectionError("public bridge keys must be strings")
            result[key] = _limit_bridge_payload(
                item,
                depth=depth + 1,
                field=key,
                scope=child_scope,
            )
        return result
    if isinstance(value, (list, tuple)):
        item_limit = 10_000 if scope == "logcat" and field == "lines" else 2_048
        return [
            _limit_bridge_payload(
                item,
                depth=depth + 1,
                field=field,
                scope=scope,
            )
            for item in value[:item_limit]
        ]
    if isinstance(value, str):
        if scope == "logcat" and field == "text":
            limit = 16 * 1_024 * 1_024 + 10_000
        elif scope == "logcat" and field == "lines":
            limit = 4_096
        else:
            limit = 32_768 if field.lower() in {"stdout", "stderr", "log", "logs"} else 131_072
        if len(value) > limit:
            return value[:limit] + f"\n[truncated {len(value) - limit} characters]"
        return value
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise PublicProjectionError(f"unsupported bridge payload type: {type(value).__name__}")


def _revision(snapshot: AppSnapshot) -> int:
    return snapshot.revision


def _apply_frame_icon(frame: wx.Frame) -> None:
    candidates = (
        Path(__file__).resolve().parents[2] / "images" / "icon-256.ico",
        Path(__file__).resolve().parents[2] / "images" / "icon-128.png",
    )
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            icon = wx.Icon(str(candidate), wx.BITMAP_TYPE_ANY)
            if icon.IsOk():
                frame.SetIcon(icon)
                return
        except Exception:
            continue
