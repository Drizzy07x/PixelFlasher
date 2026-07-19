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
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Protocol
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
    CommandAck,
    InteractionDecision,
    InteractionRequest,
    InteractionResponse,
    OperationFinished,
    OperationResult,
    ProgressEvent,
    SnapshotChanged,
)
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


class ReplayAction(StrEnum):
    EXECUTE = "execute"
    WAIT = "wait"
    REPLAY = "replay"
    CONFLICT = "conflict"
    CAPACITY = "capacity"


@dataclass(frozen=True, slots=True)
class ReplayDecision:
    action: ReplayAction
    message: dict[str, Any] | None = field(default=None, repr=False)


@dataclass(slots=True)
class _InflightReplay:
    fingerprint: str
    waiters: int = 0


@dataclass(frozen=True, slots=True)
class _CompletedReplay:
    fingerprint: str
    message: dict[str, Any] = field(repr=False)


class _RequestReplayLedger:
    """Session-bounded requestId ledger for exact at-most-once dispatch."""

    def __init__(self, *, maximum_completed: int = 1_024) -> None:
        if maximum_completed <= 0:
            raise ValueError("maximum_completed must be positive")
        self._maximum_completed = maximum_completed
        self._inflight: dict[str, _InflightReplay] = {}
        self._completed: OrderedDict[str, _CompletedReplay] = OrderedDict()
        self._lock = threading.RLock()

    def begin(self, request: BridgeRequest) -> ReplayDecision:
        fingerprint = request.fingerprint()
        with self._lock:
            completed = self._completed.get(request.request_id)
            if completed is not None:
                if completed.fingerprint != fingerprint:
                    return ReplayDecision(ReplayAction.CONFLICT)
                self._completed.move_to_end(request.request_id)
                return ReplayDecision(ReplayAction.REPLAY, dict(completed.message))

            inflight = self._inflight.get(request.request_id)
            if inflight is not None:
                if inflight.fingerprint != fingerprint:
                    return ReplayDecision(ReplayAction.CONFLICT)
                inflight.waiters += 1
                return ReplayDecision(ReplayAction.WAIT)

            # Never evict an ID: eviction would make an old request executable
            # again. Once the bounded session ledger is full, fail closed and
            # require a new host session instead of weakening idempotency.
            if len(self._completed) + len(self._inflight) >= self._maximum_completed:
                return ReplayDecision(ReplayAction.CAPACITY)
            self._inflight[request.request_id] = _InflightReplay(fingerprint)
            return ReplayDecision(ReplayAction.EXECUTE)

    def complete(
        self,
        request: BridgeRequest,
        message: Mapping[str, Any],
    ) -> tuple[dict[str, Any], ...]:
        with self._lock:
            inflight = self._inflight.pop(request.request_id, None)
            if inflight is None or inflight.fingerprint != request.fingerprint():
                raise RuntimeError("request replay ledger completion is inconsistent")
            bounded = _limit_bridge_payload(dict(message))
            if not isinstance(bounded, dict):
                raise TypeError("request replay payload must remain an object")
            stable_message = bounded
            completed = _CompletedReplay(
                inflight.fingerprint,
                stable_message,
            )
            self._completed[request.request_id] = completed
            self._completed.move_to_end(request.request_id)
            return tuple(dict(stable_message) for _ in range(inflight.waiters + 1))

    def clear(self) -> None:
        with self._lock:
            self._inflight.clear()
            self._completed.clear()


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
            self._queue.put(_CommandWorkItem(request, command))

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
            self._queue.put(None)
        self._thread.join(timeout_seconds)
        return not self._thread.is_alive()

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            outcome: OperationResult | None = None
            try:
                candidate = self._engine.execute(item.command)
                if isinstance(candidate, OperationResult):
                    outcome = candidate
            except Exception:
                outcome = None
            wx.CallAfter(self._deliver, item.request, outcome)


class FrontendAssetsNotFound(RuntimeError):
    pass


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
    raise FrontendAssetsNotFound(
        "The React application has not been built. Expected index.html at: " + checked
    )


def create_modern_webview_frame(
    engine: EngineProtocol,
    *,
    command_factory: CoreCommandFactory,
    support_destination_registrar: SupportDestinationRegistrar,
    parent: wx.Window | None = None,
    index_path: Path | None = None,
) -> ModernWebViewFrame:
    if not is_webview_available():
        raise RuntimeError("wx WebView is unavailable. Install the platform WebView runtime first.")
    return ModernWebViewFrame(
        engine=engine,
        command_factory=command_factory,
        support_destination_registrar=support_destination_registrar,
        parent=parent,
        index_path=index_path,
    )


class ModernWebViewFrame(wx.Frame):
    """One native window containing one persistent React document."""

    def __init__(
        self,
        *,
        engine: EngineProtocol,
        command_factory: CoreCommandFactory,
        support_destination_registrar: SupportDestinationRegistrar,
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
        self._command_factory = command_factory
        self._index_path = (index_path or frontend_index_path()).resolve()
        self._asset_root = self._index_path.parent
        self._loaded = False
        self._closing = False
        self._pending_messages: list[dict[str, Any]] = []
        self._replay_ledger = _RequestReplayLedger()
        self._operation_commands: dict[str, str] = {}
        self._operation_commands_lock = threading.RLock()
        self._subscription: Callable[[], None] | None = None
        self._command_factory.bind_support_destination_registrar(
            support_destination_registrar
        )
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
        self.Bind(wx.EVT_CLOSE, self._on_close)

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._view, 1, wx.EXPAND)
        self.SetSizer(sizer)
        self.Centre()

        self._subscription = self._engine.subscribe(self._on_engine_event)
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
                            "The request ledger reached its safe session limit; "
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
        if request.command.startswith("native."):
            self._handle_native_request(request)
            return
        if request.command == "app.ready":
            self._complete_request(
                request,
                response_envelope(
                    request.request_id,
                    ok=True,
                    result={
                        "status": "SUCCESS",
                        "message": "Bridge ready.",
                        "revision": _revision(self._engine.snapshot()),
                    },
                )
            )
            self._emit_snapshot()
            return
        if request.command == "snapshot.get":
            snapshot = self._engine.snapshot()
            self._complete_request(
                request,
                response_envelope(
                    request.request_id,
                    ok=True,
                    result=_mapping(snapshot),
                )
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
                )
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
        acknowledgement = (
            self._engine.cancel(operation_id)
            if isinstance(operation_id, str)
            else CommandAck(False, "invalid_operation_id", "Operation ID is required.")
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
                error={} if accepted else {
                    "code": acknowledgement.code,
                    "message": acknowledgement_message,
                },
            )
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
                error={} if accepted else {
                    "code": acknowledgement.code,
                    "message": acknowledgement_message,
                },
            )
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
                error={} if status == "SUCCESS" else {
                    "code": str(result.get("code", "operation_cancelled")),
                    "message": str(result.get("message", "Selection cancelled.")),
                    "details": result,
                },
            )
        )

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
        if isinstance(event, SnapshotChanged):
            event_type = "snapshot"
            payload = _mapping(event.snapshot)
            revision = event.revision
        elif isinstance(event, ProgressEvent):
            event_type = "progress"
            payload = _mapping(event)
        elif isinstance(event, InteractionRequest):
            event_type = "interaction"
            payload = _mapping(event)
        elif isinstance(event, OperationFinished):
            event_type = "runtime"
            with self._operation_commands_lock:
                command = self._operation_commands.get(event.result.operation_id)
            if command == "tools.wifi.discover":
                # Discovery data belongs only to the correlated request. The
                # terminal runtime event carries status, never LAN endpoints.
                payload = public_operation_summary(event.result)
            else:
                payload = (
                    project_operation_result(command, event.result)
                    if command is not None
                    else _mapping(event.result)
                )
        else:
            return
        message = event_envelope(
            event_type,
            payload,
            revision=revision,
        )
        if threading.current_thread() is threading.main_thread():
            self._emit(message)
        else:
            wx.CallAfter(self._emit, message)

    def _emit_snapshot(self) -> None:
        snapshot = self._engine.snapshot()
        self._emit(
            event_envelope(
                "snapshot",
                _mapping(snapshot),
                revision=_revision(snapshot),
            )
        )

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
        payload = json.dumps(
            _limit_bridge_payload(message),
            ensure_ascii=True,
            separators=(",", ":"),
        )
        script = (
            "window.dispatchEvent(new CustomEvent('pixelflasher:message',"
            f"{{detail:{payload}}}));"
        )
        self._view.RunScriptAsync(script)

    def _on_close(self, event: wx.CloseEvent) -> None:
        if self._closing:
            event.Skip()
            return
        self._closing = True
        if self._subscription is not None:
            self._subscription()
        try:
            self._engine.shutdown()
        finally:
            stopped = self._command_worker.shutdown()
            if not stopped:
                wx.LogWarning(
                    "PixelFlasher's operation worker did not stop within the shutdown timeout."
                )
            self._command_factory.path_grants.clear()
            self._command_factory.secret_grants.clear()
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
        return {
            "event_type": value.event_type,
            "operation_id": value.operation_id,
            "phase": value.phase.value,
            "message": safe_public_message(value.message, fallback="Operation update."),
            "percent": value.percent,
        }
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


def _limit_bridge_payload(value: Any, *, depth: int = 0, field: str = "") -> Any:
    """Keep logs and malformed service data from overwhelming the WebView."""

    if depth > 20:
        return "[depth limit]"
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:2048]:
            if not isinstance(key, str):
                raise PublicProjectionError("public bridge keys must be strings")
            result[key] = _limit_bridge_payload(item, depth=depth + 1, field=key)
        return result
    if isinstance(value, (list, tuple)):
        return [_limit_bridge_payload(item, depth=depth + 1, field=field) for item in value[:2048]]
    if isinstance(value, str):
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
