"""Native wx host for the local React application.

wx owns only the accessible system window, WebView, and native file/folder
pickers. Product state and operations belong to the injected headless engine.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, is_dataclass
from enum import Enum
import json
import os
from pathlib import Path
import sys
import threading
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import unquote, urlparse

import wx

try:
    import wx.html2 as html2
except (ImportError, ModuleNotFoundError):
    html2 = None  # type: ignore[assignment]

from constants import APPNAME, VERSION
from ui.bridge_contract import (
    BRIDGE_CHANNEL,
    BridgeProtocolError,
    BridgeRequest,
    event_envelope,
    protocol_error_envelope,
    response_envelope,
)


class EngineProtocol(Protocol):
    def snapshot(self) -> object: ...

    def subscribe(self, listener: Callable[[object], None]) -> object: ...

    def execute(self, command: object) -> object: ...

    def register_support_destination(
        self,
        destination: str | Path,
        *,
        allow_overwrite: bool = False,
    ) -> str: ...

    def shutdown(self) -> None: ...


CommandFactory = Callable[[BridgeRequest], object]


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
    frozen_root = getattr(sys, "_MEIPASS", None)
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
    command_factory: CommandFactory,
    parent: wx.Window | None = None,
    index_path: Path | None = None,
) -> "ModernWebViewFrame":
    if not is_webview_available():
        raise RuntimeError("wx WebView is unavailable. Install the platform WebView runtime first.")
    return ModernWebViewFrame(
        engine=engine,
        command_factory=command_factory,
        parent=parent,
        index_path=index_path,
    )


class ModernWebViewFrame(wx.Frame):
    """One native window containing one persistent React document."""

    def __init__(
        self,
        *,
        engine: EngineProtocol,
        command_factory: CommandFactory,
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
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pixelflasher-engine")
        self._subscription: object | None = None

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
        self._emit(event_envelope("runtime", {"status": "ready", "version": VERSION}))
        self._emit_snapshot()
        queued, self._pending_messages = self._pending_messages, []
        for message in queued:
            self._emit(message)

    def _on_load_error(self, event: object) -> None:
        message = "The local PixelFlasher interface could not be loaded."
        getter = getattr(event, "GetString", None)
        if callable(getter):
            detail = str(getter() or "").strip()
            if detail:
                message = f"{message} {detail}"
        wx.LogError(message)

    def _on_navigating(self, event: object) -> None:
        getter = getattr(event, "GetURL", None)
        url = str(getter() if callable(getter) else "")
        if _is_allowed_local_url(url, self._asset_root):
            return
        veto = getattr(event, "Veto", None)
        if callable(veto):
            veto()
        self._emit(
            event_envelope(
                "runtime",
                {"status": "navigationBlocked", "message": "Navigation stayed inside PixelFlasher."},
            )
        )

    def _on_script_message(self, event: object) -> None:
        getter = getattr(event, "GetString", None)
        raw = str(getter() if callable(getter) else "")
        try:
            request = BridgeRequest.from_json(raw)
        except BridgeProtocolError as exc:
            self._emit(protocol_error_envelope(exc))
            return

        if request.command.startswith("native."):
            self._handle_native_request(request)
            return
        if request.command == "app.ready":
            self._emit(
                response_envelope(
                    request.request_id,
                    ok=True,
                    result={"status": "SUCCESS", "message": "Bridge ready."},
                    revision=_revision(self._engine.snapshot()),
                )
            )
            self._emit_snapshot()
            return
        if request.command == "snapshot.get":
            snapshot = self._engine.snapshot()
            self._emit(
                response_envelope(
                    request.request_id,
                    ok=True,
                    result={"status": "SUCCESS", "snapshot": _jsonable(snapshot)},
                    revision=_revision(snapshot),
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
        except Exception:
            self._emit(
                response_envelope(
                    request.request_id,
                    ok=False,
                    error={"code": "invalid_command", "message": "The command payload is invalid."},
                    revision=_revision(self._engine.snapshot()),
                )
            )
            return

        future = self._executor.submit(self._execute_command, command)
        future.add_done_callback(lambda completed: self._command_finished(request, completed))

    def _handle_operation_cancel(self, request: BridgeRequest) -> None:
        operation_id = request.payload.get("operationId")
        cancel = getattr(self._engine, "cancel", None)
        if not callable(cancel):
            cancel = getattr(self._engine, "cancel_operation", None)
        accepted = bool(cancel(operation_id)) if callable(cancel) and isinstance(operation_id, str) else False
        self._emit(
            response_envelope(
                request.request_id,
                ok=accepted,
                result={
                    "status": "SUCCESS" if accepted else "FAILED",
                    "code": "cancellation_requested" if accepted else "operation_not_active",
                    "message": "Cancellation requested." if accepted else "Operation is not active.",
                },
                error={} if accepted else {
                    "code": "operation_not_active",
                    "message": "Operation is not active.",
                },
                revision=_revision(self._engine.snapshot()),
            )
        )

    def _handle_interaction_response(self, request: BridgeRequest) -> None:
        operation_id = request.payload.get("operationId")
        decision = request.payload.get("decision")
        respond = getattr(self._engine, "respond_interaction", None)
        accepted = False
        if (
            callable(respond)
            and isinstance(operation_id, str)
            and decision in {"accepted", "cancelled"}
        ):
            accepted = bool(respond(operation_id, decision, request.expected_revision))
        self._emit(
            response_envelope(
                request.request_id,
                ok=accepted,
                result={
                    "status": "SUCCESS" if accepted else "FAILED",
                    "code": "interaction_recorded" if accepted else "interaction_not_pending",
                    "message": "Decision recorded." if accepted else "Interaction is no longer pending.",
                },
                error={} if accepted else {
                    "code": "interaction_not_pending",
                    "message": "Interaction is no longer pending.",
                },
                revision=_revision(self._engine.snapshot()),
            )
        )

    def _execute_command(self, command: object) -> object:
        result = self._engine.execute(command)
        if isinstance(result, Future):
            return result.result()
        waiter = getattr(result, "wait", None)
        if callable(waiter):
            waited = waiter()
            if waited is not None:
                return waited
        result_getter = getattr(result, "result", None)
        if callable(result_getter) and not is_dataclass(result):
            return result_getter()
        return result

    def _command_finished(self, request: BridgeRequest, future: Future[object]) -> None:
        if self._closing:
            return
        try:
            result = future.result()
            serialized = _jsonable(result)
            if not isinstance(serialized, dict):
                serialized = {"status": "FAILED", "message": "Engine returned an invalid result."}
            status = str(serialized.get("status", "FAILED")).upper()
            ok = status == "SUCCESS"
            error = {}
            if status == "FAILED":
                error = {
                    "code": str(serialized.get("code", "operation_failed")),
                    "message": str(serialized.get("message", "Operation failed.")),
                }
            elif status == "CANCELLED":
                error = {
                    "code": str(serialized.get("code", "operation_cancelled")),
                    "message": str(serialized.get("message", "Operation cancelled.")),
                }
            message = response_envelope(
                request.request_id,
                ok=ok,
                result=serialized,
                error=error,
                revision=_revision(self._engine.snapshot()),
            )
        except Exception:
            message = response_envelope(
                request.request_id,
                ok=False,
                error={"code": "engine_error", "message": "The operation could not be completed."},
                revision=_revision(self._engine.snapshot()),
            )
        wx.CallAfter(self._emit, message)
        wx.CallAfter(self._emit_snapshot)

    def _handle_native_request(self, request: BridgeRequest) -> None:
        result = _run_native_picker(self, request.command, request.payload)
        if (
            request.command == "native.saveFile"
            and request.payload.get("purpose") == "support"
            and str(result.get("status", "")) == "SUCCESS"
        ):
            result = _register_support_destination_result(self._engine, result)
        status = str(result.get("status", "FAILED"))
        self._emit(
            response_envelope(
                request.request_id,
                ok=status == "SUCCESS",
                result=result,
                error={} if status == "SUCCESS" else {
                    "code": str(result.get("code", "operation_cancelled")),
                    "message": str(result.get("message", "Selection cancelled.")),
                },
                revision=_revision(self._engine.snapshot()),
            )
        )

    def _on_engine_event(self, event: object) -> None:
        if self._closing:
            return
        event_type = str(getattr(event, "event_type", "") or "").lower()
        if not event_type:
            class_name = type(event).__name__.lower()
            if "progress" in class_name:
                event_type = "progress"
            elif "interaction" in class_name:
                event_type = "interaction"
            elif "snapshot" in class_name:
                event_type = "snapshot"
            else:
                event_type = "runtime"
        if event_type not in {"snapshot", "progress", "interaction", "runtime"}:
            event_type = "runtime"
        message = event_envelope(event_type, _mapping(event))
        if threading.current_thread() is threading.main_thread():
            self._emit(message)
        else:
            wx.CallAfter(self._emit, message)

    def _emit_snapshot(self) -> None:
        snapshot = self._engine.snapshot()
        self._emit(event_envelope("snapshot", _mapping(snapshot)))

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
        _cancel_subscription(self._subscription)
        self._executor.shutdown(wait=False, cancel_futures=True)
        try:
            self._engine.shutdown()
        finally:
            event.Skip()


def _preferred_backend() -> str | None:
    if html2 is None:
        return None
    edge = getattr(html2, "WebViewBackendEdge", "")
    if edge:
        try:
            if html2.WebView.IsBackendAvailable(edge):
                return edge
        except Exception:
            pass
    default = getattr(html2, "WebViewBackendDefault", "")
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
    if parsed.scheme != "file":
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


def _run_native_picker(
    parent: wx.Window,
    command: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    title = str(payload.get("title") or "Choose a file")[:160]
    initial_directory = str(payload.get("initialDirectory") or "")

    if command == "native.pickDirectory":
        dialog = wx.DirDialog(parent, title, defaultPath=initial_directory, style=wx.DD_DEFAULT_STYLE)
        try:
            if dialog.ShowModal() != wx.ID_OK:
                return _cancelled_selection()
            return {"status": "SUCCESS", "message": "Folder selected.", "data": {"path": dialog.GetPath()}}
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
        defaultDir=initial_directory,
        defaultFile=str(payload.get("defaultName") or ""),
        wildcard=wildcard,
        style=style,
    )
    try:
        if dialog.ShowModal() != wx.ID_OK:
            return _cancelled_selection()
        if command == "native.pickFiles":
            return {
                "status": "SUCCESS",
                "message": "Files selected.",
                "data": {"paths": list(dialog.GetPaths())},
            }
        return {"status": "SUCCESS", "message": "File selected.", "data": {"path": dialog.GetPath()}}
    finally:
        dialog.Destroy()


def _register_support_destination_result(
    engine: object,
    picker_result: Mapping[str, Any],
) -> dict[str, Any]:
    """Exchange a native picker path for a one-use, WebView-safe identifier."""

    data = picker_result.get("data")
    path = data.get("path") if isinstance(data, Mapping) else None
    register = getattr(engine, "register_support_destination", None)
    if not isinstance(path, str) or not callable(register):
        return {
            "status": "FAILED",
            "code": "support_destination_unavailable",
            "message": "The selected support destination could not be registered.",
            "data": {},
        }
    try:
        destination_id = register(path, allow_overwrite=True)
    except Exception:
        return {
            "status": "FAILED",
            "code": "support_destination_invalid",
            "message": "The selected support destination is invalid.",
            "data": {},
        }
    # Do not return the filesystem path to WebView code.  The opaque grant can
    # be consumed once by support.create.
    return {
        "status": "SUCCESS",
        "message": "Support destination selected.",
        "data": {
            "destinationId": destination_id,
            "displayName": Path(path).name,
        },
    }


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
    if isinstance(mapped, dict):
        return mapped
    return {"value": mapped}


def _jsonable(value: Any) -> Any:
    converter = getattr(value, "to_dict", None)
    if callable(converter):
        return _jsonable(converter())
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _limit_bridge_payload(value: Any, *, depth: int = 0, field: str = "") -> Any:
    """Keep logs and malformed service data from overwhelming the WebView."""

    if depth > 20:
        return "[depth limit]"
    if isinstance(value, Mapping):
        return {
            str(key): _limit_bridge_payload(item, depth=depth + 1, field=str(key))
            for key, item in list(value.items())[:2048]
        }
    if isinstance(value, (list, tuple)):
        return [_limit_bridge_payload(item, depth=depth + 1, field=field) for item in value[:2048]]
    if isinstance(value, str):
        limit = 32_768 if field.lower() in {"stdout", "stderr", "log", "logs"} else 131_072
        if len(value) > limit:
            return value[:limit] + f"\n[truncated {len(value) - limit} characters]"
    return value


def _revision(snapshot: object) -> int | None:
    value = getattr(snapshot, "revision", None)
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(snapshot, Mapping):
            value = snapshot.get("revision")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _cancel_subscription(subscription: object | None) -> None:
    if subscription is None:
        return
    if callable(subscription):
        try:
            subscription()
        except Exception:
            pass
        return
    for name in ("cancel", "unsubscribe", "close"):
        method = getattr(subscription, name, None)
        if callable(method):
            try:
                method()
            except Exception:
                pass
            return


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
