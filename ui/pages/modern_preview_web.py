"""wx.html2 WebView host for Modern UI pages."""

from __future__ import annotations

import contextlib
import threading
from pathlib import Path
from types import SimpleNamespace

import wx

try:
    import wx.html2 as html2
except ModuleNotFoundError:
    html2 = None  # type: ignore[assignment]
except ImportError:
    html2 = None  # type: ignore[assignment]

from constants import APPNAME, CONFIG_FILE_NAME, VERSION
from ui.pages.modern_action_bridge import (
    DISABLED,
    GUARDED_FLOW,
    INTERNAL_FLOW,
    NAVIGATION,
    ModernAction,
    action_from_url,
)
from ui.pages.modern_action_feedback import (
    ModernActionFeedback,
    blocked_navigation_feedback,
    disabled_action_feedback,
    guarded_action_canceled_feedback,
    action_completed_feedback,
    action_unavailable_feedback,
    navigation_action_feedback,
)
from ui.pages.modern_preview_templates import DEFAULT_STATUS_MESSAGE, render_preview_html
from ui.pages.modern_readonly_state import build_readonly_state
from ui.pages.platform_tools_setup import PlatformToolsSetupError, install_platform_tools


FRAME_STYLE = wx.NO_BORDER | wx.CLIP_CHILDREN | wx.NO_FULL_REPAINT_ON_RESIZE
CHROME_BACKGROUND = "#08111f"
CHROME_TEXT = "#e7eefb"
CHROME_MUTED = "#94a3b8"
BUTTON_BACKGROUND = "#101b2d"
BUTTON_HOVER = "#1a2a44"
CLOSE_HOVER = "#b4232d"


def is_webview_available() -> bool:
    return _preferred_webview_backend() is not None


def create_modern_preview_frame(
    page: str = "dashboard",
    parent: wx.Window | None = None,
    state_host: object | None = None,
) -> wx.Frame | None:
    if not is_webview_available():
        return None
    return ModernPreviewWebFrame(parent=parent, page=page, state_host=state_host)


class ModernPreviewWebFrame(wx.Frame):
    def __init__(
        self,
        parent: wx.Window | None = None,
        page: str = "dashboard",
        state_host: object | None = None,
    ) -> None:
        super().__init__(
            parent,
            title=f"PixelFlasher {VERSION} - {_frame_title(page)}",
            size=(1536, 960),
            style=FRAME_STYLE,
        )
        self._state_host = state_host or parent or _empty_state_host()
        self._state = build_readonly_state(self._state_host, tool_resolver=lambda name: None)
        self._page = str(page or "dashboard")
        self._status_message = DEFAULT_STATUS_MESSAGE
        self._status_tone = "safe"
        self._loading_document = False
        self._action_running = False
        backend = _preferred_webview_backend()
        if backend is None:
            raise RuntimeError("wx.html2 WebView backend is not available")
        shell = wx.Panel(self)
        shell.SetBackgroundColour(_colour(CHROME_BACKGROUND))
        chrome = ModernWindowChrome(shell, self, _frame_title(page))
        self._chrome = chrome
        view = html2.WebView.New(shell, backend=backend)  # type: ignore[union-attr]
        self._view = view
        view.Bind(html2.EVT_WEBVIEW_NAVIGATING, self._on_webview_navigating)  # type: ignore[union-attr]
        view.Bind(html2.EVT_WEBVIEW_LOADED, self._on_webview_loaded)  # type: ignore[union-attr]
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(chrome, 0, wx.EXPAND)
        root.Add(view, 1, wx.EXPAND)
        shell.SetSizer(root)
        frame_sizer = wx.BoxSizer(wx.VERTICAL)
        frame_sizer.Add(shell, 1, wx.EXPAND)
        self.SetSizer(frame_sizer)
        self.Centre()
        shell.Layout()
        self.Layout()
        self._show_page(page)

    def _show_page(self, page: str, status_message: str | None = None, status_tone: str = "safe") -> None:
        self._page = str(page or "dashboard")
        if status_message is not None:
            self._status_message = status_message
            self._status_tone = status_tone
        self._state = build_readonly_state(self._state_host, tool_resolver=lambda name: None)
        html = render_preview_html(
            page=self._page,
            state=self._state,
            version=VERSION,
            status_message=self._status_message,
            status_tone=self._status_tone,
        )
        self._loading_document = True
        self._view.SetPage(html, "")
        self.SetTitle(f"PixelFlasher {VERSION} - {_frame_title(self._page)}")
        self._chrome.SetPageTitle(_frame_title(self._page))

    def _set_status(self, message: str, tone: str = "safe") -> None:
        self._show_page(self._page, message, tone)

    def _set_feedback(self, feedback: ModernActionFeedback) -> None:
        self._set_status(feedback.message, feedback.tone)

    def _on_webview_navigating(self, event) -> None:
        url = str(event.GetURL() or "")
        action = action_from_url(url)
        if action is None:
            if _is_initial_webview_url(url) or (self._loading_document and _is_safe_document_load_url(url)):
                return
            event.Veto()
            self._set_feedback(blocked_navigation_feedback())
            return
        event.Veto()
        self._handle_action(action)

    def _on_webview_loaded(self, event) -> None:
        self._loading_document = False

    def _handle_action(self, action: ModernAction) -> None:
        if self._action_running and action.safety_level in {INTERNAL_FLOW, GUARDED_FLOW}:
            self._set_status(f"{action.label}: another operation is already running.", "warning")
            return
        if action.safety_level == DISABLED or not action.enabled:
            self._set_feedback(disabled_action_feedback(action))
            wx.MessageBox(
                f"{action.label}\n\nThis Modern UI action is disabled.",
                "Modern UI action unavailable",
                wx.OK | wx.ICON_INFORMATION,
            )
            return
        if action.safety_level == NAVIGATION:
            self._handle_navigation_action(action)
            return
        if action.safety_level in {INTERNAL_FLOW, GUARDED_FLOW}:
            if action.requires_confirmation and not self._confirm_guarded_action(action):
                self._set_feedback(guarded_action_canceled_feedback(action))
                return
            self._run_engine_action(action)

    def _handle_navigation_action(self, action: ModernAction) -> None:
        page_by_action = {
            "open_modern_dashboard": "dashboard",
            "open_modern_flash_wizard": "wizard",
            "open_modern_shell": "shell",
            "open_backups": "backups",
            "open_downloads": "downloads",
            "open_settings": "settings",
            "open_tools": "tools",
            "open_safety": "safety",
            "open_about": "about",
        }
        page = page_by_action.get(action.id)
        if page:
            feedback = navigation_action_feedback(action)
            self._show_page(page, feedback.message, feedback.tone)
            return
        wx.MessageBox(
            f"{action.label}\n\n{action.description}",
            "PixelFlasher",
            wx.OK | wx.ICON_INFORMATION,
        )

    def _run_engine_action(self, action: ModernAction) -> None:
        if action.delegate == "_setup_platform_tools":
            self._setup_platform_tools(action)
            return
        if action.delegate == "select_firmware_file":
            self._select_firmware_file(action)
            return
        method = getattr(self._state_host, action.delegate, None)
        if not callable(method):
            self._set_feedback(action_unavailable_feedback(action))
            wx.MessageBox(
                f"{action.label}\n\nThis action is not available in the current session.",
                "PixelFlasher",
                wx.OK | wx.ICON_INFORMATION,
            )
            return
        self._action_running = True
        try:
            method(None)
            self._set_feedback(action_completed_feedback(action))
            wx.CallAfter(self._show_page, self._page)
        except Exception as exc:
            self._set_status(f"{action.label}: {exc}", "blocked")
            raise
        finally:
            self._action_running = False

    def _select_firmware_file(self, action: ModernAction) -> None:
        self._action_running = True
        wildcard = "Flashable files (*.zip;*.img)|*.zip;*.img|All files (*.*)|*.*"
        try:
            with wx.FileDialog(
                self,
                "Select firmware, OTA, ROM, or image",
                wildcard=wildcard,
                style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST,
            ) as dialog:
                if dialog.ShowModal() == wx.ID_CANCEL:
                    self._set_feedback(guarded_action_canceled_feedback(action))
                    return
                path = dialog.GetPath()
            picker = getattr(self._state_host, "firmware_picker", None)
            if picker is not None:
                with contextlib.suppress(Exception):
                    picker.SetPath(path)
            updater = getattr(self._state_host, "update_firmware_selection", None)
            if callable(updater):
                updater(path)
            else:
                config = getattr(self._state_host, "config", None)
                if config is not None:
                    setattr(config, "firmware_path", path)
            refresh = getattr(self._state_host, "update_widget_states", None)
            if callable(refresh):
                refresh()
            self._set_feedback(action_completed_feedback(action))
            wx.CallAfter(self._show_page, self._page)
        finally:
            self._action_running = False

    def _setup_platform_tools(self, action: ModernAction) -> None:
        self._action_running = True
        self._set_status("Platform Tools: downloading and configuring...", "warning")
        worker = threading.Thread(
            target=self._install_platform_tools_worker,
            args=(action,),
            name="PixelFlasherPlatformToolsSetup",
            daemon=True,
        )
        worker.start()

    def _install_platform_tools_worker(self, action: ModernAction) -> None:
        try:
            result = install_platform_tools()
        except Exception as exc:
            wx.CallAfter(self._finish_platform_tools_setup, action, None, exc)
            return
        wx.CallAfter(self._finish_platform_tools_setup, action, result, None)

    def _finish_platform_tools_setup(self, action: ModernAction, result, error: Exception | None) -> None:
        try:
            if error is not None:
                if isinstance(error, PlatformToolsSetupError):
                    self._set_status(f"Platform Tools: {error}", "blocked")
                    title = "Platform Tools could not be configured."
                else:
                    self._set_status(f"Platform Tools setup failed: {error}", "blocked")
                    title = "Platform Tools setup failed."
                wx.MessageBox(
                    f"{title}\n\n{error}",
                    "PixelFlasher",
                    wx.OK | wx.ICON_ERROR,
                )
                return
            config = getattr(self._state_host, "config", None)
            if config is not None:
                setattr(config, "platform_tools_path", result.platform_tools_path)
                self._save_config(config)
            picker = getattr(self._state_host, "platform_tools_picker", None)
            if picker is not None:
                with contextlib.suppress(Exception):
                    picker.SetPath(result.platform_tools_path)
            self._refresh_platform_tools()
            self._refresh_engine_state()
        except Exception as exc:
            self._set_status(f"Platform Tools setup failed: {exc}", "blocked")
            wx.MessageBox(
                f"Platform Tools setup failed.\n\n{exc}",
                "PixelFlasher",
                wx.OK | wx.ICON_ERROR,
            )
            return
        finally:
            self._action_running = False

        self._set_feedback(action_completed_feedback(action))
        wx.MessageBox(
            "Android Platform Tools are configured.\n\nUse Scan Devices to refresh connected USB devices.",
            "PixelFlasher",
            wx.OK | wx.ICON_INFORMATION,
        )
        wx.CallAfter(self._show_page, self._page)

    def _save_config(self, config: object) -> None:
        save = getattr(config, "save", None)
        if not callable(save):
            return
        with contextlib.suppress(Exception):
            import runtime as pf_runtime

            config_path = pf_runtime.get_config_file_path()
            if config_path:
                save(config_path)

    def _refresh_platform_tools(self) -> None:
        with contextlib.suppress(Exception):
            from pf_modules import check_platform_tools

            check_platform_tools(self._state_host)

        label = getattr(self._state_host, "platform_tools_label", None)
        if label is None:
            return
        with contextlib.suppress(Exception):
            import runtime as pf_runtime

            sdk_version = pf_runtime.get_sdk_version()
            label.SetLabel(f"Android Platform Tools\nVersion {sdk_version}" if sdk_version else "Android Platform Tools")

    def _refresh_engine_state(self) -> None:
        refresh = getattr(self._state_host, "update_widget_states", None)
        if callable(refresh):
            with contextlib.suppress(Exception):
                refresh()

    def _confirm_guarded_action(self, action: ModernAction) -> bool:
        body = action.confirmation_body or (
            "PixelFlasher will run this action.\n"
            "Review all prompts before continuing."
        )
        message = f"{action.label}\n\n{action.description}\n\n{body}"
        dialog = wx.MessageDialog(
            self,
            message,
            action.confirmation_title or action.label,
            wx.YES_NO | wx.NO_DEFAULT | wx.ICON_WARNING,
        )
        try:
            return dialog.ShowModal() == wx.ID_YES
        finally:
            dialog.Destroy()


class ModernWindowChrome(wx.Panel):
    def __init__(self, parent: wx.Window, frame: wx.Frame, page_title: str) -> None:
        super().__init__(parent, style=wx.BORDER_NONE)
        self._frame = frame
        self._drag_start: tuple[int, int, int, int] | None = None
        self.SetBackgroundColour(_colour(CHROME_BACKGROUND))
        self.SetMinSize((-1, 42))

        self._title = wx.StaticText(self, label="")
        self._title.SetForegroundColour(_colour(CHROME_TEXT))
        self._title.SetFont(wx.Font(10, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD))
        self._subtitle = wx.StaticText(self, label=f"PixelFlasher {VERSION}")
        self._subtitle.SetForegroundColour(_colour(CHROME_MUTED))
        self._subtitle.SetFont(wx.Font(8, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL))
        self.SetPageTitle(page_title)

        title_stack = wx.BoxSizer(wx.VERTICAL)
        title_stack.Add(self._title, 0, wx.BOTTOM, 1)
        title_stack.Add(self._subtitle, 0)

        controls = wx.BoxSizer(wx.HORIZONTAL)
        controls.Add(self._chrome_button("_", "Minimize", self._on_minimize), 0, wx.LEFT, 6)
        controls.Add(self._chrome_button("[]", "Maximize or restore", self._on_maximize_restore), 0, wx.LEFT, 6)
        controls.Add(self._chrome_button("X", "Close", self._on_close, close=True), 0, wx.LEFT, 6)

        root = wx.BoxSizer(wx.HORIZONTAL)
        root.Add(title_stack, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 16)
        root.AddStretchSpacer(1)
        root.Add(controls, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 10)
        self.SetSizer(root)

        for target in (self, self._title, self._subtitle):
            target.Bind(wx.EVT_LEFT_DOWN, self._on_left_down)
            target.Bind(wx.EVT_LEFT_UP, self._on_left_up)
            target.Bind(wx.EVT_MOTION, self._on_motion)
            target.Bind(wx.EVT_LEFT_DCLICK, self._on_double_click)

    def SetPageTitle(self, page_title: str) -> None:
        self._title.SetLabel(f"Modern UI - {page_title}")

    def _chrome_button(self, label: str, tooltip: str, handler, close: bool = False) -> wx.Button:
        button = wx.Button(self, label=label, size=(38, 28), style=wx.BORDER_NONE)
        button.SetToolTip(tooltip)
        button.SetForegroundColour(_colour(CHROME_TEXT))
        button.SetBackgroundColour(_colour(BUTTON_BACKGROUND))
        button.Bind(wx.EVT_BUTTON, handler)
        button.Bind(wx.EVT_ENTER_WINDOW, lambda event: self._set_button_hover(button, close, True, event))
        button.Bind(wx.EVT_LEAVE_WINDOW, lambda event: self._set_button_hover(button, close, False, event))
        return button

    def _set_button_hover(self, button: wx.Button, close: bool, active: bool, event: wx.Event) -> None:
        button.SetBackgroundColour(_colour(CLOSE_HOVER if close and active else BUTTON_HOVER if active else BUTTON_BACKGROUND))
        button.Refresh()
        event.Skip()

    def _on_minimize(self, event: wx.Event) -> None:
        self._frame.Iconize(True)

    def _on_maximize_restore(self, event: wx.Event) -> None:
        self._frame.Maximize(not self._frame.IsMaximized())

    def _on_close(self, event: wx.Event) -> None:
        self._frame.Close(True)

    def _on_double_click(self, event: wx.MouseEvent) -> None:
        self._frame.Maximize(not self._frame.IsMaximized())

    def _on_left_down(self, event: wx.MouseEvent) -> None:
        screen_pos = _event_screen_position(event, self)
        frame_pos = self._frame.GetPosition()
        self._drag_start = (screen_pos.x, screen_pos.y, frame_pos.x, frame_pos.y)
        self.CaptureMouse()

    def _on_left_up(self, event: wx.MouseEvent) -> None:
        self._drag_start = None
        if self.HasCapture():
            self.ReleaseMouse()

    def _on_motion(self, event: wx.MouseEvent) -> None:
        if self._drag_start is None or not event.Dragging() or not event.LeftIsDown():
            event.Skip()
            return
        if self._frame.IsMaximized():
            event.Skip()
            return
        mouse_screen = _event_screen_position(event, self)
        start_x, start_y, frame_x, frame_y = self._drag_start
        self._frame.Move((frame_x + mouse_screen.x - start_x, frame_y + mouse_screen.y - start_y))


def _event_screen_position(event: wx.MouseEvent, fallback: wx.Window) -> wx.Point:
    source = event.GetEventObject()
    if isinstance(source, wx.Window):
        return source.ClientToScreen(event.GetPosition())
    return fallback.ClientToScreen(event.GetPosition())


def _colour(value: str) -> wx.Colour:
    return wx.Colour(value)


def _empty_state_host() -> SimpleNamespace:
    return SimpleNamespace(config=_load_standalone_config(), firmware_picker=None, device_choice=None)


def _load_standalone_config() -> object:
    with contextlib.suppress(Exception):
        from config import Config
        from platformdirs import user_data_dir

        config_path = Path(user_data_dir(APPNAME, appauthor=False, roaming=True)) / CONFIG_FILE_NAME
        if config_path.exists():
            return Config.load(str(config_path))
        return Config()
    return SimpleNamespace()


def _preferred_webview_backend():
    if html2 is None or not hasattr(html2, "WebView"):
        return None
    webview = html2.WebView
    can_check_backend = hasattr(webview, "IsBackendAvailable")
    if wx.Platform == "__WXMSW__":
        edge_backend = getattr(html2, "WebViewBackendEdge", None)
        if edge_backend is not None and (not can_check_backend or webview.IsBackendAvailable(edge_backend)):
            return edge_backend
        return None
    default_backend = getattr(html2, "WebViewBackendDefault", "")
    if not can_check_backend or webview.IsBackendAvailable(default_backend):
        return default_backend
    return None


def _frame_title(page: str) -> str:
    return {
        "dashboard": "Modern Dashboard",
        "shell": "Modern Shell",
        "wizard": "Flash Wizard",
        "backups": "Backups",
        "downloads": "Downloads",
        "settings": "Settings",
        "tools": "Tools",
        "safety": "Safety",
        "about": "About",
    }.get(str(page or "dashboard"), "Modern UI")


def _is_initial_webview_url(url: str) -> bool:
    return not url or url == "about:blank"


def _is_safe_document_load_url(url: str) -> bool:
    value = str(url or "").strip().lower()
    return (
        _is_initial_webview_url(value)
        or value.startswith("data:text/html")
        or value.startswith("memory:")
        or value.startswith("wxfs:")
        or value.startswith("file:")
    )
