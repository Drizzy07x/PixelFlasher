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
APP_BACKGROUND = "#070b12"
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
        self.SetBackgroundColour(_colour(APP_BACKGROUND))
        self.SetBackgroundStyle(wx.BG_STYLE_COLOUR)
        self.SetDoubleBuffered(True)
        _apply_frame_icon(self)
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
        shell = wx.Panel(self, style=wx.BORDER_NONE | wx.CLIP_CHILDREN)
        shell.SetBackgroundColour(_colour(APP_BACKGROUND))
        shell.SetBackgroundStyle(wx.BG_STYLE_COLOUR)
        shell.SetDoubleBuffered(True)
        chrome = ModernWindowChrome(shell, self, _frame_title(page))
        self._chrome = chrome
        view = html2.WebView.New(shell, backend=backend, style=wx.BORDER_NONE)  # type: ignore[union-attr]
        view.SetBackgroundColour(_colour(APP_BACKGROUND))
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
        self._page_title = ""
        self._hover_button: str | None = None
        self._pressed_button: str | None = None
        self._drag_start: tuple[int, int, int, int] | None = None
        self._title_font = wx.Font(10, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD)
        self._subtitle_font = wx.Font(8, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL)
        self.SetBackgroundColour(_colour(CHROME_BACKGROUND))
        self.SetBackgroundStyle(wx.BG_STYLE_PAINT)
        self.SetDoubleBuffered(True)
        self.SetMinSize((-1, 42))

        self.SetPageTitle(page_title)

        self.Bind(wx.EVT_PAINT, self._on_paint)
        self.Bind(wx.EVT_ERASE_BACKGROUND, lambda event: None)
        self.Bind(wx.EVT_SIZE, self._on_size)
        self.Bind(wx.EVT_LEFT_DOWN, self._on_left_down)
        self.Bind(wx.EVT_LEFT_UP, self._on_left_up)
        self.Bind(wx.EVT_MOTION, self._on_motion)
        self.Bind(wx.EVT_LEFT_DCLICK, self._on_double_click)
        self.Bind(wx.EVT_LEAVE_WINDOW, self._on_leave_window)

    def SetPageTitle(self, page_title: str) -> None:
        self._page_title = f"Modern UI - {page_title}"
        self.Refresh(False)

    def _on_paint(self, event: wx.PaintEvent) -> None:
        dc = wx.AutoBufferedPaintDC(self)
        dc.SetBackground(wx.Brush(_colour(CHROME_BACKGROUND)))
        dc.Clear()

        dc.SetTextForeground(_colour(CHROME_TEXT))
        dc.SetFont(self._title_font)
        dc.DrawText(self._page_title, 16, 5)
        dc.SetTextForeground(_colour(CHROME_MUTED))
        dc.SetFont(self._subtitle_font)
        dc.DrawText(f"PixelFlasher {VERSION}", 16, 23)

        for action, rect in self._button_rects().items():
            active = action == self._hover_button or action == self._pressed_button
            fill = CLOSE_HOVER if action == "close" and active else BUTTON_HOVER if active else BUTTON_BACKGROUND
            dc.SetBrush(wx.Brush(_colour(fill)))
            dc.SetPen(wx.Pen(_colour(fill)))
            dc.DrawRoundedRectangle(rect.x, rect.y, rect.width, rect.height, 2)
            self._draw_button_glyph(dc, action, rect)

    def _on_size(self, event: wx.SizeEvent) -> None:
        self.Refresh(False)
        event.Skip()

    def _button_rects(self) -> dict[str, wx.Rect]:
        width, _height = self.GetClientSize()
        button_width = 38
        button_height = 28
        gap = 6
        top = 7
        right = 10
        close_x = width - right - button_width
        maximize_x = close_x - gap - button_width
        minimize_x = maximize_x - gap - button_width
        return {
            "minimize": wx.Rect(minimize_x, top, button_width, button_height),
            "maximize": wx.Rect(maximize_x, top, button_width, button_height),
            "close": wx.Rect(close_x, top, button_width, button_height),
        }

    def _button_at(self, point: wx.Point) -> str | None:
        for action, rect in self._button_rects().items():
            if rect.Contains(point):
                return action
        return None

    def _run_button_action(self, action: str) -> None:
        if action == "minimize":
            self._on_minimize()
        elif action == "maximize":
            self._on_maximize_restore()
        elif action == "close":
            self._on_close()

    def _draw_button_glyph(self, dc: wx.DC, action: str, rect: wx.Rect) -> None:
        pen = wx.Pen(_colour(CHROME_TEXT), 1)
        dc.SetPen(pen)
        cx = rect.x + rect.width // 2
        cy = rect.y + rect.height // 2
        if action == "minimize":
            dc.DrawLine(cx - 6, cy + 5, cx + 6, cy + 5)
        elif action == "maximize":
            dc.SetBrush(wx.TRANSPARENT_BRUSH)
            dc.DrawRectangle(cx - 5, cy - 5, 10, 10)
        elif action == "close":
            dc.DrawLine(cx - 5, cy - 5, cx + 5, cy + 5)
            dc.DrawLine(cx + 5, cy - 5, cx - 5, cy + 5)

    def _on_minimize(self) -> None:
        self._frame.Iconize(True)

    def _on_maximize_restore(self) -> None:
        self._frame.Maximize(not self._frame.IsMaximized())

    def _on_close(self) -> None:
        self._frame.Close(True)

    def _on_double_click(self, event: wx.MouseEvent) -> None:
        if self._button_at(event.GetPosition()) is not None:
            return
        self._frame.Maximize(not self._frame.IsMaximized())

    def _on_left_down(self, event: wx.MouseEvent) -> None:
        button = self._button_at(event.GetPosition())
        if button is not None:
            self._pressed_button = button
            if not self.HasCapture():
                self.CaptureMouse()
            self.Refresh(False)
            return
        screen_pos = _event_screen_position(event, self)
        frame_pos = self._frame.GetPosition()
        self._drag_start = (screen_pos.x, screen_pos.y, frame_pos.x, frame_pos.y)
        if not self.HasCapture():
            self.CaptureMouse()

    def _on_left_up(self, event: wx.MouseEvent) -> None:
        pressed = self._pressed_button
        released = self._button_at(event.GetPosition())
        self._pressed_button = None
        self._drag_start = None
        if self.HasCapture():
            self.ReleaseMouse()
        self.Refresh(False)
        if pressed is not None and pressed == released:
            self._run_button_action(pressed)

    def _on_motion(self, event: wx.MouseEvent) -> None:
        button = self._button_at(event.GetPosition())
        if button != self._hover_button:
            self._hover_button = button
            self.SetToolTip(
                {
                    "minimize": "Minimize",
                    "maximize": "Maximize or restore",
                    "close": "Close",
                }.get(button, "")
            )
            self.Refresh(False)
        if self._drag_start is None or not event.Dragging() or not event.LeftIsDown():
            event.Skip()
            return
        if self._frame.IsMaximized():
            event.Skip()
            return
        mouse_screen = _event_screen_position(event, self)
        start_x, start_y, frame_x, frame_y = self._drag_start
        self._frame.Move((frame_x + mouse_screen.x - start_x, frame_y + mouse_screen.y - start_y))

    def _on_leave_window(self, event: wx.MouseEvent) -> None:
        if self._hover_button is not None:
            self._hover_button = None
            self.Refresh(False)
        event.Skip()


def _event_screen_position(event: wx.MouseEvent, fallback: wx.Window) -> wx.Point:
    source = event.GetEventObject()
    if isinstance(source, wx.Window):
        return source.ClientToScreen(event.GetPosition())
    return fallback.ClientToScreen(event.GetPosition())


def _colour(value: str) -> wx.Colour:
    return wx.Colour(value)


def _apply_frame_icon(frame: wx.Frame) -> None:
    with contextlib.suppress(Exception):
        import images

        icon = images.Icon_dark_256.GetIcon()
        if icon.IsOk():
            frame.SetIcon(icon)


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
