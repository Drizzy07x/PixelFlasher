"""wx.html2 WebView host for Modern UI pages."""

from __future__ import annotations

import contextlib
from types import SimpleNamespace

import wx

try:
    import wx.html2 as html2
except ModuleNotFoundError:
    html2 = None  # type: ignore[assignment]
except ImportError:
    html2 = None  # type: ignore[assignment]

from constants import VERSION
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
        super().__init__(parent, title=f"PixelFlasher {VERSION} - {_frame_title(page)}", size=(1536, 960))
        self._state_host = state_host or parent or _empty_state_host()
        self._state = build_readonly_state(self._state_host, tool_resolver=lambda name: None)
        self._page = str(page or "dashboard")
        self._status_message = DEFAULT_STATUS_MESSAGE
        self._status_tone = "safe"
        self._loading_document = False
        backend = _preferred_webview_backend()
        if backend is None:
            raise RuntimeError("wx.html2 WebView backend is not available")
        view = html2.WebView.New(self, backend=backend)  # type: ignore[union-attr]
        self._view = view
        view.Bind(html2.EVT_WEBVIEW_NAVIGATING, self._on_webview_navigating)  # type: ignore[union-attr]
        view.Bind(html2.EVT_WEBVIEW_LOADED, self._on_webview_loaded)  # type: ignore[union-attr]
        self._show_page(page)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(view, 1, wx.EXPAND)
        self.SetSizer(root)
        self.Centre()

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
        try:
            method(None)
            self._set_feedback(action_completed_feedback(action))
            wx.CallAfter(self._show_page, self._page)
        except Exception as exc:
            self._set_status(f"{action.label}: {exc}", "blocked")
            raise

    def _select_firmware_file(self, action: ModernAction) -> None:
        wildcard = "Flashable files (*.zip;*.img)|*.zip;*.img|All files (*.*)|*.*"
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

    def _setup_platform_tools(self, action: ModernAction) -> None:
        self._set_status("Platform Tools: downloading and configuring...", "warning")
        wx.YieldIfNeeded()
        busy = wx.BusyCursor()
        try:
            result = install_platform_tools()
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
        except PlatformToolsSetupError as exc:
            self._set_status(f"Platform Tools: {exc}", "blocked")
            wx.MessageBox(
                f"Platform Tools could not be configured.\n\n{exc}",
                "PixelFlasher",
                wx.OK | wx.ICON_ERROR,
            )
            return
        except Exception as exc:
            self._set_status(f"Platform Tools setup failed: {exc}", "blocked")
            raise
        finally:
            del busy

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


def _empty_state_host() -> SimpleNamespace:
    return SimpleNamespace(config=SimpleNamespace(), firmware_picker=None, device_choice=None)


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
