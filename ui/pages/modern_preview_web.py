"""wx.html2 WebView host for static Modern UI preview pages."""

from __future__ import annotations

from collections.abc import Callable
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
    GUARDED_LEGACY_FLOW,
    OPEN_LEGACY,
    PREVIEW_ONLY,
    ModernAction,
    action_from_url,
)
from ui.pages.modern_preview_templates import render_preview_html
from ui.pages.modern_readonly_state import build_readonly_state


def is_webview_available() -> bool:
    return bool(html2 is not None and hasattr(html2, "WebView"))


def create_modern_preview_frame(
    page: str = "dashboard",
    parent: wx.Window | None = None,
    on_open_legacy: Callable[[], None] | None = None,
) -> wx.Frame | None:
    if not is_webview_available():
        return None
    try:
        return ModernPreviewWebFrame(parent=parent, page=page, on_open_legacy=on_open_legacy)
    except Exception:
        return None


class ModernPreviewWebFrame(wx.Frame):
    def __init__(
        self,
        parent: wx.Window | None = None,
        page: str = "dashboard",
        on_open_legacy: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(parent, title=f"PixelFlasher {VERSION} - {_frame_title(page)}", size=(1536, 960))
        self._on_open_legacy = on_open_legacy
        self._state = build_readonly_state(parent or _empty_state_host(), tool_resolver=lambda name: None)
        view = html2.WebView.New(self)  # type: ignore[union-attr]
        self._view = view
        view.Bind(html2.EVT_WEBVIEW_NAVIGATING, self._on_webview_navigating)  # type: ignore[union-attr]
        self._show_page(page)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(view, 1, wx.EXPAND)
        self.SetSizer(root)
        self._build_menu()
        self.Centre()

    def _build_menu(self) -> None:
        menu_bar = wx.MenuBar()
        classic = wx.Menu()
        open_legacy = classic.Append(wx.ID_ANY, "Open Classic PixelFlasher", "Open existing guarded legacy flow")
        self.Bind(wx.EVT_MENU, self._open_legacy, open_legacy)
        menu_bar.Append(classic, "Classic")
        self.SetMenuBar(menu_bar)

    def _open_legacy(self, event: wx.CommandEvent | None = None) -> None:
        if callable(self._on_open_legacy):
            self._on_open_legacy()
            return
        wx.MessageBox(
            "Open PixelFlasher with --legacy-ui to use the existing guarded legacy flow.",
            "PixelFlasher",
            wx.OK | wx.ICON_INFORMATION,
        )

    def _show_page(self, page: str) -> None:
        html = render_preview_html(page=page, state=self._state, version=VERSION)
        self._view.SetPage(html, "")
        self.SetTitle(f"PixelFlasher {VERSION} - {_frame_title(page)}")

    def _on_webview_navigating(self, event) -> None:
        url = str(event.GetURL() or "")
        action = action_from_url(url)
        if action is None:
            if _is_initial_webview_url(url):
                return
            event.Veto()
            return
        event.Veto()
        self._handle_action(action)

    def _handle_action(self, action: ModernAction) -> None:
        if action.safety_level == DISABLED or not action.enabled:
            wx.MessageBox(
                f"{action.label}\n\nThis Modern UI action is disabled.",
                "Modern UI action unavailable",
                wx.OK | wx.ICON_INFORMATION,
            )
            return
        if action.safety_level == PREVIEW_ONLY:
            self._handle_preview_action(action)
            return
        if action.safety_level in {OPEN_LEGACY, GUARDED_LEGACY_FLOW}:
            if action.requires_confirmation and not self._confirm_guarded_action(action):
                return
            self._open_legacy()

    def _handle_preview_action(self, action: ModernAction) -> None:
        page_by_action = {
            "open_modern_flash_wizard": "wizard",
            "open_modern_shell": "shell",
        }
        page = page_by_action.get(action.id)
        if page:
            self._show_page(page)
            return
        wx.MessageBox(
            f"{action.label}\n\n{action.description}",
            "Modern UI preview",
            wx.OK | wx.ICON_INFORMATION,
        )

    def _confirm_guarded_action(self, action: ModernAction) -> bool:
        body = action.confirmation_body or (
            "Existing guarded legacy flow\n\n"
            "Modern UI does not execute device commands directly.\n"
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


def _frame_title(page: str) -> str:
    return {
        "dashboard": "Modern Dashboard Preview",
        "shell": "Modern Shell Preview",
        "wizard": "Flash Wizard Preview",
    }.get(str(page or "dashboard"), "Modern UI Preview")


def _is_initial_webview_url(url: str) -> bool:
    return not url or url == "about:blank"
