"""wx.html2 WebView host for static Modern UI preview pages."""

from __future__ import annotations

from types import SimpleNamespace

import wx

try:
    import wx.html2 as html2
except ModuleNotFoundError:
    html2 = None  # type: ignore[assignment]
except ImportError:
    html2 = None  # type: ignore[assignment]

from constants import VERSION
from ui.pages.modern_preview_templates import render_preview_html
from ui.pages.modern_readonly_state import build_readonly_state


def is_webview_available() -> bool:
    return bool(html2 is not None and hasattr(html2, "WebView"))


def create_modern_preview_frame(page: str = "dashboard", parent: wx.Window | None = None) -> wx.Frame | None:
    if not is_webview_available():
        return None
    try:
        return ModernPreviewWebFrame(parent=parent, page=page)
    except Exception:
        return None


class ModernPreviewWebFrame(wx.Frame):
    def __init__(self, parent: wx.Window | None = None, page: str = "dashboard") -> None:
        super().__init__(parent, title=f"PixelFlasher {VERSION} - {_frame_title(page)}", size=(1536, 960))
        state = build_readonly_state(parent or _empty_state_host(), tool_resolver=lambda name: None)
        html = render_preview_html(page=page, state=state, version=VERSION)
        view = html2.WebView.New(self)  # type: ignore[union-attr]
        view.SetPage(html, "")
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(view, 1, wx.EXPAND)
        self.SetSizer(root)
        self.Centre()


def _empty_state_host() -> SimpleNamespace:
    return SimpleNamespace(config=SimpleNamespace(), firmware_picker=None, device_choice=None)


def _frame_title(page: str) -> str:
    return {
        "dashboard": "Modern Dashboard Preview",
        "shell": "Modern Shell Preview",
        "wizard": "Flash Wizard Preview",
    }.get(str(page or "dashboard"), "Modern UI Preview")
