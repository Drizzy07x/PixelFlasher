"""Small wx helpers for Modern UI preview-only surfaces."""

from __future__ import annotations

from collections.abc import Callable

import wx


def text(parent: wx.Window, label: str, size: int = 10, bold: bool = False, color: str | None = None) -> wx.StaticText:
    item = wx.StaticText(parent, label=label)
    font = item.GetFont()
    font.SetPointSize(size)
    if bold:
        font.SetWeight(wx.FONTWEIGHT_BOLD)
    item.SetFont(font)
    if color:
        item.SetForegroundColour(wx.Colour(color))
    return item


def muted(parent: wx.Window, theme: object, label: str, size: int = 9) -> wx.StaticText:
    return text(parent, label, size, False, theme.palette.text_muted)


def card(parent: wx.Window, theme: object, raised: bool = False) -> wx.Panel:
    panel = wx.Panel(parent)
    color = theme.palette.surface_raised if raised else theme.palette.surface
    panel.SetBackgroundColour(wx.Colour(color))
    return panel


def pad(content: wx.Sizer, amount: int) -> wx.BoxSizer:
    wrapper = wx.BoxSizer(wx.VERTICAL)
    wrapper.Add(content, 1, wx.EXPAND | wx.ALL, amount)
    return wrapper


def badge(parent: wx.Window, theme: object, label: str, tone: str = "info") -> wx.StaticText:
    colors = {
        "accent": theme.palette.accent,
        "danger": theme.palette.danger,
        "info": theme.palette.info,
        "success": theme.palette.success,
        "warning": theme.palette.warning,
    }
    item = text(parent, f"  {label}  ", 9, True, colors.get(tone, theme.palette.info))
    item.SetBackgroundColour(wx.Colour(theme.palette.surface_raised))
    return item


def section_header(parent: wx.Window, theme: object, title: str, detail: str = "") -> wx.Sizer:
    row = wx.BoxSizer(wx.HORIZONTAL)
    row.Add(text(parent, title, 12, True, theme.palette.text), 1, wx.ALIGN_CENTER_VERTICAL)
    if detail:
        row.Add(badge(parent, theme, detail, "info"), 0, wx.ALIGN_CENTER_VERTICAL)
    return row


def sidebar_row(parent: wx.Window, theme: object, title: str, detail: str, active: bool = False) -> wx.Panel:
    panel = card(parent, theme, raised=not active)
    panel.SetMinSize((-1, 54))
    stack = wx.BoxSizer(wx.VERTICAL)
    title_color = theme.palette.accent if active else theme.palette.text
    stack.Add(text(panel, title, 10, True, title_color), 0, wx.BOTTOM, 2)
    stack.Add(muted(panel, theme, detail, 8), 0)
    panel.SetSizer(pad(stack, 10))
    return panel


def action_tile(parent: wx.Window, theme: object, title: str, body: str, footer: str = "Preview only") -> wx.Panel:
    panel = card(parent, theme, raised=True)
    panel.SetMinSize((-1, 116))
    stack = wx.BoxSizer(wx.VERTICAL)
    stack.Add(text(panel, title, 11, True, theme.palette.text), 0, wx.BOTTOM, 5)
    stack.Add(muted(panel, theme, body, 9), 1, wx.EXPAND | wx.BOTTOM, 10)
    stack.Add(badge(panel, theme, footer, "info"), 0, wx.EXPAND)
    panel.SetSizer(pad(stack, 12))
    return panel


def bind_click_recursive(window: wx.Window, handler: Callable[[wx.Event], None]) -> None:
    window.Bind(wx.EVT_LEFT_UP, handler)
    for child in window.GetChildren():
        bind_click_recursive(child, handler)
