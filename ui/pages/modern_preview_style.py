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


def app_panel(parent: wx.Window, theme: object) -> wx.Panel:
    panel = wx.Panel(parent)
    panel.SetBackgroundColour(wx.Colour(theme.palette.background))
    return panel


def sidebar_container(parent: wx.Window, theme: object, width: int = 270) -> wx.Panel:
    panel = wx.Panel(parent)
    panel.SetMinSize((width, -1))
    panel.SetBackgroundColour(wx.Colour(theme.palette.surface_raised))
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


def badge_row(parent: wx.Window, theme: object, labels: tuple[str, ...]) -> wx.Sizer:
    row = wx.BoxSizer(wx.HORIZONTAL)
    for label in labels:
        tone = "warning" if "PREVIEW" in label.upper() else "info"
        row.Add(badge(parent, theme, label, tone), 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 8)
    return row


def section_header(parent: wx.Window, theme: object, title: str, detail: str = "") -> wx.Sizer:
    row = wx.BoxSizer(wx.HORIZONTAL)
    row.Add(text(parent, title, 12, True, theme.palette.text), 1, wx.ALIGN_CENTER_VERTICAL)
    if detail:
        row.Add(badge(parent, theme, detail, "info"), 0, wx.ALIGN_CENTER_VERTICAL)
    return row


def page_header(parent: wx.Window, theme: object, title: str, subtitle: str, badges: tuple[str, ...]) -> wx.Panel:
    panel = card(parent, theme)
    row = wx.BoxSizer(wx.HORIZONTAL)
    stack = wx.BoxSizer(wx.VERTICAL)
    stack.Add(text(panel, title, 22, True, theme.palette.text), 0, wx.BOTTOM, 4)
    stack.Add(muted(panel, theme, subtitle, 9), 0)
    row.Add(stack, 1, wx.ALIGN_CENTER_VERTICAL)
    row.Add(badge_row(panel, theme, badges), 0, wx.ALIGN_CENTER_VERTICAL)
    panel.SetSizer(pad(row, 18))
    return panel


def sidebar_brand(parent: wx.Window, theme: object, title: str, subtitle: str, badge_text: str = "BETA") -> wx.Panel:
    panel = card(parent, theme, raised=True)
    row = wx.BoxSizer(wx.HORIZONTAL)
    mark = text(panel, "▰", 24, True, theme.palette.accent)
    row.Add(mark, 0, wx.ALIGN_TOP | wx.RIGHT, 10)
    stack = wx.BoxSizer(wx.VERTICAL)
    title_row = wx.BoxSizer(wx.HORIZONTAL)
    title_row.Add(text(panel, title, 14, True, theme.palette.text), 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 8)
    title_row.Add(badge(panel, theme, badge_text, "info"), 0, wx.ALIGN_CENTER_VERTICAL)
    stack.Add(title_row, 0, wx.BOTTOM, 4)
    stack.Add(muted(panel, theme, subtitle, 9), 0)
    row.Add(stack, 1, wx.EXPAND)
    panel.SetSizer(pad(row, 16))
    return panel


def sidebar_row(parent: wx.Window, theme: object, title: str, detail: str, active: bool = False, icon: str = "•") -> wx.Panel:
    panel = card(parent, theme, raised=not active)
    panel.SetMinSize((-1, 62))
    row = wx.BoxSizer(wx.HORIZONTAL)
    icon_color = theme.palette.accent if active else theme.palette.text_muted
    row.Add(text(panel, icon, 17, True, icon_color), 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 12)
    stack = wx.BoxSizer(wx.VERTICAL)
    title_color = theme.palette.accent if active else theme.palette.text
    stack.Add(text(panel, title, 10, True, title_color), 0, wx.BOTTOM, 2)
    stack.Add(muted(panel, theme, detail, 8), 0)
    row.Add(stack, 1, wx.ALIGN_CENTER_VERTICAL)
    panel.SetSizer(pad(row, 10))
    return panel


def metric_card(parent: wx.Window, theme: object, title: str, value: str, tone: str = "info") -> wx.Panel:
    panel = card(parent, theme, raised=True)
    stack = wx.BoxSizer(wx.VERTICAL)
    stack.Add(muted(panel, theme, title, 8), 0, wx.BOTTOM, 4)
    stack.Add(text(panel, value, 12, True, _tone_color(theme, tone)), 0)
    panel.SetSizer(pad(stack, 10))
    return panel


def info_row(parent: wx.Window, theme: object, title: str, value: str, icon: str = "") -> wx.Panel:
    panel = card(parent, theme, raised=True)
    row = wx.BoxSizer(wx.HORIZONTAL)
    if icon:
        row.Add(text(panel, icon, 11, True, theme.palette.accent), 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 8)
    row.Add(muted(panel, theme, title), 1, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 10)
    row.Add(text(panel, value, 10, True, theme.palette.text), 1, wx.ALIGN_CENTER_VERTICAL)
    panel.SetSizer(pad(row, 8))
    return panel


def info_column(parent: wx.Window, theme: object, title: str, value: str, tone: str = "info") -> wx.Panel:
    panel = card(parent, theme, raised=True)
    stack = wx.BoxSizer(wx.VERTICAL)
    stack.Add(muted(panel, theme, title, 8), 0, wx.BOTTOM, 3)
    stack.Add(text(panel, value, 11, True, _tone_color(theme, tone)), 0)
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


def icon_action_tile(parent: wx.Window, theme: object, icon: str, title: str, body: str, footer: str = "Preview only") -> wx.Panel:
    panel = card(parent, theme, raised=True)
    panel.SetMinSize((-1, 78))
    row = wx.BoxSizer(wx.HORIZONTAL)
    row.Add(text(panel, icon, 18, True, theme.palette.accent), 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 12)
    stack = wx.BoxSizer(wx.VERTICAL)
    stack.Add(text(panel, title, 11, True, theme.palette.text), 0, wx.BOTTOM, 3)
    stack.Add(muted(panel, theme, body, 9), 0, wx.BOTTOM, 6)
    stack.Add(badge(panel, theme, footer, "info"), 0)
    row.Add(stack, 1, wx.ALIGN_CENTER_VERTICAL)
    panel.SetSizer(pad(row, 12))
    return panel


def notice_card(parent: wx.Window, theme: object, title: str, body: str, tone: str = "info") -> wx.Panel:
    panel = card(parent, theme, raised=True)
    stack = wx.BoxSizer(wx.VERTICAL)
    stack.Add(badge(panel, theme, title.upper(), tone), 0, wx.BOTTOM, 8)
    stack.Add(muted(panel, theme, body, 9), 0)
    panel.SetSizer(pad(stack, 12))
    return panel


def safety_boundary_card(parent: wx.Window, theme: object, lines: tuple[str, ...]) -> wx.Panel:
    panel = card(parent, theme)
    stack = wx.BoxSizer(wx.VERTICAL)
    stack.Add(section_header(panel, theme, "Safety Boundary", "Preview-only"), 0, wx.EXPAND | wx.BOTTOM, 10)
    for line in lines:
        stack.Add(text(panel, f"✓ {line}", 9, False, theme.palette.success), 0, wx.BOTTOM, 5)
    panel.SetSizer(pad(stack, 16))
    return panel


def checklist_card(parent: wx.Window, theme: object, title: str, lines: tuple[str, ...]) -> wx.Panel:
    panel = card(parent, theme)
    stack = wx.BoxSizer(wx.VERTICAL)
    stack.Add(text(panel, title, 10, True, theme.palette.text), 0, wx.BOTTOM, 7)
    for line in lines:
        stack.Add(muted(panel, theme, f"• {line}", 9), 0, wx.BOTTOM, 4)
    panel.SetSizer(pad(stack, 10))
    return panel


def stepper_cell(parent: wx.Window, theme: object, title: str, state: str, active: bool = False) -> wx.Panel:
    panel = card(parent, theme, raised=not active)
    panel.SetMinSize((-1, 72))
    stack = wx.BoxSizer(wx.VERTICAL)
    stack.Add(text(panel, title, 9, True, theme.palette.accent if active else theme.palette.text), 0, wx.BOTTOM, 3)
    stack.Add(badge(panel, theme, state, "info" if active else "success" if state == "Ready" else "info"), 0)
    panel.SetSizer(pad(stack, 10))
    return panel


def button_panel(parent: wx.Window, theme: object, label: str, tone: str = "info") -> wx.Panel:
    panel = card(parent, theme, raised=True)
    panel.SetMinSize((112, 34))
    row = wx.BoxSizer(wx.HORIZONTAL)
    row.AddStretchSpacer(1)
    row.Add(badge(panel, theme, label, tone), 0, wx.ALIGN_CENTER_VERTICAL)
    row.AddStretchSpacer(1)
    panel.SetSizer(pad(row, 4))
    return panel


def bind_click_recursive(window: wx.Window, handler: Callable[[wx.Event], None]) -> None:
    window.Bind(wx.EVT_LEFT_UP, handler)
    for child in window.GetChildren():
        bind_click_recursive(child, handler)


def _tone_color(theme: object, tone: str) -> str:
    colors = {
        "accent": theme.palette.accent,
        "danger": theme.palette.danger,
        "info": theme.palette.info,
        "muted": theme.palette.text_muted,
        "success": theme.palette.success,
        "warning": theme.palette.warning,
    }
    return colors.get(tone, theme.palette.info)
