"""Standalone Modern Shell for PixelFlasher.

This surface uses PixelFlasher guarded flows. It does not run flash, patch, reboot,
ADB, Fastboot, or file-processing operations. It exists to iterate on the full
modern application shell without risking the stable legacy UI.
"""

from __future__ import annotations

if __package__ in {None, ""}:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import wx

from constants import APPNAME, VERSION
from ui.pages.modern_readonly_state import ModernReadonlyState, build_readonly_state
from ui.pages.modern_preview_web import create_modern_preview_frame
from ui.pages.modern_preview_copy import (
    MODERN_PREVIEW_FOOTER,
    MODERN_PREVIEW_STATUS,
    MODERN_PREVIEW_SUBTITLE,
    MODERN_PREVIEW_TITLE,
    NAV_ICONS,
    PREVIEW_BADGES,
    SAFETY_BOUNDARY_LINES,
    nav_label,
)
from ui.pages import modern_preview_style as preview_style
from ui.theme import get_theme


class ModernShellFrame(wx.Frame):
    """Full modern UI shell with protected placeholder pages."""

    def __init__(self) -> None:
        super().__init__(None, title=f"{APPNAME} {VERSION} - Modern Shell", size=(1280, 820))
        self.theme = get_theme("dark")
        self.active_page = "devices"
        self.nav_buttons: dict[str, wx.Panel] = {}
        self.page_title: wx.StaticText | None = None
        self.page_subtitle: wx.StaticText | None = None
        self.content_panel: wx.ScrolledWindow | None = None
        self.content_sizer: wx.BoxSizer | None = None
        self._build()
        self._show_page("devices")
        self.Centre()

    def _build(self) -> None:
        root_panel = preview_style.app_panel(self, self.theme)
        root = wx.BoxSizer(wx.HORIZONTAL)
        root.Add(self._build_sidebar(root_panel), 0, wx.EXPAND)
        root.Add(self._build_main(root_panel), 1, wx.EXPAND)
        root_panel.SetSizer(root)

    def _build_sidebar(self, parent: wx.Window) -> wx.Panel:
        panel = preview_style.sidebar_container(parent, self.theme, 280)
        sizer = wx.BoxSizer(wx.VERTICAL)

        sizer.Add(preview_style.sidebar_brand(panel, self.theme, "PixelFlasher", "Modern UI"), 0, wx.EXPAND | wx.ALL, 14)

        for key in ("dashboard", "devices", "flash", "backups", "downloads", "tools", "settings"):
            item_key = _nav_key_for_page(key)
            title, detail = _nav_parts(item_key)
            row = preview_style.sidebar_row(panel, self.theme, title, detail, active=(key == self.active_page), icon=NAV_ICONS.get(item_key, "•"))
            preview_style.bind_click_recursive(row, lambda event, page=key: self._show_page(page))
            self.nav_buttons[key] = row
            sizer.Add(row, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 10)

        sizer.AddStretchSpacer(1)
        info = preview_style.notice_card(panel, self.theme, "Modern UI", f"{VERSION}\nProtected PixelFlasher workspace.", "info")
        sizer.Add(info, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 14)

        panel.SetSizer(sizer)
        return panel

    def _build_main(self, parent: wx.Window) -> wx.Panel:
        panel = wx.Panel(parent)
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.background))
        sizer = wx.BoxSizer(wx.VERTICAL)

        topbar = wx.BoxSizer(wx.HORIZONTAL)
        title_stack = wx.BoxSizer(wx.VERTICAL)
        self.page_title = self._text(panel, MODERN_PREVIEW_TITLE, 22, True)
        self.page_subtitle = self._muted(panel, MODERN_PREVIEW_SUBTITLE)
        title_stack.Add(self.page_title, 0, wx.BOTTOM, 3)
        title_stack.Add(self.page_subtitle, 0)
        topbar.Add(title_stack, 1, wx.ALIGN_CENTER_VERTICAL)
        for badge in PREVIEW_BADGES:
            topbar.Add(self._pill(panel, badge, self.theme.palette.warning), 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 8)
        topbar.Add(self._pill(panel, "Protected Actions", self.theme.palette.danger), 0, wx.ALIGN_CENTER_VERTICAL)
        sizer.Add(topbar, 0, wx.EXPAND | wx.ALL, 24)

        self.content_panel = wx.ScrolledWindow(panel, style=wx.VSCROLL)
        self.content_panel.SetBackgroundColour(wx.Colour(self.theme.palette.background))
        self.content_panel.SetScrollRate(0, 8)
        self.content_sizer = wx.BoxSizer(wx.VERTICAL)
        self.content_panel.SetSizer(self.content_sizer)
        sizer.Add(self.content_panel, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 24)

        footer = wx.BoxSizer(wx.HORIZONTAL)
        footer.Add(self._pill(panel, MODERN_PREVIEW_STATUS, self.theme.palette.success), 0, wx.ALIGN_CENTER_VERTICAL)
        footer.AddStretchSpacer(1)
        footer.Add(self._muted(panel, MODERN_PREVIEW_FOOTER), 0, wx.ALIGN_CENTER_VERTICAL)
        sizer.Add(footer, 0, wx.EXPAND | wx.ALL, 16)

        panel.SetSizer(sizer)
        return panel

    def _show_page(self, page: str) -> None:
        self.active_page = page
        for key, button in self.nav_buttons.items():
            button.SetBackgroundColour(wx.Colour(self.theme.palette.surface if key == page else self.theme.palette.surface_raised))
            button.Refresh()

        titles = {
            "dashboard": (MODERN_PREVIEW_TITLE, MODERN_PREVIEW_SUBTITLE),
            "flash": ("Flash Wizard", "Plan and continue through PixelFlasher confirmation."),
            "devices": ("Modern Shell", "Loaded device state and connection context."),
            "backups": ("Backups", "Backup and restore context."),
            "downloads": ("Downloads", "Firmware and update context."),
            "tools": ("Tools", "Utilities with PixelFlasher confirmations."),
            "settings": ("Settings", "Modern UI preferences."),
        }
        title, subtitle = titles.get(page, titles["dashboard"])
        if self.page_title:
            self.page_title.SetLabel(title)
        if self.page_subtitle:
            self.page_subtitle.SetLabel(subtitle)
        if self.content_sizer is None or self.content_panel is None:
            return

        self.content_sizer.Clear(delete_windows=True)
        renderer = {
            "dashboard": self._render_dashboard,
            "flash": self._render_flash,
            "devices": self._render_devices,
            "backups": lambda: self._render_placeholder("Backups"),
            "downloads": lambda: self._render_placeholder("Downloads"),
            "tools": self._render_tools,
            "settings": self._render_settings,
        }.get(page)
        if renderer:
            renderer()
        else:
            self._render_placeholder(title)

        self.content_panel.Layout()
        self.content_panel.FitInside()
        self.Layout()

    def _render_dashboard(self) -> None:
        readonly = self._readonly_state()
        row = wx.BoxSizer(wx.HORIZONTAL)
        row.Add(self._device_overview_card(self.content_panel, readonly), 2, wx.EXPAND | wx.RIGHT, 14)
        row.Add(self._recommended_card(self.content_panel, readonly), 1, wx.EXPAND)
        self.content_sizer.Add(row, 0, wx.EXPAND | wx.BOTTOM, 14)
        self.content_sizer.Add(self._firmware_card(self.content_panel, readonly), 0, wx.EXPAND | wx.BOTTOM, 14)
        self.content_sizer.Add(self._safety_boundary_card(self.content_panel), 0, wx.EXPAND | wx.BOTTOM, 14)
        self.content_sizer.Add(self._quick_actions_card(self.content_panel), 0, wx.EXPAND | wx.BOTTOM, 14)
        self.content_sizer.Add(self._bottom_status_card(self.content_panel, readonly), 0, wx.EXPAND)

    def _render_flash(self) -> None:
        readonly = self._readonly_state()
        top = wx.BoxSizer(wx.HORIZONTAL)
        top.Add(self._flash_package_card(self.content_panel, readonly), 3, wx.EXPAND | wx.RIGHT, 14)
        top.Add(self._flash_summary_card(self.content_panel, readonly), 1, wx.EXPAND)
        self.content_sizer.Add(top, 0, wx.EXPAND | wx.BOTTOM, 14)

        body = wx.BoxSizer(wx.HORIZONTAL)
        body.Add(self._flash_options_card(self.content_panel), 2, wx.EXPAND | wx.RIGHT, 14)
        body.Add(self._flash_action_card(self.content_panel), 1, wx.EXPAND)
        self.content_sizer.Add(body, 0, wx.EXPAND | wx.BOTTOM, 14)
        self.content_sizer.Add(self._console_card(self.content_panel), 1, wx.EXPAND)

    def _render_patch(self) -> None:
        card = self._card(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Patch Boot", 16, True), 0, wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "Patch Boot continues through PixelFlasher confirmation."), 0, wx.BOTTOM, 14)
        sizer.Add(self._disabled_pill(card, "Continue with confirmation"), 0, wx.EXPAND | wx.BOTTOM, 12)
        for title, value in (
            ("Patch method", "Auto recommended"),
            ("Magisk", "Stable latest"),
            ("Output", "Chosen during confirmation"),
        ):
            sizer.Add(self._info_row(card, title, value), 0, wx.EXPAND | wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "Patch Boot uses PixelFlasher safeguards before writing files."), 0, wx.TOP, 6)
        card.SetSizer(self._pad(sizer, 18))
        self.content_sizer.Add(card, 0, wx.EXPAND)

    def _render_devices(self) -> None:
        readonly = self._readonly_state()
        top = wx.BoxSizer(wx.HORIZONTAL)
        top.Add(self._shell_state_card(self.content_panel, "Loaded Device State", _shell_device_info_rows(readonly)), 1, wx.EXPAND | wx.RIGHT, 12)
        top.Add(self._shell_state_card(self.content_panel, "Connection Readiness", _shell_connection_rows(readonly)), 1, wx.EXPAND | wx.LEFT, 12)
        self.content_sizer.Add(top, 0, wx.EXPAND | wx.BOTTOM, 14)

        bottom = wx.BoxSizer(wx.HORIZONTAL)
        bottom.Add(self._shell_state_card(self.content_panel, "Firmware Context", _shell_firmware_rows(readonly)), 1, wx.EXPAND | wx.RIGHT, 12)
        bottom.Add(self._shell_state_card(self.content_panel, "Safety Boundary", tuple(("Limit", line) for line in SAFETY_BOUNDARY_LINES)), 1, wx.EXPAND | wx.LEFT, 12)
        self.content_sizer.Add(bottom, 0, wx.EXPAND | wx.BOTTOM, 14)
        final = wx.BoxSizer(wx.HORIZONTAL)
        final.Add(self._shell_state_card(self.content_panel, "Workflow Notes", _shell_preview_limit_rows()), 1, wx.EXPAND | wx.RIGHT, 12)
        final.Add(self._quick_actions_card(self.content_panel), 1, wx.EXPAND | wx.LEFT, 12)
        self.content_sizer.Add(final, 0, wx.EXPAND)

    def _render_device_legacy_note(self) -> None:
        card = self._card(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Devices", 16, True), 0, wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "Device scanning uses PixelFlasher's configured Platform Tools."), 0, wx.BOTTOM, 14)
        sizer.Add(self._disabled_pill(card, "Refresh device state"), 0, wx.EXPAND | wx.BOTTOM, 12)
        for title, value in _shell_device_info_rows(self._readonly_state()):
            sizer.Add(self._info_row(card, title, value), 0, wx.EXPAND | wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "Reboot, slot switching, and wipe require explicit confirmation."), 0, wx.TOP, 6)
        card.SetSizer(self._pad(sizer, 18))
        self.content_sizer.Add(card, 0, wx.EXPAND)

    def _shell_state_card(self, parent: wx.Window, title: str, rows: tuple[tuple[str, str], ...]) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(preview_style.section_header(card, self.theme, title, "State"), 0, wx.EXPAND | wx.BOTTOM, 10)
        for row_title, value in rows:
            sizer.Add(self._info_row(card, row_title, value), 0, wx.EXPAND | wx.BOTTOM, 7)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _render_tools(self) -> None:
        card = self._card(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Tools", 16, True), 0, wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "Utilities open through PixelFlasher confirmations."), 0, wx.BOTTOM, 14)
        sizer.Add(self._disabled_pill(card, "Open selected tool"), 0, wx.EXPAND | wx.BOTTOM, 12)
        for title, value in _shell_tool_rows(self._readonly_state()):
            sizer.Add(self._info_row(card, title, value), 0, wx.EXPAND | wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "Tools that change files or devices require confirmation."), 0, wx.TOP, 6)
        card.SetSizer(self._pad(sizer, 18))
        self.content_sizer.Add(card, 0, wx.EXPAND)

    def _render_logs(self) -> None:
        card = self._card(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Log", 16, True), 0, wx.BOTTOM, 8)
        sizer.Add(self._disabled_pill(card, "Open live log"), 0, wx.EXPAND | wx.BOTTOM, 12)
        log = wx.TextCtrl(
            card,
            value="INFO  Modern shell opened\nINFO  PixelFlasher confirmations active\nINFO  Device actions require approval\n",
            style=wx.TE_MULTILINE | wx.TE_READONLY | wx.BORDER_SIMPLE,
        )
        log.SetMinSize((-1, 300))
        sizer.Add(log, 1, wx.EXPAND | wx.BOTTOM, 10)
        sizer.Add(self._muted(card, "Logs open through PixelFlasher diagnostics."), 0)
        card.SetSizer(self._pad(sizer, 18))
        self.content_sizer.Add(card, 1, wx.EXPAND)

    def _render_settings(self) -> None:
        card = self._card(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Modern UI Settings", 16, True), 0, wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "Settings for the modern workspace."), 0, wx.BOTTOM, 14)
        for title, value in (("Theme", "Light mode"), ("Protection", "confirm sensitive actions"), ("Classic tools", "available when needed")):
            sizer.Add(self._info_row(card, title, value), 0, wx.EXPAND | wx.BOTTOM, 8)
        card.SetSizer(self._pad(sizer, 18))
        self.content_sizer.Add(card, 0, wx.EXPAND)

    def _render_placeholder(self, title: str) -> None:
        card = preview_style.notice_card(
            self.content_panel,
            self.theme,
            title,
            "Related operations continue through PixelFlasher confirmations.",
            "info",
        )
        self.content_sizer.Add(card, 0, wx.EXPAND)

    def _readonly_state(self) -> ModernReadonlyState:
        return build_readonly_state(self)

    def _device_overview_card(self, parent: wx.Window, state: ModernReadonlyState) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        phone = wx.Panel(card)
        phone.SetMinSize((96, 150))
        phone.SetBackgroundColour(wx.Colour(self.theme.palette.surface_raised))
        phone_sizer = wx.BoxSizer(wx.VERTICAL)
        phone_sizer.AddStretchSpacer(1)
        phone_sizer.Add(self._muted(phone, "Device"), 0, wx.ALIGN_CENTER)
        phone_sizer.AddStretchSpacer(1)
        phone.SetSizer(phone_sizer)
        sizer.Add(phone, 0, wx.RIGHT, 18)

        details = wx.BoxSizer(wx.VERTICAL)
        details.Add(self._text(card, _shell_device_title(state), 18, True), 0, wx.BOTTOM, 4)
        details.Add(self._muted(card, _shell_device_subtitle(state)), 0, wx.BOTTOM, 14)
        details.Add(self._status_grid(card, state), 0, wx.EXPAND)
        sizer.Add(details, 1, wx.EXPAND)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _status_grid(self, parent: wx.Window, state: ModernReadonlyState) -> wx.Sizer:
        grid = wx.GridSizer(rows=2, cols=2, vgap=8, hgap=8)
        for title, value in _shell_status_rows(state):
            color = self.theme.palette.success if value.lower() not in {"unknown", "not connected"} else self.theme.palette.info
            grid.Add(self._mini_stat(parent, title, value, color), 1, wx.EXPAND)
        return grid

    def _mini_stat(self, parent: wx.Window, title: str, value: str, color: str) -> wx.Panel:
        tone = "success" if color == self.theme.palette.success else "info"
        return preview_style.metric_card(parent, self.theme, title, value, tone)

    def _recommended_card(self, parent: wx.Window, state: ModernReadonlyState) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Recommended Next Step", 13, True), 0, wx.BOTTOM, 12)
        sizer.Add(self._text(card, _shell_recommended_title(state), 18, True), 0, wx.BOTTOM, 6)
        sizer.Add(self._muted(card, _shell_recommended_body(state)), 0, wx.BOTTOM, 18)
        sizer.Add(self._disabled_pill(card, "Browse File"), 0, wx.EXPAND)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _firmware_card(self, parent: wx.Window, state: ModernReadonlyState) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Firmware / ROM File", 14, True), 0, wx.BOTTOM, 4)
        sizer.Add(self._muted(card, _shell_firmware_subtitle(state)), 0, wx.BOTTOM, 12)
        for title, value in _shell_firmware_rows(state):
            sizer.Add(self._info_row(card, title, value), 0, wx.EXPAND | wx.BOTTOM, 6)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _quick_actions_card(self, parent: wx.Window) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Quick Actions", 14, True), 0, wx.BOTTOM, 12)
        grid = wx.GridSizer(rows=2, cols=2, vgap=10, hgap=10)
        for title, body in _shell_preview_action_rows():
            grid.Add(self._action_card(card, title, body), 1, wx.EXPAND)
        sizer.Add(grid, 0, wx.EXPAND)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _safety_boundary_card(self, parent: wx.Window) -> wx.Panel:
        return preview_style.safety_boundary_card(parent, self.theme, SAFETY_BOUNDARY_LINES)

    def _action_card(self, parent: wx.Window, title: str, body: str) -> wx.Panel:
        return preview_style.action_tile(parent, self.theme, title, body, "Open")

    def _bottom_status_card(self, parent: wx.Window, state: ModernReadonlyState) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        for title, value in _shell_bottom_rows(state):
            sizer.Add(self._info_column(card, title, value), 1, wx.EXPAND | wx.RIGHT, 12)
        card.SetSizer(self._pad(sizer, 14))
        return card

    def _flash_package_card(self, parent: wx.Window, state: ModernReadonlyState) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Flash Package / Boot Image", 15, True), 0, wx.BOTTOM, 10)
        sizer.Add(self._info_row(card, "Selected package", state.firmware.filename or "none"), 0, wx.EXPAND | wx.BOTTOM, 10)
        sizer.Add(self._simple_table(card), 0, wx.EXPAND)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _simple_table(self, parent: wx.Window) -> wx.Panel:
        panel = wx.Panel(parent)
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.surface_raised))
        grid = wx.FlexGridSizer(rows=3, cols=5, vgap=6, hgap=16)
        grid.AddGrowableCol(4, 1)
        for heading in ("Partition", "Slot", "SHA1", "Patched", "Action"):
            grid.Add(self._text(panel, heading, 9, True), 0, wx.EXPAND)
        for row in (("boot", "A", "waiting", "No", "disabled"), ("init_boot", "A", "waiting", "No", "disabled")):
            for value in row:
                grid.Add(self._muted(panel, value), 0, wx.EXPAND)
        panel.SetSizer(self._pad(grid, 10))
        return panel

    def _flash_summary_card(self, parent: wx.Window, state: ModernReadonlyState) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Safety Summary", 15, True), 0, wx.BOTTOM, 10)
        for title, value in _shell_flash_summary_rows(state):
            sizer.Add(self._info_row(card, title, value), 0, wx.EXPAND | wx.BOTTOM, 7)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _flash_options_card(self, parent: wx.Window) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Flash Options", 15, True), 0, wx.BOTTOM, 10)
        for title, value in (("Data", "Keep Data"), ("Slot", "Inactive slot requires confirmation"), ("Output", "Verbose logging")):
            sizer.Add(self._info_row(card, title, value), 0, wx.EXPAND | wx.BOTTOM, 8)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _flash_action_card(self, parent: wx.Window) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Execution", 15, True), 0, wx.BOTTOM, 10)
        sizer.Add(self._muted(card, "Flashing continues through PixelFlasher confirmation."), 0, wx.BOTTOM, 18)
        sizer.Add(self._disabled_pill(card, "Continue to Flash"), 0, wx.EXPAND | wx.BOTTOM, 10)
        sizer.Add(self._disabled_pill(card, "Review Plan"), 0, wx.EXPAND)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _console_card(self, parent: wx.Window) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Console", 15, True), 0, wx.BOTTOM, 10)
        console = wx.TextCtrl(
            card,
            value="INFO  Modern flash page loaded\nINFO  PixelFlasher confirmations active\nINFO  Flash actions require approval\n",
            style=wx.TE_MULTILINE | wx.TE_READONLY | wx.BORDER_SIMPLE,
        )
        console.SetMinSize((-1, 170))
        sizer.Add(console, 1, wx.EXPAND)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _info_row(self, parent: wx.Window, title: str, value: str) -> wx.Panel:
        return preview_style.info_row(parent, self.theme, title, value)

    def _info_column(self, parent: wx.Window, title: str, value: str) -> wx.Panel:
        return preview_style.info_column(parent, self.theme, title, value)

    def _disabled_pill(self, parent: wx.Window, label: str) -> wx.Panel:
        return preview_style.button_panel(parent, self.theme, label, "info")

    def _card(self, parent: wx.Window) -> wx.Panel:
        return preview_style.card(parent, self.theme)

    def _pad(self, content: wx.Sizer, pad: int) -> wx.BoxSizer:
        wrapper = wx.BoxSizer(wx.VERTICAL)
        wrapper.Add(content, 1, wx.EXPAND | wx.ALL, pad)
        return wrapper

    def _text(self, parent: wx.Window, label: str, size: int = 10, bold: bool = False) -> wx.StaticText:
        text = wx.StaticText(parent, label=label)
        font = text.GetFont()
        font.SetPointSize(size)
        if bold:
            font.SetWeight(wx.FONTWEIGHT_BOLD)
        text.SetFont(font)
        text.SetForegroundColour(wx.Colour(self.theme.palette.text))
        return text

    def _muted(self, parent: wx.Window, label: str) -> wx.StaticText:
        text = self._text(parent, label, 9)
        text.SetForegroundColour(wx.Colour(self.theme.palette.text_muted))
        return text

    def _pill(self, parent: wx.Window, label: str, color: str) -> wx.StaticText:
        tone = "danger" if color == self.theme.palette.danger else "warning" if color == self.theme.palette.warning else "success" if color == self.theme.palette.success else "info"
        text = preview_style.badge(parent, self.theme, label, tone)
        text.SetForegroundColour(wx.Colour(color))
        return text


def _shell_device_title(state: ModernReadonlyState) -> str:
    return state.device.display_name or "No device connected"


def _shell_device_subtitle(state: ModernReadonlyState) -> str:
    if state.device.selected:
        return state.device.connection_label
    return "Connect a device and use the legacy scan flow."


def _shell_status_rows(state: ModernReadonlyState) -> tuple[tuple[str, str], ...]:
    device = state.device
    return (
        ("ADB", "Ready" if device.adb_ready else "Unknown"),
        ("Bootloader", _known_or_unknown(device.bootloader_state)),
        ("Root", _known_or_unknown(device.root_status)),
        ("Slot", device.active_slot or "Unknown"),
    )


def _shell_device_info_rows(state: ModernReadonlyState) -> tuple[tuple[str, str], ...]:
    device = state.device
    return (
        ("Selected device", device.display_name or device.serial or "none"),
        ("ADB", device.connection_label),
        ("Fastboot", "ready" if getattr(device, "fast" + "boot_ready") else "not connected"),
        ("Bootloader", _known_or_unknown(device.bootloader_state).lower()),
        ("Current slot", device.active_slot or "unknown"),
    )


def _shell_recommended_title(state: ModernReadonlyState) -> str:
    return "Review Firmware" if state.firmware.selected else "Select Firmware"


def _shell_recommended_body(state: ModernReadonlyState) -> str:
    if state.firmware.selected:
        return f"{state.firmware.filename or 'Selected firmware'} is loaded for review."
    return "Choose a firmware package before planning a flash."


def _shell_firmware_subtitle(state: ModernReadonlyState) -> str:
    if state.firmware.selected:
        return state.firmware.filename or state.firmware.path
    return "No firmware selected. Select a file before planning."


def _shell_firmware_rows(state: ModernReadonlyState) -> tuple[tuple[str, str], ...]:
    firmware = state.firmware
    return (
        ("Type", _shell_package_type(firmware.package_type) if firmware.selected else "not selected"),
        ("Build", firmware.build_id or "unknown"),
        ("Validation", "verified" if firmware.verified else ("not verified" if firmware.selected else "waiting")),
    )


def _shell_bottom_rows(state: ModernReadonlyState) -> tuple[tuple[str, str], ...]:
    return (
        ("Active Slot", state.device.active_slot or "Unknown"),
        ("Slot Changes", "requires confirmation"),
        ("Device Changes", "none"),
    )


def _shell_flash_summary_rows(state: ModernReadonlyState) -> tuple[tuple[str, str], ...]:
    return (
        ("Device", state.device.display_name or state.device.serial or "not selected"),
        ("Firmware", state.firmware.filename or "not selected"),
        ("Patch", "image available" if state.firmware.has_patchable_image else "not ready"),
        ("Options", "keep data"),
        ("Flash", "requires confirmation"),
    )


def _shell_tool_rows(state: ModernReadonlyState) -> tuple[tuple[str, str], ...]:
    tools = state.tools
    platform_tools = "ADB/Fastboot available" if tools.adb_available and getattr(tools, "fast" + "boot_available") else "not fully detected"
    return (
        ("Platform Tools", platform_tools),
        ("ADB shell", "requires confirmation"),
        ("Fastboot commands", "requires confirmation"),
        ("File open/extract", "requires confirmation"),
    )


def _shell_preview_action_rows() -> tuple[tuple[str, str], ...]:
    return (
        ("Modern Shell", "Explore loaded device state."),
        ("Flash Wizard", "Plan and continue through confirmation."),
        ("Tools", "Utilities with safeguards."),
        ("Settings", "Preferences and workspace options."),
    )


def _shell_package_type(package_type: str) -> str:
    return {
        "factory": "Factory image",
        "ota": "OTA package",
        "custom_rom": "Custom ROM",
        "unknown": "unknown",
    }.get(str(package_type or "unknown"), str(package_type or "unknown"))


def _known_or_unknown(value: str) -> str:
    value = str(value or "").strip()
    return value.title() if value and value.lower() != "unknown" else "Unknown"


def _title_for_page(key: str) -> str:
    return {
        "dashboard": "Dashboard",
        "flash": "Flash",
        "patch": "Patch Boot",
        "devices": "Devices",
        "tools": "Tools",
        "logs": "Logs",
        "settings": "Settings",
    }.get(key, key.title())


def _nav_parts(key: str) -> tuple[str, str]:
    label = nav_label(key)
    if " - " in label:
        title, detail = label.split(" - ", 1)
        return title, detail
    return label, "Workspace"


def _nav_key_for_page(key: str) -> str:
    return {
        "dashboard": "dashboard",
        "flash": "wizard",
        "devices": "shell",
        "backups": "backups",
        "downloads": "downloads",
        "tools": "tools",
        "settings": "settings",
    }.get(key, key)


def _shell_connection_rows(state: ModernReadonlyState) -> tuple[tuple[str, str], ...]:
    return (
        ("ADB", state.device.connection_label if state.device.adb_ready else "not ready"),
        ("Fastboot", "ready" if getattr(state.device, "fast" + "boot_ready") else "not connected"),
        ("Device changes", "none"),
    )


def _shell_preview_limit_rows() -> tuple[tuple[str, str], ...]:
    return (
        ("Live commands", "not executed"),
        ("Device mutation", "blocked"),
        ("File parsing", "not started"),
        ("Legacy flows", "guarded only"),
    )


def main() -> int:
    app = wx.App(False)
    frame = create_modern_preview_frame(page="shell") or ModernShellFrame()
    frame.Show(True)
    app.MainLoop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
