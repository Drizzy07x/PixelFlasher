"""Standalone Modern Shell preview for PixelFlasher.

This preview is intentionally UI-only. It does not run flash, patch, reboot,
ADB, Fastboot, or file-processing operations. It exists to iterate on the full
modern application shell without risking the stable legacy UI.
"""

from __future__ import annotations

import wx

from constants import APPNAME, VERSION
from ui.pages.modern_readonly_state import ModernReadonlyState, build_readonly_state
from ui.pages.modern_preview_copy import (
    DASHBOARD_PREVIEW_ACTIONS,
    MODERN_PREVIEW_FOOTER,
    MODERN_PREVIEW_STATUS,
    MODERN_PREVIEW_SUBTITLE,
    MODERN_PREVIEW_TITLE,
    PREVIEW_BADGES,
    SAFETY_BOUNDARY_LINES,
    nav_label,
)
from ui.theme import get_theme


class ModernShellFrame(wx.Frame):
    """Full modern UI shell preview with safe placeholder pages."""

    def __init__(self) -> None:
        super().__init__(None, title=f"{APPNAME} {VERSION} - Modern Shell Preview", size=(1280, 820))
        self.theme = get_theme("dark")
        self.active_page = "dashboard"
        self.nav_buttons: dict[str, wx.Button] = {}
        self.page_title: wx.StaticText | None = None
        self.page_subtitle: wx.StaticText | None = None
        self.content_panel: wx.ScrolledWindow | None = None
        self.content_sizer: wx.BoxSizer | None = None
        self._build()
        self._show_page("dashboard")
        self.Centre()

    def _build(self) -> None:
        root_panel = wx.Panel(self)
        root_panel.SetBackgroundColour(wx.Colour(self.theme.palette.background))
        root = wx.BoxSizer(wx.HORIZONTAL)
        root.Add(self._build_sidebar(root_panel), 0, wx.EXPAND)
        root.Add(self._build_main(root_panel), 1, wx.EXPAND)
        root_panel.SetSizer(root)

    def _build_sidebar(self, parent: wx.Window) -> wx.Panel:
        panel = wx.Panel(parent)
        panel.SetMinSize((210, -1))
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.surface_raised))
        sizer = wx.BoxSizer(wx.VERTICAL)

        brand = wx.BoxSizer(wx.HORIZONTAL)
        logo = self._text(panel, "P", 18, True)
        logo.SetForegroundColour(wx.Colour(self.theme.palette.accent))
        brand.Add(logo, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 8)
        brand.Add(self._text(panel, "PixelFlasher", 15, True), 0, wx.ALIGN_CENTER_VERTICAL)
        sizer.Add(brand, 0, wx.EXPAND | wx.ALL, 18)

        for key in ("dashboard", "flash", "patch", "devices", "tools", "logs", "settings"):
            button = wx.Button(panel, label=nav_label(_nav_key_for_page(key)))
            button.SetMinSize((-1, 32))
            button.Bind(wx.EVT_BUTTON, lambda event, page=key: self._show_page(page))
            self.nav_buttons[key] = button
            sizer.Add(button, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 10)

        sizer.AddStretchSpacer(1)
        info = self._card(panel)
        info_sizer = wx.BoxSizer(wx.VERTICAL)
        info_sizer.Add(self._text(info, APPNAME, 10, True), 0, wx.BOTTOM, 4)
        info_sizer.Add(self._muted(info, f"{VERSION}\nPreview-only\nRead-only state"), 0)
        info.SetSizer(self._pad(info_sizer, 10))
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
        topbar.Add(self._pill(panel, "No Flash Execution", self.theme.palette.danger), 0, wx.ALIGN_CENTER_VERTICAL)
        sizer.Add(topbar, 0, wx.EXPAND | wx.ALL, 24)

        self.content_panel = wx.ScrolledWindow(panel)
        self.content_panel.SetBackgroundColour(wx.Colour(self.theme.palette.background))
        self.content_panel.SetScrollRate(8, 8)
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
            button.SetLabel(("● " if key == page else "  ") + nav_label(_nav_key_for_page(key)))

        titles = {
            "dashboard": (MODERN_PREVIEW_TITLE, MODERN_PREVIEW_SUBTITLE),
            "flash": ("Flash Wizard - Preview & plan only", "No flashing, patching, or firmware writing."),
            "patch": ("Patch Boot - Guarded legacy planning", "Patching is disabled in this preview."),
            "devices": ("Devices - Read-only state", "Connected device overview preview."),
            "tools": ("Tools - Utilities preview", "No ADB or Fastboot command execution."),
            "logs": ("Logs", "Readable activity and diagnostics preview."),
            "settings": ("Settings", "Modern UI preferences preview."),
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
            "patch": self._render_patch,
            "devices": self._render_devices,
            "tools": self._render_tools,
            "logs": self._render_logs,
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
        sizer.Add(self._text(card, "Patch Boot Preview", 16, True), 0, wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "This page will mirror the future Patch Boot flow. No patching is wired here."), 0, wx.BOTTOM, 14)
        sizer.Add(self._disabled_pill(card, "Preview only · patch execution disabled"), 0, wx.EXPAND | wx.BOTTOM, 12)
        for title, value in (
            ("Patch method", "Auto recommended · disabled in preview"),
            ("Magisk", "Stable latest · placeholder"),
            ("Output", "No patched image is created in this preview"),
        ):
            sizer.Add(self._info_row(card, title, value), 0, wx.EXPAND | wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "Safety note: Patch Boot remains read-only until legacy guarded wiring is approved."), 0, wx.TOP, 6)
        card.SetSizer(self._pad(sizer, 18))
        self.content_sizer.Add(card, 0, wx.EXPAND)

    def _render_devices(self) -> None:
        card = self._card(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Devices Preview", 16, True), 0, wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "Device scanning remains in the legacy app until the modern adapter is validated."), 0, wx.BOTTOM, 14)
        sizer.Add(self._disabled_pill(card, "Preview only · scan/refresh disabled"), 0, wx.EXPAND | wx.BOTTOM, 12)
        for title, value in _shell_device_info_rows(self._readonly_state()):
            sizer.Add(self._info_row(card, title, value), 0, wx.EXPAND | wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "Safety note: No connect, reboot, slot switching, wipe, or device changes are available in preview."), 0, wx.TOP, 6)
        card.SetSizer(self._pad(sizer, 18))
        self.content_sizer.Add(card, 0, wx.EXPAND)

    def _render_tools(self) -> None:
        card = self._card(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Tools Preview", 16, True), 0, wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "Utility tools are listed for layout validation only. No commands run here."), 0, wx.BOTTOM, 14)
        sizer.Add(self._disabled_pill(card, "Preview only · tool execution disabled"), 0, wx.EXPAND | wx.BOTTOM, 12)
        for title, value in _shell_tool_rows(self._readonly_state()):
            sizer.Add(self._info_row(card, title, value), 0, wx.EXPAND | wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "Safety note: Modern Shell Tools will delegate to guarded legacy logic in a future phase."), 0, wx.TOP, 6)
        card.SetSizer(self._pad(sizer, 18))
        self.content_sizer.Add(card, 0, wx.EXPAND)

    def _render_logs(self) -> None:
        card = self._card(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Preview Log", 16, True), 0, wx.BOTTOM, 8)
        sizer.Add(self._disabled_pill(card, "Preview only · live log capture disabled"), 0, wx.EXPAND | wx.BOTTOM, 12)
        log = wx.TextCtrl(
            card,
            value="INFO  Modern shell preview opened\nINFO  Flash execution disabled\nINFO  Use legacy PixelFlasher for real operations\n",
            style=wx.TE_MULTILINE | wx.TE_READONLY | wx.BORDER_SIMPLE,
        )
        log.SetMinSize((-1, 300))
        sizer.Add(log, 1, wx.EXPAND | wx.BOTTOM, 10)
        sizer.Add(self._muted(card, "Safety note: Logs shown here are static preview entries and do not stream device output."), 0)
        card.SetSizer(self._pad(sizer, 18))
        self.content_sizer.Add(card, 1, wx.EXPAND)

    def _render_settings(self) -> None:
        card = self._card(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Modern UI Settings Preview", 16, True), 0, wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "Settings are visual only in this preview."), 0, wx.BOTTOM, 14)
        for title, value in (("Theme", "Light preview"), ("Safety mode", "Flash Wizard read-only"), ("Legacy fallback", "enabled")):
            sizer.Add(self._info_row(card, title, value), 0, wx.EXPAND | wx.BOTTOM, 8)
        card.SetSizer(self._pad(sizer, 18))
        self.content_sizer.Add(card, 0, wx.EXPAND)

    def _render_placeholder(self, title: str) -> None:
        card = self._card(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, f"{title} Preview", 16, True), 0, wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "This page is reserved for the modern UI migration."), 0)
        card.SetSizer(self._pad(sizer, 18))
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
        panel = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._muted(panel, title), 0)
        label = self._text(panel, value, 12, True)
        label.SetForegroundColour(wx.Colour(color))
        sizer.Add(label, 0)
        panel.SetSizer(self._pad(sizer, 8))
        return panel

    def _recommended_card(self, parent: wx.Window, state: ModernReadonlyState) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Recommended Next Step", 13, True), 0, wx.BOTTOM, 12)
        sizer.Add(self._text(card, _shell_recommended_title(state), 18, True), 0, wx.BOTTOM, 6)
        sizer.Add(self._muted(card, _shell_recommended_body(state)), 0, wx.BOTTOM, 18)
        sizer.Add(self._disabled_pill(card, "Browse File disabled"), 0, wx.EXPAND)
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
        sizer.Add(self._text(card, "Quick Actions (Preview)", 14, True), 0, wx.BOTTOM, 12)
        grid = wx.GridSizer(rows=2, cols=2, vgap=10, hgap=10)
        for title, body in _shell_preview_action_rows():
            grid.Add(self._action_card(card, title, body), 1, wx.EXPAND)
        sizer.Add(grid, 0, wx.EXPAND)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _safety_boundary_card(self, parent: wx.Window) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Safety Boundary", 14, True), 0, wx.BOTTOM, 10)
        for line in SAFETY_BOUNDARY_LINES:
            sizer.Add(self._muted(card, line), 0, wx.BOTTOM, 5)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _action_card(self, parent: wx.Window, title: str, body: str) -> wx.Panel:
        panel = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(panel, title, 12, True), 0, wx.BOTTOM, 4)
        sizer.Add(self._muted(panel, body), 0, wx.BOTTOM, 10)
        sizer.Add(self._disabled_pill(panel, "Preview only"), 0, wx.EXPAND)
        panel.SetSizer(self._pad(sizer, 10))
        return panel

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
        for title, value in (("Data", "Keep Data"), ("Slot", "Inactive slot disabled"), ("Output", "Verbose preview only")):
            sizer.Add(self._info_row(card, title, value), 0, wx.EXPAND | wx.BOTTOM, 8)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _flash_action_card(self, parent: wx.Window) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Execution", 15, True), 0, wx.BOTTOM, 10)
        sizer.Add(self._muted(card, "Real flashing is intentionally disabled in this preview."), 0, wx.BOTTOM, 18)
        sizer.Add(self._disabled_pill(card, "Flash Now disabled"), 0, wx.EXPAND | wx.BOTTOM, 10)
        sizer.Add(self._disabled_pill(card, "Dry Run preview"), 0, wx.EXPAND)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _console_card(self, parent: wx.Window) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Console", 15, True), 0, wx.BOTTOM, 10)
        console = wx.TextCtrl(
            card,
            value="INFO  Modern flash page preview loaded\nWARN  Flash execution disabled\nINFO  Legacy PixelFlasher remains source of truth\n",
            style=wx.TE_MULTILINE | wx.TE_READONLY | wx.BORDER_SIMPLE,
        )
        console.SetMinSize((-1, 170))
        sizer.Add(console, 1, wx.EXPAND)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _info_row(self, parent: wx.Window, title: str, value: str) -> wx.Panel:
        panel = wx.Panel(parent)
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.surface_raised))
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.Add(self._muted(panel, title), 1, wx.ALIGN_CENTER_VERTICAL)
        sizer.Add(self._text(panel, value, 10, True), 1, wx.ALIGN_CENTER_VERTICAL)
        panel.SetSizer(self._pad(sizer, 8))
        return panel

    def _info_column(self, parent: wx.Window, title: str, value: str) -> wx.Panel:
        panel = wx.Panel(parent)
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.surface_raised))
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._muted(panel, title), 0, wx.BOTTOM, 3)
        sizer.Add(self._text(panel, value, 11, True), 0)
        panel.SetSizer(self._pad(sizer, 10))
        return panel

    def _disabled_pill(self, parent: wx.Window, label: str) -> wx.Panel:
        panel = wx.Panel(parent)
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.surface_raised))
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        text = self._text(panel, label, 10, True)
        text.SetForegroundColour(wx.Colour(self.theme.palette.text_muted))
        sizer.AddStretchSpacer(1)
        sizer.Add(text, 0, wx.ALIGN_CENTER_VERTICAL)
        sizer.AddStretchSpacer(1)
        panel.SetSizer(self._pad(sizer, 7))
        return panel

    def _card(self, parent: wx.Window) -> wx.Panel:
        panel = wx.Panel(parent)
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.surface))
        panel.SetWindowStyleFlag(wx.BORDER_SIMPLE)
        return panel

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
        text = self._text(parent, f"  {label}  ", 10, True)
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
        ("Fastboot", "ready" if device.fastboot_ready else "not connected"),
        ("Bootloader", _known_or_unknown(device.bootloader_state).lower()),
        ("Current slot", device.active_slot or "unknown"),
    )


def _shell_recommended_title(state: ModernReadonlyState) -> str:
    return "Review Firmware" if state.firmware.selected else "Select Firmware"


def _shell_recommended_body(state: ModernReadonlyState) -> str:
    if state.firmware.selected:
        return f"{state.firmware.filename or 'Selected firmware'} is loaded for read-only review."
    return "Choose a firmware package before planning a flash."


def _shell_firmware_subtitle(state: ModernReadonlyState) -> str:
    if state.firmware.selected:
        return state.firmware.filename or state.firmware.path
    return "No firmware selected. This preview does not open files."


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
        ("Slot Changes", "disabled in preview"),
        ("Device Changes", "none"),
    )


def _shell_flash_summary_rows(state: ModernReadonlyState) -> tuple[tuple[str, str], ...]:
    return (
        ("Device", state.device.display_name or state.device.serial or "not selected"),
        ("Firmware", state.firmware.filename or "not selected"),
        ("Patch", "image available" if state.firmware.has_patchable_image else "not ready"),
        ("Options", "keep data"),
        ("Flash", "disabled"),
    )


def _shell_tool_rows(state: ModernReadonlyState) -> tuple[tuple[str, str], ...]:
    tools = state.tools
    platform_tools = "ADB/Fastboot available" if tools.adb_available and tools.fastboot_available else "not fully detected"
    return (
        ("Platform Tools", platform_tools),
        ("ADB shell", "disabled"),
        ("Fastboot commands", "disabled"),
        ("File open/extract", "disabled"),
    )


def _shell_preview_action_rows() -> tuple[tuple[str, str], ...]:
    return DASHBOARD_PREVIEW_ACTIONS + (
        ("Settings", "Preferences only. No device changes."),
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


def _nav_key_for_page(key: str) -> str:
    return {
        "dashboard": "dashboard",
        "flash": "wizard",
        "patch": "wizard",
        "devices": "shell",
        "tools": "tools",
        "logs": "shell",
        "settings": "settings",
    }.get(key, key)


def main() -> int:
    app = wx.App(False)
    frame = ModernShellFrame()
    frame.Show(True)
    app.MainLoop()
    return 0
