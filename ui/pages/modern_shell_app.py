"""Standalone Modern Shell preview for PixelFlasher.

This preview is intentionally UI-only. It does not run flash, patch, reboot,
ADB, Fastboot, or file-processing operations. It exists to iterate on the full
modern application shell without risking the stable legacy UI.
"""

from __future__ import annotations

import wx

from constants import APPNAME, VERSION
from ui.theme import get_theme


class ModernShellFrame(wx.Frame):
    """Full modern UI shell preview with safe placeholder pages."""

    def __init__(self) -> None:
        super().__init__(None, title=f"{APPNAME} {VERSION} - Modern Shell Preview", size=(1280, 820))
        self.theme = get_theme("light")
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
        panel.SetBackgroundColour(wx.Colour("#F8FAFC"))
        sizer = wx.BoxSizer(wx.VERTICAL)

        brand = wx.BoxSizer(wx.HORIZONTAL)
        logo = self._text(panel, "P", 18, True)
        logo.SetForegroundColour(wx.Colour(self.theme.palette.accent))
        brand.Add(logo, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 8)
        brand.Add(self._text(panel, "PixelFlasher", 15, True), 0, wx.ALIGN_CENTER_VERTICAL)
        sizer.Add(brand, 0, wx.EXPAND | wx.ALL, 18)

        for key in ("dashboard", "flash", "patch", "devices", "tools", "logs", "settings"):
            button = wx.Button(panel, label=_title_for_page(key))
            button.SetMinSize((-1, 32))
            button.Bind(wx.EVT_BUTTON, lambda event, page=key: self._show_page(page))
            self.nav_buttons[key] = button
            sizer.Add(button, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 10)

        sizer.AddStretchSpacer(1)
        info = self._card(panel)
        info_sizer = wx.BoxSizer(wx.VERTICAL)
        info_sizer.Add(self._text(info, APPNAME, 10, True), 0, wx.BOTTOM, 4)
        info_sizer.Add(self._muted(info, f"{VERSION}\nPreview-only shell"), 0)
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
        self.page_title = self._text(panel, "Dashboard", 22, True)
        self.page_subtitle = self._muted(panel, "Modern shell preview")
        title_stack.Add(self.page_title, 0, wx.BOTTOM, 3)
        title_stack.Add(self.page_subtitle, 0)
        topbar.Add(title_stack, 1, wx.ALIGN_CENTER_VERTICAL)
        topbar.Add(self._pill(panel, "Preview Only", self.theme.palette.warning), 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 8)
        topbar.Add(self._pill(panel, "No Flash Execution", self.theme.palette.danger), 0, wx.ALIGN_CENTER_VERTICAL)
        sizer.Add(topbar, 0, wx.EXPAND | wx.ALL, 24)

        self.content_panel = wx.ScrolledWindow(panel)
        self.content_panel.SetBackgroundColour(wx.Colour(self.theme.palette.background))
        self.content_panel.SetScrollRate(8, 8)
        self.content_sizer = wx.BoxSizer(wx.VERTICAL)
        self.content_panel.SetSizer(self.content_sizer)
        sizer.Add(self.content_panel, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 24)

        footer = wx.BoxSizer(wx.HORIZONTAL)
        footer.Add(self._pill(panel, "Ready", self.theme.palette.success), 0, wx.ALIGN_CENTER_VERTICAL)
        footer.AddStretchSpacer(1)
        footer.Add(self._muted(panel, "Modern Shell Preview · Real operations remain in legacy PixelFlasher"), 0, wx.ALIGN_CENTER_VERTICAL)
        sizer.Add(footer, 0, wx.EXPAND | wx.ALL, 16)

        panel.SetSizer(sizer)
        return panel

    def _show_page(self, page: str) -> None:
        self.active_page = page
        for key, button in self.nav_buttons.items():
            button.SetLabel(("● " if key == page else "  ") + _title_for_page(key))

        titles = {
            "dashboard": ("Dashboard", "Device status, firmware readiness, and safe next steps."),
            "flash": ("Flash", "Modern flash planning preview. Execution is disabled."),
            "patch": ("Patch Boot", "Boot/init_boot patch planning preview."),
            "devices": ("Devices", "Connected device overview preview."),
            "tools": ("Tools", "Safe utility launcher preview."),
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
        row = wx.BoxSizer(wx.HORIZONTAL)
        row.Add(self._device_overview_card(self.content_panel), 2, wx.EXPAND | wx.RIGHT, 14)
        row.Add(self._recommended_card(self.content_panel), 1, wx.EXPAND)
        self.content_sizer.Add(row, 0, wx.EXPAND | wx.BOTTOM, 14)
        self.content_sizer.Add(self._firmware_card(self.content_panel), 0, wx.EXPAND | wx.BOTTOM, 14)
        self.content_sizer.Add(self._quick_actions_card(self.content_panel), 0, wx.EXPAND | wx.BOTTOM, 14)
        self.content_sizer.Add(self._bottom_status_card(self.content_panel), 0, wx.EXPAND)

    def _render_flash(self) -> None:
        top = wx.BoxSizer(wx.HORIZONTAL)
        top.Add(self._flash_package_card(self.content_panel), 3, wx.EXPAND | wx.RIGHT, 14)
        top.Add(self._flash_summary_card(self.content_panel), 1, wx.EXPAND)
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
        for title, value in (
            ("Patch method", "Auto recommended · disabled in preview"),
            ("Magisk", "Stable latest · placeholder"),
            ("Output", "No patched image is created in this preview"),
        ):
            sizer.Add(self._info_row(card, title, value), 0, wx.EXPAND | wx.BOTTOM, 8)
        card.SetSizer(self._pad(sizer, 18))
        self.content_sizer.Add(card, 0, wx.EXPAND)

    def _render_devices(self) -> None:
        card = self._card(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "No device selected", 16, True), 0, wx.BOTTOM, 8)
        sizer.Add(self._muted(card, "Device scanning remains in the legacy app until the modern adapter is validated."), 0, wx.BOTTOM, 14)
        for title, value in (("ADB", "not connected"), ("Fastboot", "not connected"), ("Bootloader", "unknown")):
            sizer.Add(self._info_row(card, title, value), 0, wx.EXPAND | wx.BOTTOM, 8)
        card.SetSizer(self._pad(sizer, 18))
        self.content_sizer.Add(card, 0, wx.EXPAND)

    def _render_logs(self) -> None:
        card = self._card(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Preview Log", 16, True), 0, wx.BOTTOM, 8)
        log = wx.TextCtrl(
            card,
            value="INFO  Modern shell preview opened\nINFO  Flash execution disabled\nINFO  Use legacy PixelFlasher for real operations\n",
            style=wx.TE_MULTILINE | wx.TE_READONLY | wx.BORDER_SIMPLE,
        )
        log.SetMinSize((-1, 300))
        sizer.Add(log, 1, wx.EXPAND)
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

    def _device_overview_card(self, parent: wx.Window) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        phone = wx.Panel(card)
        phone.SetMinSize((96, 150))
        phone.SetBackgroundColour(wx.Colour("#E5E7EB"))
        phone_sizer = wx.BoxSizer(wx.VERTICAL)
        phone_sizer.AddStretchSpacer(1)
        phone_sizer.Add(self._muted(phone, "Device"), 0, wx.ALIGN_CENTER)
        phone_sizer.AddStretchSpacer(1)
        phone.SetSizer(phone_sizer)
        sizer.Add(phone, 0, wx.RIGHT, 18)

        details = wx.BoxSizer(wx.VERTICAL)
        details.Add(self._text(card, "No device connected", 18, True), 0, wx.BOTTOM, 4)
        details.Add(self._muted(card, "Connect a device and use the legacy scan flow."), 0, wx.BOTTOM, 14)
        details.Add(self._status_grid(card), 0, wx.EXPAND)
        sizer.Add(details, 1, wx.EXPAND)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _status_grid(self, parent: wx.Window) -> wx.Sizer:
        grid = wx.GridSizer(rows=2, cols=2, vgap=8, hgap=8)
        for title, value, color in (
            ("ADB", "Unknown", self.theme.palette.info),
            ("Bootloader", "Unknown", self.theme.palette.info),
            ("Root", "Unknown", self.theme.palette.info),
            ("Slot", "Unknown", self.theme.palette.info),
        ):
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

    def _recommended_card(self, parent: wx.Window) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Recommended Next Step", 13, True), 0, wx.BOTTOM, 12)
        sizer.Add(self._text(card, "Select Firmware", 18, True), 0, wx.BOTTOM, 6)
        sizer.Add(self._muted(card, "Choose a firmware package before planning a flash."), 0, wx.BOTTOM, 18)
        sizer.Add(self._disabled_pill(card, "Browse File disabled"), 0, wx.EXPAND)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _firmware_card(self, parent: wx.Window) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Firmware / ROM File", 14, True), 0, wx.BOTTOM, 4)
        sizer.Add(self._muted(card, "No firmware selected. This preview does not open files."), 0, wx.BOTTOM, 12)
        for title, value in (("Type", "not selected"), ("Build", "unknown"), ("Validation", "waiting")):
            sizer.Add(self._info_row(card, title, value), 0, wx.EXPAND | wx.BOTTOM, 6)
        card.SetSizer(self._pad(sizer, 18))
        return card

    def _quick_actions_card(self, parent: wx.Window) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Quick Actions", 14, True), 0, wx.BOTTOM, 12)
        grid = wx.GridSizer(rows=2, cols=2, vgap=10, hgap=10)
        for title, body in (
            ("Patch Boot", "Plan patching flow"),
            ("Flash Device", "Disabled in preview"),
            ("Reboot", "Legacy action later"),
            ("Open Folder", "Disabled in preview"),
        ):
            grid.Add(self._action_card(card, title, body), 1, wx.EXPAND)
        sizer.Add(grid, 0, wx.EXPAND)
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

    def _bottom_status_card(self, parent: wx.Window) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        for title, value in (("Active Slot", "Unknown"), ("Magisk", "Unknown"), ("Backup", "No backup found")):
            sizer.Add(self._info_column(card, title, value), 1, wx.EXPAND | wx.RIGHT, 12)
        card.SetSizer(self._pad(sizer, 14))
        return card

    def _flash_package_card(self, parent: wx.Window) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Flash Package / Boot Image", 15, True), 0, wx.BOTTOM, 10)
        sizer.Add(self._info_row(card, "Selected package", "none"), 0, wx.EXPAND | wx.BOTTOM, 10)
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

    def _flash_summary_card(self, parent: wx.Window) -> wx.Panel:
        card = self._card(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Safety Summary", 15, True), 0, wx.BOTTOM, 10)
        for title, value in (("Device", "not selected"), ("Firmware", "not selected"), ("Patch", "not ready"), ("Options", "keep data"), ("Flash", "disabled")):
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
        panel.SetBackgroundColour(wx.Colour("#F1F5F9"))
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


def main() -> int:
    app = wx.App(False)
    frame = ModernShellFrame()
    frame.Show(True)
    app.MainLoop()
    return 0
