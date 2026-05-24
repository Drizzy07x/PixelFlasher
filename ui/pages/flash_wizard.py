"""Safe Flash Wizard preview for the modern PixelFlasher UI rollout.

This is UI-only scaffolding. It does not run flash, patch, adb, fastboot, or
file-processing operations. Real operations must stay in the existing guarded
PixelFlasher flows until each wizard step is individually validated.
"""

from __future__ import annotations

import wx

from ui.pages.flash_wizard_details import step_detail_lines, warning_lines
from ui.pages.flash_wizard_model import STEPS, WizardSession
from ui.theme import get_theme

_STEP_NOTES: dict[str, tuple[str, ...]] = {
    "device": (
        "Use the legacy Scan Devices control until wizard device scanning is wired.",
        "This step is complete only when a device is selected and ADB/Fastboot is ready.",
    ),
    "firmware": (
        "Firmware must be verified before the final review can pass.",
        "Invalid or mismatched packages should block the final flash step.",
    ),
    "patch": (
        "Patching remains disabled in this preview.",
        "Patch choices will be wired only after firmware and target device checks are reliable.",
    ),
    "options": (
        "Dangerous options require explicit confirmation later.",
        "Safe default remains keep data and avoid force options.",
    ),
    "review": (
        "Review uses WizardSession.review_lines() and WizardSession.warnings().",
        "Final action remains blocked while can_flash is false.",
    ),
    "flash": (
        "Flash execution is disabled in this preview.",
        "When implemented, this step should delegate to the existing guarded legacy flash flow.",
    ),
}


class FlashWizardPanel(wx.Panel):
    """UI-only wizard panel for the future guided flash flow."""

    def __init__(self, parent: wx.Window, session: WizardSession | None = None):
        super().__init__(parent)
        self.theme = get_theme("light")
        self.session = session or WizardSession()
        self.current_index = 0
        self._step_labels: list[wx.StaticText] = []
        self._step_badges: list[wx.StaticText] = []
        self._title: wx.StaticText | None = None
        self._body: wx.StaticText | None = None
        self._status_badge: wx.StaticText | None = None
        self._content_panel: wx.Panel | None = None
        self._content_sizer: wx.BoxSizer | None = None
        self._summary: wx.StaticText | None = None
        self._warning: wx.StaticText | None = None
        self._back: wx.Button | None = None
        self._next: wx.Button | None = None
        self._build()
        self._render()

    def _build(self) -> None:
        palette = self.theme.palette
        self.SetBackgroundColour(wx.Colour(palette.background))
        root = wx.BoxSizer(wx.VERTICAL)

        header = wx.BoxSizer(wx.HORIZONTAL)
        title_stack = wx.BoxSizer(wx.VERTICAL)
        title_stack.Add(self._text(self, "Flash Wizard", 20, True), 0, wx.BOTTOM, 3)
        title_stack.Add(self._muted(self, "Guided preview. Reads WizardSession only; no commands are executed."), 0)
        header.Add(title_stack, 1, wx.EXPAND)
        self._status_badge = self._badge(self, "Preview", "info")
        header.Add(self._status_badge, 0, wx.ALIGN_CENTER_VERTICAL)
        root.Add(header, 0, wx.EXPAND | wx.ALL, 16)

        root.Add(self._build_steps(), 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 12)

        content_row = wx.BoxSizer(wx.HORIZONTAL)
        content_row.Add(self._build_step_card(), 2, wx.EXPAND | wx.RIGHT, 10)
        content_row.Add(self._build_summary_card(), 1, wx.EXPAND | wx.LEFT, 10)
        root.Add(content_row, 1, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 12)

        root.Add(self._build_footer(), 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 16)
        self.SetSizer(root)

    def _build_steps(self) -> wx.Panel:
        panel = self._card(self)
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        self._step_labels.clear()
        self._step_badges.clear()
        for index, step in enumerate(STEPS):
            cell = wx.BoxSizer(wx.VERTICAL)
            label = self._text(panel, f"{index + 1}. {step.title}", 10, True)
            badge = self._badge(panel, "Todo", "muted")
            self._step_labels.append(label)
            self._step_badges.append(badge)
            cell.Add(label, 0, wx.BOTTOM, 4)
            cell.Add(badge, 0)
            sizer.Add(cell, 1, wx.EXPAND | wx.RIGHT, 8)
        panel.SetSizer(self._wrap(sizer, 10))
        return panel

    def _build_step_card(self) -> wx.Panel:
        card = self._card(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        heading = wx.BoxSizer(wx.HORIZONTAL)
        title_stack = wx.BoxSizer(wx.VERTICAL)
        self._title = self._text(card, "", 18, True)
        self._body = self._muted(card, "")
        title_stack.Add(self._title, 0, wx.BOTTOM, 4)
        title_stack.Add(self._body, 0)
        heading.Add(title_stack, 1, wx.EXPAND)
        sizer.Add(heading, 0, wx.EXPAND | wx.BOTTOM, 14)

        self._content_panel = wx.Panel(card)
        self._content_panel.SetBackgroundColour(wx.Colour(self.theme.palette.surface_raised))
        self._content_sizer = wx.BoxSizer(wx.VERTICAL)
        self._content_panel.SetSizer(self._wrap(self._content_sizer, 14))
        sizer.Add(self._content_panel, 1, wx.EXPAND)
        card.SetSizer(self._wrap(sizer, 16))
        return card

    def _build_summary_card(self) -> wx.Panel:
        card = self._card(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        top = wx.BoxSizer(wx.HORIZONTAL)
        top.Add(self._text(card, "Session summary", 13, True), 1, wx.ALIGN_CENTER_VERTICAL)
        top.Add(self._badge(card, "Read-only", "info"), 0, wx.ALIGN_CENTER_VERTICAL)
        sizer.Add(top, 0, wx.EXPAND | wx.BOTTOM, 10)

        self._summary = self._muted(card, "")
        sizer.Add(self._summary, 1, wx.EXPAND | wx.BOTTOM, 12)

        sizer.Add(self._text(card, "Blocking state", 11, True), 0, wx.BOTTOM, 6)
        self._warning = self._text(card, "", 10, True)
        self._warning.SetForegroundColour(wx.Colour(self.theme.palette.warning))
        sizer.Add(self._warning, 0, wx.EXPAND)
        card.SetSizer(self._wrap(sizer, 14))
        return card

    def _build_footer(self) -> wx.Panel:
        panel = wx.Panel(self)
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.background))
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.Add(self._muted(panel, "Preview mode: navigation only. Flash remains disabled unless a future guarded flow enables it."), 1, wx.ALIGN_CENTER_VERTICAL)
        self._back = wx.Button(panel, label="Back")
        self._next = wx.Button(panel, label="Next")
        self._back.Bind(wx.EVT_BUTTON, self._on_back)
        self._next.Bind(wx.EVT_BUTTON, self._on_next)
        sizer.Add(self._back, 0, wx.RIGHT, 8)
        sizer.Add(self._next, 0)
        panel.SetSizer(sizer)
        return panel

    def _render(self) -> None:
        step = STEPS[self.current_index]
        if self._title:
            self._title.SetLabel(step.title)
        if self._body:
            self._body.SetLabel(step.description)
        if self._summary:
            self._summary.SetLabel(self._summary_text())
        if self._warning:
            self._warning.SetLabel(self._warning_text())
        if self._status_badge:
            if self.session.can_flash:
                self._set_badge(self._status_badge, "Ready", "ready")
            else:
                self._set_badge(self._status_badge, "Blocked", "warning")
        self._render_step_content(step.key.value)

        for index, label in enumerate(self._step_labels):
            badge = self._step_badges[index]
            step_complete = self.session.step_complete(STEPS[index].key)
            if index == self.current_index:
                label.SetForegroundColour(wx.Colour(self.theme.palette.accent))
                self._set_badge(badge, "Active", "info")
            elif step_complete:
                label.SetForegroundColour(wx.Colour(self.theme.palette.success))
                self._set_badge(badge, "Ready", "ready")
            else:
                label.SetForegroundColour(wx.Colour(self.theme.palette.text_muted))
                self._set_badge(badge, "Todo", "muted")

        if self._back:
            self._back.Enable(self.current_index > 0)
        if self._next:
            if self.current_index == len(STEPS) - 1:
                self._next.SetLabel("Flash disabled" if not self.session.can_flash else "Flash")
                self._next.Enable(self.session.can_flash)
            else:
                self._next.SetLabel("Next")
                self._next.Enable(True)
        self.Layout()

    def _render_step_content(self, step_key: str) -> None:
        if self._content_panel is None or self._content_sizer is None:
            return
        self._content_sizer.Clear(delete_windows=True)

        current = self._section(self._content_panel, "Current state")
        self._content_sizer.Add(current, 0, wx.EXPAND | wx.BOTTOM, 8)
        for line in step_detail_lines(self.session, step_key):
            self._content_sizer.Add(self._line(self._content_panel, line), 0, wx.EXPAND | wx.BOTTOM, 4)

        self._content_sizer.AddSpacer(8)
        self._content_sizer.Add(self._section(self._content_panel, "Notes"), 0, wx.EXPAND | wx.BOTTOM, 8)
        for item in _STEP_NOTES.get(step_key, ()):
            self._content_sizer.Add(self._line(self._content_panel, item, bullet=True), 0, wx.EXPAND | wx.BOTTOM, 6)

        if step_key in {"review", "flash"}:
            self._content_sizer.AddSpacer(8)
            self._content_sizer.Add(self._section(self._content_panel, "Warnings"), 0, wx.EXPAND | wx.BOTTOM, 8)
            for line in warning_lines(self.session):
                self._content_sizer.Add(self._line(self._content_panel, line, warning=line.startswith("Warning:")), 0, wx.EXPAND | wx.BOTTOM, 4)

        if step_key == "flash":
            self._content_sizer.AddSpacer(10)
            final = wx.Button(self._content_panel, label="Flash Device disabled" if not self.session.can_flash else "Flash Device")
            final.Enable(self.session.can_flash)
            final.SetToolTip("Preview only. Real flashing is not wired here.")
            self._content_sizer.Add(final, 0, wx.EXPAND)
        self._content_panel.Layout()

    def _summary_text(self) -> str:
        lines = [
            f"Current step: {STEPS[self.current_index].title}",
            f"Can flash: {'yes' if self.session.can_flash else 'no'}",
            f"Warnings: {len(self.session.warnings())}",
            "",
        ]
        lines.extend(self.session.review_lines()[:7])
        return "\n".join(lines)

    def _warning_text(self) -> str:
        warnings = self.session.warnings()
        if not warnings:
            return "No blocking warnings."
        first = warnings[0]
        extra = len(warnings) - 1
        if extra > 0:
            return f"Blocked: {first} (+{extra} more)"
        return f"Blocked: {first}"

    def _on_back(self, event: wx.CommandEvent) -> None:
        if self.current_index > 0:
            self.current_index -= 1
            self._render()

    def _on_next(self, event: wx.CommandEvent) -> None:
        if self.current_index < len(STEPS) - 1:
            self.current_index += 1
            self._render()
        elif self.session.can_flash:
            wx.MessageBox("Flash would run here in a future guarded build.", "PixelFlasher", wx.OK | wx.ICON_INFORMATION)

    def _card(self, parent: wx.Window) -> wx.Panel:
        panel = wx.Panel(parent)
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.surface))
        panel.SetWindowStyleFlag(wx.BORDER_SIMPLE)
        return panel

    def _wrap(self, content: wx.Sizer, pad: int = 10) -> wx.BoxSizer:
        wrapper = wx.BoxSizer(wx.VERTICAL)
        wrapper.Add(content, 1, wx.EXPAND | wx.ALL, pad)
        return wrapper

    def _section(self, parent: wx.Window, label: str) -> wx.StaticText:
        text = self._text(parent, label, 11, True)
        text.SetForegroundColour(wx.Colour(self.theme.palette.accent))
        return text

    def _line(self, parent: wx.Window, label: str, bullet: bool = False, warning: bool = False) -> wx.StaticText:
        prefix = "• " if bullet else ""
        text = self._muted(parent, f"{prefix}{label}")
        if warning:
            text.SetForegroundColour(wx.Colour(self.theme.palette.warning))
        return text

    def _badge(self, parent: wx.Window, label: str, kind: str) -> wx.StaticText:
        text = self._text(parent, label, 9, True)
        self._set_badge(text, label, kind)
        return text

    def _set_badge(self, text: wx.StaticText, label: str, kind: str) -> None:
        text.SetLabel(label)
        color = {
            "ready": self.theme.palette.success,
            "warning": self.theme.palette.warning,
            "info": self.theme.palette.info,
            "muted": self.theme.palette.text_muted,
        }.get(kind, self.theme.palette.text_muted)
        text.SetForegroundColour(wx.Colour(color))

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
        text = self._text(parent, label, 10)
        text.SetForegroundColour(wx.Colour(self.theme.palette.text_muted))
        return text
