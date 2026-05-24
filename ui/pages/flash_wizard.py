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
        self._title: wx.StaticText | None = None
        self._body: wx.StaticText | None = None
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

        header = wx.BoxSizer(wx.VERTICAL)
        header.Add(self._text(self, "Flash Wizard", 20, True), 0, wx.BOTTOM, 3)
        header.Add(self._muted(self, "Guided flow preview. State is driven by WizardSession."), 0)
        root.Add(header, 0, wx.EXPAND | wx.ALL, 16)

        root.Add(self._build_steps(), 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 16)

        content_row = wx.BoxSizer(wx.HORIZONTAL)
        content_row.Add(self._build_step_card(), 2, wx.EXPAND | wx.RIGHT, 10)
        content_row.Add(self._build_summary_card(), 1, wx.EXPAND | wx.LEFT, 10)
        root.Add(content_row, 1, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 16)

        root.Add(self._build_footer(), 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 16)
        self.SetSizer(root)

    def _build_steps(self) -> wx.Panel:
        panel = self._card(self)
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        self._step_labels.clear()
        for index, step in enumerate(STEPS):
            label = self._text(panel, f"{index + 1}. {step.title}", 10, True)
            self._step_labels.append(label)
            sizer.Add(label, 1, wx.EXPAND | wx.RIGHT, 8)
        panel.SetSizer(self._wrap(sizer))
        return panel

    def _build_step_card(self) -> wx.Panel:
        card = self._card(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        self._title = self._text(card, "", 18, True)
        self._body = self._muted(card, "")
        sizer.Add(self._title, 0, wx.BOTTOM, 8)
        sizer.Add(self._body, 0, wx.BOTTOM, 14)
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
        sizer.Add(self._text(card, "Session summary", 13, True), 0, wx.BOTTOM, 8)
        self._summary = self._muted(card, "")
        sizer.Add(self._summary, 1, wx.EXPAND | wx.BOTTOM, 12)
        self._warning = self._text(card, "", 10, True)
        self._warning.SetForegroundColour(wx.Colour(self.theme.palette.warning))
        sizer.Add(self._warning, 0)
        card.SetSizer(self._wrap(sizer, 14))
        return card

    def _build_footer(self) -> wx.Panel:
        panel = wx.Panel(self)
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.background))
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.Add(self._muted(panel, "Preview mode: navigation only. No commands are executed."), 1, wx.ALIGN_CENTER_VERTICAL)
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
        self._render_step_content(step.key.value)

        for index, label in enumerate(self._step_labels):
            step_complete = self.session.step_complete(STEPS[index].key)
            if index == self.current_index:
                label.SetForegroundColour(wx.Colour(self.theme.palette.accent))
            elif step_complete:
                label.SetForegroundColour(wx.Colour(self.theme.palette.success))
            else:
                label.SetForegroundColour(wx.Colour(self.theme.palette.text_muted))

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
        self._content_sizer.Add(self._text(self._content_panel, "Current state", 11, True), 0, wx.BOTTOM, 6)
        for line in step_detail_lines(self.session, step_key):
            self._content_sizer.Add(self._muted(self._content_panel, line), 0, wx.EXPAND | wx.BOTTOM, 4)
        self._content_sizer.AddSpacer(8)
        self._content_sizer.Add(self._text(self._content_panel, "Notes", 11, True), 0, wx.BOTTOM, 6)
        for item in _STEP_NOTES.get(step_key, ()):
            self._content_sizer.Add(self._muted(self._content_panel, f"• {item}"), 0, wx.EXPAND | wx.BOTTOM, 6)
        if step_key == "review":
            self._content_sizer.AddSpacer(8)
            self._content_sizer.Add(self._text(self._content_panel, "Warnings", 11, True), 0, wx.BOTTOM, 6)
            for line in warning_lines(self.session):
                text = self._muted(self._content_panel, line)
                text.SetForegroundColour(wx.Colour(self.theme.palette.warning if line.startswith("Warning:") else self.theme.palette.text_muted))
                self._content_sizer.Add(text, 0, wx.EXPAND | wx.BOTTOM, 4)
        if step_key == "flash":
            self._content_sizer.AddSpacer(8)
            disabled = wx.Button(self._content_panel, label="Flash Device disabled" if not self.session.can_flash else "Flash Device")
            disabled.Enable(self.session.can_flash)
            self._content_sizer.Add(disabled, 0, wx.EXPAND)
        self._content_panel.Layout()

    def _summary_text(self) -> str:
        lines = [
            f"Current step: {STEPS[self.current_index].title}",
            "Mode: preview only",
            f"Can flash: {'yes' if self.session.can_flash else 'no'}",
            "",
        ]
        lines.extend(self.session.review_lines()[:6])
        return "\n".join(lines)

    def _warning_text(self) -> str:
        warnings = self.session.warnings()
        if not warnings:
            return "No model warnings."
        first = warnings[0]
        extra = len(warnings) - 1
        if extra > 0:
            return f"Warning: {first} (+{extra} more)"
        return f"Warning: {first}"

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
