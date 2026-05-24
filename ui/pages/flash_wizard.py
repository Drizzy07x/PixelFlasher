"""Safe Flash Wizard preview for the modern PixelFlasher UI rollout.

This is UI-only scaffolding. It does not run flash, patch, adb, fastboot, or
file-processing operations. Real operations must stay in the existing guarded
PixelFlasher flows until each wizard step is individually validated.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import wx

from ui.theme import get_theme


class WizardStepState(str, Enum):
    TODO = "todo"
    ACTIVE = "active"
    COMPLETE = "complete"
    WARNING = "warning"


@dataclass(frozen=True)
class WizardStep:
    key: str
    title: str
    description: str


STEPS: tuple[WizardStep, ...] = (
    WizardStep("device", "Device", "Confirm the target device."),
    WizardStep("firmware", "Firmware", "Select OTA, factory image, or ROM."),
    WizardStep("patch", "Patch Boot", "Optional root image preparation."),
    WizardStep("options", "Options", "Choose safe flashing behavior."),
    WizardStep("review", "Review", "Verify everything before continuing."),
    WizardStep("flash", "Flash", "Run the guarded legacy flash flow later."),
)


class FlashWizardPanel(wx.Panel):
    """UI-only wizard panel for the future guided flash flow."""

    def __init__(self, parent: wx.Window):
        super().__init__(parent)
        self.theme = get_theme("light")
        self.current_index = 0
        self._step_labels: list[wx.StaticText] = []
        self._title: wx.StaticText | None = None
        self._body: wx.StaticText | None = None
        self._summary: wx.StaticText | None = None
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
        header.Add(self._muted(self, "Guided flow preview. No flashing operations are connected yet."), 0)
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
        sizer.Add(self._body, 0, wx.BOTTOM, 18)
        sizer.Add(self._build_step_placeholder(card), 1, wx.EXPAND)
        card.SetSizer(self._wrap(sizer, 16))
        return card

    def _build_step_placeholder(self, parent: wx.Window) -> wx.Panel:
        panel = wx.Panel(parent)
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.surface_raised))
        sizer = wx.BoxSizer(wx.VERTICAL)
        items = (
            "Device detection and firmware parsing will be wired later.",
            "Dangerous choices stay disabled until pre-flight checks exist.",
            "Final flash action will delegate to the existing guarded flow.",
        )
        for item in items:
            sizer.Add(self._muted(panel, f"• {item}"), 0, wx.BOTTOM, 8)
        panel.SetSizer(self._wrap(sizer, 14))
        return panel

    def _build_summary_card(self) -> wx.Panel:
        card = self._card(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Session summary", 13, True), 0, wx.BOTTOM, 8)
        self._summary = self._muted(card, "")
        sizer.Add(self._summary, 1, wx.EXPAND | wx.BOTTOM, 12)
        warning = self._text(card, "Flash is disabled in this preview.", 10, True)
        warning.SetForegroundColour(wx.Colour(self.theme.palette.warning))
        sizer.Add(warning, 0)
        card.SetSizer(self._wrap(sizer, 14))
        return card

    def _build_footer(self) -> wx.Panel:
        panel = wx.Panel(self)
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.background))
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.AddStretchSpacer(1)
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

        for index, label in enumerate(self._step_labels):
            if index < self.current_index:
                label.SetForegroundColour(wx.Colour(self.theme.palette.success))
            elif index == self.current_index:
                label.SetForegroundColour(wx.Colour(self.theme.palette.accent))
            else:
                label.SetForegroundColour(wx.Colour(self.theme.palette.text_muted))

        if self._back:
            self._back.Enable(self.current_index > 0)
        if self._next:
            self._next.SetLabel("Finish preview" if self.current_index == len(STEPS) - 1 else "Next")
        self.Layout()

    def _summary_text(self) -> str:
        completed = [step.title for step in STEPS[: self.current_index]]
        active = STEPS[self.current_index].title
        lines = [
            f"Current step: {active}",
            "Mode: preview only",
            "Flash execution: disabled",
        ]
        if completed:
            lines.append("Completed: " + ", ".join(completed))
        else:
            lines.append("Completed: none")
        return "\n".join(lines)

    def _on_back(self, event: wx.CommandEvent) -> None:
        if self.current_index > 0:
            self.current_index -= 1
            self._render()

    def _on_next(self, event: wx.CommandEvent) -> None:
        if self.current_index < len(STEPS) - 1:
            self.current_index += 1
            self._render()
        else:
            wx.MessageBox("Wizard preview complete. Real flashing remains disabled.", "PixelFlasher", wx.OK | wx.ICON_INFORMATION)

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
