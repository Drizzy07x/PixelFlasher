"""Flash Wizard surface for the modern PixelFlasher UI.

This is UI-only scaffolding. It does not run flash, patch, ADB, Fastboot, or
file-processing operations. Real operations must stay in the existing guarded
PixelFlasher flows until each wizard step is individually validated.
"""

from __future__ import annotations

if __package__ in {None, ""}:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import wx

from constants import VERSION
from ui.pages.flash_wizard_details import step_detail_lines, warning_lines
from ui.pages.flash_wizard_model import STEPS, WizardSession
from ui.pages.modern_preview_copy import MODERN_PREVIEW_FOOTER, MODERN_PREVIEW_SUBTITLE, PREVIEW_BADGES
from ui.pages import modern_preview_style as preview_style
from ui.pages.modern_preview_web import create_modern_preview_frame
from ui.theme import get_theme

FLASH_WIZARD_PREVIEW_TITLE = "Flash Wizard"

_STEP_NOTES: dict[str, tuple[str, ...]] = {
    "device": (
        "Legacy scan remains the source of truth.",
        "Complete when a device is selected and ADB/Fastboot is ready.",
    ),
    "firmware": (
        "Firmware must be verified before review passes.",
        "Mismatched packages should block the final flash step.",
    ),
    "patch": (
        "Patching continues through PixelFlasher confirmation.",
        "Patch choices depend on firmware checks.",
    ),
    "options": (
        "Dangerous options require explicit confirmation later.",
        "Safe default remains keep data and avoid force options.",
    ),
    "review": (
        "Review uses WizardSession summary and warnings.",
        "Final action requires PixelFlasher confirmation.",
    ),
    "flash": (
        "Flash execution requires PixelFlasher confirmation.",
        "Final handoff uses the guarded PixelFlasher flash flow.",
    ),
}


class FlashWizardPanel(wx.Panel):
    """UI-only wizard panel for the future guided flash flow."""

    def __init__(self, parent: wx.Window, session: WizardSession | None = None):
        super().__init__(parent)
        self.theme = get_theme("dark")
        self.session = session or WizardSession()
        self.current_index = 0
        self._step_cells: list[wx.Panel] = []
        self._step_labels: list[wx.StaticText] = []
        self._step_badges: list[wx.StaticText] = []
        self._title: wx.StaticText | None = None
        self._body: wx.StaticText | None = None
        self._status_badge: wx.StaticText | None = None
        self._content_panel: wx.Panel | None = None
        self._content_sizer: wx.BoxSizer | None = None
        self._summary: wx.StaticText | None = None
        self._warning: wx.StaticText | None = None
        self._back: wx.Window | None = None
        self._next: wx.Window | None = None
        self._build()
        self._render()

    def _build(self) -> None:
        palette = self.theme.palette
        self.SetBackgroundColour(wx.Colour(palette.background))
        root = wx.BoxSizer(wx.VERTICAL)

        header = wx.BoxSizer(wx.HORIZONTAL)
        title_stack = wx.BoxSizer(wx.VERTICAL)
        title_stack.Add(self._text(self, _wx_static_label(FLASH_WIZARD_PREVIEW_TITLE), 18, True), 0, wx.BOTTOM, 2)
        title_stack.Add(self._muted(self, MODERN_PREVIEW_SUBTITLE), 0)
        header.Add(title_stack, 1, wx.EXPAND)
        for badge in PREVIEW_BADGES:
            header.Add(self._badge(self, badge, "info"), 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 8)
        self._status_badge = self._badge(self, "Blocked", "warning")
        header.Add(self._status_badge, 0, wx.ALIGN_CENTER_VERTICAL)
        root.Add(header, 0, wx.EXPAND | wx.ALL, 14)

        root.Add(self._build_steps(), 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 10)

        content_row = wx.BoxSizer(wx.HORIZONTAL)
        content_row.Add(self._build_step_card(), 5, wx.EXPAND | wx.RIGHT, 8)
        content_row.Add(self._build_summary_card(), 2, wx.EXPAND | wx.LEFT, 8)
        root.Add(content_row, 1, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 10)

        root.Add(self._build_footer(), 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 12)
        self.SetSizer(root)

    def _build_steps(self) -> wx.Panel:
        panel = self._card(self)
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        self._step_cells.clear()
        self._step_labels.clear()
        self._step_badges.clear()
        for index, step in enumerate(STEPS):
            step_panel = preview_style.stepper_cell(panel, self.theme, f"{index + 1}. {step.title}", "Todo")
            label = step_panel._step_label  # type: ignore[attr-defined]
            badge = step_panel._step_badge  # type: ignore[attr-defined]
            self._step_cells.append(step_panel)
            self._step_labels.append(label)
            self._step_badges.append(badge)
            sizer.Add(step_panel, 1, wx.EXPAND | wx.RIGHT, 8)
        panel.SetSizer(self._wrap(sizer, 10))
        return panel

    def _build_step_card(self) -> wx.Panel:
        card = self._card(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(preview_style.section_header(card, self.theme, "Wizard Step", "Navigation only"), 0, wx.EXPAND | wx.BOTTOM, 10)
        self._title = self._text(card, "", 17, True)
        self._body = self._muted(card, "")
        sizer.Add(self._title, 0, wx.BOTTOM, 4)
        sizer.Add(self._body, 0, wx.BOTTOM, 12)

        self._content_panel = wx.Panel(card)
        self._content_panel.SetBackgroundColour(wx.Colour(self.theme.palette.surface_raised))
        self._content_sizer = wx.BoxSizer(wx.VERTICAL)
        self._content_panel.SetSizer(self._wrap(self._content_sizer, 12))
        sizer.Add(self._content_panel, 1, wx.EXPAND)
        card.SetSizer(self._wrap(sizer, 14))
        return card

    def _build_summary_card(self) -> wx.Panel:
        card = self._card(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        top = wx.BoxSizer(wx.HORIZONTAL)
        top.Add(self._text(card, "Summary", 12, True), 1, wx.ALIGN_CENTER_VERTICAL)
        top.Add(self._badge(card, "Protected", "info"), 0, wx.ALIGN_CENTER_VERTICAL)
        sizer.Add(top, 0, wx.EXPAND | wx.BOTTOM, 8)

        alert = preview_style.notice_card(
            card,
            self.theme,
            "Confirmation Required",
            "Flash continues through PixelFlasher's guarded confirmation flow.",
            "warning",
        )
        sizer.Add(alert, 0, wx.EXPAND | wx.BOTTOM, 12)

        self._summary = self._muted(card, "")
        sizer.Add(self._summary, 1, wx.EXPAND | wx.BOTTOM, 8)

        sizer.Add(self._text(card, "Review", 10, True), 0, wx.BOTTOM, 4)
        self._warning = self._text(card, "", 9, True)
        self._warning.SetForegroundColour(wx.Colour(self.theme.palette.warning))
        sizer.Add(self._warning, 0, wx.EXPAND)
        card.SetSizer(self._wrap(sizer, 12))
        return card

    def _build_footer(self) -> wx.Panel:
        panel = wx.Panel(self)
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.background))
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.Add(self._muted(panel, f"PixelFlasher workflow. {MODERN_PREVIEW_FOOTER}"), 1, wx.ALIGN_CENTER_VERTICAL)
        self._back = preview_style.button_panel(panel, self.theme, "Back", "info")
        self._next = preview_style.button_panel(panel, self.theme, "Next", "info")
        preview_style.bind_click_recursive(self._back, self._on_back)
        preview_style.bind_click_recursive(self._next, self._on_next)
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
            self._set_badge(self._status_badge, "Ready" if self.session.can_flash else "Needs Review", "ready" if self.session.can_flash else "warning")
        self._render_step_content(step.key.value)

        for index, label in enumerate(self._step_labels):
            badge = self._step_badges[index]
            cell = self._step_cells[index]
            step_complete = self.session.step_complete(STEPS[index].key)
            if index == self.current_index:
                cell.SetBackgroundColour(wx.Colour(self.theme.palette.surface))
                label.SetForegroundColour(wx.Colour(self.theme.palette.accent))
                self._set_badge(badge, "Active", "info")
            elif step_complete:
                cell.SetBackgroundColour(wx.Colour(self.theme.palette.surface_raised))
                label.SetForegroundColour(wx.Colour(self.theme.palette.success))
                self._set_badge(badge, "Ready", "ready")
            else:
                cell.SetBackgroundColour(wx.Colour(self.theme.palette.surface_raised))
                label.SetForegroundColour(wx.Colour(self.theme.palette.text_muted))
                self._set_badge(badge, "Todo", "muted")
            cell.Refresh()

        if self._back:
            self._back.Enable(self.current_index > 0)
        if self._next:
            if self.current_index == len(STEPS) - 1:
                self._next.Hide()
            else:
                self._next.Show()
                self._next.Enable(True)
        self.Layout()

    def _render_step_content(self, step_key: str) -> None:
        if self._content_panel is None or self._content_sizer is None:
            return
        self._content_sizer.Clear(delete_windows=True)

        self._content_sizer.Add(self._step_preview_cards(self._content_panel, step_key), 0, wx.EXPAND | wx.BOTTOM, 10)

        self._content_sizer.Add(self._section(self._content_panel, "Current state"), 0, wx.EXPAND | wx.BOTTOM, 7)
        for line in step_detail_lines(self.session, step_key):
            self._content_sizer.Add(self._line(self._content_panel, _shorten(line, 76)), 0, wx.EXPAND | wx.BOTTOM, 3)

        self._content_sizer.AddSpacer(7)
        self._content_sizer.Add(self._section(self._content_panel, "Notes"), 0, wx.EXPAND | wx.BOTTOM, 7)
        for item in _STEP_NOTES.get(step_key, ()):
            self._content_sizer.Add(self._line(self._content_panel, item, bullet=True), 0, wx.EXPAND | wx.BOTTOM, 5)

        if step_key in {"review", "flash"}:
            self._content_sizer.AddSpacer(7)
            self._content_sizer.Add(self._section(self._content_panel, "Warnings"), 0, wx.EXPAND | wx.BOTTOM, 7)
            for line in warning_lines(self.session):
                self._content_sizer.Add(self._line(self._content_panel, _shorten(line, 76), warning=line.startswith("Warning:")), 0, wx.EXPAND | wx.BOTTOM, 3)

        if step_key == "flash":
            self._content_sizer.AddSpacer(8)
            notice = self._badge(self._content_panel, "Continue through PixelFlasher confirmation", "muted")
            notice.SetToolTip("Final flash action uses PixelFlasher's guarded confirmation flow.")
            self._content_sizer.Add(notice, 0, wx.EXPAND)
        self._content_panel.Layout()

    def _step_preview_cards(self, parent: wx.Window, step_key: str) -> wx.Panel:
        panel = wx.Panel(parent)
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.surface_raised))
        grid = wx.GridSizer(rows=2, cols=2, vgap=8, hgap=8)
        for title, lines in _step_preview_sections(step_key):
            grid.Add(self._checklist_card(panel, title, lines), 1, wx.EXPAND)
        panel.SetSizer(grid)
        return panel

    def _checklist_card(self, parent: wx.Window, title: str, lines: tuple[str, ...]) -> wx.Panel:
        return preview_style.checklist_card(parent, self.theme, title, lines)

    def _summary_text(self) -> str:
        lines = [
            f"Step: {STEPS[self.current_index].title}",
            f"Can flash: {'yes' if self.session.can_flash else 'no'}",
            f"Warnings: {len(self.session.warnings())}",
            "",
        ]
        for line in self.session.review_lines()[:6]:
            lines.append(_shorten(line, 36))
        return "\n".join(lines)

    def _warning_text(self) -> str:
        if not self.session.warnings():
            return "None"
        return "Review warnings before continuing."

    def _on_back(self, event: wx.CommandEvent) -> None:
        if self.current_index > 0:
            self.current_index -= 1
            self._render()

    def _on_next(self, event: wx.CommandEvent) -> None:
        if self.current_index < len(STEPS) - 1:
            self.current_index += 1
            self._render()
        elif self.session.can_flash:
            wx.MessageBox("Continue through PixelFlasher confirmation before flashing.", "PixelFlasher", wx.OK | wx.ICON_INFORMATION)

    def _card(self, parent: wx.Window) -> wx.Panel:
        return preview_style.card(parent, self.theme)

    def _wrap(self, content: wx.Sizer, pad: int = 10) -> wx.BoxSizer:
        wrapper = wx.BoxSizer(wx.VERTICAL)
        wrapper.Add(content, 1, wx.EXPAND | wx.ALL, pad)
        return wrapper

    def _section(self, parent: wx.Window, label: str) -> wx.StaticText:
        text = self._text(parent, label, 10, True)
        text.SetForegroundColour(wx.Colour(self.theme.palette.accent))
        return text

    def _line(self, parent: wx.Window, label: str, bullet: bool = False, warning: bool = False) -> wx.StaticText:
        prefix = "• " if bullet else ""
        text = self._muted(parent, f"{prefix}{label}")
        if warning:
            text.SetForegroundColour(wx.Colour(self.theme.palette.warning))
        return text

    def _badge(self, parent: wx.Window, label: str, kind: str) -> wx.StaticText:
        tone = {"ready": "success", "warning": "warning", "info": "info", "muted": "info"}.get(kind, "info")
        item = preview_style.badge(parent, self.theme, label, tone)
        self._set_badge(item, label, kind)
        return item

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
        text = self._text(parent, label, 9)
        text.SetForegroundColour(wx.Colour(self.theme.palette.text_muted))
        return text


def _shorten(value: str, limit: int) -> str:
    value = str(value or "")
    if len(value) <= limit:
        return value
    return value[: max(1, limit - 1)] + "…"


def _wx_static_label(label: str) -> str:
    return label.replace("&", "&&")


def _step_preview_sections(step_key: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    common_blocked = (
        "Flash action requires confirmation.",
        "Patch and wipe operations require confirmation.",
        "Device changes require explicit approval.",
    )
    sections = {
        "device": (
            ("Device Readiness Checklist", ("Device selection is read from the current session.", "ADB/Fastboot readiness is displayed only.", "No scan, reboot, or slot action runs here.")),
            ("Firmware Readiness Checklist", ("Firmware status is shown from loaded state.", "Verification remains a future guarded step.", "No archive parsing or file access starts here.")),
            ("Confirmation Checklist", common_blocked),
            ("Workflow Notes", ("Navigation updates this workspace.", "Warnings explain required review.", "PixelFlasher confirmations remain the source of truth.")),
        ),
        "firmware": (
            ("Firmware Context", ("Selected package is loaded from current state.", "Package validation is shown before confirmation.", "Archive handling stays in PixelFlasher.")),
            ("Target Match", ("Device and build labels guide review.", "Mismatch warnings require confirmation.", "PixelFlasher review stays the source of truth.")),
            ("Confirmation Checklist", common_blocked),
            ("Workflow Notes", ("File selection uses PixelFlasher controls.", "Firmware files are not changed by navigation.", "Continue after review.")),
        ),
        "patch": (
            ("Patch Plan", ("Patch choices summarize the selected workflow.", "Boot image handling stays in PixelFlasher.", "Magisk patching requires confirmation.")),
            ("Image Readiness", ("Patchable image status is shown.", "Output path is chosen during confirmation.", "Guarded patch flow remains separate.")),
            ("Confirmation Checklist", common_blocked),
            ("Workflow Notes", ("File changes require confirmation.", "Package parsing stays in PixelFlasher.", "Review before continuing.")),
        ),
        "options": (
            ("Safe Defaults", ("Keep data remains the default.", "Dangerous toggles require confirmation.", "Slot choices require confirmation.")),
            ("Guarded Options", ("Force options require review.", "Wipe and slot switching require confirmation.", "Reboot paths stay guarded.")),
            ("Confirmation Checklist", common_blocked),
            ("Workflow Notes", ("Options update the plan.", "Device commands require confirmation.", "PixelFlasher confirmations remain separate.")),
        ),
        "review": (
            ("Review Summary", ("WizardSession summary is current.", "Warnings require review.", "Final action requires confirmation.")),
            ("Safety Gate", ("Can flash depends on readiness.", "Execution requires guarded PixelFlasher flow.", "No command runs before confirmation.")),
            ("Confirmation Checklist", common_blocked),
            ("Workflow Notes", ("Review prepares the plan.", "Files and devices change only after confirmation.", "Continue when ready.")),
        ),
        "flash": (
            ("Final Step", ("Flash execution requires final confirmation.", "Dry-run output stays informational.", "Device communication starts only after approval.")),
            ("Confirmation", common_blocked),
            ("Safety Boundary", ("Flash, patch, reboot, wipe, and slot switching require confirmation.", "ADB/Fastboot commands stay behind PixelFlasher safeguards.", "Firmware handling uses PixelFlasher flows.")),
            ("Workflow Notes", ("This screen is the review end state.", "Use guarded PixelFlasher flow for device operations.", "Modern UI stays inside the app workflow.")),
        ),
    }
    return sections.get(step_key, sections["device"])


class FlashWizardPreviewFrame(wx.Frame):
    """Standalone frame for the Flash Wizard surface."""

    def __init__(self) -> None:
        super().__init__(None, title=f"PixelFlasher {VERSION} - Flash Wizard", size=(1120, 760))
        panel = FlashWizardPanel(self, session=WizardSession())
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(panel, 1, wx.EXPAND)
        self.SetSizer(root)
        self.Centre()


def main() -> int:
    app = wx.App(False)
    frame = create_modern_preview_frame(page="wizard") or FlashWizardPreviewFrame()
    frame.Show(True)
    app.MainLoop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
