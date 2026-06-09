"""Standalone launcher for the safe Flash Wizard preview."""

from __future__ import annotations

import wx

from constants import VERSION
from ui.pages.flash_wizard import FlashWizardPanel
from ui.pages.modern_preview_web import create_modern_preview_frame


class _FlashWizardPreviewFrame(wx.Frame):
    def __init__(self, demo: bool = False):
        title_suffix = "Demo" if demo else "Preview"
        super().__init__(None, title=f"PixelFlasher {VERSION} - Flash Wizard {title_suffix}", size=(980, 640))
        session = None
        if demo:
            from ui.pages.flash_wizard_demo import demo_session
            session = demo_session()
        panel = FlashWizardPanel(self, session=session)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(panel, 1, wx.EXPAND)
        self.SetSizer(root)
        self.Centre()


def main(demo: bool = False) -> int:
    app = wx.App(False)
    frame = None if demo else create_modern_preview_frame(page="wizard")
    frame = frame or _FlashWizardPreviewFrame(demo=demo)
    frame.Show(True)
    app.MainLoop()
    return 0
