"""Standalone launcher for the safe Flash Wizard preview."""

from __future__ import annotations

import wx

from constants import VERSION
from ui.pages.flash_wizard import FlashWizardPanel


class _FlashWizardPreviewFrame(wx.Frame):
    def __init__(self):
        super().__init__(None, title=f"PixelFlasher {VERSION} - Flash Wizard Preview", size=(980, 640))
        panel = FlashWizardPanel(self)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(panel, 1, wx.EXPAND)
        self.SetSizer(root)
        self.Centre()


def main() -> int:
    app = wx.App(False)
    frame = _FlashWizardPreviewFrame()
    frame.Show(True)
    app.MainLoop()
    return 0
