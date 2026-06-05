"""Standalone preview launcher for the modern PixelFlasher dashboard."""

from __future__ import annotations

import wx

from constants import VERSION
from config import Config
from ui.pages.dashboard import ModernDashboardPanel


class _PreviewFrame(wx.Frame):
    def __init__(self):
        super().__init__(None, title=f"PixelFlasher {VERSION} - Modern Dashboard Preview", size=(1180, 760))
        self.config = Config()
        self.config.modern_ui_enabled = True
        self.config.modern_dashboard_enabled = True
        self.firmware_picker = _NullPicker()
        self.device_choice = _NullChoice()
        panel = ModernDashboardPanel(self, self)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(panel, 1, wx.EXPAND)
        self.SetSizer(root)
        self.Centre()

    def _on_scan(self, event):
        wx.MessageBox("Device scanning stays in the guarded legacy flow for this preview build.", "PixelFlasher", wx.OK | wx.ICON_INFORMATION)

    def _on_flash(self, event):
        wx.MessageBox("Modern UI preview does not flash devices. Use the guarded legacy flow for real operations.", "PixelFlasher", wx.OK | wx.ICON_WARNING)

    def _on_magisk_patch_boot(self, event):
        wx.MessageBox("Modern UI preview does not patch images. Use the guarded legacy flow for real operations.", "PixelFlasher", wx.OK | wx.ICON_INFORMATION)

    def _on_support_zip(self, event):
        wx.MessageBox("Diagnostics stay available through the guarded legacy support flow.", "PixelFlasher", wx.OK | wx.ICON_INFORMATION)


class _NullPicker:
    def GetPath(self) -> str:
        return ""

    def SetFocus(self) -> None:
        return None


class _NullChoice:
    def GetStringSelection(self) -> str:
        return ""


def main() -> int:
    app = wx.App(False)
    frame = _PreviewFrame()
    frame.Show(True)
    app.MainLoop()
    return 0
