"""Standalone preview launcher for the modern PixelFlasher dashboard."""

from __future__ import annotations

if __package__ in {None, ""}:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import wx

from constants import VERSION
from config import Config
from ui.pages.dashboard import ModernDashboardPanel


class DashboardPreviewFrame(wx.Frame):
    def __init__(self, parent: wx.Window | None = None):
        super().__init__(parent, title=f"PixelFlasher {VERSION} - Modern Dashboard Preview", size=(1360, 900))
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
    frame = show_dashboard_preview()
    app.MainLoop()
    return 0


def show_dashboard_preview(parent: wx.Window | None = None) -> DashboardPreviewFrame:
    frame = DashboardPreviewFrame(parent)
    frame.Show(True)
    frame.Raise()
    return frame


if __name__ == "__main__":
    raise SystemExit(main())
