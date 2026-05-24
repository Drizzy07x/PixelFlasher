"""Runtime integration hook for the modern dashboard.

This module intentionally avoids editing ``Main.py`` directly. It monkey-patches
only when explicitly enabled by ``PixelFlasher.py --modern-dashboard`` or the
``PIXELFLASHER_MODERN_DASHBOARD=1`` environment variable.
"""

from __future__ import annotations

import contextlib
import os
from typing import Any

import wx


_INSTALLED = False


def install(Main: Any) -> bool:
    """Install the modern dashboard into the legacy wx frame at runtime.

    Returns True when the hook was installed, False when it was already installed
    or disabled.
    """
    global _INSTALLED
    if _INSTALLED:
        return False
    if os.environ.get("PIXELFLASHER_MODERN_DASHBOARD") != "1":
        return False
    if not hasattr(Main, "PixelFlasher"):
        return False

    frame_cls = Main.PixelFlasher
    original_init_ui = frame_cls._init_ui
    original_initialize = frame_cls.initialize

    def _init_ui_with_dashboard(self):
        original_init_ui(self)
        _attach_dashboard(self)
        _bind_dashboard_refresh_events(self)
        _refresh_dashboard(self)

    def _initialize_with_dashboard(self):
        original_initialize(self)
        _refresh_dashboard(self)

    frame_cls._init_ui = _init_ui_with_dashboard
    frame_cls.initialize = _initialize_with_dashboard
    _INSTALLED = True
    return True


def _attach_dashboard(frame: wx.Frame) -> None:
    if getattr(frame, "modern_dashboard_panel", None):
        return
    try:
        from ui.pages.dashboard import ModernDashboardPanel

        legacy_panel = _find_legacy_panel(frame)
        if legacy_panel is None:
            return
        sizer = legacy_panel.GetSizer()
        if sizer is None:
            return
        dashboard = ModernDashboardPanel(legacy_panel, frame)
        frame.modern_dashboard_panel = dashboard
        sizer.Insert(0, dashboard, 0, wx.LEFT | wx.RIGHT | wx.TOP | wx.EXPAND, 10)
        sizer.Layout()
        legacy_panel.Layout()
        frame.Layout()
        with contextlib.suppress(Exception):
            frame.statusBar.SetStatusText("Modern dashboard enabled for this session", 1)
    except Exception as exc:
        print(f"WARNING: Modern dashboard integration failed: {exc}")
        with contextlib.suppress(Exception):
            import traceback
            traceback.print_exc()


def _find_legacy_panel(frame: wx.Frame) -> wx.Panel | None:
    for child in frame.GetChildren():
        if isinstance(child, wx.Panel) and child.GetSizer() is not None:
            return child
    return None


def _bind_dashboard_refresh_events(frame: wx.Frame) -> None:
    bindings = (
        ("device_choice", wx.EVT_COMBOBOX),
        ("scan_button", wx.EVT_BUTTON),
        ("scan_all_button", wx.EVT_BUTTON),
        ("firmware_picker", wx.EVT_FILEPICKER_CHANGED),
    )
    for attr, event_type in bindings:
        control = getattr(frame, attr, None)
        if control is None:
            continue
        with contextlib.suppress(Exception):
            control.Bind(event_type, lambda event: _refresh_event(frame, event))


def _refresh_event(frame: wx.Frame, event: wx.Event) -> None:
    event.Skip()
    _refresh_dashboard(frame)


def _refresh_dashboard(frame: wx.Frame) -> None:
    dashboard = getattr(frame, "modern_dashboard_panel", None)
    if dashboard is not None:
        with contextlib.suppress(Exception):
            wx.CallAfter(dashboard.refresh)
