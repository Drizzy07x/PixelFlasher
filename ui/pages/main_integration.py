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
        from ui.pages.dashboard_compact import CompactModernDashboardPanel

        legacy_panel = _find_legacy_panel(frame)
        if legacy_panel is None:
            return
        sizer = legacy_panel.GetSizer()
        if sizer is None:
            return

        wrapper = wx.Panel(legacy_panel)
        wrapper_sizer = wx.BoxSizer(wx.VERTICAL)
        toolbar = _build_dashboard_toolbar(wrapper, frame)
        dashboard = CompactModernDashboardPanel(wrapper, frame)

        frame.modern_dashboard_wrapper = wrapper
        frame.modern_dashboard_panel = dashboard
        frame.modern_dashboard_visible = True

        wrapper_sizer.Add(toolbar, 0, wx.EXPAND | wx.BOTTOM, 2)
        wrapper_sizer.Add(dashboard, 0, wx.EXPAND)
        wrapper.SetSizer(wrapper_sizer)

        sizer.Insert(0, wrapper, 0, wx.LEFT | wx.RIGHT | wx.TOP | wx.EXPAND, 8)
        sizer.Layout()
        legacy_panel.Layout()
        frame.Layout()
        with contextlib.suppress(Exception):
            frame.statusBar.SetStatusText("Modern dashboard enabled", 1)
    except Exception as exc:
        print(f"WARNING: Modern dashboard integration failed: {exc}")
        with contextlib.suppress(Exception):
            import traceback
            traceback.print_exc()


def _build_dashboard_toolbar(parent: wx.Window, frame: wx.Frame) -> wx.Panel:
    toolbar = wx.Panel(parent)
    toolbar_sizer = wx.BoxSizer(wx.HORIZONTAL)
    label = wx.StaticText(toolbar, label="Modern Dashboard")
    font = label.GetFont()
    font.SetWeight(wx.FONTWEIGHT_BOLD)
    label.SetFont(font)
    hint = wx.StaticText(toolbar, label="  beta overlay")
    wizard = wx.Button(toolbar, label="Wizard")
    refresh = wx.Button(toolbar, label="Refresh")
    toggle = wx.Button(toolbar, label="Hide")

    frame.modern_dashboard_toggle_button = toggle
    wizard.Bind(wx.EVT_BUTTON, lambda event: _open_flash_wizard_preview(frame))
    refresh.Bind(wx.EVT_BUTTON, lambda event: _refresh_dashboard(frame))
    toggle.Bind(wx.EVT_BUTTON, lambda event: _toggle_dashboard(frame))

    toolbar_sizer.Add(label, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 4)
    toolbar_sizer.Add(hint, 1, wx.ALIGN_CENTER_VERTICAL)
    toolbar_sizer.Add(wizard, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 6)
    toolbar_sizer.Add(refresh, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 6)
    toolbar_sizer.Add(toggle, 0, wx.ALIGN_CENTER_VERTICAL)
    toolbar.SetSizer(toolbar_sizer)
    return toolbar


def _open_flash_wizard_preview(frame: wx.Frame) -> None:
    try:
        from ui.pages.flash_wizard import FlashWizardPanel
        from ui.pages.flash_wizard_state_adapter import build_wizard_session

        session = build_wizard_session(frame)
        wizard_frame = wx.Frame(frame, title="PixelFlasher - Flash Wizard Preview", size=(1040, 660))
        panel = FlashWizardPanel(wizard_frame, session=session)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(panel, 1, wx.EXPAND)
        wizard_frame.SetSizer(root)
        wizard_frame.CentreOnParent()
        wizard_frame.Show(True)
        frame.modern_flash_wizard_preview = wizard_frame
        with contextlib.suppress(Exception):
            frame.statusBar.SetStatusText("Flash Wizard preview opened", 1)
    except Exception as exc:
        wx.MessageBox(f"Unable to open Flash Wizard preview: {exc}", "PixelFlasher", wx.OK | wx.ICON_WARNING)
        with contextlib.suppress(Exception):
            import traceback
            traceback.print_exc()


def _toggle_dashboard(frame: wx.Frame) -> None:
    dashboard = getattr(frame, "modern_dashboard_panel", None)
    button = getattr(frame, "modern_dashboard_toggle_button", None)
    if dashboard is None:
        return
    visible = not bool(getattr(frame, "modern_dashboard_visible", True))
    frame.modern_dashboard_visible = visible
    dashboard.Show(visible)
    if button is not None:
        with contextlib.suppress(Exception):
            button.SetLabel("Hide" if visible else "Show")
    parent = dashboard.GetParent()
    if parent is not None:
        parent.Layout()
    top = dashboard.GetTopLevelParent()
    if top is not None:
        top.Layout()


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
