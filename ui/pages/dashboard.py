"""Modern dashboard preview panel for PixelFlasher.

The panel is intentionally non-invasive: it reads available state from the
existing ``PixelFlasher`` frame and delegates actions back to existing handlers.
It does not flash, patch, reboot, or scan by itself.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Callable

import wx

from ui.components.models import DeviceStatus, FirmwareInfo, QuickAction, StatusLevel
from ui.theme import get_theme


class ModernDashboardPanel(wx.Panel):
    """A safe dashboard preview that can sit above the legacy controls."""

    def __init__(self, parent: wx.Window, frame: object):
        super().__init__(parent)
        self.frame = frame
        self.theme = get_theme("dark" if _is_dark_mode() else "light")
        self._labels: dict[str, wx.StaticText] = {}
        self._buttons: dict[str, wx.Button] = {}
        self._build()
        self.refresh()

    def _build(self) -> None:
        palette = self.theme.palette
        self.SetBackgroundColour(wx.Colour(palette.background))

        root = wx.BoxSizer(wx.VERTICAL)
        shell = wx.BoxSizer(wx.HORIZONTAL)

        sidebar = self._build_sidebar()
        content = wx.BoxSizer(wx.VERTICAL)

        header = self._build_header()
        top_row = wx.BoxSizer(wx.HORIZONTAL)
        top_row.Add(self._build_device_card(), 2, wx.EXPAND | wx.RIGHT, 10)
        top_row.Add(self._build_next_step_card(), 1, wx.EXPAND | wx.LEFT, 10)

        content.Add(header, 0, wx.EXPAND | wx.BOTTOM, 12)
        content.Add(top_row, 0, wx.EXPAND | wx.BOTTOM, 12)
        content.Add(self._build_firmware_card(), 0, wx.EXPAND | wx.BOTTOM, 12)
        content.Add(self._build_quick_actions(), 0, wx.EXPAND)

        shell.Add(sidebar, 0, wx.EXPAND | wx.RIGHT, 12)
        shell.Add(content, 1, wx.EXPAND)
        root.Add(shell, 1, wx.EXPAND | wx.ALL, 12)
        self.SetSizer(root)

    def _build_sidebar(self) -> wx.Panel:
        panel = self._card(self, pad=12)
        sizer = wx.BoxSizer(wx.VERTICAL)
        title = self._text(panel, "PixelFlasher", 14, bold=True)
        badge = self._muted(panel, "Modern Dashboard Preview")
        sizer.Add(title, 0, wx.BOTTOM, 2)
        sizer.Add(badge, 0, wx.BOTTOM, 14)
        for label in ("Dashboard", "Flash", "Patch Boot", "Devices", "Tools", "Logs", "Settings"):
            item = self._text(panel, f"  {label}", 10, bold=(label == "Dashboard"))
            if label == "Dashboard":
                item.SetForegroundColour(wx.Colour(self.theme.palette.accent))
            sizer.Add(item, 0, wx.EXPAND | wx.BOTTOM, 8)
        sizer.AddStretchSpacer(1)
        sizer.Add(self._muted(panel, "Safe preview: no flashing logic changed."), 0, wx.EXPAND)
        panel.SetSizer(sizer)
        panel.SetMinSize((190, -1))
        return panel

    def _build_header(self) -> wx.Sizer:
        sizer = wx.BoxSizer(wx.HORIZONTAL)
        title_stack = wx.BoxSizer(wx.VERTICAL)
        title_stack.Add(self._text(self, "Dashboard", 20, bold=True), 0, wx.BOTTOM, 2)
        title_stack.Add(self._muted(self, "Device status, firmware selection, and safe quick actions."), 0)
        sizer.Add(title_stack, 1, wx.EXPAND)
        self._labels["connection_badge"] = self._pill(self, "ADB: Unknown", StatusLevel.INFO)
        sizer.Add(self._labels["connection_badge"], 0, wx.ALIGN_CENTER_VERTICAL)
        return sizer

    def _build_device_card(self) -> wx.Panel:
        card = self._card(self)
        grid = wx.FlexGridSizer(cols=2, vgap=10, hgap=12)
        grid.AddGrowableCol(1, 1)

        name = self._text(card, "No device", 16, bold=True)
        codename = self._muted(card, "Connect a device and scan")
        self._labels["device_name"] = name
        self._labels["device_subtitle"] = codename
        device_stack = wx.BoxSizer(wx.VERTICAL)
        device_stack.Add(name, 0, wx.BOTTOM, 2)
        device_stack.Add(codename, 0)

        self._labels["adb_status"] = self._pill(card, "ADB Unknown", StatusLevel.INFO)
        self._labels["bootloader_status"] = self._pill(card, "Bootloader Unknown", StatusLevel.INFO)
        self._labels["root_status"] = self._pill(card, "Root Unknown", StatusLevel.INFO)
        self._labels["slot_status"] = self._pill(card, "Slot Unknown", StatusLevel.INFO)
        self._labels["android_status"] = self._pill(card, "Android Unknown", StatusLevel.INFO)

        status_grid = wx.GridSizer(rows=2, cols=2, vgap=8, hgap=8)
        status_grid.Add(self._labels["adb_status"], 1, wx.EXPAND)
        status_grid.Add(self._labels["bootloader_status"], 1, wx.EXPAND)
        status_grid.Add(self._labels["root_status"], 1, wx.EXPAND)
        status_grid.Add(self._labels["slot_status"], 1, wx.EXPAND)

        left = wx.BoxSizer(wx.VERTICAL)
        left.Add(device_stack, 0, wx.BOTTOM, 12)
        left.Add(self._labels["android_status"], 0, wx.EXPAND)

        grid.Add(left, 1, wx.EXPAND)
        grid.Add(status_grid, 1, wx.EXPAND)
        card.SetSizer(grid)
        return card

    def _build_next_step_card(self) -> wx.Panel:
        card = self._card(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Recommended next step", 12, bold=True), 0, wx.BOTTOM, 8)
        self._labels["next_step_title"] = self._text(card, "Select firmware", 15, bold=True)
        self._labels["next_step_body"] = self._muted(card, "Choose a factory image, OTA package, or custom ROM.")
        sizer.Add(self._labels["next_step_title"], 0, wx.BOTTOM, 4)
        sizer.Add(self._labels["next_step_body"], 0, wx.BOTTOM, 12)
        button = wx.Button(card, label="Browse firmware")
        button.Bind(wx.EVT_BUTTON, self._focus_legacy_firmware_picker)
        self._buttons["browse_firmware"] = button
        sizer.Add(button, 0, wx.EXPAND)
        card.SetSizer(sizer)
        return card

    def _build_firmware_card(self) -> wx.Panel:
        card = self._card(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Firmware / ROM file", 12, bold=True), 0, wx.BOTTOM, 8)
        self._labels["firmware_filename"] = self._text(card, "No firmware selected", 11, bold=True)
        self._labels["firmware_details"] = self._muted(card, "Use the existing selector below, or the Browse firmware button above.")
        sizer.Add(self._labels["firmware_filename"], 0, wx.BOTTOM, 3)
        sizer.Add(self._labels["firmware_details"], 0)
        card.SetSizer(sizer)
        return card

    def _build_quick_actions(self) -> wx.Panel:
        card = self._card(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Quick actions", 12, bold=True), 0, wx.BOTTOM, 8)
        actions = wx.GridSizer(rows=1, cols=4, vgap=8, hgap=8)
        for action in self._quick_actions():
            actions.Add(self._action_button(card, action), 1, wx.EXPAND)
        sizer.Add(actions, 0, wx.EXPAND)
        card.SetSizer(sizer)
        return card

    def _quick_actions(self) -> tuple[QuickAction, ...]:
        return (
            QuickAction("patch", "Patch Boot", "Use existing patch flow", "patch_boot"),
            QuickAction("flash", "Flash Device", "Existing guarded flash", "flash", StatusLevel.WARNING, True),
            QuickAction("scan", "Scan Devices", "Refresh device list", "devices"),
            QuickAction("support", "Diagnostics", "Create support package", "logs"),
        )

    def _action_button(self, parent: wx.Window, action: QuickAction) -> wx.Panel:
        panel = self._card(parent, pad=8)
        sizer = wx.BoxSizer(wx.VERTICAL)
        title = self._text(panel, action.title, 11, bold=True)
        body = self._muted(panel, action.description)
        button = wx.Button(panel, label="Run")
        button.Bind(wx.EVT_BUTTON, self._action_handler(action.key))
        if action.dangerous:
            button.SetToolTip("Uses the existing PixelFlasher confirmation and safety flow.")
        sizer.Add(title, 0, wx.BOTTOM, 3)
        sizer.Add(body, 0, wx.BOTTOM, 8)
        sizer.Add(button, 0, wx.EXPAND)
        panel.SetSizer(sizer)
        return panel

    def refresh(self) -> None:
        device = self._device_status()
        firmware = self._firmware_info()
        self._labels["device_name"].SetLabel(device.display_name)
        self._labels["device_subtitle"].SetLabel(device.codename or device.redacted_serial() or "No connected device selected")
        self._set_pill(self._labels["connection_badge"], "ADB Ready" if device.adb_ready else "ADB Unknown", StatusLevel.READY if device.adb_ready else StatusLevel.INFO)
        self._set_pill(self._labels["adb_status"], "ADB Ready" if device.adb_ready else "ADB Unknown", StatusLevel.READY if device.adb_ready else StatusLevel.INFO)
        self._set_pill(self._labels["bootloader_status"], f"Bootloader {device.bootloader_state}", StatusLevel.READY if device.bootloader_state.lower() in {"unlocked", "locked"} else StatusLevel.INFO)
        self._set_pill(self._labels["root_status"], f"Root {device.root_status}", StatusLevel.READY if "root" in device.root_status.lower() else StatusLevel.INFO)
        self._set_pill(self._labels["slot_status"], f"Slot {device.active_slot or 'Unknown'}", StatusLevel.INFO)
        self._set_pill(self._labels["android_status"], device.android_version or "Android Unknown", StatusLevel.INFO)

        if firmware.filename:
            self._labels["firmware_filename"].SetLabel(firmware.filename)
            self._labels["firmware_details"].SetLabel(f"{firmware.package_type} • {firmware.device or 'unknown device'} • {firmware.size_label}")
            self._labels["next_step_title"].SetLabel("Review flash options")
            self._labels["next_step_body"].SetLabel("Firmware is selected. Keep dangerous options in the legacy controls below for now.")
        else:
            self._labels["firmware_filename"].SetLabel("No firmware selected")
            self._labels["firmware_details"].SetLabel("Use the existing selector below, or the Browse firmware button above.")
            self._labels["next_step_title"].SetLabel("Select firmware")
            self._labels["next_step_body"].SetLabel("Choose a factory image, OTA package, or custom ROM.")
        self.Layout()

    def _focus_legacy_firmware_picker(self, event: wx.CommandEvent) -> None:
        picker = getattr(self.frame, "firmware_picker", None)
        if picker is not None:
            with contextlib.suppress(Exception):
                picker.SetFocus()
        wx.MessageBox("Use the existing firmware selector below for this preview build.", "PixelFlasher", wx.OK | wx.ICON_INFORMATION)

    def _device_status(self) -> DeviceStatus:
        selected = ""
        with contextlib.suppress(Exception):
            selected = self.frame.device_choice.GetStringSelection()
        phone = None
        with contextlib.suppress(Exception):
            from runtime import get_phone
            phone = get_phone()
        if phone:
            return DeviceStatus(
                display_name=getattr(phone, "model", None) or getattr(phone, "hardware", None) or "Connected device",
                codename=getattr(phone, "hardware", "") or "",
                serial=getattr(phone, "id", "") or selected,
                android_version=str(getattr(phone, "build", "") or getattr(phone, "api_level", "") or ""),
                adb_ready=getattr(phone, "mode", "") == "adb" or getattr(phone, "true_mode", "") == "adb",
                bootloader_state="unlocked" if getattr(phone, "unlocked", False) else "unknown",
                root_status="rooted" if getattr(phone, "rooted", False) else "unknown",
                active_slot=str(getattr(phone, "active_slot", "") or ""),
            )
        return DeviceStatus(display_name="Selected device" if selected else "No device", serial=selected, adb_ready=bool(selected))

    def _firmware_info(self) -> FirmwareInfo:
        path = ""
        with contextlib.suppress(Exception):
            path = self.frame.firmware_picker.GetPath()
        if not path:
            with contextlib.suppress(Exception):
                path = self.frame.config.firmware_path or ""
        size = 0
        with contextlib.suppress(Exception):
            size = Path(path).stat().st_size
        package_type = "OTA package" if getattr(getattr(self.frame, "config", object()), "firmware_is_ota", False) else "Firmware package"
        device = ""
        with contextlib.suppress(Exception):
            device = getattr(getattr(self.frame, "config", object()), "device", "") or ""
        return FirmwareInfo(path=path or "", package_type=package_type, device=device, size_bytes=size, verified=bool(path))

    def _action_handler(self, key: str) -> Callable[[wx.CommandEvent], None]:
        mapping = {
            "patch": "_on_magisk_patch_boot",
            "flash": "_on_flash",
            "scan": "_on_scan",
            "support": "_on_support_zip",
        }
        return self._delegate(mapping.get(key, ""))

    def _delegate(self, method_name: str) -> Callable[[wx.CommandEvent], None]:
        def handler(event: wx.CommandEvent) -> None:
            method = getattr(self.frame, method_name, None)
            if callable(method):
                method(event)
                wx.CallAfter(self.refresh)
            else:
                wx.MessageBox(f"Action is not wired yet: {method_name}", "PixelFlasher", wx.OK | wx.ICON_INFORMATION)
        return handler

    def _card(self, parent: wx.Window, pad: int = 14) -> wx.Panel:
        panel = wx.Panel(parent)
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.surface))
        panel.SetWindowStyleFlag(wx.BORDER_SIMPLE)
        sizer = wx.BoxSizer(wx.VERTICAL)
        panel.SetSizer(sizer)
        panel._modern_card_padding = pad  # type: ignore[attr-defined]
        return panel

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

    def _pill(self, parent: wx.Window, label: str, level: StatusLevel) -> wx.StaticText:
        text = self._text(parent, label, 10, bold=True)
        self._set_pill(text, label, level)
        return text

    def _set_pill(self, label: wx.StaticText, text: str, level: StatusLevel) -> None:
        label.SetLabel(text)
        colors = {
            StatusLevel.READY: self.theme.palette.success,
            StatusLevel.INFO: self.theme.palette.info,
            StatusLevel.WARNING: self.theme.palette.warning,
            StatusLevel.DANGER: self.theme.palette.danger,
            StatusLevel.DISABLED: self.theme.palette.text_muted,
        }
        label.SetForegroundColour(wx.Colour(colors.get(level, self.theme.palette.info)))


def _is_dark_mode() -> bool:
    with contextlib.suppress(Exception):
        import darkdetect
        return bool(darkdetect.isDark())
    return False
