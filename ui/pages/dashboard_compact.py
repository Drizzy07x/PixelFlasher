"""Compact modern dashboard for embedding above the legacy PixelFlasher UI."""

from __future__ import annotations

import contextlib
from pathlib import Path

import wx

from ui.components.models import DeviceStatus, FirmwareInfo, StatusLevel
from ui.theme import get_theme


class CompactModernDashboardPanel(wx.Panel):
    """Small status strip for the real app integration.

    This panel is display-oriented. It does not run flash, patch, reboot, adb, or
    fastboot operations directly.
    """

    def __init__(self, parent: wx.Window, frame: object):
        super().__init__(parent)
        self.frame = frame
        self.theme = get_theme("dark" if _is_dark_mode() else "light")
        self._labels: dict[str, wx.StaticText] = {}
        self._build()
        self.refresh()

    def _build(self) -> None:
        palette = self.theme.palette
        self.SetBackgroundColour(wx.Colour(palette.background))
        root = wx.BoxSizer(wx.HORIZONTAL)

        root.Add(self._build_device_section(), 2, wx.EXPAND | wx.RIGHT, 6)
        root.Add(self._build_firmware_section(), 2, wx.EXPAND | wx.RIGHT, 6)
        root.Add(self._build_next_step_section(), 1, wx.EXPAND)

        self.SetSizer(root)
        self.SetMinSize((-1, 64))
        self.SetMaxSize((-1, 78))

    def _build_device_section(self) -> wx.Panel:
        card = self._card(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        title_row = wx.BoxSizer(wx.HORIZONTAL)
        title_row.Add(self._text(card, "Device", 9, True), 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 6)
        self._labels["connection_badge"] = self._pill(card, "ADB ?", StatusLevel.INFO)
        title_row.Add(self._labels["connection_badge"], 0, wx.ALIGN_CENTER_VERTICAL)
        sizer.Add(title_row, 0, wx.BOTTOM, 1)

        self._labels["device_name"] = self._text(card, "No device", 11, True)
        self._labels["device_subtitle"] = self._muted(card, "No connected device")
        sizer.Add(self._labels["device_name"], 0)
        sizer.Add(self._labels["device_subtitle"], 0)
        card.SetSizer(self._wrap(sizer))
        return card

    def _build_firmware_section(self) -> wx.Panel:
        card = self._card(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._text(card, "Firmware / ROM", 9, True), 0, wx.BOTTOM, 1)
        self._labels["firmware_filename"] = self._text(card, "No firmware", 11, True)
        self._labels["firmware_details"] = self._muted(card, "Select below")
        sizer.Add(self._labels["firmware_filename"], 0)
        sizer.Add(self._labels["firmware_details"], 0)
        card.SetSizer(self._wrap(sizer))
        return card

    def _build_next_step_section(self) -> wx.Panel:
        card = self._card(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        top = wx.BoxSizer(wx.HORIZONTAL)
        top.Add(self._text(card, "Next", 9, True), 1, wx.ALIGN_CENTER_VERTICAL)
        self._labels["firmware_state"] = self._pill(card, "Waiting", StatusLevel.INFO)
        top.Add(self._labels["firmware_state"], 0, wx.ALIGN_CENTER_VERTICAL)
        sizer.Add(top, 0, wx.EXPAND | wx.BOTTOM, 1)

        self._labels["next_step_title"] = self._text(card, "Select firmware", 11, True)
        self._labels["next_step_body"] = self._muted(card, "Review options")
        sizer.Add(self._labels["next_step_title"], 0)
        sizer.Add(self._labels["next_step_body"], 0)
        card.SetSizer(self._wrap(sizer))
        return card

    def refresh(self) -> None:
        device = self._device_status()
        firmware = self._firmware_info()

        self._labels["device_name"].SetLabel(_shorten(device.display_name, 28))
        self._labels["device_subtitle"].SetLabel(_shorten(device.codename or device.redacted_serial() or "No connected device", 34))
        self._set_pill(self._labels["connection_badge"], "ADB OK" if device.adb_ready else "ADB ?", StatusLevel.READY if device.adb_ready else StatusLevel.INFO)

        if firmware.filename:
            self._labels["firmware_filename"].SetLabel(_shorten(firmware.filename, 34))
            details = f"{firmware.package_type} • {firmware.device or 'unknown'}"
            self._labels["firmware_details"].SetLabel(_shorten(details, 38))
            self._set_pill(self._labels["firmware_state"], "Ready", StatusLevel.READY)
            self._labels["next_step_title"].SetLabel("Review options")
            self._labels["next_step_body"].SetLabel("Use legacy controls")
        else:
            self._labels["firmware_filename"].SetLabel("No firmware")
            self._labels["firmware_details"].SetLabel("Select below")
            self._set_pill(self._labels["firmware_state"], "Waiting", StatusLevel.INFO)
            self._labels["next_step_title"].SetLabel("Select firmware")
            self._labels["next_step_body"].SetLabel("Review options")
        self.Layout()

    def _focus_firmware_picker(self, event: wx.CommandEvent) -> None:
        picker = getattr(self.frame, "firmware_picker", None)
        if picker is not None:
            with contextlib.suppress(Exception):
                picker.SetFocus()

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
        package_type = "OTA" if getattr(getattr(self.frame, "config", object()), "firmware_is_ota", False) else "Firmware"
        device = ""
        with contextlib.suppress(Exception):
            device = getattr(getattr(self.frame, "config", object()), "device", "") or ""
        return FirmwareInfo(path=path or "", package_type=package_type, device=device, size_bytes=size, verified=bool(path))

    def _card(self, parent: wx.Window) -> wx.Panel:
        panel = wx.Panel(parent)
        panel.SetBackgroundColour(wx.Colour(self.theme.palette.surface))
        panel.SetWindowStyleFlag(wx.BORDER_SIMPLE)
        return panel

    def _wrap(self, content: wx.Sizer) -> wx.BoxSizer:
        wrapper = wx.BoxSizer(wx.VERTICAL)
        wrapper.Add(content, 1, wx.EXPAND | wx.ALL, 5)
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
        text = self._text(parent, label, 8)
        text.SetForegroundColour(wx.Colour(self.theme.palette.text_muted))
        return text

    def _pill(self, parent: wx.Window, label: str, level: StatusLevel) -> wx.StaticText:
        text = self._text(parent, label, 8, True)
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


def _shorten(value: str, limit: int) -> str:
    value = str(value or "")
    if len(value) <= limit:
        return value
    return value[: max(1, limit - 1)] + "…"
