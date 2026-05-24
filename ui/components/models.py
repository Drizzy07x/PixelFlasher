"""Typed view models for future wxPython panels.

These classes keep UI data shaping out of the huge Main.py file and are safe to
unit test without launching a desktop window.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path


class StatusLevel(str, Enum):
    READY = "ready"
    INFO = "info"
    WARNING = "warning"
    DANGER = "danger"
    DISABLED = "disabled"


@dataclass(frozen=True)
class DeviceStatus:
    display_name: str = "No device"
    codename: str = ""
    serial: str = ""
    android_version: str = ""
    adb_ready: bool = False
    bootloader_state: str = "unknown"
    root_status: str = "unknown"
    active_slot: str = ""

    @property
    def connected(self) -> bool:
        return bool(self.serial or self.adb_ready)

    def redacted_serial(self) -> str:
        if len(self.serial) <= 6:
            return self.serial
        return f"{self.serial[:4]}…{self.serial[-2:]}"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class FirmwareInfo:
    path: str = ""
    package_type: str = "unknown"
    build: str = ""
    device: str = ""
    size_bytes: int = 0
    verified: bool = False

    @property
    def filename(self) -> str:
        return Path(self.path).name if self.path else ""

    @property
    def size_label(self) -> str:
        size = float(self.size_bytes)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024 or unit == "GB":
                return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
            size /= 1024
        return f"{self.size_bytes} B"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class QuickAction:
    key: str
    title: str
    description: str
    icon: str
    status: StatusLevel = StatusLevel.READY
    dangerous: bool = False

    def requires_confirmation(self) -> bool:
        return self.dangerous or self.status in {StatusLevel.WARNING, StatusLevel.DANGER}
