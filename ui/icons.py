"""Modern icon registry for the UI refresh.

Icons live as SVG sources so the project is not locked to one bitmap scale.
wxPython integration can rasterize these later at 16/20/24/32 px.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ICON_ROOT = Path(__file__).resolve().parent.parent / "assets" / "icons" / "symbolic"
ICON_SIZES = (16, 20, 24, 32)


@dataclass(frozen=True)
class IconSpec:
    name: str
    filename: str
    description: str
    dangerous: bool = False

    @property
    def path(self) -> Path:
        return ICON_ROOT / self.filename


ICON_REGISTRY: dict[str, IconSpec] = {
    "dashboard": IconSpec("dashboard", "dashboard.svg", "Dashboard navigation"),
    "flash": IconSpec("flash", "flash.svg", "Flash action", dangerous=True),
    "patch_boot": IconSpec("patch_boot", "patch_boot.svg", "Patch boot image"),
    "devices": IconSpec("devices", "devices.svg", "Connected devices"),
    "tools": IconSpec("tools", "tools.svg", "Utilities and tools"),
    "logs": IconSpec("logs", "logs.svg", "Logs and diagnostics"),
    "settings": IconSpec("settings", "settings.svg", "Settings"),
    "adb": IconSpec("adb", "adb.svg", "ADB status"),
    "bootloader": IconSpec("bootloader", "bootloader.svg", "Bootloader state", dangerous=True),
    "root": IconSpec("root", "root.svg", "Root status"),
    "slot": IconSpec("slot", "slot.svg", "Active slot"),
    "android": IconSpec("android", "android.svg", "Android version"),
    "firmware": IconSpec("firmware", "firmware.svg", "Firmware package"),
    "reboot": IconSpec("reboot", "reboot.svg", "Reboot device"),
    "folder": IconSpec("folder", "folder.svg", "Open folder"),
    "backup": IconSpec("backup", "backup.svg", "Backup status"),
    "warning": IconSpec("warning", "warning.svg", "Warning or risk", dangerous=True),
}


def icon_path(name: str) -> Path:
    try:
        return ICON_REGISTRY[name].path
    except KeyError as exc:
        raise KeyError(f"Unknown icon {name!r}. Available: {', '.join(sorted(ICON_REGISTRY))}") from exc


def load_svg(name: str) -> str:
    return icon_path(name).read_text(encoding="utf-8")


def validate_icon_registry() -> list[str]:
    errors: list[str] = []
    for name, spec in ICON_REGISTRY.items():
        if not spec.path.is_file():
            errors.append(f"missing icon: {name} -> {spec.path}")
            continue
        content = spec.path.read_text(encoding="utf-8", errors="replace").lstrip()
        if not content.startswith("<svg"):
            errors.append(f"invalid svg: {name} -> {spec.path}")
    return errors
