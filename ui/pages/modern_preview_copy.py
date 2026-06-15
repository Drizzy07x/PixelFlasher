"""Shared Modern UI copy."""

from __future__ import annotations


MODERN_PREVIEW_TITLE = "Modern UI"
MODERN_PREVIEW_SUBTITLE = "PixelFlasher's modern workspace for device, firmware, patch, and flash workflows."
MODERN_PREVIEW_STATUS = "Modern UI"
MODERN_PREVIEW_FOOTER = "Ready"

PREVIEW_BADGES: tuple[str, ...] = (
    "Ready",
    "Modern UI",
    "Protected",
)

NAV_ICONS: dict[str, str] = {
    "dashboard": "◇",
    "shell": "▣",
    "wizard": "◆",
    "backups": "◫",
    "downloads": "⇩",
    "settings": "◌",
    "tools": "⚙",
    "safety": "◇",
    "about": "ⓘ",
}

NAV_ITEMS: tuple[tuple[str, str, str], ...] = (
    ("dashboard", "Dashboard", "Overview & device summary"),
    ("shell", "Modern Shell", "Device state explorer"),
    ("wizard", "Flash Wizard", "Plan and continue safely"),
    ("backups", "Backups", "Backup context"),
    ("downloads", "Downloads", "Firmware updates"),
    ("settings", "Settings", "Preferences"),
    ("tools", "Tools", "Utilities"),
    ("safety", "System", "Protection & confirmations"),
    ("about", "About", "Version & info"),
)

SAFETY_BOUNDARY_LINES: tuple[str, ...] = (
    "Sensitive operations require existing PixelFlasher confirmation.",
    "ADB and Fastboot actions use PixelFlasher confirmations.",
    "Reboot, wipe, and slot changes require dedicated PixelFlasher flows.",
    "External navigation stays inside the PixelFlasher workspace.",
)

DASHBOARD_PREVIEW_ACTIONS: tuple[tuple[str, str], ...] = (
    ("Flash Wizard", "Plan and continue through confirmation."),
    ("Modern Shell", "Review loaded device state."),
    ("Downloads", "Browse update information."),
)


def nav_label(key: str) -> str:
    for item_key, title, detail in NAV_ITEMS:
        if item_key == key:
            return f"{title} - {detail}"
    return str(key).title()
