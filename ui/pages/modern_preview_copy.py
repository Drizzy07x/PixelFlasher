"""Shared preview/read-only copy for Modern UI surfaces."""

from __future__ import annotations


MODERN_PREVIEW_TITLE = "Modern UI – Preview"
MODERN_PREVIEW_SUBTITLE = "Safe by default. No device changes. No flashing. No patches."
MODERN_PREVIEW_STATUS = "Modern UI: Preview-Only Mode"
MODERN_PREVIEW_FOOTER = "No device changes will be made."

PREVIEW_BADGES: tuple[str, ...] = (
    "PREVIEW ONLY",
    "Read-Only",
    "No Device Changes",
)

NAV_ICONS: dict[str, str] = {
    "dashboard": "◇",
    "shell": "▣",
    "wizard": "◆",
    "backups": "◫",
    "downloads": "⇩",
    "settings": "◌",
    "tools": "⚙",
    "about": "ⓘ",
}

NAV_ITEMS: tuple[tuple[str, str, str], ...] = (
    ("dashboard", "Dashboard", "Overview & device summary"),
    ("shell", "Modern Shell", "Read-only device state"),
    ("wizard", "Flash Wizard", "Preview & plan only"),
    ("backups", "Backups", "Browse restore preview"),
    ("downloads", "Downloads", "Firmware updates"),
    ("settings", "Settings", "Preferences"),
    ("tools", "Tools", "Utilities preview"),
    ("about", "About", "Version & info"),
)

SAFETY_BOUNDARY_LINES: tuple[str, ...] = (
    "No flashing, patching, or firmware writing.",
    "No ADB or Fastboot command execution.",
    "No reboot, wipe, slot switching, or device changes.",
    "Preview-only. Read-only state. Legacy flows guarded.",
)

DASHBOARD_PREVIEW_ACTIONS: tuple[tuple[str, str], ...] = (
    ("Flash Wizard (Preview)", "Plan only. Execution remains disabled."),
    ("Modern Shell (Read-Only)", "Review loaded state without commands."),
    ("Downloads", "Browse update information in preview."),
)


def nav_label(key: str) -> str:
    for item_key, title, detail in NAV_ITEMS:
        if item_key == key:
            return f"{title} - {detail}"
    return str(key).title()
