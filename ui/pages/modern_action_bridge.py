"""Allow-listed Modern UI action metadata."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


NAVIGATION = "navigation"
INTERNAL_FLOW = "internal_flow"
GUARDED_FLOW = "guarded_flow"
DISABLED = "disabled"
ACTION_SCHEME = "pixelflasher"
ACTION_HOST = "action"


@dataclass(frozen=True)
class ModernAction:
    id: str
    label: str
    description: str
    safety_level: str
    enabled: bool
    requires_confirmation: bool = False
    delegate: str = ""
    dangerous: bool = False
    confirmation_title: str = ""
    confirmation_body: str = ""


MODERN_ACTIONS: tuple[ModernAction, ...] = (
    ModernAction(
        "open_modern_dashboard",
        "Open Dashboard",
        "Return to the Modern UI overview.",
        NAVIGATION,
        True,
    ),
    ModernAction(
        "open_modern_flash_wizard",
        "Open Flash Wizard",
        "Plan and run the selected flash workflow.",
        NAVIGATION,
        True,
    ),
    ModernAction(
        "open_modern_shell",
        "Open Modern Shell",
        "Review device and firmware state.",
        NAVIGATION,
        True,
    ),
    ModernAction(
        "open_backups",
        "Open Backups",
        "Review and manage available backup tools.",
        NAVIGATION,
        True,
    ),
    ModernAction(
        "open_downloads",
        "Open Downloads",
        "Browse firmware and rooting app downloads.",
        NAVIGATION,
        True,
    ),
    ModernAction(
        "open_settings",
        "Open Settings",
        "Open PixelFlasher settings.",
        NAVIGATION,
        True,
    ),
    ModernAction(
        "open_tools",
        "Open Tools",
        "Open PixelFlasher tools.",
        NAVIGATION,
        True,
    ),
    ModernAction(
        "open_safety",
        "Open Safety",
        "Review operation boundaries and confirmations.",
        NAVIGATION,
        True,
    ),
    ModernAction(
        "open_about",
        "Open About",
        "View application information.",
        NAVIGATION,
        True,
    ),
    ModernAction(
        "scan_devices",
        "Scan Devices",
        "Refresh connected devices using the existing PixelFlasher scanner.",
        INTERNAL_FLOW,
        True,
        delegate="_on_scan",
    ),
    ModernAction(
        "select_firmware",
        "Select Firmware",
        "Choose a firmware, OTA, or ROM package.",
        INTERNAL_FLOW,
        True,
        delegate="select_firmware_file",
    ),
    ModernAction(
        "process_firmware",
        "Process Firmware",
        "Extract and prepare firmware using PixelFlasher's existing processor.",
        INTERNAL_FLOW,
        True,
        delegate="_on_process_firmware",
    ),
    ModernAction(
        "flash_device",
        "Flash Device",
        "Run the configured flash workflow using PixelFlasher's existing flash engine.",
        GUARDED_FLOW,
        True,
        requires_confirmation=True,
        delegate="_on_flash",
        dangerous=True,
        confirmation_title="Flash Device?",
        confirmation_body=(
            "PixelFlasher will run the configured flash workflow.\n"
            "Review every prompt before continuing."
        ),
    ),
    ModernAction(
        "patch_boot",
        "Patch Boot",
        "Patch the selected boot image using the configured root solution.",
        GUARDED_FLOW,
        True,
        requires_confirmation=True,
        delegate="_on_magisk_patch_boot",
        dangerous=True,
        confirmation_title="Patch Boot Image?",
        confirmation_body=(
            "PixelFlasher will use the selected boot image and connected device.\n"
            "Review every prompt before continuing."
        ),
    ),
    ModernAction(
        "create_support_package",
        "Create Support Package",
        "Create a sanitized support package.",
        GUARDED_FLOW,
        True,
        requires_confirmation=True,
        delegate="_on_support_zip",
        dangerous=True,
        confirmation_title="Create Support Package?",
        confirmation_body=(
            "PixelFlasher will create and save a support package.\n"
            "Choose the destination in the next dialog.\n"
            "Review every prompt before continuing."
        ),
    ),
    ModernAction(
        "backup_manager",
        "Backup Manager",
        "Open the Magisk backup manager.",
        INTERNAL_FLOW,
        True,
        delegate="_on_backup_manager",
    ),
    ModernAction(
        "firmware_downloads",
        "Firmware Downloads",
        "Show available firmware downloads for the selected device.",
        INTERNAL_FLOW,
        True,
        delegate="_on_show_device_download",
    ),
    ModernAction(
        "settings_dialog",
        "Settings",
        "Open PixelFlasher settings.",
        INTERNAL_FLOW,
        True,
        delegate="_on_advanced_config",
    ),
    ModernAction(
        "rooting_app",
        "Rooting App",
        "Download or install Magisk, KernelSU, APatch, or related tools.",
        INTERNAL_FLOW,
        True,
        delegate="_on_rooting_app",
    ),
    ModernAction(
        "magisk_modules",
        "Magisk Modules",
        "Manage installed Magisk modules.",
        INTERNAL_FLOW,
        True,
        delegate="_on_magisk",
    ),
    ModernAction(
        "partition_manager",
        "Partition Manager",
        "Open the partition manager.",
        GUARDED_FLOW,
        True,
        requires_confirmation=True,
        delegate="_on_partition_manager",
        dangerous=True,
        confirmation_title="Open Partition Manager?",
        confirmation_body="Partition tools can modify device data. Review every prompt before continuing.",
    ),
    ModernAction(
        "disabled_reboot",
        "Reboot",
        "Use the dedicated reboot controls after selecting a device.",
        DISABLED,
        False,
    ),
    ModernAction(
        "disabled_wipe",
        "Wipe",
        "Wipe operations require a configured flash flow.",
        DISABLED,
        False,
    ),
    ModernAction(
        "disabled_slot_switch",
        "Switch Slot",
        "Slot switching requires a selected device.",
        DISABLED,
        False,
    ),
)


def modern_actions() -> tuple[ModernAction, ...]:
    return MODERN_ACTIONS


def action_by_id(action_id: str) -> ModernAction | None:
    for action in MODERN_ACTIONS:
        if action.id == action_id:
            return action
    return None


def action_url(action_id: str) -> str:
    return f"{ACTION_SCHEME}://{ACTION_HOST}/{action_id}"


def action_from_url(url: str) -> ModernAction | None:
    parsed = urlparse(str(url or ""))
    if parsed.scheme.lower() != ACTION_SCHEME or parsed.netloc.lower() != ACTION_HOST:
        return None
    if parsed.params or parsed.query or parsed.fragment:
        return None
    action_id = parsed.path.strip("/")
    if not action_id or "/" in action_id:
        return None
    return action_by_id(action_id)


def is_engine_action(action: ModernAction) -> bool:
    return action.enabled and bool(action.delegate) and action.safety_level in {
        INTERNAL_FLOW,
        GUARDED_FLOW,
    }
