"""Safe Modern UI action metadata for future guarded wiring."""

from __future__ import annotations

from dataclasses import dataclass


PREVIEW_ONLY = "preview_only"
OPEN_LEGACY = "open_legacy"
GUARDED_LEGACY_FLOW = "guarded_legacy_flow"
DISABLED = "disabled"


@dataclass(frozen=True)
class ModernAction:
    id: str
    label: str
    description: str
    safety_level: str
    enabled: bool
    requires_confirmation: bool = False
    legacy_delegate: str = ""


MODERN_ACTIONS: tuple[ModernAction, ...] = (
    ModernAction(
        "open_legacy_ui",
        "Open Classic PixelFlasher",
        "Open the existing guarded legacy UI. Real device operations remain guarded.",
        OPEN_LEGACY,
        True,
    ),
    ModernAction(
        "open_flash_wizard_preview",
        "Open Flash Wizard planning preview",
        "Plan safely in Modern UI. Final execution remains delegated to guarded legacy flow.",
        PREVIEW_ONLY,
        True,
    ),
    ModernAction(
        "open_modern_shell",
        "Open Modern Shell",
        "Review loaded state in a read-only explorer.",
        PREVIEW_ONLY,
        True,
    ),
    ModernAction(
        "open_downloads_preview",
        "Open Downloads preview",
        "Browse update context without applying files to a device.",
        PREVIEW_ONLY,
        True,
    ),
    ModernAction(
        "open_tools_preview",
        "Open Tools preview",
        "View tool categories. Command execution remains disabled in Modern UI.",
        PREVIEW_ONLY,
        True,
    ),
    ModernAction(
        "guarded_legacy_flash_flow",
        "Guarded legacy flash flow",
        "Existing legacy confirmations remain required before execution.",
        GUARDED_LEGACY_FLOW,
        True,
        True,
        "_on_flash",
    ),
    ModernAction(
        "guarded_legacy_patch_flow",
        "Guarded legacy patch flow",
        "Existing legacy confirmations remain required before patching.",
        GUARDED_LEGACY_FLOW,
        True,
        True,
        "_on_magisk_patch_boot",
    ),
    ModernAction(
        "guarded_legacy_support_zip",
        "Guarded legacy diagnostics flow",
        "Support package creation remains in the guarded legacy UI.",
        GUARDED_LEGACY_FLOW,
        True,
        True,
        "_on_support_zip",
    ),
    ModernAction(
        "disabled_reboot",
        "Reboot disabled in Modern UI",
        "Use guarded legacy flows for any real device operation.",
        DISABLED,
        False,
    ),
    ModernAction(
        "disabled_wipe",
        "Wipe disabled in Modern UI",
        "Modern UI does not expose destructive device operations.",
        DISABLED,
        False,
    ),
    ModernAction(
        "disabled_slot_switch",
        "Slot switch disabled in Modern UI",
        "Slot changes remain unavailable from Modern UI.",
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
