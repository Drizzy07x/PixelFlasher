"""Safe Modern UI action metadata for guarded legacy handoffs."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


PREVIEW_ONLY = "preview_only"
OPEN_LEGACY = "open_legacy"
GUARDED_LEGACY_FLOW = "guarded_legacy_flow"
DISABLED = "disabled"
ACTION_SCHEME = "pixelflasher"
ACTION_HOST = "action"
LEGACY_UI_DELEGATE = "open_legacy_ui"


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
        "open_legacy_ui",
        "Open Classic PixelFlasher",
        "Open the existing guarded legacy UI. Real device operations remain guarded.",
        OPEN_LEGACY,
        True,
        delegate=LEGACY_UI_DELEGATE,
    ),
    ModernAction(
        "open_modern_flash_wizard",
        "Open Flash Wizard planning preview",
        "Plan safely in Modern UI. Execution is delegated to the guarded legacy flow.",
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
        "Continue to Guarded Legacy Flash Flow",
        "Modern UI prepares the plan; execution is delegated to existing guarded PixelFlasher flow.",
        GUARDED_LEGACY_FLOW,
        True,
        requires_confirmation=True,
        delegate=LEGACY_UI_DELEGATE,
        dangerous=True,
        confirmation_title="Continue to Guarded Legacy Flash Flow?",
        confirmation_body=(
            "Existing guarded legacy flow\n\n"
            "Modern UI does not execute device commands directly.\n"
            "No flash command is run from Modern UI.\n"
            "Review all prompts before continuing."
        ),
    ),
    ModernAction(
        "guarded_legacy_patch_flow",
        "Guarded legacy patch flow",
        "Boot image patching remains delegated to existing guarded PixelFlasher flow.",
        GUARDED_LEGACY_FLOW,
        True,
        requires_confirmation=True,
        delegate=LEGACY_UI_DELEGATE,
        dangerous=True,
        confirmation_title="Continue to Guarded Legacy Patch Flow?",
        confirmation_body=(
            "Existing guarded legacy flow\n\n"
            "Modern UI does not execute device commands directly.\n"
            "Review all prompts before continuing."
        ),
    ),
    ModernAction(
        "guarded_legacy_support_zip",
        "Guarded legacy diagnostics flow",
        "Support package creation remains in the guarded legacy UI.",
        GUARDED_LEGACY_FLOW,
        True,
        requires_confirmation=True,
        delegate=LEGACY_UI_DELEGATE,
        dangerous=True,
        confirmation_title="Continue to Guarded Legacy Diagnostics Flow?",
        confirmation_body=(
            "Existing guarded legacy flow\n\n"
            "Modern UI does not execute device commands directly.\n"
            "Review all prompts before continuing."
        ),
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


def action_url(action_id: str) -> str:
    return f"{ACTION_SCHEME}://{ACTION_HOST}/{action_id}"


def action_from_url(url: str) -> ModernAction | None:
    parsed = urlparse(str(url or ""))
    if parsed.scheme != ACTION_SCHEME or parsed.netloc != ACTION_HOST:
        return None
    action_id = parsed.path.strip("/")
    if not action_id or "/" in action_id:
        return None
    return action_by_id(action_id)


def is_legacy_handoff(action: ModernAction) -> bool:
    return action.enabled and action.delegate == LEGACY_UI_DELEGATE and action.safety_level in {
        OPEN_LEGACY,
        GUARDED_LEGACY_FLOW,
    }
