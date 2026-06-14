"""Safe status feedback copy for Modern UI actions."""

from __future__ import annotations

from dataclasses import dataclass

from ui.pages.modern_action_bridge import ModernAction


SAFE = "safe"
WARNING = "warning"
BLOCKED = "blocked"


@dataclass(frozen=True)
class ModernActionFeedback:
    message: str
    tone: str = SAFE


def classic_handoff_feedback() -> ModernActionFeedback:
    return ModernActionFeedback(
        "Classic PixelFlasher handoff requested. Use --legacy-ui for the guarded legacy flow.",
        WARNING,
    )


def blocked_navigation_feedback() -> ModernActionFeedback:
    return ModernActionFeedback("Blocked unknown or external navigation. No action was run.", BLOCKED)


def disabled_action_feedback(action: ModernAction) -> ModernActionFeedback:
    return ModernActionFeedback(f"{action.label}: disabled in Modern UI. No device changes.", BLOCKED)


def preview_action_feedback(action: ModernAction) -> ModernActionFeedback:
    return ModernActionFeedback(f"{action.label}: preview page opened. No device changes.", SAFE)


def guarded_action_canceled_feedback(action: ModernAction) -> ModernActionFeedback:
    return ModernActionFeedback(f"{action.label}: canceled. No legacy flow opened.", WARNING)


def guarded_action_opening_feedback(action: ModernAction) -> ModernActionFeedback:
    return ModernActionFeedback(f"{action.label}: opening existing guarded legacy flow.", WARNING)
