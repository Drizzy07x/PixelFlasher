"""Status feedback copy for Modern UI actions."""

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


def blocked_navigation_feedback() -> ModernActionFeedback:
    return ModernActionFeedback("Navigation stayed inside the PixelFlasher workspace.", BLOCKED)


def disabled_action_feedback(action: ModernAction) -> ModernActionFeedback:
    return ModernActionFeedback(f"{action.label}: select the required device or firmware first.", BLOCKED)


def navigation_action_feedback(action: ModernAction) -> ModernActionFeedback:
    return ModernActionFeedback(f"{action.label}: opened.", SAFE)


def guarded_action_canceled_feedback(action: ModernAction) -> ModernActionFeedback:
    return ModernActionFeedback(f"{action.label}: canceled.", WARNING)


def action_completed_feedback(action: ModernAction) -> ModernActionFeedback:
    return ModernActionFeedback(f"{action.label}: complete.", SAFE)


def action_unavailable_feedback(action: ModernAction) -> ModernActionFeedback:
    return ModernActionFeedback(f"{action.label}: connect the required state and try again.", BLOCKED)
