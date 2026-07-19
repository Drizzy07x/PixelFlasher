"""Shared PyInstaller exclusions for the React/WebView desktop artifact."""

from __future__ import annotations

# Main.py remains in the source tree only while its 9.x behavior is being
# characterized.  The rest of these modules belonged exclusively to the
# retired wx preview and widget-state adapter stack.
RETIRED_UI_MODULES = (
    "Main",
    "ui.components",
    "ui.icons",
    "ui.theme",
    "ui.pages.dashboard",
    "ui.pages.dashboard_app",
    "ui.pages.dashboard_compact",
    "ui.pages.flash_wizard",
    "ui.pages.flash_wizard_app",
    "ui.pages.flash_wizard_demo",
    "ui.pages.flash_wizard_details",
    "ui.pages.flash_wizard_model",
    "ui.pages.flash_wizard_state_adapter",
    "ui.pages.modern_action_bridge",
    "ui.pages.modern_action_feedback",
    "ui.pages.modern_preview_copy",
    "ui.pages.modern_preview_style",
    "ui.pages.modern_preview_templates",
    "ui.pages.modern_preview_web",
    "ui.pages.modern_readonly_state",
    "ui.pages.modern_shell_app",
    "ui.pages.platform_tools_setup",
)

RETIRED_UI_DATA_DIRS = ("assets/icons/symbolic",)
