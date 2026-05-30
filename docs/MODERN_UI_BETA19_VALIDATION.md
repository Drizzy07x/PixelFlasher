# Modern UI Beta 19 Validation

## Scope

Beta 19 closes the current Modern UI safety/state consolidation pass.

Covered work:

- #6 Add shared Modern UI read-only state adapter
- #7 Reuse shared read-only state in Flash Wizard adapter
- #8 Reuse shared read-only state in Modern Dashboard
- #9 Clarify Modern Dashboard legacy action copy
- #10 Check required runtime modules in self-test
- #11 Reuse shared read-only state in Modern Shell

## Current State

- Flash Wizard uses shared read-only state.
- Modern Dashboard uses shared read-only state.
- Modern Shell uses shared read-only state.
- Self-test covers required runtime modules: darkdetect and json5.
- Dashboard quick-action copy now clarifies legacy/guarded flow ownership.

## Safety Boundary

Beta 19 remains UI-preview/read-only focused.

No behavior changed for flash execution, patch execution, ADB commands, Fastboot commands, reboot actions, slot switching, wipe actions, firmware parsing, file mutation, or legacy guarded flows.

Modern UI screens remain preview-only unless explicitly delegated to existing legacy behavior.

## Validation Commands

Run:

    python -m unittest tests.test_modern_shell_readonly_state tests.test_self_test_dependencies tests.test_modern_dashboard_copy_safety tests.test_modern_dashboard_readonly_state tests.test_modern_readonly_state tests.test_flash_wizard_state_adapter tests.test_flash_wizard_model tests.test_flash_wizard_details tests.test_modern_shell_preview_safety
    python PixelFlasher.py --self-test

Expected result:

    Ran 35 tests
    OK
    Required failures: 0
    Warnings: 0

## Manual Preview Checks

Recommended manual checks:

    python PixelFlasher.py --modern-dashboard
    python PixelFlasher.py --modern-shell-preview
    python PixelFlasher.py --flash-wizard-demo

Visual expectations:

- Modern Dashboard no longer shows generic Run action buttons.
- Dashboard quick actions clearly indicate legacy or guarded flow ownership.
- Flash Wizard final step does not expose a flash execution button.
- Modern Shell pages show preview-only / disabled execution messaging.
- Device, firmware, tool, and flash summary labels render from shared read-only state.
- No Modern UI preview screen performs flash, patch, ADB, Fastboot, reboot, wipe, slot, or file mutation operations.

## Known Non-Blocking GTK Noise

Ubuntu/wxPython may emit repeated GTK warnings while launching the full app path:

    Gtk-CRITICAL **: gtk_image_menu_item_set_image: assertion GTK_IS_IMAGE_MENU_ITEM failed

This is treated as non-blocking GTK/wx noise because it is not a Python traceback, does not fail self-test, does not fail Modern UI unit tests, and the UI can continue launching.

Handle this separately from beta 19 as a GTK menu/icon cleanup task.

## Recommendation

Beta 19 is suitable as a guarded validation checkpoint once CI passes.
