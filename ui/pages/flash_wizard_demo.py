"""Demo session for reviewing the Flash Wizard UI safely."""

from __future__ import annotations

from ui.pages.flash_wizard_model import (
    PatchChoice,
    WizardDevice,
    WizardFirmware,
    WizardOptions,
    WizardSession,
)


def demo_session() -> WizardSession:
    return WizardSession(
        device=WizardDevice(
            display_name="Pixel 8 Pro",
            serial="demo-device",
            adb_ready=True,
            bootloader_unlocked=True,
            active_slot="a",
        ),
        firmware=WizardFirmware(
            path="husky-factory-demo.zip",
            package_type="factory",
            target_device="husky",
            build_id="AP1A-demo",
            has_boot_image=True,
            has_init_boot_image=True,
            sha256="demo-hash",
            verified=True,
        ),
        patch_choice=PatchChoice.SKIP,
        options=WizardOptions(),
        preflight_passed=True,
        flash_connected=False,
    )
