#!/usr/bin/env python3
"""Open a headless runtime with the packaged distributions wired in.

`ApplicationRuntime.open` does not load the signed catalogs by itself: the GUI
entrypoint resolves each one and injects it. A headless session that skips that
step reports every catalog-backed capability as unavailable, so the same wiring
is reproduced here and shared by the hardware, firmware and root harnesses.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from pixelflasher_core import ApplicationRuntime  # noqa: E402
from pixelflasher_core.firmware_distribution import (  # noqa: E402
    load_optional_firmware_distribution,
)
from pixelflasher_core.keybox_distribution import (  # noqa: E402
    load_optional_keybox_revocations,
)
from pixelflasher_core.patch_resources import (  # noqa: E402
    load_optional_packaged_patch_resource_registry,
)
from pixelflasher_core.platform_tools_distribution import (  # noqa: E402
    load_optional_platform_tools_distribution,
)
from pixelflasher_core.root_app_distribution import (  # noqa: E402
    load_optional_root_app_distribution,
)
from pixelflasher_core.scrcpy_distribution import (  # noqa: E402
    load_optional_scrcpy_distribution,
)
from pixelflasher_core.support_distribution import (  # noqa: E402
    load_optional_support_recipient,
)
from pixelflasher_core.update_distribution import (  # noqa: E402
    load_optional_update_distribution,
)

RESOURCES = REPOSITORY_ROOT / "resources"


def open_runtime(config_path: Path, **overrides: object) -> ApplicationRuntime:
    """Open a runtime carrying every distribution that is provisioned."""

    platform_tools = load_optional_platform_tools_distribution(RESOURCES / "platform-tools" / "runtime")
    root_apps = load_optional_root_app_distribution(RESOURCES / "root-apps" / "runtime")
    firmware = load_optional_firmware_distribution(RESOURCES / "firmware" / "runtime")
    scrcpy = load_optional_scrcpy_distribution(RESOURCES / "scrcpy" / "runtime")
    updates = load_optional_update_distribution(RESOURCES / "updates" / "runtime" / "manifest.json")
    support = load_optional_support_recipient(RESOURCES / "support" / "recipient-public-key.pem")
    keybox = load_optional_keybox_revocations(RESOURCES / "keybox" / "revocations.json")

    wiring: dict[str, object] = {
        "platform_tools_catalog": platform_tools.catalog if platform_tools else None,
        "platform_tools_downloader": platform_tools.downloader if platform_tools else None,
        "patch_resource_registry": load_optional_packaged_patch_resource_registry(REPOSITORY_ROOT),
        "root_app_catalog": root_apps.catalog if root_apps else None,
        "root_app_downloader": root_apps.downloader if root_apps else None,
        "firmware_catalog": firmware.catalog if firmware else None,
        "firmware_downloader": firmware.downloader if firmware else None,
        "scrcpy_catalog": scrcpy.catalog if scrcpy else None,
        "scrcpy_downloader": scrcpy.downloader if scrcpy else None,
        "update_manifest_source": updates.source if updates else None,
        "update_manifest_verifier": updates.verifier if updates else None,
        "support_recipient_public_key": support.public_key_pem if support else None,
        "support_key_id": support.key_id if support else None,
        "keybox_revocation_provider": keybox.provider if keybox else None,
    }
    wiring.update(overrides)
    return ApplicationRuntime.open(config_path, **wiring)  # type: ignore[arg-type]


def provisioned_distributions() -> dict[str, bool]:
    """Report which distributions a session will actually have available."""

    return {
        "platformTools": load_optional_platform_tools_distribution(
            RESOURCES / "platform-tools" / "runtime"
        )
        is not None,
        "rootApps": load_optional_root_app_distribution(RESOURCES / "root-apps" / "runtime") is not None,
        "firmware": load_optional_firmware_distribution(RESOURCES / "firmware" / "runtime") is not None,
        "scrcpy": load_optional_scrcpy_distribution(RESOURCES / "scrcpy" / "runtime") is not None,
        "updates": load_optional_update_distribution(
            RESOURCES / "updates" / "runtime" / "manifest.json"
        )
        is not None,
        "supportRecipient": load_optional_support_recipient(
            RESOURCES / "support" / "recipient-public-key.pem"
        )
        is not None,
        "keyboxRevocations": load_optional_keybox_revocations(
            RESOURCES / "keybox" / "revocations.json"
        )
        is not None,
    }
